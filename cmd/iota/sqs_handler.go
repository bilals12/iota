package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/bilals12/iota/internal/alertforwarder"
	"github.com/bilals12/iota/internal/alerts"
	"github.com/bilals12/iota/internal/bloom"
	"github.com/bilals12/iota/internal/datalake"
	"github.com/bilals12/iota/internal/deduplication"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/events"
	gluecatalog "github.com/bilals12/iota/internal/glue"
	"github.com/bilals12/iota/internal/logprocessor"
	"github.com/bilals12/iota/internal/state"
	"github.com/bilals12/iota/internal/telemetry"
	"github.com/bilals12/iota/pkg/cloudtrail"
	"go.opentelemetry.io/otel/attribute"
)

func runSQS(ctx context.Context, queueURL, s3Bucket, region, rulesDir, python, enginePy, stateFile, dataLakeBucket, bloomFile string, bloomExpectedItems uint64, bloomFalsePositive float64, downloadWorkers, processWorkers int, glueDatabase, athenaWorkgroup, athenaResultBucket string, slackClient *alerts.SlackClient) error {
	log.Printf("starting SQS processor: queue=%s", queueURL)

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	sqsClient := sqs.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)

	stateDB, err := state.Open(stateFile)
	if err != nil {
		return fmt.Errorf("open state database: %w", err)
	}
	defer stateDB.Close()

	eng := engine.New(python, enginePy, rulesDir)

	var bloomFilter *bloom.Filter
	if bloomFile != "" {
		var err error
		bloomFilter, err = bloom.Load(bloomFile, uint(bloomExpectedItems), bloomFalsePositive)
		if err != nil {
			return fmt.Errorf("load bloom filter: %w", err)
		}
		defer func() {
			if err := bloomFilter.Save(); err != nil {
				log.Printf("warning: failed to save bloom filter: %v", err)
			}
		}()
	}

	var processor *logprocessor.Processor
	if bloomFilter != nil {
		processor = logprocessor.NewWithBloomFilter(bloomFilter)
	} else {
		processor = logprocessor.New()
	}

	dedup, err := deduplication.New(stateFile)
	if err != nil {
		return fmt.Errorf("create deduplicator: %w", err)
	}
	defer dedup.Close()

	var outputs []alertforwarder.Output
	if slackClient != nil {
		outputs = append(outputs, alerts.NewSlackOutput(slackClient.WebhookURL()))
	}

	forwarder := alertforwarder.New(dedup, outputs)

	var dataLakeWriter *datalake.Writer
	if dataLakeBucket != "" {
		if glueDatabase != "" {
			glueClient := gluecatalog.New(glue.NewFromConfig(awsCfg), glueDatabase, dataLakeBucket)
			if err := glueClient.EnsureDatabase(ctx); err != nil {
				log.Printf("warning: failed to ensure glue database: %v", err)
			}
			dataLakeWriter = datalake.NewWithGlue(s3Client, dataLakeBucket, 50*1024*1024, time.Minute, glueClient)
		} else {
			dataLakeWriter = datalake.New(s3Client, dataLakeBucket, 50*1024*1024, time.Minute)
		}
		defer dataLakeWriter.Flush(ctx)
	}

	handler := func(ctx context.Context, bucket, key string) error {
		op, ctx := telemetry.StartOperation(ctx, "process_s3_object",
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		)

		accountID, eventRegion, err := events.ExtractAccountRegionFromKey(key)
		if err != nil {
			log.Printf("warning: failed to parse s3 key, skipping state check: %v", err)
			accountID = "unknown"
			eventRegion = "unknown"
		}
		op.SetAttributes(
			attribute.String("aws.account_id", accountID),
			attribute.String("aws.region", eventRegion),
		)

		lastKey, err := stateDB.GetLastProcessedKey(bucket, accountID, eventRegion)
		if err != nil {
			log.Printf("warning: failed to get last processed key: %v", err)
		}

		if lastKey == key {
			log.Printf("skipping already processed s3 object: s3://%s/%s", bucket, key)
			op.SetAttributes(attribute.Bool("skipped", true))
			op.End(nil)
			return nil
		}

		log.Printf("processing s3 object: s3://%s/%s", bucket, key)

		downloadCtx, downloadSpan := telemetry.StartSpan(ctx, "s3.GetObject")
		result, err := s3Client.GetObject(downloadCtx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		downloadSpan.End()
		if err != nil {
			op.End(err)
			return fmt.Errorf("get object: %w", err)
		}
		defer result.Body.Close()

		processCtx, processSpan := telemetry.StartSpan(ctx, "logprocessor.Process")
		processedEvents, errs := processor.Process(processCtx, result.Body)

		var batch []*cloudtrail.Event
		for event := range processedEvents {
			if dataLakeWriter != nil {
				if err := dataLakeWriter.WriteEvent(ctx, event); err != nil {
					log.Printf("error writing to data lake: %v", err)
				}
			}

			batch = append(batch, event.Event)
		}

		if err := <-errs; err != nil {
			processSpan.End()
			op.End(err)
			return fmt.Errorf("process events: %w", err)
		}
		processSpan.End()

		op.SetAttributes(attribute.Int("events.count", len(batch)))

		if len(batch) == 0 {
			if accountID != "unknown" && eventRegion != "unknown" {
				if err := stateDB.UpdateLastProcessedKey(bucket, accountID, eventRegion, key); err != nil {
					log.Printf("warning: failed to update state: %v", err)
				}
			}
			op.End(nil)
			return nil
		}

		analyzeCtx, analyzeSpan := telemetry.StartSpan(ctx, "engine.Analyze")
		analyzeSpan.SetAttributes(attribute.Int("events.count", len(batch)))
		matches, err := eng.Analyze(analyzeCtx, batch)
		analyzeSpan.End()
		if err != nil {
			op.End(err)
			return fmt.Errorf("analyze: %w", err)
		}

		op.SetAttributes(attribute.Int("matches.count", len(matches)))

		for _, match := range matches {
			if err := forwarder.ProcessMatch(ctx, match, 60); err != nil {
				log.Printf("error processing match: %v", err)
			}
		}

		if accountID != "unknown" && eventRegion != "unknown" {
			if err := stateDB.UpdateLastProcessedKey(bucket, accountID, eventRegion, key); err != nil {
				log.Printf("warning: failed to update state: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		op.End(nil)
		return nil
	}

	sqsProcessor := events.NewSQSProcessor(sqsClient, events.Config{
		QueueURL:    queueURL,
		Handler:     handler,
		MaxMessages: 10,
		WaitTime:    20,
	})

	log.Println("SQS processor started, press ctrl+c to stop")
	return sqsProcessor.Process(ctx)
}
