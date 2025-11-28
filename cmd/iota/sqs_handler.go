package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/bilals12/iota/internal/alerts"
	"github.com/bilals12/iota/internal/alertforwarder"
	"github.com/bilals12/iota/internal/datalake"
	"github.com/bilals12/iota/internal/deduplication"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/events"
	"github.com/bilals12/iota/internal/logprocessor"
	"github.com/bilals12/iota/pkg/cloudtrail"
	"time"
)

func runSQS(ctx context.Context, queueURL, s3Bucket, region, rulesDir, python, enginePy, stateFile, dataLakeBucket string, slackClient *alerts.SlackClient) error {
	log.Printf("starting SQS processor: queue=%s", queueURL)

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	sqsClient := sqs.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)

	eng := engine.New(python, enginePy, rulesDir)
	processor := logprocessor.New()

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
		dataLakeWriter = datalake.New(s3Client, dataLakeBucket, 50*1024*1024, time.Minute)
		defer dataLakeWriter.Flush(ctx)
	}

	handler := func(ctx context.Context, bucket, key string) error {
		log.Printf("processing s3 object: s3://%s/%s", bucket, key)

		result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return fmt.Errorf("get object: %w", err)
		}
		defer result.Body.Close()

		processedEvents, errs := processor.Process(ctx, result.Body)

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
			return fmt.Errorf("process events: %w", err)
		}

		if len(batch) == 0 {
			return nil
		}

		matches, err := eng.Analyze(ctx, batch)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}

		for _, match := range matches {
			if err := forwarder.ProcessMatch(ctx, match, 60); err != nil {
				log.Printf("error processing match: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
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
