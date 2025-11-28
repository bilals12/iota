package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bilals12/iota/internal/alerts"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/reader"
	"github.com/bilals12/iota/internal/s3poller"
	"github.com/bilals12/iota/internal/watcher"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		mode         = flag.String("mode", "sqs", "mode: once, watch, s3-poll, or sqs")
		jsonlFile    = flag.String("jsonl", "", "path to jsonl file (once mode)")
		eventsDir    = flag.String("events-dir", "", "path to events directory (watch mode)")
		s3Bucket     = flag.String("s3-bucket", "", "S3 bucket name (s3-poll or sqs mode)")
		s3Prefix     = flag.String("s3-prefix", "AWSLogs/", "S3 prefix (s3-poll mode)")
		sqsQueueURL  = flag.String("sqs-queue-url", "", "SQS queue URL (sqs mode)")
		pollInterval = flag.String("poll-interval", "5m", "polling interval (s3-poll mode)")
		awsRegion    = flag.String("aws-region", "us-east-1", "AWS region")
		rulesDir     = flag.String("rules", "", "path to rules directory")
		python       = flag.String("python", "python3", "python executable path")
		enginePy     = flag.String("engine", "engines/iota/engine.py", "path to engine.py")
		stateFile    = flag.String("state", "iota.db", "path to state database")
		slackWebhook = flag.String("slack-webhook", "", "slack webhook url for alerts")
		dataLakeBucket = flag.String("data-lake-bucket", "", "S3 bucket for processed data lake (optional)")
	)
	flag.Parse()

	if *rulesDir == "" {
		return fmt.Errorf("rules flag is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("received shutdown signal")
		cancel()
	}()

	var slackClient *alerts.SlackClient
	if *slackWebhook != "" {
		slackClient = alerts.NewSlackClient(*slackWebhook)
	}

	switch *mode {
	case "once":
		return runOnce(ctx, *jsonlFile, *rulesDir, *python, *enginePy, slackClient)
	case "watch":
		return runWatch(ctx, *eventsDir, *rulesDir, *python, *enginePy, *stateFile, slackClient)
	case "s3-poll":
		interval, err := time.ParseDuration(*pollInterval)
		if err != nil {
			return fmt.Errorf("invalid poll-interval: %w", err)
		}
		return runS3Poll(ctx, *s3Bucket, *s3Prefix, *awsRegion, interval, *rulesDir, *python, *enginePy, *stateFile, slackClient)
	case "sqs":
		if *sqsQueueURL == "" {
			return fmt.Errorf("sqs-queue-url flag is required in sqs mode")
		}
		return runSQS(ctx, *sqsQueueURL, *s3Bucket, *awsRegion, *rulesDir, *python, *enginePy, *stateFile, *dataLakeBucket, slackClient)
	default:
		return fmt.Errorf("invalid mode: %s (must be once, watch, s3-poll, or sqs)", *mode)
	}
}

func runOnce(ctx context.Context, jsonlFile, rulesDir, python, enginePy string, slackClient *alerts.SlackClient) error {
	if jsonlFile == "" {
		return fmt.Errorf("jsonl flag is required in once mode")
	}

	r := reader.New()
	events, errs := r.ReadFile(ctx, jsonlFile)

	var batch []*cloudtrail.Event
	for event := range events {
		batch = append(batch, event)
	}

	if err := <-errs; err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	eng := engine.New(python, enginePy, rulesDir)
	matches, err := eng.Analyze(ctx, batch)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	for _, match := range matches {
		if err := handleAlert(match, slackClient); err != nil {
			log.Printf("error handling alert: %v", err)
		}
	}

	return nil
}

func runWatch(ctx context.Context, eventsDir, rulesDir, python, enginePy, stateFile string, slackClient *alerts.SlackClient) error {
	if eventsDir == "" {
		return fmt.Errorf("events-dir flag is required in watch mode")
	}

	log.Printf("starting watcher on %s", eventsDir)

	eng := engine.New(python, enginePy, rulesDir)
	r := reader.New()

	handler := func(path string) error {
		log.Printf("processing file: %s", path)

		events, errs := r.ReadFile(ctx, path)

		var batch []*cloudtrail.Event
		for event := range events {
			batch = append(batch, event)
		}

		if err := <-errs; err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		if len(batch) == 0 {
			return nil
		}

		matches, err := eng.Analyze(ctx, batch)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}

		for _, match := range matches {
			if err := handleAlert(match, slackClient); err != nil {
				log.Printf("error handling alert: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		return nil
	}

	w, err := watcher.New(eventsDir, stateFile, handler)
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer w.Close()

	log.Println("watcher started, press ctrl+c to stop")
	return w.Watch(ctx)
}

func runS3Poll(ctx context.Context, bucket, prefix, region string, interval time.Duration, rulesDir, python, enginePy, stateFile string, slackClient *alerts.SlackClient) error {
	if bucket == "" {
		return fmt.Errorf("s3-bucket flag is required in s3-poll mode")
	}

	log.Printf("starting S3 poller: bucket=%s prefix=%s interval=%v", bucket, prefix, interval)

	eng := engine.New(python, enginePy, rulesDir)
	r := reader.New()

	// Handler function that processes CloudTrail JSON from S3
	handler := func(ioReader io.Reader) error {
		events, errs := r.Read(ctx, ioReader)

		var batch []*cloudtrail.Event
		for event := range events {
			batch = append(batch, event)
		}

		if err := <-errs; err != nil {
			return fmt.Errorf("read events: %w", err)
		}

		if len(batch) == 0 {
			return nil
		}

		matches, err := eng.Analyze(ctx, batch)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}

		for _, match := range matches {
			if err := handleAlert(match, slackClient); err != nil {
				log.Printf("error handling alert: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		return nil
	}

	poller, err := s3poller.New(ctx, s3poller.Config{
		Bucket:   bucket,
		Prefix:   prefix,
		StateFile: stateFile,
		Handler:  handler,
		Interval: interval,
		Region:   region,
	})
	if err != nil {
		return fmt.Errorf("create S3 poller: %w", err)
	}
	defer poller.Close()

	log.Println("S3 poller started, press ctrl+c to stop")
	return poller.Poll(ctx)
}

func handleAlert(match engine.Match, slackClient *alerts.SlackClient) error {
	output, err := json.MarshalIndent(match, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	fmt.Println(string(output))

	if slackClient != nil {
		if err := slackClient.SendAlert(match); err != nil {
			return fmt.Errorf("send to slack: %w", err)
		}
		log.Printf("sent alert to slack: %s", match.Title)
	}

	return nil
}
