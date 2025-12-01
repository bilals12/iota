package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type SQSProcessor struct {
	client      *sqs.Client
	queueURL    string
	handler     func(ctx context.Context, s3Bucket, s3Key string) error
	maxMessages int32
	waitTime    int32
}

type Config struct {
	QueueURL    string
	Handler     func(ctx context.Context, s3Bucket, s3Key string) error
	MaxMessages int32
	WaitTime    int32
}

func NewSQSProcessor(client *sqs.Client, cfg Config) *SQSProcessor {
	maxMessages := cfg.MaxMessages
	if maxMessages == 0 {
		maxMessages = 10
	}
	waitTime := cfg.WaitTime
	if waitTime == 0 {
		waitTime = 20
	}

	return &SQSProcessor{
		client:      client,
		queueURL:    cfg.QueueURL,
		handler:     cfg.Handler,
		maxMessages: maxMessages,
		waitTime:    waitTime,
	}
}

func (p *SQSProcessor) Process(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := p.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(p.queueURL),
			MaxNumberOfMessages: p.maxMessages,
			WaitTimeSeconds:     p.waitTime,
			VisibilityTimeout:   int32(300),
		})
		if err != nil {
			return fmt.Errorf("receive message: %w", err)
		}

		for _, message := range result.Messages {
			if err := p.processMessage(ctx, message); err != nil {
				continue
			}

			if _, err := p.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl:      aws.String(p.queueURL),
				ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				return fmt.Errorf("delete message: %w", err)
			}
		}
	}
}

func (p *SQSProcessor) processMessage(ctx context.Context, message types.Message) error {
	var snsMessage struct {
		Type             string `json:"Type"`
		Message          string `json:"Message"`
		MessageId        string `json:"MessageId"`
		Timestamp        string `json:"Timestamp"`
		TopicArn         string `json:"TopicArn"`
		SignatureVersion string `json:"SignatureVersion"`
		Signature        string `json:"Signature"`
		SigningCertURL   string `json:"SigningCertURL"`
		UnsubscribeURL  string `json:"UnsubscribeURL"`
	}

	if err := json.Unmarshal([]byte(*message.Body), &snsMessage); err != nil {
		return fmt.Errorf("unmarshal sns message: %w", err)
	}

	if snsMessage.Type != "Notification" {
		return nil
	}

	var s3Notification struct {
		Records []struct {
			EventVersion      string `json:"eventVersion"`
			EventSource       string `json:"eventSource"`
			AWSRegion         string `json:"awsRegion"`
			EventTime         string `json:"eventTime"`
			EventName         string `json:"eventName"`
			S3                struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key  string `json:"key"`
					Size int64  `json:"size"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
	}

	if err := json.Unmarshal([]byte(snsMessage.Message), &s3Notification); err != nil {
		return fmt.Errorf("unmarshal s3 notification: %w", err)
	}

	for _, record := range s3Notification.Records {
		if record.EventName != "ObjectCreated:Put" && record.EventName != "ObjectCreated:CompleteMultipartUpload" {
			continue
		}

		bucket := record.S3.Bucket.Name
		key := record.S3.Object.Key

		if err := p.handler(ctx, bucket, key); err != nil {
			return fmt.Errorf("handle s3 object %s/%s: %w", bucket, key, err)
		}
	}

	return nil
}


func ParseS3Notification(body string) ([]S3Object, error) {
	var snsMessage struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}

	if err := json.Unmarshal([]byte(body), &snsMessage); err != nil {
		return nil, fmt.Errorf("unmarshal sns message: %w", err)
	}

	if snsMessage.Type != "Notification" {
		return nil, nil
	}

	var s3Notification struct {
		Records []struct {
			EventName string `json:"eventName"`
			S3        struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key string `json:"key"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
	}

	if err := json.Unmarshal([]byte(snsMessage.Message), &s3Notification); err != nil {
		return nil, fmt.Errorf("unmarshal s3 notification: %w", err)
	}

	var objects []S3Object
	for _, record := range s3Notification.Records {
		if record.EventName != "ObjectCreated:Put" && record.EventName != "ObjectCreated:CompleteMultipartUpload" {
			continue
		}

		objects = append(objects, S3Object{
			Bucket: record.S3.Bucket.Name,
			Key:    record.S3.Object.Key,
		})
	}

	return objects, nil
}

type S3Object struct {
	Bucket string
	Key    string
}
