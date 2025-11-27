package reader

import (
	"context"
	"strings"
	"testing"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

func TestReader(t *testing.T) {
	jsonl := `{"eventVersion":"1.08","eventTime":"2024-01-01T00:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4","userAgent":"Mozilla","requestID":"req-123","eventID":"event-123","eventType":"AwsApiCall","recipientAccountId":"123456789012","userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012"}}
{"eventVersion":"1.08","eventTime":"2024-01-01T00:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4","userAgent":"aws-cli","requestID":"req-456","eventID":"event-456","eventType":"AwsApiCall","recipientAccountId":"123456789012","userIdentity":{"type":"IAMUser","principalId":"AIDAI123","arn":"arn:aws:iam::123456789012:user/test","accountId":"123456789012","userName":"test"}}`

	r := New()
	ctx := context.Background()

	var buf strings.Builder
	buf.WriteString(jsonl)

	events := make(chan *cloudtrail.Event, 10)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)
		if err := r.read(ctx, strings.NewReader(buf.String()), events); err != nil {
			errs <- err
		}
	}()

	var count int
	for event := range events {
		if event != nil {
			count++
		}
	}

	if err := <-errs; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 events, got %d", count)
	}
}
