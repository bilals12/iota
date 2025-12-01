package parsers

import (
	"testing"
)

func TestS3ServerAccessParser_ParseLog(t *testing.T) {
	parser := NewS3ServerAccessParser()

	logLine := "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be mybucket [06/Feb/2019:00:00:38 +0000] 192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 3E57427F3EXAMPLE REST.GET.BUCKET - \"GET /mybucket HTTP/1.1\" 200 - 113 - 7 - \"-\" \"S3Console/0.4\" - - - - - - -"

	events, err := parser.ParseLog(logLine)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got: %d", len(events))
	}

	event := events[0]
	if event.EventSource != "s3.amazonaws.com" {
		t.Errorf("expected EventSource 's3.amazonaws.com', got: %s", event.EventSource)
	}
	if event.EventName != "REST.GET.BUCKET" {
		t.Errorf("expected EventName 'REST.GET.BUCKET', got: %s", event.EventName)
	}
}
