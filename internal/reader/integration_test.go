package reader

import (
	"context"
	"testing"
)

func TestReaderWithRealCloudTrail(t *testing.T) {
	r := New()
	ctx := context.Background()

	events, errs := r.ReadFile(ctx, "../../testdata/sample.jsonl")

	var count int
	for event := range events {
		if event != nil {
			count++
			t.Logf("parsed event: %s from %s", event.EventName, event.EventSource)
		}
	}

	if err := <-errs; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if count == 0 {
		t.Error("expected at least 1 event, got 0")
	}

	t.Logf("successfully parsed %d real cloudtrail events", count)
}
