package parsers

import (
	"testing"
)

func TestVPCFlowParser_HeaderDetection(t *testing.T) {
	parser := NewVPCFlowParser()

	headerLine := "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"

	result, err := parser.ParseLog(headerLine)
	if err != nil {
		t.Fatalf("expected no error for header line, got: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for header line, got: %v", result)
	}

	if parser.columnMap == nil {
		t.Fatal("expected columnMap to be populated after header detection")
	}
}

func TestVPCFlowParser_ParseLog(t *testing.T) {
	parser := NewVPCFlowParser()

	headerLine := "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
	_, _ = parser.ParseLog(headerLine)

	dataLine := "2 123456789012 eni-12345678 10.0.1.5 10.0.1.6 443 8080 6 10 1000 1234567890 1234567900 ACCEPT OK"

	events, err := parser.ParseLog(dataLine)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got: %d", len(events))
	}

	event := events[0]
	if event.EventName != "VPCFlow" {
		t.Errorf("expected EventName 'VPCFlow', got: %s", event.EventName)
	}
	if event.EventSource != "vpcflowlogs.amazonaws.com" {
		t.Errorf("expected EventSource 'vpcflowlogs.amazonaws.com', got: %s", event.EventSource)
	}
}
