package events

import (
	"encoding/json"
	"fmt"
	"time"
)

type EventBridgeEnvelope struct {
	Version    string          `json:"version"`
	ID         string          `json:"id"`
	DetailType string          `json:"detail-type"`
	Source     string          `json:"source"`
	Account    string          `json:"account"`
	Time       time.Time       `json:"time"`
	Region     string          `json:"region"`
	Resources  []string        `json:"resources,omitempty"`
	Detail     json.RawMessage `json:"detail"`
}

func IsEventBridgeEvent(data []byte) bool {
	var envelope struct {
		DetailType string          `json:"detail-type"`
		Source     string          `json:"source"`
		Detail     json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}
	return envelope.DetailType != "" && envelope.Source != "" && len(envelope.Detail) > 0
}

func UnwrapEventBridgeEvent(data []byte) ([]byte, *EventBridgeEnvelope, error) {
	if !IsEventBridgeEvent(data) {
		return data, nil, nil
	}

	var envelope EventBridgeEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, nil, fmt.Errorf("unmarshal eventbridge envelope: %w", err)
	}

	return envelope.Detail, &envelope, nil
}

func DetectEventSource(envelope *EventBridgeEnvelope) string {
	if envelope == nil {
		return ""
	}

	if envelope.Source == "aws.partner/okta.com" ||
		envelope.DetailType == "Okta Log Event" ||
		envelope.DetailType == "okta-systemlog" {
		return "Okta.SystemLog"
	}

	if envelope.Source == "aws.partner/1password.com" ||
		envelope.DetailType == "1Password Event" {
		return "OnePassword.SignInAttempt"
	}

	if envelope.Source == "aws.partner/sailpoint.com" {
		return "Sailpoint.Event"
	}

	if envelope.Source == "google.workspace" ||
		envelope.DetailType == "GSuite Activity" {
		return "GSuite.Reports"
	}

	return ""
}
