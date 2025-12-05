package parsers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type OnePasswordParser struct{}

func NewOnePasswordParser() *OnePasswordParser {
	return &OnePasswordParser{}
}

func (p *OnePasswordParser) LogType() string {
	return "OnePassword.SignInAttempt"
}

func (p *OnePasswordParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var event OnePasswordSignInAttempt
	if err := json.Unmarshal([]byte(log), &event); err != nil {
		return nil, fmt.Errorf("failed to parse 1Password log: %w", err)
	}

	if event.UUID == nil || *event.UUID == "" {
		return nil, fmt.Errorf("missing uuid")
	}

	if event.Timestamp == nil || *event.Timestamp == "" {
		return nil, fmt.Errorf("missing timestamp")
	}

	eventTime, err := time.Parse("2006-01-02 15:04:05", *event.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	var sourceIP string
	if event.Client != nil && event.Client.IPAddress != nil {
		sourceIP = *event.Client.IPAddress
	}

	eventName := "SignInAttempt"
	if event.Type != nil {
		eventName = *event.Type
	}

	onepasswordData := map[string]interface{}{
		"uuid":         event.UUID,
		"session_uuid": event.SessionUUID,
		"timestamp":    event.Timestamp,
		"category":     event.Category,
		"type":         event.Type,
		"country":      event.Country,
		"target_user":  event.TargetUser,
		"client":       event.Client,
	}

	ctEvent := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventTime:          eventTime,
		EventSource:        "1password.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    sourceIP,
		UserAgent:          "",
		RequestID:          *event.UUID,
		EventID:            *event.UUID,
		EventType:          "OnePasswordSignIn",
		RecipientAccountID: "",
		RequestParameters:  onepasswordData,
	}

	return []*cloudtrail.Event{ctEvent}, nil
}

var _ ParserInterface = (*OnePasswordParser)(nil)

type OnePasswordSignInAttempt struct {
	UUID        *string                `json:"uuid"`
	SessionUUID *string                `json:"session_uuid,omitempty"`
	Timestamp   *string                `json:"timestamp"`
	Category    *string                `json:"category"`
	Type        *string                `json:"type,omitempty"`
	Country     *string                `json:"country,omitempty"`
	TargetUser  *OnePasswordTargetUser `json:"target_user,omitempty"`
	Client      *OnePasswordClient     `json:"client,omitempty"`
}

type OnePasswordTargetUser struct {
	Email *string `json:"email,omitempty"`
	Name  *string `json:"name,omitempty"`
	UUID  *string `json:"uuid,omitempty"`
}

type OnePasswordClient struct {
	AppName         *string `json:"app_name,omitempty"`
	AppVersion      *string `json:"app_version,omitempty"`
	IPAddress       *string `json:"ip_address,omitempty"`
	OSName          *string `json:"os_name,omitempty"`
	OSVersion       *string `json:"os_version,omitempty"`
	PlatformName    *string `json:"platform_name,omitempty"`
	PlatformVersion *string `json:"platform_version,omitempty"`
}
