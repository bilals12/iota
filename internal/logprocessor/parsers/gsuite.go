package parsers

import (
	"encoding/json"
	"fmt"

	"github.com/bilals12/iota/internal/logprocessor/parsers/timestamp"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type GSuiteParser struct{}

func NewGSuiteParser() *GSuiteParser {
	return &GSuiteParser{}
}

func (p *GSuiteParser) LogType() string {
	return "GSuite.Reports"
}

func (p *GSuiteParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var event GSuiteReports
	if err := json.Unmarshal([]byte(log), &event); err != nil {
		return nil, fmt.Errorf("failed to parse GSuite log: %w", err)
	}

	if event.ID == nil {
		return nil, fmt.Errorf("missing id")
	}

	if event.ID.Time == nil {
		return nil, fmt.Errorf("missing time in id")
	}

	eventTime := event.ID.Time.Time()

	if event.Kind != "admin#reports#activity" {
		return nil, fmt.Errorf("invalid kind: expected admin#reports#activity, got %s", event.Kind)
	}

	var sourceIP string
	if event.IPAddress != nil {
		sourceIP = string(*event.IPAddress)
	}

	eventName := "GSuiteActivity"
	if len(event.Events) > 0 && event.Events[0].Name != nil {
		eventName = string(*event.Events[0].Name)
	}

	uniqueQualifier := ""
	if event.ID.UniqueQualifier != nil {
		uniqueQualifier = string(*event.ID.UniqueQualifier)
	}

	eventID := fmt.Sprintf("gsuite-%s-%s", eventTime.Format("20060102150405"), uniqueQualifier)
	if event.ID.CustomerID != nil {
		eventID = fmt.Sprintf("gsuite-%s-%s-%s", string(*event.ID.CustomerID), eventTime.Format("20060102150405"), uniqueQualifier)
	}

	gsuiteData := map[string]interface{}{
		"id":          event.ID,
		"actor":       event.Actor,
		"kind":        event.Kind,
		"ownerDomain": event.OwnerDomain,
		"ipAddress":   event.IPAddress,
		"events":      event.Events,
	}

	ctEvent := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventTime:          eventTime,
		EventSource:        "googleapis.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    sourceIP,
		UserAgent:          "",
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "GSuiteActivity",
		RecipientAccountID: "",
		RequestParameters:  gsuiteData,
	}

	return []*cloudtrail.Event{ctEvent}, nil
}

var _ ParserInterface = (*GSuiteParser)(nil)

type GSuiteReports struct {
	ID          *GSuiteID     `json:"id"`
	Actor       *GSuiteActor  `json:"actor"`
	Kind        GSuiteString  `json:"kind"`
	OwnerDomain *GSuiteString `json:"ownerDomain,omitempty"`
	IPAddress   *GSuiteString `json:"ipAddress,omitempty"`
	Events      []GSuiteEvent `json:"events"`
}

type GSuiteID struct {
	ApplicationName *GSuiteString      `json:"applicationName"`
	CustomerID      *GSuiteString      `json:"customerId"`
	Time            *timestamp.RFC3339 `json:"time"`
	UniqueQualifier *GSuiteString      `json:"uniqueQualifier"`
}

type GSuiteActor struct {
	Email      *GSuiteString `json:"email,omitempty"`
	ProfileID  *GSuiteString `json:"profileId,omitempty"`
	CallerType *GSuiteString `json:"callerType,omitempty"`
	Key        *GSuiteString `json:"key,omitempty"`
}

type GSuiteEvent struct {
	Type       *GSuiteString     `json:"type,omitempty"`
	Name       *GSuiteString     `json:"name,omitempty"`
	Parameters []GSuiteParameter `json:"parameters,omitempty"`
}

type GSuiteParameter struct {
	Name              *GSuiteString     `json:"name,omitempty"`
	Value             *GSuiteString     `json:"value,omitempty"`
	IntValue          *int64            `json:"intValue,omitempty"`
	BoolValue         *bool             `json:"boolValue,omitempty"`
	MultiValue        []string          `json:"multiValue,omitempty"`
	MultiIntValue     []int64           `json:"multiIntValue,omitempty"`
	MessageValue      json.RawMessage   `json:"messageValue,omitempty"`
	MultiMessageValue []json.RawMessage `json:"multiMessageValue,omitempty"`
}

type GSuiteString string

func (s *GSuiteString) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = GSuiteString(str)
	return nil
}

func (s GSuiteString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}
