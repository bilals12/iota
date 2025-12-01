package event

import (
	"encoding/json"
	"time"
)

type Event struct {
	LogType         string                 `json:"logType"`
	EventTime       time.Time              `json:"eventTime"`
	EventID         string                 `json:"eventID,omitempty"`
	Data            map[string]interface{} `json:"data"`
}

func New(logType string, eventTime time.Time, data map[string]interface{}) *Event {
	return &Event{
		LogType:   logType,
		EventTime: eventTime,
		Data:      data,
	}
}

func (e *Event) Get(key string) interface{} {
	return e.Data[key]
}

func (e *Event) DeepGet(keys ...string) interface{} {
	if len(keys) == 0 {
		return nil
	}

	val := e.Data[keys[0]]
	if len(keys) == 1 {
		return val
	}

	if m, ok := val.(map[string]interface{}); ok {
		return deepGetFromMap(m, keys[1:])
	}

	return nil
}

func deepGetFromMap(m map[string]interface{}, keys []string) interface{} {
	if len(keys) == 0 {
		return nil
	}

	val := m[keys[0]]
	if len(keys) == 1 {
		return val
	}

	if nextMap, ok := val.(map[string]interface{}); ok {
		return deepGetFromMap(nextMap, keys[1:])
	}

	return nil
}

func (e *Event) ToCloudTrailEvent() (*CloudTrailEvent, error) {
	if e.LogType != "AWS.CloudTrail" {
		return nil, nil
	}

	dataBytes, err := json.Marshal(e.Data)
	if err != nil {
		return nil, err
	}

	var ctEvent CloudTrailEvent
	if err := json.Unmarshal(dataBytes, &ctEvent); err != nil {
		return nil, err
	}

	return &ctEvent, nil
}

type CloudTrailEvent struct {
	EventVersion       string                 `json:"eventVersion"`
	UserIdentity       map[string]interface{} `json:"userIdentity"`
	EventTime          time.Time              `json:"eventTime"`
	EventSource        string                 `json:"eventSource"`
	EventName          string                 `json:"eventName"`
	AWSRegion          string                 `json:"awsRegion"`
	SourceIPAddress    string                 `json:"sourceIPAddress"`
	UserAgent          string                 `json:"userAgent"`
	ErrorCode          string                 `json:"errorCode,omitempty"`
	ErrorMessage       string                 `json:"errorMessage,omitempty"`
	RequestParameters  map[string]interface{} `json:"requestParameters,omitempty"`
	ResponseElements   map[string]interface{} `json:"responseElements,omitempty"`
	RequestID          string                 `json:"requestID"`
	EventID            string                 `json:"eventID"`
	EventType          string                 `json:"eventType"`
	RecipientAccountID string                 `json:"recipientAccountId"`
	Resources          []map[string]interface{} `json:"resources,omitempty"`
}

func (e *CloudTrailEvent) Get(key string) interface{} {
	switch key {
	case "eventName":
		return e.EventName
	case "eventSource":
		return e.EventSource
	case "sourceIPAddress":
		return e.SourceIPAddress
	case "recipientAccountId":
		return e.RecipientAccountID
	default:
		return nil
	}
}

func (e *CloudTrailEvent) DeepGet(keys ...string) interface{} {
	if len(keys) == 0 {
		return nil
	}

	if keys[0] == "userIdentity" {
		if len(keys) == 1 {
			return e.UserIdentity
		}
		if e.UserIdentity != nil {
			return e.UserIdentity[keys[1]]
		}
	}

	if keys[0] == "responseElements" && len(keys) > 1 {
		if e.ResponseElements != nil {
			return e.ResponseElements[keys[1]]
		}
	}

	return nil
}
