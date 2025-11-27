package cloudtrail

import "time"

type Event struct {
	EventVersion       string                 `json:"eventVersion"`
	UserIdentity       UserIdentity           `json:"userIdentity"`
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
	Resources          []Resource             `json:"resources,omitempty"`
}

type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalID    string          `json:"principalId"`
	ARN            string          `json:"arn"`
	AccountID      string          `json:"accountId"`
	AccessKeyID    string          `json:"accessKeyId,omitempty"`
	UserName       string          `json:"userName,omitempty"`
	SessionContext *SessionContext `json:"sessionContext,omitempty"`
}

type SessionContext struct {
	Attributes    SessionAttributes `json:"attributes"`
	SessionIssuer *SessionIssuer    `json:"sessionIssuer,omitempty"`
}

type SessionAttributes struct {
	MFAAuthenticated string    `json:"mfaAuthenticated"`
	CreationDate     time.Time `json:"creationDate"`
}

type SessionIssuer struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName,omitempty"`
}

type Resource struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

func (e *Event) Get(key string) interface{} {
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

func (e *Event) DeepGet(keys ...string) interface{} {
	if len(keys) == 0 {
		return nil
	}

	if keys[0] == "userIdentity" {
		if len(keys) == 1 {
			return e.UserIdentity
		}
		switch keys[1] {
		case "type":
			return e.UserIdentity.Type
		case "arn":
			return e.UserIdentity.ARN
		case "accountId":
			return e.UserIdentity.AccountID
		}
	}

	if keys[0] == "responseElements" && len(keys) > 1 {
		if e.ResponseElements != nil {
			return e.ResponseElements[keys[1]]
		}
	}

	return nil
}
