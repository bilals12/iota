package parsers

import (
	"encoding/json"
	"fmt"

	"github.com/bilals12/iota/internal/logprocessor/parsers/timestamp"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type OktaParser struct{}

func NewOktaParser() *OktaParser {
	return &OktaParser{}
}

func (p *OktaParser) LogType() string {
	return "Okta.SystemLog"
}

func (p *OktaParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var event OktaLogEvent
	if err := json.Unmarshal([]byte(log), &event); err != nil {
		return nil, fmt.Errorf("failed to parse Okta log: %w", err)
	}

	if event.UUID == nil {
		return nil, fmt.Errorf("missing UUID")
	}

	if event.Published == nil {
		return nil, fmt.Errorf("missing published timestamp")
	}

	eventTime := event.Published.Time()

	var sourceIP string
	var userAgent string

	if event.Client != nil {
		if event.Client.IPAddress != nil {
			sourceIP = *event.Client.IPAddress
		}
		if event.Client.UserAgent != nil && event.Client.UserAgent.RawUserAgent != nil {
			userAgent = *event.Client.UserAgent.RawUserAgent
		}
	}

	if event.Request != nil && len(event.Request.IPChain) > 0 {
		if event.Request.IPChain[0].IP != nil {
			sourceIP = *event.Request.IPChain[0].IP
		}
	}

	eventName := "OktaEvent"
	if event.EventType != nil {
		eventName = *event.EventType
	}

	oktaData := map[string]interface{}{
		"uuid":                  event.UUID,
		"eventType":             event.EventType,
		"version":               event.Version,
		"severity":              event.Severity,
		"displayMessage":        event.DisplayMessage,
		"actor":                 event.Actor,
		"client":                event.Client,
		"request":               event.Request,
		"outcome":               event.Outcome,
		"target":                event.Target,
		"transaction":           event.Transaction,
		"authenticationContext": event.AuthenticationContext,
		"securityContext":       event.SecurityContext,
	}

	ctEvent := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventTime:          eventTime,
		EventSource:        "okta.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    sourceIP,
		UserAgent:          userAgent,
		RequestID:          *event.UUID,
		EventID:            *event.UUID,
		EventType:          "OktaSystemLog",
		RecipientAccountID: "",
		RequestParameters:  oktaData,
	}

	return []*cloudtrail.Event{ctEvent}, nil
}

var _ ParserInterface = (*OktaParser)(nil)

type OktaLogEvent struct {
	UUID                  *string                    `json:"uuid"`
	Published             *timestamp.RFC3339         `json:"published"`
	EventType             *string                    `json:"eventType"`
	Version               *string                    `json:"version"`
	Severity              *string                    `json:"severity"`
	LegacyEventType       *string                    `json:"legacyEventType,omitempty"`
	DisplayMessage        *string                    `json:"displayMessage,omitempty"`
	Actor                 *OktaActor                 `json:"actor,omitempty"`
	Client                *OktaClient                `json:"client,omitempty"`
	Request               *OktaRequest               `json:"request,omitempty"`
	Outcome               *OktaOutcome               `json:"outcome,omitempty"`
	Target                []OktaTarget               `json:"target,omitempty"`
	Transaction           *OktaTransaction           `json:"transaction,omitempty"`
	DebugContext          *OktaDebugContext          `json:"debugContext,omitempty"`
	AuthenticationContext *OktaAuthenticationContext `json:"authenticationContext,omitempty"`
	SecurityContext       *OktaSecurityContext       `json:"securityContext,omitempty"`
}

type OktaActor struct {
	ID          *string         `json:"id"`
	Type        *string         `json:"type"`
	AlternateID *string         `json:"alternateId,omitempty"`
	DisplayName *string         `json:"displayName,omitempty"`
	Details     json.RawMessage `json:"details,omitempty"`
}

type OktaClient struct {
	ID                  *string                  `json:"id,omitempty"`
	UserAgent           *OktaUserAgent           `json:"userAgent,omitempty"`
	GeographicalContext *OktaGeographicalContext `json:"geographicalContext,omitempty"`
	Zone                *string                  `json:"zone,omitempty"`
	IPAddress           *string                  `json:"ipAddress,omitempty"`
	Device              *string                  `json:"device,omitempty"`
}

type OktaUserAgent struct {
	Browser      *string `json:"browser,omitempty"`
	OS           *string `json:"os,omitempty"`
	RawUserAgent *string `json:"rawUserAgent,omitempty"`
}

type OktaGeographicalContext struct {
	GeoLocation *OktaGeoLocation `json:"geolocation,omitempty"`
	City        *string          `json:"city,omitempty"`
	State       *string          `json:"state,omitempty"`
	Country     *string          `json:"country,omitempty"`
	PostalCode  *string          `json:"postalCode,omitempty"`
}

type OktaGeoLocation struct {
	Latitude  *float64 `json:"lat"`
	Longitude *float64 `json:"lon"`
}

type OktaTarget struct {
	ID          *string         `json:"id"`
	Type        *string         `json:"type"`
	AlternateID *string         `json:"alternateId,omitempty"`
	DisplayName *string         `json:"displayName,omitempty"`
	Details     json.RawMessage `json:"details,omitempty"`
}

type OktaRequest struct {
	IPChain []OktaIPAddress `json:"ipChain,omitempty"`
}

type OktaIPAddress struct {
	IP                  *string                  `json:"ip,omitempty"`
	GeographicalContext *OktaGeographicalContext `json:"geographicalContext,omitempty"`
	Version             *string                  `json:"version,omitempty"`
	Source              *string                  `json:"source,omitempty"`
}

type OktaOutcome struct {
	Result *string `json:"result,omitempty"`
	Reason *string `json:"reason,omitempty"`
}

type OktaTransaction struct {
	ID     *string         `json:"id,omitempty"`
	Type   *string         `json:"type,omitempty"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

type OktaDebugContext struct {
	DebugData json.RawMessage `json:"debugData,omitempty"`
}

type OktaAuthenticationContext struct {
	AuthenticationProvider *string     `json:"authenticatorProvider,omitempty"`
	AuthenticationStep     *int32      `json:"authenticationStep,omitempty"`
	CredentialProvider     *string     `json:"credentialProvider,omitempty"`
	CredentialType         *string     `json:"credentialType,omitempty"`
	Issuer                 *OktaIssuer `json:"issuer,omitempty"`
	ExternalSessionID      *string     `json:"externalSessionId,omitempty"`
	Interface              *string     `json:"interface,omitempty"`
}

type OktaIssuer struct {
	ID   *string `json:"id,omitempty"`
	Type *string `json:"type,omitempty"`
}

type OktaSecurityContext struct {
	AutonomousSystemNumber       *int64  `json:"asNumber,omitempty"`
	AutonomousSystemOrganization *string `json:"asOrg,omitempty"`
	ISP                          *string `json:"isp,omitempty"`
	Domain                       *string `json:"domain,omitempty"`
	IsProxy                      *bool   `json:"isProxy,omitempty"`
}
