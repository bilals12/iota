package parsers

import (
	"encoding/json"
	"fmt"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type ParserInterface interface {
	ParseLog(log string) ([]*cloudtrail.Event, error)
	LogType() string
}

type CloudTrailParser struct{}

func NewCloudTrailParser() *CloudTrailParser {
	return &CloudTrailParser{}
}

func (p *CloudTrailParser) LogType() string {
	return "AWS.CloudTrail"
}

func (p *CloudTrailParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var event cloudtrail.Event
	if err := json.Unmarshal([]byte(log), &event); err != nil {
		return nil, fmt.Errorf("failed to parse CloudTrail event: %w", err)
	}

	if event.EventID == "" {
		return nil, fmt.Errorf("missing EventID")
	}

	return []*cloudtrail.Event{&event}, nil
}

var _ ParserInterface = (*CloudTrailParser)(nil)
