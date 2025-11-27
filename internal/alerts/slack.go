package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bilals12/iota/internal/engine"
)

type SlackClient struct {
	webhookURL string
	client     *http.Client
}

type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Blocks      []slackBlock      `json:"blocks,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackBlock struct {
	Type string         `json:"type"`
	Text *slackTextNode `json:"text,omitempty"`
}

type slackTextNode struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackAttachment struct {
	Color  string              `json:"color"`
	Blocks []slackBlock        `json:"blocks,omitempty"`
	Fields []slackAttachField  `json:"fields,omitempty"`
}

type slackAttachField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func NewSlackClient(webhookURL string) *SlackClient {
	return &SlackClient{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackClient) SendAlert(match engine.Match) error {
	msg := s.formatMessage(match)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

func (s *SlackClient) formatMessage(match engine.Match) slackMessage {
	color := severityColor(match.Severity)

	return slackMessage{
		Attachments: []slackAttachment{
			{
				Color: color,
				Blocks: []slackBlock{
					{
						Type: "header",
						Text: &slackTextNode{
							Type: "plain_text",
							Text: match.Title,
						},
					},
					{
						Type: "section",
						Text: &slackTextNode{
							Type: "mrkdwn",
							Text: fmt.Sprintf("*severity:* %s\n*rule:* %s\n*dedup:* %s",
								match.Severity, match.RuleID, match.Dedup),
						},
					},
				},
				Fields: []slackAttachField{
					{
						Title: "event name",
						Value: match.Event.EventName,
						Short: true,
					},
					{
						Title: "event source",
						Value: match.Event.EventSource,
						Short: true,
					},
					{
						Title: "source ip",
						Value: match.Event.SourceIPAddress,
						Short: true,
					},
					{
						Title: "region",
						Value: match.Event.AWSRegion,
						Short: true,
					},
					{
						Title: "user identity type",
						Value: match.Event.UserIdentity.Type,
						Short: true,
					},
					{
						Title: "account id",
						Value: match.Event.RecipientAccountID,
						Short: true,
					},
				},
			},
		},
	}
}

func severityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return "#d32f2f"
	case "HIGH":
		return "#f57c00"
	case "MEDIUM":
		return "#fbc02d"
	case "LOW":
		return "#689f38"
	case "INFO":
		return "#1976d2"
	default:
		return "#757575"
	}
}
