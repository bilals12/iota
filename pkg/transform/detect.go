package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bilals12/iota/pkg/condition"
	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
	"github.com/google/uuid"
)

type detectConfig struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	Tags        []string      `json:"tags"`
	Condition   config.Config `json:"condition"`
	DedupKey    string        `json:"dedup_key"`
	Threshold   int           `json:"threshold"`
}

type detect struct {
	id          string
	title       string
	description string
	severity    string
	tags        []string
	condition   condition.Conditioner
	dedupKey    string
	threshold   int
}

func newDetect(ctx context.Context, cfg config.Config) (*detect, error) {
	var conf detectConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform detect: %v", err)
	}

	if conf.ID == "" {
		return nil, fmt.Errorf("transform detect: id is required")
	}

	if conf.Condition.Type == "" {
		return nil, fmt.Errorf("transform detect: condition is required")
	}

	cond, err := condition.New(ctx, conf.Condition)
	if err != nil {
		return nil, fmt.Errorf("transform detect: %v", err)
	}

	severity := conf.Severity
	if severity == "" {
		severity = "INFO"
	}

	threshold := conf.Threshold
	if threshold == 0 {
		threshold = 1
	}

	return &detect{
		id:          conf.ID,
		title:       conf.Title,
		description: conf.Description,
		severity:    severity,
		tags:        conf.Tags,
		condition:   cond,
		dedupKey:    conf.DedupKey,
		threshold:   threshold,
	}, nil
}

func (t *detect) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}

	ok, err := t.condition.Condition(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("transform detect %s: %v", t.id, err)
	}

	if !ok {
		return []*message.Message{msg}, nil
	}

	dedupValue := ""
	if t.dedupKey != "" {
		dedupValue = msg.GetValue(t.dedupKey).String()
	}

	alert := Alert{
		ID:          uuid.New().String(),
		RuleID:      t.id,
		Title:       t.title,
		Description: t.description,
		Severity:    t.severity,
		Tags:        t.tags,
		DedupKey:    dedupValue,
		Threshold:   t.threshold,
		Timestamp:   time.Now().UTC(),
		Event:       msg.Data(),
	}

	alertData, err := json.Marshal(alert)
	if err != nil {
		return nil, fmt.Errorf("transform detect %s: %v", t.id, err)
	}

	if err := msg.SetValue("meta alert", json.RawMessage(alertData)); err != nil {
		return nil, fmt.Errorf("transform detect %s: %v", t.id, err)
	}

	return []*message.Message{msg}, nil
}

type Alert struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags"`
	DedupKey    string    `json:"dedup_key"`
	Threshold   int       `json:"threshold"`
	Timestamp   time.Time `json:"timestamp"`
	Event       []byte    `json:"event"`
}

type alertConfig struct {
	Outputs []config.Config `json:"outputs"`
}

type alert struct {
	outputs []Transformer
}

func newAlert(ctx context.Context, cfg config.Config) (*alert, error) {
	var conf alertConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform alert: %v", err)
	}

	outputs := make([]Transformer, len(conf.Outputs))
	for i, oc := range conf.Outputs {
		tf, err := New(ctx, oc)
		if err != nil {
			return nil, fmt.Errorf("transform alert: %v", err)
		}
		outputs[i] = tf
	}

	return &alert{outputs: outputs}, nil
}

func (t *alert) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return Apply(ctx, t.outputs, msg)
	}

	alertVal := msg.GetValue("meta alert")
	if !alertVal.Exists() {
		return []*message.Message{msg}, nil
	}

	alertMsg := message.New(message.WithData(alertVal.Bytes()))
	_, err := Apply(ctx, t.outputs, alertMsg)
	if err != nil {
		return nil, err
	}

	return []*message.Message{msg}, nil
}
