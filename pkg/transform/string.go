package transform

import (
	"context"
	"fmt"
	"strings"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type stringConfig struct {
	Object config.Object `json:"object"`
}

type stringToLower struct {
	sourceKey string
	targetKey string
}

func newStringToLower(ctx context.Context, cfg config.Config) (*stringToLower, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform string_to_lower: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey
	}
	return &stringToLower{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
	}, nil
}

func (t *stringToLower) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}
	if err := msg.SetValue(t.targetKey, strings.ToLower(v.String())); err != nil {
		return nil, fmt.Errorf("transform string_to_lower: %v", err)
	}
	return []*message.Message{msg}, nil
}

type stringToUpper struct {
	sourceKey string
	targetKey string
}

func newStringToUpper(ctx context.Context, cfg config.Config) (*stringToUpper, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform string_to_upper: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey
	}
	return &stringToUpper{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
	}, nil
}

func (t *stringToUpper) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}
	if err := msg.SetValue(t.targetKey, strings.ToUpper(v.String())); err != nil {
		return nil, fmt.Errorf("transform string_to_upper: %v", err)
	}
	return []*message.Message{msg}, nil
}

type stringReplaceConfig struct {
	Object  config.Object `json:"object"`
	Pattern string        `json:"pattern"`
	Replace string        `json:"replacement"`
}

type stringReplace struct {
	sourceKey string
	targetKey string
	pattern   string
	replace   string
}

func newStringReplace(ctx context.Context, cfg config.Config) (*stringReplace, error) {
	var conf stringReplaceConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform string_replace: %v", err)
	}
	targetKey := conf.Object.TargetKey
	if targetKey == "" {
		targetKey = conf.Object.SourceKey
	}
	return &stringReplace{
		sourceKey: conf.Object.SourceKey,
		targetKey: targetKey,
		pattern:   conf.Pattern,
		replace:   conf.Replace,
	}, nil
}

func (t *stringReplace) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}
	replaced := strings.ReplaceAll(v.String(), t.pattern, t.replace)
	if err := msg.SetValue(t.targetKey, replaced); err != nil {
		return nil, fmt.Errorf("transform string_replace: %v", err)
	}
	return []*message.Message{msg}, nil
}
