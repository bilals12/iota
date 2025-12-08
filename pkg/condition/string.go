package condition

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type stringConfig struct {
	Object config.Object `json:"object"`
	Value  string        `json:"value"`
}

type stringContains struct {
	key   string
	value string
}

func newStringContains(ctx context.Context, cfg config.Config) (*stringContains, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition string_contains: %v", err)
	}
	return &stringContains{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *stringContains) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return strings.Contains(v.String(), c.value), nil
}

type stringEquals struct {
	key   string
	value string
}

func newStringEquals(ctx context.Context, cfg config.Config) (*stringEquals, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition string_equals: %v", err)
	}
	return &stringEquals{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *stringEquals) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return v.String() == c.value, nil
}

type stringStartsWith struct {
	key   string
	value string
}

func newStringStartsWith(ctx context.Context, cfg config.Config) (*stringStartsWith, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition string_starts_with: %v", err)
	}
	return &stringStartsWith{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *stringStartsWith) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return strings.HasPrefix(v.String(), c.value), nil
}

type stringEndsWith struct {
	key   string
	value string
}

func newStringEndsWith(ctx context.Context, cfg config.Config) (*stringEndsWith, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition string_ends_with: %v", err)
	}
	return &stringEndsWith{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *stringEndsWith) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return strings.HasSuffix(v.String(), c.value), nil
}

type stringMatch struct {
	key   string
	regex *regexp.Regexp
}

func newStringMatch(ctx context.Context, cfg config.Config) (*stringMatch, error) {
	var conf stringConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition string_match: %v", err)
	}
	re, err := regexp.Compile(conf.Value)
	if err != nil {
		return nil, fmt.Errorf("condition string_match: %v", err)
	}
	return &stringMatch{
		key:   conf.Object.SourceKey,
		regex: re,
	}, nil
}

func (c *stringMatch) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return c.regex.MatchString(v.String()), nil
}
