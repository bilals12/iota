package condition

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type numberConfig struct {
	Object config.Object `json:"object"`
	Value  float64       `json:"value"`
}

type numberEquals struct {
	key   string
	value float64
}

func newNumberEquals(ctx context.Context, cfg config.Config) (*numberEquals, error) {
	var conf numberConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition number_equals: %v", err)
	}
	return &numberEquals{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *numberEquals) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return v.Float() == c.value, nil
}

type numberGreaterThan struct {
	key   string
	value float64
}

func newNumberGreaterThan(ctx context.Context, cfg config.Config) (*numberGreaterThan, error) {
	var conf numberConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition number_greater_than: %v", err)
	}
	return &numberGreaterThan{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *numberGreaterThan) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return v.Float() > c.value, nil
}

type numberLessThan struct {
	key   string
	value float64
}

func newNumberLessThan(ctx context.Context, cfg config.Config) (*numberLessThan, error) {
	var conf numberConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition number_less_than: %v", err)
	}
	return &numberLessThan{
		key:   conf.Object.SourceKey,
		value: conf.Value,
	}, nil
}

func (c *numberLessThan) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	v := msg.GetValue(c.key)
	if !v.Exists() {
		return false, nil
	}
	return v.Float() < c.value, nil
}
