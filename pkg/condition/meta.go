package condition

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type metaConfig struct {
	Conditions []config.Config `json:"conditions"`
}

type metaAll struct {
	conditions []Conditioner
}

func newMetaAll(ctx context.Context, cfg config.Config) (*metaAll, error) {
	var conf metaConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition meta_all: %v", err)
	}

	conditions := make([]Conditioner, len(conf.Conditions))
	for i, c := range conf.Conditions {
		cond, err := New(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("condition meta_all: %v", err)
		}
		conditions[i] = cond
	}

	return &metaAll{conditions: conditions}, nil
}

func (c *metaAll) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	for _, cond := range c.conditions {
		ok, err := cond.Condition(ctx, msg)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

type metaAny struct {
	conditions []Conditioner
}

func newMetaAny(ctx context.Context, cfg config.Config) (*metaAny, error) {
	var conf metaConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition meta_any: %v", err)
	}

	conditions := make([]Conditioner, len(conf.Conditions))
	for i, c := range conf.Conditions {
		cond, err := New(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("condition meta_any: %v", err)
		}
		conditions[i] = cond
	}

	return &metaAny{conditions: conditions}, nil
}

func (c *metaAny) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	for _, cond := range c.conditions {
		ok, err := cond.Condition(ctx, msg)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

type metaNone struct {
	conditions []Conditioner
}

func newMetaNone(ctx context.Context, cfg config.Config) (*metaNone, error) {
	var conf metaConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition meta_none: %v", err)
	}

	conditions := make([]Conditioner, len(conf.Conditions))
	for i, c := range conf.Conditions {
		cond, err := New(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("condition meta_none: %v", err)
		}
		conditions[i] = cond
	}

	return &metaNone{conditions: conditions}, nil
}

func (c *metaNone) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	for _, cond := range c.conditions {
		ok, err := cond.Condition(ctx, msg)
		if err != nil {
			return false, err
		}
		if ok {
			return false, nil
		}
	}
	return true, nil
}
