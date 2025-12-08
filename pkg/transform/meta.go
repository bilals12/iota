package transform

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/condition"
	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type metaSwitchCase struct {
	Condition  config.Config   `json:"condition"`
	Transforms []config.Config `json:"transforms"`
}

type metaSwitchConfig struct {
	Cases []metaSwitchCase `json:"cases"`
}

type switchCase struct {
	condition  condition.Conditioner
	transforms []Transformer
	isDefault  bool
}

type metaSwitch struct {
	cases []switchCase
}

type defaultCondition struct{}

func (c *defaultCondition) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	return true, nil
}

func newMetaSwitch(ctx context.Context, cfg config.Config) (*metaSwitch, error) {
	var conf metaSwitchConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform meta_switch: %v", err)
	}

	cases := make([]switchCase, len(conf.Cases))
	for i, c := range conf.Cases {
		sc := switchCase{}

		if c.Condition.Type == "" {
			sc.condition = &defaultCondition{}
			sc.isDefault = true
		} else {
			cond, err := condition.New(ctx, c.Condition)
			if err != nil {
				return nil, fmt.Errorf("transform meta_switch: %v", err)
			}
			sc.condition = cond
		}

		for _, tc := range c.Transforms {
			tf, err := New(ctx, tc)
			if err != nil {
				return nil, fmt.Errorf("transform meta_switch: %v", err)
			}
			sc.transforms = append(sc.transforms, tf)
		}

		cases[i] = sc
	}

	return &metaSwitch{cases: cases}, nil
}

func (t *metaSwitch) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		var results []*message.Message
		for _, c := range t.cases {
			out, err := Apply(ctx, c.transforms, msg)
			if err != nil {
				return nil, err
			}
			results = append(results, out...)
		}
		var filtered []*message.Message
		for _, m := range results {
			if !m.IsControl() {
				filtered = append(filtered, m)
			}
		}
		filtered = append(filtered, msg)
		return filtered, nil
	}

	for _, c := range t.cases {
		ok, err := c.condition.Condition(ctx, msg)
		if err != nil {
			return nil, err
		}
		if ok {
			return Apply(ctx, c.transforms, msg)
		}
	}

	return []*message.Message{msg}, nil
}

type metaForEachConfig struct {
	Object     config.Object   `json:"object"`
	Transforms []config.Config `json:"transforms"`
}

type metaForEach struct {
	key        string
	transforms []Transformer
}

func newMetaForEach(ctx context.Context, cfg config.Config) (*metaForEach, error) {
	var conf metaForEachConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform meta_for_each: %v", err)
	}

	transforms := make([]Transformer, len(conf.Transforms))
	for i, tc := range conf.Transforms {
		tf, err := New(ctx, tc)
		if err != nil {
			return nil, fmt.Errorf("transform meta_for_each: %v", err)
		}
		transforms[i] = tf
	}

	return &metaForEach{
		key:        conf.Object.SourceKey,
		transforms: transforms,
	}, nil
}

func (t *metaForEach) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return Apply(ctx, t.transforms, msg)
	}

	v := msg.GetValue(t.key)
	if !v.IsArray() {
		return []*message.Message{msg}, nil
	}

	var results []*message.Message
	for _, item := range v.Array() {
		itemMsg := message.New(message.WithData(item.Bytes()))
		out, err := Apply(ctx, t.transforms, itemMsg)
		if err != nil {
			return nil, err
		}
		results = append(results, out...)
	}

	return results, nil
}
