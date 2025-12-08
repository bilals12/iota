package transform

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type objectCopyConfig struct {
	Object config.Object `json:"object"`
}

type objectCopy struct {
	sourceKey string
	targetKey string
}

func newObjectCopy(ctx context.Context, cfg config.Config) (*objectCopy, error) {
	var conf objectCopyConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform object_copy: %v", err)
	}
	return &objectCopy{
		sourceKey: conf.Object.SourceKey,
		targetKey: conf.Object.TargetKey,
	}, nil
}

func (t *objectCopy) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	v := msg.GetValue(t.sourceKey)
	if !v.Exists() {
		return []*message.Message{msg}, nil
	}
	if err := msg.SetValue(t.targetKey, v.Value()); err != nil {
		return nil, fmt.Errorf("transform object_copy: %v", err)
	}
	return []*message.Message{msg}, nil
}

type objectDeleteConfig struct {
	Object config.Object `json:"object"`
}

type objectDelete struct {
	key string
}

func newObjectDelete(ctx context.Context, cfg config.Config) (*objectDelete, error) {
	var conf objectDeleteConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform object_delete: %v", err)
	}
	return &objectDelete{key: conf.Object.SourceKey}, nil
}

func (t *objectDelete) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	if err := msg.DeleteValue(t.key); err != nil {
		return nil, fmt.Errorf("transform object_delete: %v", err)
	}
	return []*message.Message{msg}, nil
}

type objectInsertConfig struct {
	Object config.Object `json:"object"`
	Value  interface{}   `json:"value"`
}

type objectInsert struct {
	key   string
	value interface{}
}

func newObjectInsert(ctx context.Context, cfg config.Config) (*objectInsert, error) {
	var conf objectInsertConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform object_insert: %v", err)
	}
	return &objectInsert{
		key:   conf.Object.TargetKey,
		value: conf.Value,
	}, nil
}

func (t *objectInsert) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	if err := msg.SetValue(t.key, t.value); err != nil {
		return nil, fmt.Errorf("transform object_insert: %v", err)
	}
	return []*message.Message{msg}, nil
}
