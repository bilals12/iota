package condition

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type existsConfig struct {
	Object config.Object `json:"object"`
}

type exists struct {
	key string
}

func newExists(ctx context.Context, cfg config.Config) (*exists, error) {
	var conf existsConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("condition exists: %v", err)
	}
	return &exists{key: conf.Object.SourceKey}, nil
}

func (c *exists) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	return msg.GetValue(c.key).Exists(), nil
}

type formatJSON struct{}

func newFormatJSON(ctx context.Context, cfg config.Config) (*formatJSON, error) {
	return &formatJSON{}, nil
}

func (c *formatJSON) Condition(ctx context.Context, msg *message.Message) (bool, error) {
	return json.Valid(msg.Data()), nil
}
