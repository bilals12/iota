package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
	"github.com/bilals12/iota/pkg/transform"
)

type Config struct {
	Transforms []config.Config `json:"transforms"`
}

type Pipeline struct {
	cfg    Config
	tforms []transform.Transformer
}

func New(ctx context.Context, cfg Config) (*Pipeline, error) {
	if len(cfg.Transforms) == 0 {
		return nil, fmt.Errorf("no transforms configured")
	}

	p := &Pipeline{cfg: cfg}

	for _, c := range cfg.Transforms {
		t, err := transform.New(ctx, c)
		if err != nil {
			return nil, err
		}
		p.tforms = append(p.tforms, t)
	}

	return p, nil
}

func NewFromFile(ctx context.Context, path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return New(ctx, cfg)
}

func (p *Pipeline) Transform(ctx context.Context, msgs ...*message.Message) ([]*message.Message, error) {
	return transform.Apply(ctx, p.tforms, msgs...)
}

func (p *Pipeline) Process(ctx context.Context, data []byte) ([]*message.Message, error) {
	msg := message.New(message.WithData(data))
	return p.Transform(ctx, msg)
}

func (p *Pipeline) ProcessBatch(ctx context.Context, batch [][]byte) ([]*message.Message, error) {
	msgs := make([]*message.Message, len(batch))
	for i, data := range batch {
		msgs[i] = message.New(message.WithData(data))
	}
	return p.Transform(ctx, msgs...)
}

func (p *Pipeline) Finalize(ctx context.Context) ([]*message.Message, error) {
	ctrl := message.New().AsControl()
	return p.Transform(ctx, ctrl)
}

func (p *Pipeline) String() string {
	b, _ := json.Marshal(p.cfg)
	return string(b)
}
