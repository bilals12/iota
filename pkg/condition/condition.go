package condition

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type Conditioner interface {
	Condition(context.Context, *message.Message) (bool, error)
}

type Factory func(context.Context, config.Config) (Conditioner, error)

func New(ctx context.Context, cfg config.Config) (Conditioner, error) {
	switch cfg.Type {
	case "all", "meta_all":
		return newMetaAll(ctx, cfg)
	case "any", "meta_any":
		return newMetaAny(ctx, cfg)
	case "none", "meta_none":
		return newMetaNone(ctx, cfg)
	case "string_contains":
		return newStringContains(ctx, cfg)
	case "string_equals":
		return newStringEquals(ctx, cfg)
	case "string_starts_with":
		return newStringStartsWith(ctx, cfg)
	case "string_ends_with":
		return newStringEndsWith(ctx, cfg)
	case "string_match":
		return newStringMatch(ctx, cfg)
	case "number_equals":
		return newNumberEquals(ctx, cfg)
	case "number_greater_than":
		return newNumberGreaterThan(ctx, cfg)
	case "number_less_than":
		return newNumberLessThan(ctx, cfg)
	case "exists":
		return newExists(ctx, cfg)
	case "format_json":
		return newFormatJSON(ctx, cfg)
	default:
		return nil, fmt.Errorf("condition %s: unknown type", cfg.Type)
	}
}
