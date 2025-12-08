package transform

import (
	"context"
	"fmt"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type Transformer interface {
	Transform(context.Context, *message.Message) ([]*message.Message, error)
}

type Factory func(context.Context, config.Config) (Transformer, error)

func New(ctx context.Context, cfg config.Config) (Transformer, error) {
	switch cfg.Type {
	case "object_copy":
		return newObjectCopy(ctx, cfg)
	case "object_delete":
		return newObjectDelete(ctx, cfg)
	case "object_insert":
		return newObjectInsert(ctx, cfg)
	case "string_to_lower":
		return newStringToLower(ctx, cfg)
	case "string_to_upper":
		return newStringToUpper(ctx, cfg)
	case "string_replace":
		return newStringReplace(ctx, cfg)
	case "meta_switch":
		return newMetaSwitch(ctx, cfg)
	case "meta_for_each":
		return newMetaForEach(ctx, cfg)
	case "utility_drop":
		return newUtilityDrop(ctx, cfg)
	case "utility_control":
		return newUtilityControl(ctx, cfg)
	case "send_stdout":
		return newSendStdout(ctx, cfg)
	case "detect":
		return newDetect(ctx, cfg)
	case "alert":
		return newAlert(ctx, cfg)
	case "enrich_dns_reverse":
		return newEnrichDNSReverse(ctx, cfg)
	case "enrich_dns_forward":
		return newEnrichDNSForward(ctx, cfg)
	case "enrich_http_get":
		return newEnrichHTTPGet(ctx, cfg)
	case "enrich_geoip":
		return newEnrichGeoIP(ctx, cfg)
	case "send_slack":
		return newSendSlack(ctx, cfg)
	case "send_http_post":
		return newSendHTTPPost(ctx, cfg)
	default:
		return nil, fmt.Errorf("transform %s: unknown type", cfg.Type)
	}
}

func Apply(ctx context.Context, tfs []Transformer, msgs ...*message.Message) ([]*message.Message, error) {
	result := make([]*message.Message, len(msgs))
	copy(result, msgs)

	for i := 0; len(result) > 0 && i < len(tfs); i++ {
		var next []*message.Message
		for _, m := range result {
			out, err := tfs[i].Transform(ctx, m)
			if err != nil {
				return nil, err
			}
			next = append(next, out...)
		}
		result = next
	}

	return result, nil
}
