package config

import (
	"encoding/json"

	"github.com/mitchellh/mapstructure"
)

type Config struct {
	Type     string                 `json:"type"`
	Settings map[string]interface{} `json:"settings"`
}

func (c Config) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}

func Decode(input interface{}, output interface{}) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           output,
		TagName:          "json",
		WeaklyTypedInput: true,
	})
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}

type Object struct {
	SourceKey string `json:"source_key"`
	TargetKey string `json:"target_key"`
	BatchKey  string `json:"batch_key"`
}

type Batch struct {
	Count    int    `json:"count"`
	Size     int    `json:"size"`
	Duration string `json:"duration"`
}
