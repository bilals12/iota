package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-jsonnet"
)

//go:embed iota.libsonnet
var Library string

type JsonnetLoader struct {
	vm *jsonnet.VM
}

func NewJsonnetLoader() *JsonnetLoader {
	vm := jsonnet.MakeVM()

	vm.Importer(&jsonnet.FileImporter{
		JPaths: []string{"."},
	})

	return &JsonnetLoader{vm: vm}
}

func (l *JsonnetLoader) LoadFile(path string) ([]Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return l.Load(string(data), absPath)
}

func (l *JsonnetLoader) Load(snippet string, filename string) ([]Config, error) {
	jsonStr, err := l.vm.EvaluateAnonymousSnippet(filename, snippet)
	if err != nil {
		return nil, fmt.Errorf("evaluate jsonnet: %w", err)
	}

	var pipelineCfg struct {
		Transforms []Config `json:"transforms"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &pipelineCfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return pipelineCfg.Transforms, nil
}

func LoadConfig(path string) ([]Config, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".jsonnet", ".libsonnet":
		loader := NewJsonnetLoader()
		return loader.LoadFile(path)
	case ".json":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
		var pipelineCfg struct {
			Transforms []Config `json:"transforms"`
		}
		if err := json.Unmarshal(data, &pipelineCfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		return pipelineCfg.Transforms, nil
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}
}
