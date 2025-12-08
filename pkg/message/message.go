package message

import (
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const metaPrefix = "meta "

type Message struct {
	data []byte
	meta []byte
	ctrl bool
}

func New(opts ...func(*Message)) *Message {
	msg := &Message{}
	for _, o := range opts {
		o(msg)
	}
	return msg
}

func WithData(data []byte) func(*Message) {
	return func(m *Message) {
		m.data = data
	}
}

func WithMetadata(meta []byte) func(*Message) {
	return func(m *Message) {
		m.meta = meta
	}
}

func (m *Message) AsControl() *Message {
	m.data = nil
	m.meta = nil
	m.ctrl = true
	return m
}

func (m *Message) IsControl() bool {
	return m.ctrl
}

func (m *Message) Data() []byte {
	if m.ctrl {
		return nil
	}
	return m.data
}

func (m *Message) SetData(data []byte) *Message {
	if m.ctrl {
		return m
	}
	m.data = data
	return m
}

func (m *Message) Metadata() []byte {
	if m.ctrl {
		return nil
	}
	return m.meta
}

func (m *Message) SetMetadata(metadata []byte) *Message {
	if m.ctrl {
		return m
	}
	m.meta = metadata
	return m
}

func (m *Message) String() string {
	return string(m.data)
}

func (m *Message) GetValue(key string) Value {
	if strings.HasPrefix(key, metaPrefix) {
		key = strings.TrimPrefix(key, metaPrefix)
		key = strings.TrimSpace(key)
		return Value{result: gjson.GetBytes(m.meta, key)}
	}
	key = strings.TrimSpace(key)
	return Value{result: gjson.GetBytes(m.data, key)}
}

func (m *Message) SetValue(key string, value interface{}) error {
	if strings.HasPrefix(key, metaPrefix) {
		key = strings.TrimPrefix(key, metaPrefix)
		key = strings.TrimSpace(key)
		meta, err := sjson.SetBytes(m.meta, key, value)
		if err != nil {
			return err
		}
		m.meta = meta
		return nil
	}
	key = strings.TrimSpace(key)
	data, err := sjson.SetBytes(m.data, key, value)
	if err != nil {
		return err
	}
	m.data = data
	return nil
}

func (m *Message) DeleteValue(key string) error {
	if strings.HasPrefix(key, metaPrefix) {
		key = strings.TrimPrefix(key, metaPrefix)
		key = strings.TrimSpace(key)
		meta, err := sjson.DeleteBytes(m.meta, key)
		if err != nil {
			return err
		}
		m.meta = meta
		return nil
	}
	key = strings.TrimSpace(key)
	data, err := sjson.DeleteBytes(m.data, key)
	if err != nil {
		return err
	}
	m.data = data
	return nil
}

func (m *Message) Copy() *Message {
	cp := &Message{
		ctrl: m.ctrl,
	}
	if m.data != nil {
		cp.data = make([]byte, len(m.data))
		copy(cp.data, m.data)
	}
	if m.meta != nil {
		cp.meta = make([]byte, len(m.meta))
		copy(cp.meta, m.meta)
	}
	return cp
}

type Value struct {
	result gjson.Result
}

func (v Value) Exists() bool {
	return v.result.Exists()
}

func (v Value) String() string {
	return v.result.String()
}

func (v Value) Bytes() []byte {
	return []byte(v.result.String())
}

func (v Value) Int() int64 {
	return v.result.Int()
}

func (v Value) Uint() uint64 {
	return v.result.Uint()
}

func (v Value) Float() float64 {
	return v.result.Float()
}

func (v Value) Bool() bool {
	return v.result.Bool()
}

func (v Value) IsArray() bool {
	return v.result.IsArray()
}

func (v Value) IsObject() bool {
	return v.result.IsObject()
}

func (v Value) Array() []Value {
	var values []Value
	for _, r := range v.result.Array() {
		values = append(values, Value{result: r})
	}
	return values
}

func (v Value) Map() map[string]Value {
	values := make(map[string]Value)
	for k, r := range v.result.Map() {
		values[k] = Value{result: r}
	}
	return values
}

func (v Value) Raw() string {
	return v.result.Raw
}

func (v Value) Value() interface{} {
	return v.result.Value()
}

func (v Value) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.result.Value())
}
