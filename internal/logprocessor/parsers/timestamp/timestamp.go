package timestamp

import (
	"encoding/json"
	"time"
)

type RFC3339 time.Time

func Parse(layout, value string) (RFC3339, error) {
	t, err := time.Parse(layout, value)
	if err != nil {
		return RFC3339{}, err
	}
	return RFC3339(t), nil
}

func Unix(sec, nsec int64) RFC3339 {
	return RFC3339(time.Unix(sec, nsec))
}

func (t RFC3339) Time() time.Time {
	return time.Time(t)
}

func (t *RFC3339) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*t = RFC3339(parsed)
	return nil
}

func (t RFC3339) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(time.RFC3339))
}
