package query

import (
	"testing"
	"time"
)

func TestBuildS3Paths(t *testing.T) {
	client := &DuckDBClient{
		s3Bucket: "test-bucket",
	}

	tests := []struct {
		name     string
		logType  string
		start    time.Time
		end      time.Time
		expected int
	}{
		{
			name:     "single hour",
			logType:  "cloudtrail",
			start:    time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			expected: 1,
		},
		{
			name:     "24 hours",
			logType:  "cloudtrail",
			start:    time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 15, 23, 59, 0, 0, time.UTC),
			expected: 24,
		},
		{
			name:     "cross day",
			logType:  "cloudtrail",
			start:    time.Date(2024, 1, 15, 22, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 16, 2, 0, 0, 0, time.UTC),
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := client.buildS3Paths(tt.logType, TimeRange{tt.start, tt.end})
			if len(paths) != tt.expected {
				t.Errorf("expected %d paths, got %d", tt.expected, len(paths))
				for i, p := range paths {
					t.Logf("  path[%d]: %s", i, p)
				}
			}
		})
	}
}

func TestBuildTableSource(t *testing.T) {
	client := &DuckDBClient{}

	tests := []struct {
		name     string
		paths    []string
		expected string
	}{
		{
			name:     "single path",
			paths:    []string{"s3://bucket/cloudtrail/year=2024/month=01/day=15/hour=10/*.parquet"},
			expected: "read_parquet('s3://bucket/cloudtrail/year=2024/month=01/day=15/hour=10/*.parquet', hive_partitioning=true)",
		},
		{
			name:     "multiple paths",
			paths:    []string{"s3://bucket/a/*.parquet", "s3://bucket/b/*.parquet"},
			expected: "read_parquet(['s3://bucket/a/*.parquet', 's3://bucket/b/*.parquet'], hive_partitioning=true)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.buildTableSource(tt.paths)
			if result != tt.expected {
				t.Errorf("expected:\n%s\ngot:\n%s", tt.expected, result)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"24h", 24 * time.Hour, false},
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseDurationHelper(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func parseDurationHelper(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}
	return time.ParseDuration(s)
}

func TestMergeResults(t *testing.T) {
	a := &QueryResult{
		Columns: []string{"col1", "col2"},
		Rows:    [][]interface{}{{"a1", "a2"}, {"b1", "b2"}},
		Elapsed: 100 * time.Millisecond,
	}
	b := &QueryResult{
		Columns: []string{"col1", "col2"},
		Rows:    [][]interface{}{{"c1", "c2"}},
		Elapsed: 50 * time.Millisecond,
	}

	merged := mergeResults(a, b)

	if len(merged.Rows) != 3 {
		t.Errorf("expected 3 rows, got %d", len(merged.Rows))
	}
	if merged.Elapsed != 150*time.Millisecond {
		t.Errorf("expected 150ms elapsed, got %v", merged.Elapsed)
	}
}

func TestMergeResultsNil(t *testing.T) {
	a := &QueryResult{
		Columns: []string{"col1"},
		Rows:    [][]interface{}{{"a"}},
	}

	if mergeResults(nil, a) != a {
		t.Error("expected merge(nil, a) = a")
	}

	if mergeResults(a, nil) != a {
		t.Error("expected merge(a, nil) = a")
	}
}
