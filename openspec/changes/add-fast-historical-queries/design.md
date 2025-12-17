# Design: Fast Historical Query Engine

## Technical Architecture

### DuckDB Integration

Use `github.com/marcboeker/go-duckdb` for Go bindings. DuckDB supports querying Parquet/JSON files on S3 directly via the `httpfs` extension.

```go
package duckdb

import (
    "context"
    "database/sql"
    "fmt"

    _ "github.com/marcboeker/go-duckdb"
)

type Client struct {
    db *sql.DB
}

func New(s3Region string) (*Client, error) {
    db, err := sql.Open("duckdb", "")
    if err != nil {
        return nil, err
    }

    // Load extensions and configure S3
    setup := []string{
        "INSTALL httpfs",
        "LOAD httpfs",
        fmt.Sprintf("SET s3_region='%s'", s3Region),
        "SET s3_use_ssl=true",
    }
    for _, stmt := range setup {
        if _, err := db.Exec(stmt); err != nil {
            return nil, fmt.Errorf("setup %s: %w", stmt, err)
        }
    }

    return &Client{db: db}, nil
}

func (c *Client) Query(ctx context.Context, sql string) (*QueryResult, error) {
    rows, err := c.db.QueryContext(ctx, sql)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    return scanResults(rows)
}
```

### S3 Path Generation

Generate S3 paths for DuckDB to query based on time range:

```go
func (c *Client) buildS3Paths(bucket, logType string, start, end time.Time) []string {
    var paths []string
    current := start.Truncate(time.Hour)

    for current.Before(end) {
        path := fmt.Sprintf(
            "s3://%s/%s/year=%d/month=%02d/day=%02d/hour=%02d/*.parquet",
            bucket, logType,
            current.Year(), current.Month(), current.Day(), current.Hour(),
        )
        paths = append(paths, path)
        current = current.Add(time.Hour)
    }

    return paths
}
```

### Query Interface

```go
type QueryEngine struct {
    duckdb    *duckdb.Client
    athena    *athena.Client
    bucket    string
    threshold time.Duration // Default: 30 days
}

type TimeRange struct {
    Start time.Time
    End   time.Time
}

func (q *QueryEngine) Query(ctx context.Context, logType, sql string, tr TimeRange) (*Results, error) {
    cutoff := time.Now().Add(-q.threshold)

    if tr.Start.After(cutoff) {
        // Entirely within DuckDB range
        return q.queryDuckDB(ctx, logType, sql, tr)
    }

    if tr.End.Before(cutoff) {
        // Entirely historical - use Athena
        return q.queryAthena(ctx, logType, sql, tr)
    }

    // Split query: DuckDB for recent, Athena for historical
    recentResults, err := q.queryDuckDB(ctx, logType, sql, TimeRange{cutoff, tr.End})
    if err != nil {
        return nil, err
    }

    historicalResults, err := q.queryAthena(ctx, logType, sql, TimeRange{tr.Start, cutoff})
    if err != nil {
        return nil, err
    }

    return mergeResults(recentResults, historicalResults), nil
}
```

### CLI Commands

```go
// cmd/iota/query.go

var queryCmd = &cobra.Command{
    Use:   "query",
    Short: "Query the data lake",
    RunE:  runQuery,
}

func init() {
    queryCmd.Flags().String("sql", "", "SQL query to execute")
    queryCmd.Flags().String("log-type", "cloudtrail", "Log type to query")
    queryCmd.Flags().Duration("last", 24*time.Hour, "Query last N duration (e.g., 7d, 24h)")
    queryCmd.Flags().String("range", "", "Date range YYYY-MM-DD:YYYY-MM-DD")
    queryCmd.Flags().String("output", "table", "Output format: table, json, csv")
    queryCmd.Flags().Bool("force-athena", false, "Force Athena even for recent data")
}

func runQuery(cmd *cobra.Command, args []string) error {
    sql, _ := cmd.Flags().GetString("sql")
    logType, _ := cmd.Flags().GetString("log-type")
    last, _ := cmd.Flags().GetDuration("last")
    forceAthena, _ := cmd.Flags().GetBool("force-athena")

    engine, err := query.NewEngine(cfg)
    if err != nil {
        return err
    }

    tr := query.TimeRange{
        Start: time.Now().Add(-last),
        End:   time.Now(),
    }

    var results *query.Results
    if forceAthena {
        results, err = engine.QueryAthena(ctx, logType, sql, tr)
    } else {
        results, err = engine.Query(ctx, logType, sql, tr)
    }

    return outputResults(results, outputFormat)
}
```

### Memory Management

DuckDB can use significant memory for large queries. Configure limits:

```go
func New(s3Region string, memoryLimit string) (*Client, error) {
    db, err := sql.Open("duckdb", "")
    if err != nil {
        return nil, err
    }

    setup := []string{
        fmt.Sprintf("SET memory_limit='%s'", memoryLimit), // e.g., "4GB"
        "SET threads=4",
        "SET temp_directory='/tmp/duckdb'",
        // ... httpfs setup
    }
    // ...
}
```

### Correlation Rules (Future)

Enable Python rules to perform lookups during detection:

```python
# rules/aws_cloudtrail/suspicious_login_from_new_country.py

def rule(event):
    if event.get("eventName") != "ConsoleLogin":
        return False

    user = event.get("userIdentity", {}).get("arn", "")
    country = event.get("sourceIPAddress_geo", {}).get("country", "")

    # Query recent logins for this user
    recent_countries = iota.query(
        "SELECT DISTINCT sourceIPAddress_geo.country FROM cloudtrail "
        "WHERE userIdentity.arn = ? AND eventName = 'ConsoleLogin'",
        [user],
        last="30d"
    )

    # Alert if logging in from a country never seen before
    return country not in recent_countries
```

This enables correlation rules that reference historical data without the Athena latency penalty.

## Data Lake Format

### Current: JSON (gzipped)

```
s3://bucket/cloudtrail/year=2024/month=12/day=17/hour=14/events.json.gz
```

### Recommended: Parquet

Parquet provides:
- 10-100x better compression than gzipped JSON
- Column pruning (only read needed columns)
- Predicate pushdown (filter at storage layer)
- Native support in DuckDB and Athena

Migration path:
1. Update data lake writer to output Parquet
2. Keep Glue catalog pointing to Parquet tables
3. Both DuckDB and Athena query same files

```go
func (w *DataLakeWriter) Flush(ctx context.Context) error {
    // Convert buffered events to Parquet
    parquetData, err := eventsToParquet(w.buffer)
    if err != nil {
        return err
    }

    key := fmt.Sprintf(
        "%s/year=%d/month=%02d/day=%02d/hour=%02d/events.parquet",
        w.logType, now.Year(), now.Month(), now.Day(), now.Hour(),
    )

    return w.s3.PutObject(ctx, w.bucket, key, parquetData)
}
```

## File Structure

```
internal/
├── query/
│   ├── engine.go      # Query routing logic
│   ├── duckdb.go      # DuckDB client
│   ├── results.go     # Result types and merging
│   └── paths.go       # S3 path generation
cmd/
└── iota/
    └── query.go       # CLI command
```

## Testing Strategy

1. **Unit tests**: Mock S3, test path generation and query routing
2. **Integration tests**: Local DuckDB with sample Parquet files
3. **Performance tests**: Benchmark against Athena with real data volumes

```go
func BenchmarkDuckDBQuery(b *testing.B) {
    // Setup: 1GB of Parquet data
    client, _ := duckdb.New("us-west-2", "4GB")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        client.Query(ctx, "SELECT COUNT(*) FROM read_parquet('s3://...')")
    }
}
```

## Dependencies

```go
// go.mod additions
require (
    github.com/marcboeker/go-duckdb v1.7.0
)
```

Note: go-duckdb requires CGO. Build with `CGO_ENABLED=1`.
