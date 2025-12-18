package query

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenaclient "github.com/bilals12/iota/internal/athena"
)

type TimeRange struct {
	Start time.Time
	End   time.Time
}

type Engine struct {
	duckdb    *DuckDBClient
	athena    *athenaclient.Client
	bucket    string
	threshold time.Duration
}

type EngineConfig struct {
	S3Region     string
	S3Bucket     string
	AthenaClient *athena.Client
	Workgroup    string
	Database     string
	ResultBucket string
	MemoryLimit  string
	Threshold    time.Duration
}

func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Threshold == 0 {
		cfg.Threshold = 30 * 24 * time.Hour
	}

	duckdb, err := NewDuckDB(DuckDBConfig{
		S3Region:    cfg.S3Region,
		S3Bucket:    cfg.S3Bucket,
		MemoryLimit: cfg.MemoryLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("create duckdb: %w", err)
	}

	var athenaClient *athenaclient.Client
	if cfg.AthenaClient != nil {
		athenaClient = athenaclient.New(cfg.AthenaClient, cfg.Workgroup, cfg.Database, cfg.ResultBucket)
	}

	return &Engine{
		duckdb:    duckdb,
		athena:    athenaClient,
		bucket:    cfg.S3Bucket,
		threshold: cfg.Threshold,
	}, nil
}

type QueryOptions struct {
	LogType     string
	ForceAthena bool
	ForceDuckDB bool
}

func (e *Engine) Query(ctx context.Context, sql string, tr TimeRange, opts QueryOptions) (*QueryResult, error) {
	if opts.ForceAthena {
		return e.queryAthena(ctx, opts.LogType, sql, tr)
	}
	if opts.ForceDuckDB {
		return e.duckdb.QueryS3(ctx, opts.LogType, sql, tr)
	}

	cutoff := time.Now().Add(-e.threshold)

	if tr.Start.After(cutoff) {
		return e.duckdb.QueryS3(ctx, opts.LogType, sql, tr)
	}

	if tr.End.Before(cutoff) {
		return e.queryAthena(ctx, opts.LogType, sql, tr)
	}

	recentResults, err := e.duckdb.QueryS3(ctx, opts.LogType, sql, TimeRange{cutoff, tr.End})
	if err != nil {
		return nil, fmt.Errorf("duckdb query: %w", err)
	}

	historicalResults, err := e.queryAthena(ctx, opts.LogType, sql, TimeRange{tr.Start, cutoff})
	if err != nil {
		return nil, fmt.Errorf("athena query: %w", err)
	}

	return mergeResults(recentResults, historicalResults), nil
}

func (e *Engine) QueryDuckDB(ctx context.Context, logType, sql string, tr TimeRange) (*QueryResult, error) {
	return e.duckdb.QueryS3(ctx, logType, sql, tr)
}

func (e *Engine) QueryAthena(ctx context.Context, logType, sql string, tr TimeRange) (*QueryResult, error) {
	return e.queryAthena(ctx, logType, sql, tr)
}

func (e *Engine) queryAthena(ctx context.Context, logType, sql string, tr TimeRange) (*QueryResult, error) {
	if e.athena == nil {
		return nil, fmt.Errorf("athena not configured")
	}

	start := time.Now()
	wrappedSQL := e.wrapWithPartitionFilter(sql, logType, tr)

	results, err := e.athena.RunQuery(ctx, wrappedSQL)
	if err != nil {
		return nil, err
	}

	return athenaToQueryResult(results, time.Since(start))
}

func (e *Engine) wrapWithPartitionFilter(sql, logType string, tr TimeRange) string {
	return sql
}

func athenaToQueryResult(results *athena.GetQueryResultsOutput, elapsed time.Duration) (*QueryResult, error) {
	if results.ResultSet == nil || len(results.ResultSet.Rows) == 0 {
		return &QueryResult{Columns: []string{}, Rows: [][]interface{}{}, Elapsed: elapsed}, nil
	}

	var columns []string
	if len(results.ResultSet.ResultSetMetadata.ColumnInfo) > 0 {
		for _, col := range results.ResultSet.ResultSetMetadata.ColumnInfo {
			columns = append(columns, *col.Name)
		}
	}

	var rows [][]interface{}
	for i, row := range results.ResultSet.Rows {
		if i == 0 {
			continue
		}
		var values []interface{}
		for _, data := range row.Data {
			if data.VarCharValue != nil {
				values = append(values, *data.VarCharValue)
			} else {
				values = append(values, nil)
			}
		}
		rows = append(rows, values)
	}

	return &QueryResult{
		Columns: columns,
		Rows:    rows,
		Elapsed: elapsed,
	}, nil
}

func mergeResults(a, b *QueryResult) *QueryResult {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}

	merged := &QueryResult{
		Columns: a.Columns,
		Rows:    make([][]interface{}, 0, len(a.Rows)+len(b.Rows)),
		Elapsed: a.Elapsed + b.Elapsed,
	}

	merged.Rows = append(merged.Rows, a.Rows...)
	merged.Rows = append(merged.Rows, b.Rows...)

	return merged
}

func (e *Engine) Close() error {
	if e.duckdb != nil {
		return e.duckdb.Close()
	}
	return nil
}
