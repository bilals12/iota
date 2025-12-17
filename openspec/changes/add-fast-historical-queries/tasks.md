# Tasks: Fast Historical Query Engine

## Phase 1: Foundation

- [ ] Add `github.com/marcboeker/go-duckdb` dependency
- [ ] Create `internal/query/duckdb.go` with basic client
- [ ] Test DuckDB can query local Parquet files
- [ ] Configure httpfs extension for S3 access
- [ ] Test DuckDB can query S3 Parquet with IAM credentials

## Phase 2: Query Engine

- [ ] Create `internal/query/engine.go` with routing logic
- [ ] Implement time-range based query routing
- [ ] Implement S3 path generation from time range
- [ ] Add memory limit configuration
- [ ] Add result merging for split queries (recent + historical)

## Phase 3: CLI Interface

- [ ] Create `cmd/iota/query.go` command
- [ ] Implement `--sql`, `--log-type`, `--last`, `--range` flags
- [ ] Implement `--output` formats: table, json, csv
- [ ] Add `--force-athena` flag for comparison
- [ ] Add query timing output

## Phase 4: Data Lake Format (Optional)

- [ ] Update data lake writer to support Parquet output
- [ ] Add configuration for JSON vs Parquet format
- [ ] Update Glue catalog for Parquet tables
- [ ] Test both DuckDB and Athena can query Parquet

## Phase 5: Testing & Documentation

- [ ] Add unit tests for query routing
- [ ] Add integration tests with sample data
- [ ] Benchmark DuckDB vs Athena latency
- [ ] Document CLI usage
- [ ] Update architecture docs

## Acceptance Criteria

1. `iota query --sql "SELECT * FROM cloudtrail WHERE eventName='ConsoleLogin'" --last 7d` returns results in <5 seconds
2. Query routing correctly uses DuckDB for recent data, Athena for historical
3. Results are consistent between DuckDB and Athena for same query
4. Memory limits prevent OOM on large queries
