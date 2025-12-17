# Proposal: Fast Historical Query Engine

## Problem Statement

Current Athena-based historical queries have latency characteristics unsuitable for incident response:

1. **Query queue time**: 2-10 seconds before query starts executing
2. **Scan time**: Proportional to data volume, typically 30s-5min for multi-day queries
3. **Poll interval**: 2-second polling in current implementation
4. **Total latency**: 30 seconds to 5+ minutes per query iteration

During incident response, analysts iterate rapidly through hypotheses. A 2-minute query latency means 10 iterations takes 20+ minutes. This kills investigation momentum and extends MTTR.

### Feedback from peer reviewer

> "Athena latency was killing us during investigations. We went a different direction on the query engine specifically because of this."

### When Athena works

- Scheduled compliance checks (latency irrelevant)
- Dashboard queries (cached results)
- Infrequent ad-hoc analysis (acceptable wait)

### When Athena fails

- Active incident response (need sub-10s iteration)
- Threat hunting sessions (many exploratory queries)
- Alert triage (quick context lookup)

## Proposed Solution

Add DuckDB as a fast query layer for recent data (7-30 days).

### Why DuckDB

| Feature | DuckDB | ClickHouse | Athena |
|---------|--------|------------|--------|
| Query latency (1GB) | <1s | <1s | 30-120s |
| Infrastructure | Embedded | Server cluster | Serverless |
| S3 direct query | Yes (httpfs) | Yes | Yes |
| Cost | $0 | Server costs | Per-scan |
| Complexity | Low | High | Low |

DuckDB fits iota's philosophy:
- **Embedded**: No additional infrastructure to manage
- **Fast**: Sub-second on 100M+ rows
- **Compatible**: Queries same Parquet/JSON on S3
- **Zero cost**: No runtime charges

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Query Interface                     │
│                    (CLI / API)                       │
└─────────────────────┬───────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
┌─────────────────┐      ┌─────────────────┐
│     DuckDB      │      │     Athena      │
│  (Recent Data)  │      │ (Historical)    │
│   0-30 days     │      │   30+ days      │
└────────┬────────┘      └────────┬────────┘
         │                        │
         └──────────┬─────────────┘
                    ▼
         ┌─────────────────┐
         │   S3 Data Lake  │
         │   (Parquet)     │
         └─────────────────┘
```

### Query routing

```go
func (q *QueryEngine) Query(ctx context.Context, sql string, timeRange TimeRange) (*Results, error) {
    if timeRange.End.After(time.Now().Add(-30 * 24 * time.Hour)) {
        // Recent data: use DuckDB for speed
        return q.duckdb.Query(ctx, sql)
    }
    // Historical data: use Athena for cost efficiency
    return q.athena.RunQuery(ctx, sql)
}
```

### CLI interface

```bash
# Fast query (DuckDB, sub-second)
iota query --sql "SELECT * FROM cloudtrail WHERE userIdentity.arn LIKE '%attacker%'" --last 7d

# Historical query (Athena, minutes)
iota query --sql "SELECT * FROM cloudtrail WHERE eventName = 'ConsoleLogin'" --range 2024-01-01:2024-06-30
```

## Scope

### In scope

- DuckDB integration for querying S3 data lake
- Query routing based on time range
- CLI interface for ad-hoc queries
- Python bindings for rule-based lookups (correlation rules)

### Out of scope

- Real-time streaming queries (different problem)
- Full-text search (would need Elasticsearch)
- Replacing Athena (keep for historical/compliance)

## Success Metrics

| Metric | Current (Athena) | Target (DuckDB) |
|--------|------------------|-----------------|
| P50 query latency | 45s | <2s |
| P99 query latency | 180s | <10s |
| Iterations per hour (IR) | 15-20 | 100+ |

## Risks

1. **Data freshness**: DuckDB queries S3 directly, so data freshness depends on data lake writer flush interval (currently hourly). May need to reduce to 5-15 minutes for IR use cases.

2. **Memory usage**: DuckDB loads data into memory for processing. Large queries could OOM. Mitigation: Set memory limits, use streaming results.

3. **Concurrent queries**: DuckDB is single-writer. Multiple concurrent queries need connection pooling or separate processes.

## Alternatives Considered

### 1. ClickHouse

Pros: Very fast, battle-tested at scale
Cons: Additional infrastructure (servers, replication, backups), operational overhead

Rejected because it contradicts iota's "minimal infrastructure" philosophy.

### 2. Streaming query engine (e.g., Materialize, RisingWave)

Pros: True real-time, continuous queries
Cons: Significant complexity, requires separate deployment, overkill for IR use case

Rejected because the problem is query latency during IR, not continuous detection.

### 3. Keep recent data in SQLite

Pros: Already using SQLite for state
Cons: Not designed for analytical queries, poor performance on large scans

Rejected because SQLite is OLTP-optimized, not OLAP.

### 4. Status quo (Athena only)

Pros: No additional complexity
Cons: IR effectiveness severely impacted

Rejected because the latency problem is real and impactful.

## Implementation Estimate

| Task | Effort |
|------|--------|
| DuckDB Go bindings integration | 2 days |
| Query router logic | 1 day |
| CLI interface | 1 day |
| S3 httpfs configuration | 0.5 days |
| Testing with real data | 1 day |
| Documentation | 0.5 days |
| **Total** | **6 days** |
