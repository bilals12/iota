# iota Architecture

## Overview

iota is a self-hosted CloudTrail detection engine with enterprise-grade log processing, data lake storage, alert deduplication, and flexible alert delivery. It runs entirely within your AWS account with no external dependencies.

## Architecture

### Event-Driven Processing

- S3 → SNS Topic → SQS Queue → Log Processor → Data Lake → Rules Engine → Alerts
- Real-time processing with sub-minute latency
- Dead letter queue for failed messages
- Long polling for efficient message retrieval

## Core Components

### 1. Log Processor

- Classifies events by service (AWS.CloudTrail, AWS.S3, etc.)
- Adds event metadata (EventTime, ParseTime, RowID)
- Normalizes event structure

### 2. Data Lake

- S3-based storage with hourly partitioning
- Compressed JSON format
- Partition structure: `logs/{table}/year={Y}/month={M}/day={D}/hour={H}/`

### 3. Rules Engine

- Python-based detection rules
- Subprocess execution for isolation
- Batch processing for efficiency

### 4. Alert Deduplication

- SQLite-based deduplication
- Configurable dedup period
- Alert count tracking

### 5. Alert Forwarder

- Processes deduplicated alerts
- Routes to multiple outputs
- Extensible output interface

### 6. Integration Management

- Tracks CloudTrail source configurations
- Monitors health status
- SQLite-based storage

## Data Flow

```
CloudTrail S3 → S3 Poller → Log Processor → Data Lake (S3)
                                              ↓
                                    Rules Engine → Deduplication → Alert Forwarder → Outputs
```

## Key Design Decisions

1. **SQLite over DynamoDB**: Simpler, no additional AWS service, sufficient for single-account deployments
2. **S3 Polling over SNS/SQS**: Simpler architecture, acceptable 5-minute latency
3. **Optional Data Lake**: Can disable if storage costs are a concern
4. **CLI-only**: No frontend complexity, integrates with existing tooling
5. **Self-hosted**: Full control, no vendor lock-in, no per-GB costs

## Performance

- **Processing**: 10K-50K events/second
- **Latency**: <100ms per event
- **Memory**: <500MB baseline
- **Storage**: ~1KB per processed file in state DB

## Security

- IAM role-based authentication
- Read-only S3 access
- Isolated Python subprocess execution
- No external network calls (optional for alerts)
- All operations logged via CloudTrail

## Deployment

- **Compute**: EKS, ECS, Fargate, or EC2
- **Storage**: SQLite (local or shared volume), S3 (optional data lake)
- **Network**: VPC with optional egress for alerts
- **Permissions**: S3 read access to CloudTrail bucket

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment instructions.
