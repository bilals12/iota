# iota Architecture

## Overview

iota is a self-hosted CloudTrail detection engine with enterprise-grade architecture. It runs entirely within your AWS account, consuming CloudTrail logs via S3 and applying custom detection rules locally. No data leaves your control boundary.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  AWS CloudTrail (Organization Trail)                        │
│  • S3 bucket: CloudTrail logs                               │
│  • Writes .json.gz files every ~5 minutes                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingestion: Event-Driven (SNS/SQS)                          │
│  • S3 bucket notifications → SNS Topic                      │
│  • SNS Topic → SQS Queue (with DLQ)                         │
│  • SQS Queue → iota SQS Processor                           │
│  • Downloads .json.gz files from S3                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Log Processor (internal/logprocessor)                      │
│  • Downloads and decompresses .json.gz files              │
│  • Adaptive classifier with penalty-based priority queue  │
│  • Supports CloudTrail, S3, VPC Flow, ALB, Aurora MySQL │
│  • Parses and normalizes events by log type              │
│  • Adds event metadata (EventTime, ParseTime, RowID)       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Data Lake Writer (internal/datalake)                      │
│  • Buffers processed events                                │
│  • Writes to S3 with hourly partitioning                   │
│  • Format: logs/{table}/year={Y}/month={M}/day={D}/hour={H}│
│  • Compressed JSON (.json.gz)                              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Rules Engine (internal/engine)                             │
│  • Executes Python detection rules                         │
│  • Processes events in batches                             │
│  • Returns rule matches                                    │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Deduplication (internal/deduplication)              │
│  • SQLite-based deduplication                             │
│  • Groups alerts by rule_id + dedup_string                 │
│  • Tracks alert count and timestamps                       │
│  • Configurable dedup period (default: 60 minutes)         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Forwarder (internal/alertforwarder)                 │
│  • Processes deduplicated alerts                           │
│  • Enriches with alert metadata                            │
│  • Routes to configured outputs                            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Delivery (internal/alerts)                           │
│  • Slack webhook                                            │
│  • JSON stdout (for piping to other tools)                 │
│  • Extensible output interface                             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Health Check Server (internal/api)                         │
│  • HTTP server on port 8080                                │
│  • /health endpoint (liveness probe)                       │
│  • /ready endpoint (readiness probe)                       │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Log Processor (internal/logprocessor)

Processes raw logs and classifies them using an adaptive classifier.

**Adaptive Classification System**:
- Uses penalty-based priority queue to identify log types
- Parsers that fail receive a penalty, reducing priority for future classifications
- Supports multiple log types: CloudTrail, S3 Server Access, VPC Flow, ALB, Aurora MySQL Audit
- Handles both CloudTrail JSON files (with `Records` array) and line-delimited logs
- Adds event metadata (EventTime, ParseTime, RowID)
- Normalizes event structure

**Supported Log Types**:
- `AWS.CloudTrail`: CloudTrail API audit logs (JSON format)
- `AWS.S3ServerAccess`: S3 server access logs (CSV format)
- `AWS.VPCFlow`: VPC Flow Logs (CSV format)
- `AWS.ALB`: Application Load Balancer access logs (CSV format)
- `AWS.AuroraMySQLAudit`: Aurora MySQL audit logs (CSV format)

**Key Types**:
```go
type Processor struct {
    adaptiveClassifier *AdaptiveClassifier
}

type ProcessedEvent struct {
    Event           *cloudtrail.Event
    LogType         string
    EventTime       time.Time
    ParseTime       time.Time
    RowID           string
}

type AdaptiveClassifier struct {
    parsers     *ParserPriorityQueue
    stats       ClassifierStats
    parserStats map[string]*ParserStats
}

type ParserPriorityQueue struct {
    items []*ParserQueueItem
}

type ParserQueueItem struct {
    logType string
    parser  parsers.ParserInterface
    penalty int
    index   int
}
```

**Usage**:
```go
processor := logprocessor.New()
events, errs := processor.Process(ctx, reader)
for event := range events {
    // Processed event with classification
}
```

**How Adaptive Classification Works**:
1. All parsers start with penalty=1 in a min-heap priority queue
2. For each log line, the classifier tries parsers in priority order (lowest penalty first)
3. If a parser fails, it receives penalty+1 and is moved down in the queue
4. If a parser succeeds, its penalty is reset to 0 and it moves to the front
5. This ensures frequently-used parsers are tried first, improving performance

### 2. Data Lake Writer (internal/datalake)

Writes processed events to S3 with partitioning for efficient querying.

**Features**:
- Hourly partitioning (year/month/day/hour)
- Buffered writes (50MB or 1 minute)
- GZIP compression
- S3 key format: `logs/{table}/year={Y}/month={M}/day={D}/hour={H}/{timestamp}-{uuid}.json.gz`

**Key Types**:
```go
type Writer struct {
    s3Client *s3.Client
    bucket   string
    buffer   *EventBuffer
}

func (w *Writer) WriteEvent(ctx context.Context, event *logprocessor.ProcessedEvent) error
func (w *Writer) Flush(ctx context.Context) error
```

**Usage**:
```go
writer := datalake.New(s3Client, "processed-data-bucket", 50*1024*1024, time.Minute)
defer writer.Flush(ctx)

for event := range processedEvents {
    writer.WriteEvent(ctx, event)
}
```

### 3. Alert Deduplication (internal/deduplication)

Deduplicates alerts using SQLite to prevent alert fatigue.

**Features**:
- Groups alerts by `rule_id` + `dedup_string`
- Tracks alert count and creation/update times
- Configurable dedup period (default: 60 minutes)
- Generates unique alert IDs

**Key Types**:
```go
type Deduplicator struct {
    db *sql.DB
}

type AlertInfo struct {
    AlertID          string
    AlertCount       int
    AlertCreationTime time.Time
    AlertUpdateTime   time.Time
    Title            string
    Severity         string
}

func (d *Deduplicator) UpdateAlertInfo(ctx context.Context, ruleID, dedup, title, severity string, dedupPeriodMinutes int) (*AlertInfo, error)
```

**Usage**:
```go
dedup, err := deduplication.New("alerts.db")
alertInfo, err := dedup.UpdateAlertInfo(ctx, ruleID, dedupString, title, severity, 60)
```

### 4. Alert Forwarder (internal/alertforwarder)

Processes rule matches and forwards them to configured outputs.

**Features**:
- Integrates with deduplication system
- Enriches alerts with context
- Supports multiple output destinations
- Extensible output interface

**Key Types**:
```go
type Forwarder struct {
    deduplicator *deduplication.Deduplicator
    outputs      []Output
}

type Output interface {
    SendAlert(ctx context.Context, alert *Alert) error
}

type Alert struct {
    AlertID          string
    RuleID           string
    Title            string
    Severity         string
    Event            *cloudtrail.Event
    AlertContext     map[string]interface{}
    AlertCreationTime string
    AlertUpdateTime   string
    AlertCount       int
}
```

**Usage**:
```go
outputs := []alertforwarder.Output{
    alerts.NewSlackOutput(webhookURL),
}
forwarder := alertforwarder.New(deduplicator, outputs)
forwarder.ProcessMatch(ctx, match, 60)
```

### 5. Integration Management (internal/integration)

Manages CloudTrail source integrations.

**Features**:
- Tracks integration configurations
- Monitors last event time
- Tracks event status (ACTIVE, INACTIVE)
- SQLite-based storage

**Key Types**:
```go
type Integration struct {
    ID             string
    Type           string
    Label          string
    AWSAccountID   string
    S3Bucket       string
    S3Prefix      string
    Enabled        bool
    CreatedAt      time.Time
    LastEventTime *time.Time
    EventStatus    string
}

type Manager struct {
    db *sql.DB
}
```

**Usage**:
```go
manager, err := integration.NewManager("integrations.db")
integration := &integration.Integration{
    ID: "integration-1",
    Type: "aws-s3",
    Label: "Production CloudTrail",
    S3Bucket: "cloudtrail-logs",
    S3Prefix: "AWSLogs/",
}
manager.Create(ctx, integration)
```

### 6. Detection Engine (internal/engine)

Orchestrates Python rule execution via subprocess.

**Implementation**:
- Spawns Python subprocess for each batch
- Sends JSON request via stdin
- Receives JSON response via stdout
- Captures stderr for debugging
- Uses context for timeout

**Key Types**:
```go
type Engine struct {
    pythonPath string
    enginePath string
    rulesDir   string
}

type Match struct {
    RuleID   string
    Title    string
    Severity string
    Dedup    string
    Event    *cloudtrail.Event
}
```

### 7. SQS Processor (internal/events)

Processes SQS messages containing S3 event notifications.

**Features**:
- Long polling (20 seconds) for efficient message retrieval
- Parses SNS messages containing S3 notifications
- Downloads CloudTrail log files from S3
- Automatic message deletion after successful processing
- Dead letter queue support for failed messages

**Key Types**:
```go
type SQSProcessor struct {
    client      *sqs.Client
    queueURL    string
    handler     func(ctx context.Context, s3Bucket, s3Key string) error
    maxMessages int32
    waitTime    int32
}
```

### 8. Health Check Server (internal/api)

Provides HTTP endpoints for Kubernetes health checks.

**Features**:
- `/health` endpoint for liveness probes
- `/ready` endpoint for readiness probes
- Graceful shutdown on context cancellation
- Configurable port (default: 8080)

**Key Types**:
```go
type HealthServer struct {
    server *http.Server
}

func NewHealthServer(port string) *HealthServer
func (s *HealthServer) Start(ctx context.Context) error
```

## Data Flow

### Complete Processing Pipeline

1. **S3 Notifications**: CloudTrail writes logs to S3, triggering bucket notifications
2. **SNS Topic**: S3 notifications published to SNS topic
3. **SQS Queue**: SNS messages delivered to SQS queue (with DLQ for failures)
4. **SQS Processing**: iota receives SQS messages and extracts S3 bucket/key
5. **Download**: Downloads `.json.gz` files from S3
6. **Log Processing**: Decompresses and parses log files
7. **Adaptive Classification**: Uses penalty-based priority queue to identify log type (CloudTrail, S3, VPC Flow, ALB, Aurora MySQL)
8. **Parsing**: Parses events according to identified log type
9. **Data Lake**: Writes processed events to S3 with partitioning (optional)
10. **Rules Engine**: Executes Python detection rules
11. **Deduplication**: Checks for existing alerts within dedup period
12. **Alert Forwarding**: Routes alerts to configured outputs
13. **Delivery**: Sends alerts to Slack, stdout, or other destinations
14. **Health Checks**: HTTP endpoints available for Kubernetes probes

## Deployment Model

iota is self-hosted and runs in your AWS environment:

**Compute**: EKS pod, ECS task, Fargate container, or EC2 instance
**Permissions**: IAM role with:
- S3 read access to CloudTrail bucket
- SQS receive/delete message permissions
- KMS decrypt permissions for encrypted logs
**Network**: VPC with optional egress to alert destinations
**Storage**:
- SQLite databases for state and deduplication
- S3 bucket for processed data lake (optional)
**Infrastructure**: Terraform module for SQS queue, IAM roles, and SNS subscriptions
**Health Monitoring**: HTTP endpoints on port 8080 for Kubernetes probes

## Security Boundaries

- Logs never leave your AWS account
- No network calls to external services (unless you configure alerts)
- Python rules run in isolated subprocess
- Read-only access to CloudTrail S3 bucket
- IAM role-based authentication (no stored credentials)
- All iota operations logged via CloudTrail

## Performance Characteristics

**Processing**:
- 10,000-50,000 events/second per instance
- <100ms latency per event
- <500MB memory footprint

**Scalability**:
- Horizontal scaling via multiple replicas
- State databases can be shared via ReadWriteMany volumes
- S3 data lake scales automatically

**Tested With**:
- 100GB+ daily CloudTrail volume
- 50+ concurrent rules
- Real AWS CloudTrail logs from production environments

## Design Decisions

- **Event-Driven**: SNS/SQS for real-time processing with sub-minute latency
- **Adaptive Classifier**: Penalty-based priority queue for efficient multi-log source support
- **SQLite**: Simple state management without additional AWS services
- **Self-Hosted**: Full control, no vendor lock-in, no per-GB costs
- **CLI-Only**: Integrates with existing tooling, no frontend complexity
- **Health Checks**: HTTP endpoints for Kubernetes liveness/readiness probes
- **Terraform Module**: Infrastructure as code for SQS, IAM, and SNS setup

## Future Enhancements

- **Glue Catalog Integration**: Automatic table creation and partition management
- **Athena Queries**: Query processed data lake via Athena
- **Multiple Outputs**: PagerDuty, webhooks, custom integrations
- **Health Monitoring**: CloudWatch metrics and alarms
- **Cross-Account Support**: Assume role for multi-account setups
- **State Tracking**: Resume processing from last processed key per bucket/account/region
- **Bloom Filter Deduplication**: Cross-trail deduplication for duplicate events
- **Parallel Processing**: Configurable worker pools for concurrent log processing
- **S3 Delimiter Discovery**: Efficient S3 key discovery for large buckets
- **Additional Log Sources**: Support for more AWS log types (GuardDuty, CloudWatch Logs, etc.)
- **Correlation Engine**: Time-windowed event correlation across log types

## References

- AWS CloudTrail Log Format: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
- iota Repository: https://github.com/bilals12/iota
