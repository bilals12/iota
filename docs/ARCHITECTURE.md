# iota architecture

## overview

iota is a self-hosted cloudtrail detection engine built in go. it runs entirely within your aws account, consuming cloudtrail logs via s3 and applying custom detection rules locally. no data leaves your control boundary.

## system architecture

```
┌─────────────────────────────────────────────────────────────┐
│  aws cloudtrail (organization trail)                        │
│  • s3 bucket: cloudtrail logs                               │
│  • consumed by: wiz, expel, iota                            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  ingestion: gocloudtrail                                    │
│  • downloads .json.gz from s3                               │
│  • decompresses & deduplicates                              │
│  • outputs: events/{account}/{region}/{date}/events_*.jsonl│
└───────────────────────┬─────────────────────────────────────┘
                        │ jsonl files
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  detection engine: iota (go + python subprocess)            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  jsonl reader (go)                                    │  │
│  │    ↓                                                  │  │
│  │  cloudtrail event parser (go)                        │  │
│  │    ↓                                                  │  │
│  │  engine orchestrator (go)                            │  │
│  │    ├─ json request (stdin) ─→ python subprocess     │  │
│  │    │                           │                      │  │
│  │    │                           • rule discovery       │  │
│  │    │                           • load .py files       │  │
│  │    │                           • execute rule()       │  │
│  │    │                           │                      │  │
│  │    ←─ json response (stdout) ─┘                      │  │
│  │    ↓                                                  │  │
│  │  alert builder (go)                                  │  │
│  └───────────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────────┘
                        │ alerts (json to stdout)
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  alert routing (your choice)                                │
│  • slack webhook                                            │
│  • pagerduty events api                                     │
│  • siem (splunk, sumo, datadog)                             │
│  • wiz issues api                                           │
└─────────────────────────────────────────────────────────────┘
```

## deployment model

iota is self-hosted and runs in your aws environment:

**compute**: eks pod, ecs task, fargate container, or ec2 instance
**permissions**: iam role with s3:getobject on cloudtrail bucket
**network**: vpc with optional egress to alert destinations
**storage**: local disk or efs for rule cache

### data flow

1. gocloudtrail downloads cloudtrail logs from s3
2. gocloudtrail decompresses and outputs jsonl to filesystem
3. iota reads jsonl files
4. iota streams events, executes python rules
5. matching events generate alerts to stdout
6. alerts piped to downstream systems

### security boundaries

- logs never leave your aws account
- no network calls to external services (unless you configure alerts)
- python rules run in isolated subprocess
- read-only access to cloudtrail s3 bucket
- iam role-based authentication (no stored credentials)
- all iota operations logged via cloudtrail

## components

### 1. jsonl reader (internal/reader)

streams cloudtrail events from jsonl files.

**implementation**:
- buffered line-by-line reading with bufio.scanner
- streams to avoid loading entire file into memory
- skips malformed json lines
- context-aware cancellation
- 1mb max line size

**key types**:
```go
type Reader struct {
    maxLineSize int
}

func (r *Reader) ReadFile(ctx context.Context, path string) (<-chan *cloudtrail.Event, <-chan error)
```

**usage**:
```go
r := reader.New()
events, errs := r.ReadFile(ctx, "events/2024-11-27/events_0001.jsonl")
for event := range events {
    // process event
}
if err := <-errs; err != nil {
    // handle error
}
```

### 2. cloudtrail event types (pkg/cloudtrail)

defines cloudtrail event schema matching aws format.

**key types**:
```go
type Event struct {
    EventVersion       string
    UserIdentity       UserIdentity
    EventTime          time.Time
    EventSource        string
    EventName          string
    AWSRegion          string
    SourceIPAddress    string
    RequestParameters  map[string]interface{}
    ResponseElements   map[string]interface{}
    // ...
}
```

**helper methods**:
```go
func (e *Event) Get(key string) interface{}
func (e *Event) DeepGet(keys ...string) interface{}
```

### 3. detection engine (internal/engine)

orchestrates python rule execution via subprocess.

**implementation**:
- spawns python subprocess for each batch
- sends json request via stdin
- receives json response via stdout
- captures stderr for debugging
- uses context for timeout

**key types**:
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

**usage**:
```go
eng := engine.New("python3", "engines/iota/engine.py", "rules/")
matches, err := eng.Analyze(ctx, events)
```

### 4. python rules engine (engines/iota/engine.py)

discovers and executes python detection rules.

**rule structure**:
```python
def rule(event):
    """returns true if event matches"""
    return event.get("eventName") == "ConsoleLogin"

def title(event):
    """returns alert title"""
    return f"console login from {event.get('sourceIPAddress')}"

def severity():
    """returns severity level"""
    return "HIGH"

def dedup(event):
    """optional: deduplication key"""
    return event.get("userIdentity", {}).get("arn")
```

**rule discovery**:
- recursively scans rules directory for .py files
- skips files starting with underscore
- dynamically loads python modules
- errors in rules don't stop execution

### 5. cli entrypoint (cmd/iota)

command-line interface for running iota.

**usage**:
```bash
iota \
  --jsonl /data/events/2024-11-27/events_0001.jsonl \
  --rules /rules \
  --python python3 \
  --engine engines/iota/engine.py
```

**flags**:
- `--jsonl`: path to jsonl file
- `--rules`: path to rules directory
- `--python`: python executable (default: python3)
- `--engine`: path to engine.py (default: engines/iota/engine.py)

**output**:
alerts printed as json to stdout, one per line.

## writing detection rules

rules are python files that define detection logic.

### minimal rule

```python
def rule(event):
    return event.get("eventName") == "DeleteBucket"
```

### full-featured rule

```python
def rule(event):
    """detect root account console logins"""
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("userIdentity", {}).get("type") == "Root"
    )

def title(event):
    """dynamic alert title"""
    ip = event.get("sourceIPAddress")
    return f"root console login from {ip}"

def severity():
    """alert severity"""
    return "CRITICAL"

def dedup(event):
    """deduplication key (optional)"""
    return f"root-login-{event.get('sourceIPAddress')}"
```

### rule conventions

- `rule(event)`: required. returns bool.
- `title(event)`: optional. returns string. defaults to rule filename.
- `severity()`: optional. returns string (INFO, LOW, MEDIUM, HIGH, CRITICAL). defaults to INFO.
- `dedup(event)`: optional. returns string. defaults to rule filename.

### event access

```python
# direct field access
event.get("eventName")
event.get("eventSource")
event.get("sourceIPAddress")

# nested field access
event.get("userIdentity", {}).get("type")
event.get("requestParameters", {}).get("bucketName")

# checking field existence
if "errorCode" in event:
    # handle error

# iterating resources
for resource in event.get("resources", []):
    arn = resource.get("ARN")
```

## deployment options

### eks (recommended)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iota
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: iota
      containers:
      - name: iota
        image: your-registry/iota:latest
        command:
        - /iota
        - --jsonl=/data/events
        - --rules=/rules
        volumeMounts:
        - name: events
          mountPath: /data/events
        - name: rules
          mountPath: /rules
      volumes:
      - name: events
        persistentVolumeClaim:
          claimName: gocloudtrail-output
      - name: rules
        configMap:
          name: detection-rules
```

### iam permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-cloudtrail-bucket",
        "arn:aws:s3:::your-cloudtrail-bucket/*"
      ]
    }
  ]
}
```

### alert routing

iota outputs json to stdout. pipe to your tools:

```bash
# to slack
./iota ... | jq -r '.title' | slack-webhook

# to pagerduty
./iota ... | pagerduty-alert

# to siem
./iota ... | fluent-bit -c siem.conf
```

## performance

**current**:
- 1000+ events/second single-threaded
- <10ms latency per event
- <100mb memory footprint

**tested with**:
- 10,000 event files
- 50+ concurrent rules
- real aws cloudtrail logs

## future enhancements

phase 2: file watching (automatically process new files)
phase 3: alert deduplication and correlation
phase 4: postgres storage for alert history
phase 5: integrations (slack, pagerduty, wiz apis)
phase 6: web ui for alert management

## security considerations

- **isolation**: python rules run in subprocess, not embedded interpreter
- **read-only**: only s3:getobject permission required
- **no egress**: network egress optional (only for alerting)
- **auditability**: all code open source, verifiable
- **data locality**: logs never leave your aws account
- **iam roles**: no credential storage required

## troubleshooting

### rule not triggering

```bash
# test rule directly
echo '{"eventName": "ConsoleLogin"}' | python3 -c "
import json, sys
event = json.load(sys.stdin)
exec(open('rule.py').read())
print(rule(event))
"
```

### parse errors

```bash
# validate jsonl
jq empty < events.jsonl

# check event structure
head -1 events.jsonl | jq .
```

### performance issues

```bash
# profile go code
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof

# check python subprocess overhead
time python3 engine.py < request.json
```

## references

- aws cloudtrail log format: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
- gocloudtrail: https://github.com/deceptiq/gocloudtrail
- iota repository: https://github.com/bilals12/iota
