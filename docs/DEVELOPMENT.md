# development guide

## prerequisites

- go 1.23+
- python 3.11+
- aws cli configured
- git

## setup

```bash
# clone repo
git clone https://github.com/bilals12/iota.git
cd iota

# build
go build -o bin/iota ./cmd/iota

# run tests
go test ./...
```

## running locally

### with sample data

```bash
# use included sample data
./bin/iota \
  --jsonl testdata/sample.jsonl \
  --rules testdata/rules \
  --python python3 \
  --engine engines/iota/engine.py
```

### with real cloudtrail data

```bash
# fetch real cloudtrail logs
aws cloudtrail lookup-events --max-results 10 --output json | \
  jq -r '.Events[].CloudTrailEvent' > testdata/real.jsonl

# run iota
./bin/iota \
  --jsonl testdata/real.jsonl \
  --rules testdata/rules \
  --python python3 \
  --engine engines/iota/engine.py
```

## writing rules

### create a new rule

```bash
# create rule file
cat > testdata/rules/my_detection.py <<'EOF'
def rule(event):
    """detect something interesting"""
    return event.get("eventName") == "DeleteBucket"

def title(event):
    """alert title"""
    bucket = event.get("requestParameters", {}).get("bucketName", "unknown")
    return f"bucket deleted: {bucket}"

def severity():
    """alert severity"""
    return "HIGH"
EOF

# test rule
./bin/iota --jsonl testdata/real.jsonl --rules testdata/rules
```

### test a rule directly

```bash
# create test event
echo '{"eventName": "DeleteBucket", "requestParameters": {"bucketName": "test-bucket"}}' > /tmp/event.json

# test rule function
python3 <<EOF
import json
event = json.load(open('/tmp/event.json'))
exec(open('testdata/rules/my_detection.py').read())
print(f"matches: {rule(event)}")
print(f"title: {title(event)}")
print(f"severity: {severity()}")
EOF
```

## testing

### unit tests

```bash
# run all tests
go test ./...

# run specific package
go test ./internal/reader -v

# run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### integration tests

```bash
# test with real cloudtrail data
go test ./internal/reader -run TestReaderWithRealCloudTrail -v

# test full pipeline
sh -c 'cd /Users/bilalsiddiqui/code/iota && \
  go build -o bin/iota ./cmd/iota && \
  ./bin/iota --jsonl testdata/real-cloudtrail.jsonl --rules testdata/rules'
```

## debugging

### enable verbose output

```bash
# add debug prints to engine.go
cat >> internal/engine/engine.go <<'EOF'
func (e *Engine) debug(msg string, args ...interface{}) {
    log.Printf("[DEBUG] "+msg, args...)
}
EOF
```

### inspect python subprocess

```bash
# test python engine directly
python3 engines/iota/engine.py <<'EOF'
{
  "rules_dir": "testdata/rules",
  "events": [
    {
      "eventName": "ConsoleLogin",
      "userIdentity": {"type": "Root"},
      "sourceIPAddress": "1.2.3.4"
    }
  ]
}
EOF
```

### check rule loading

```bash
# list all rules
find testdata/rules -name "*.py" -not -name "_*"

# check for syntax errors
for rule in testdata/rules/*.py; do
    python3 -m py_compile "$rule" || echo "error in $rule"
done
```

## project structure

```
iota/
├── cmd/
│   └── iota/              # cli entrypoint
│       └── main.go
├── internal/
│   ├── reader/            # jsonl reader
│   │   ├── reader.go
│   │   └── reader_test.go
│   └── engine/            # detection engine orchestrator
│       └── engine.go
├── pkg/
│   └── cloudtrail/        # cloudtrail event types
│       └── event.go
├── engines/
│   └── panther/           # python rules engine
│       └── engine.py
├── testdata/
│   ├── rules/             # detection rules
│   │   ├── root_login.py
│   │   └── s3_bucket_access.py
│   ├── sample.jsonl       # sample data
│   └── real-cloudtrail.jsonl  # real cloudtrail logs
├── docs/
│   ├── ARCHITECTURE.md
│   └── DEVELOPMENT.md
├── go.mod
├── go.sum
└── README.md
```

## code style

### go conventions

- lowercase package names
- underscore-separated filenames
- PascalCase types
- camelCase functions
- use context for cancellation
- return errors, don't panic

```go
// good
func (r *Reader) ReadFile(ctx context.Context, path string) (<-chan *cloudtrail.Event, <-chan error)

// bad
func ReadFile(path string) []Event
```

### python conventions

- lowercase functions
- docstrings for rule logic
- return bool from rule()
- return str from title()/severity()/dedup()

```python
# good
def rule(event):
    """detect root logins"""
    return event.get("userIdentity", {}).get("type") == "Root"

# bad
def Rule(Event):
    if Event["userIdentity"]["type"] == "Root":
        return True
    else:
        return False
```

## performance optimization

### profiling

```bash
# cpu profile
go test -cpuprofile=cpu.prof -bench=. ./internal/reader
go tool pprof cpu.prof

# memory profile
go test -memprofile=mem.prof -bench=. ./internal/reader
go tool pprof mem.prof
```

### benchmarks

```bash
# run benchmarks
go test -bench=. ./internal/reader

# compare before/after
go test -bench=. ./internal/reader > before.txt
# make changes
go test -bench=. ./internal/reader > after.txt
benchcmp before.txt after.txt
```

## common issues

### import errors

```
cannot find package "github.com/bilals12/iota/..."
```

fix: verify go.mod module path matches import paths

```bash
# check module path
head -1 go.mod

# should be: module github.com/bilals12/iota
```

### python subprocess errors

```
execute engine: exit status 1, stderr: ModuleNotFoundError
```

fix: check python path and rule directory

```bash
# test python directly
python3 engines/iota/engine.py < /tmp/request.json

# verify rules directory exists
ls -la testdata/rules/
```

### jsonl parse errors

```
malformed json on line 42
```

fix: validate jsonl format

```bash
# check for syntax errors
jq empty < testdata/sample.jsonl

# find bad lines
awk '{if (system("echo '\''" $0 "'\'' | jq empty 2>/dev/null")) print NR ": " $0}' testdata/sample.jsonl
```

## contributing

### before committing

```bash
# format code
go fmt ./...

# run linter
golangci-lint run

# run tests
go test ./...

# check imports
go mod tidy
```

### commit messages

use conventional commits:

```
feat: add root login detection rule
fix: handle null useridentity field
docs: update deployment guide
test: add integration test for s3 events
```

## deployment

see readme.md for deployment instructions.

quick reference:

```bash
# build binary
go build -o bin/iota ./cmd/iota

# build docker image
docker build -t iota:latest .

# push to registry
docker tag iota:latest your-registry/iota:v1.0.0
docker push your-registry/iota:v1.0.0
```

## resources

- [go documentation](https://golang.org/doc/)
- [cloudtrail log format](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [gocloudtrail](https://github.com/deceptiq/gocloudtrail)
- [python importlib](https://docs.python.org/3/library/importlib.html)
