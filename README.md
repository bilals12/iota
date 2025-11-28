# iota

self-hosted cloudtrail detection engine. runs entirely within your aws account. consumes cloudtrail via s3, applies detection logic locally, emits alerts to your existing tooling. no telemetry exfiltration.

## why iota?

stuck with legacy siems that can't keep up? tired of paying per-gb for detection-as-a-service? need full control over your security detections?

iota gives you:

- **data sovereignty**: logs never leave your control boundary
- **auditability**: open source, verify no phone-home behavior
- **customization**: modify detection rules without vendor release cycles
- **simplicity**: fork, deploy to your infra, point at your logs

## how it works

```
cloudtrail (s3) → s3 notifications → sns topic → sqs queue → iota processor → log processor → data lake (s3) → rules engine → deduplication → alert forwarder → alerts
```

1. **cloudtrail** writes logs to s3 bucket
2. **s3 notifications** trigger sns topic on new object creation
3. **sns → sqs** delivers notifications to sqs queue
4. **iota sqs processor** receives notifications and downloads log files
5. **log processor** classifies and normalizes events
6. **data lake** stores processed events in s3 with partitioning (optional)
7. **rules engine** executes python detection rules
8. **deduplication** prevents alert fatigue
9. **alert forwarder** routes alerts to slack, stdout, or other outputs

## quick start

### prerequisites

- go 1.23+
- python 3.11+
- aws credentials with cloudtrail s3 read access
- gocloudtrail installed and configured

### installation

```bash
# clone repo
git clone https://github.com/bilals12/iota.git
cd iota

# build
go build -o bin/iota ./cmd/iota

# test with sample data
./bin/iota \
  --jsonl testdata/events/root-login.jsonl \
  --rules rules/aws_cloudtrail \
  --python python3 \
  --engine engines/iota/engine.py
```

### deployment

iota runs in your aws environment:

**compute**: eks, ecs, fargate, or ec2
**permissions**: s3 read access to cloudtrail bucket, sqs receive/delete messages
**network**: vpc with egress to alert destinations
**storage**: local disk for state database and alert deduplication

example eks deployment:

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
            - /app/iota
          args:
            - --mode=sqs
            - --sqs-queue-url=$(SQS_QUEUE_URL)
            - --s3-bucket=$(S3_BUCKET)
            - --aws-region=$(AWS_REGION)
            - --rules=/app/rules/aws_cloudtrail
            - --state=/data/state.db
          env:
            - name: SQS_QUEUE_URL
              value: "https://sqs.us-east-1.amazonaws.com/123456789012/iota-cloudtrail-queue"
            - name: S3_BUCKET
              value: "your-cloudtrail-bucket"
            - name: AWS_REGION
              value: "us-east-1"
          ports:
            - name: health
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          volumeMounts:
            - name: state
              mountPath: /data
            - name: rules
              mountPath: /app/rules
              readOnly: true
      volumes:
        - name: state
          persistentVolumeClaim:
            claimName: iota-state
        - name: rules
          configMap:
            name: iota-detection-rules
```

iam policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-cloudtrail-bucket",
        "arn:aws:s3:::your-cloudtrail-bucket/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:iota-cloudtrail-queue"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
    }
  ]
}
```

## detection rules

iota ships with **39 production-grade CloudTrail detection rules** covering all 14 MITRE ATT&CK tactics:

- **4 Critical** severity rules (root access, public snapshots)
- **18 High** severity rules (IAM backdoors, security logging disabled, data deletion)
- **15 Medium** severity rules (MFA bypasses, unusual access patterns)
- **2 Info/Low** severity rules (failed logins, secret access tracking)

rules are python files in `rules/aws_cloudtrail/`:

```python
# rules/aws_cloudtrail/aws_console_root_login.py
def rule(event):
    """detect root account console logins"""
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("userIdentity", {}).get("type") == "Root"
    )

def title(event):
    """alert title"""
    return f"root console login from {event.get('sourceIPAddress')}"

def severity():
    """alert severity"""
    return "CRITICAL"
```

see [rules/aws_cloudtrail/README.md](rules/aws_cloudtrail/README.md) for complete rule catalog.

rule structure:

- `rule(event)`: returns true if event matches detection logic
- `title(event)`: returns alert title string
- `severity()`: returns severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `alert_context(event)`: optional additional context for analysts

## integration

alerts output as json to stdout. pipe to your existing tools:

```bash
# send to slack
./bin/iota ... | jq -r '.title' | slack-notify

# send to pagerduty
./bin/iota ... | pagerduty-alert --severity HIGH

# send to siem
./bin/iota ... | fluent-bit -c /etc/fluent-bit/siem.conf
```

## rule updates

pull upstream detection rules:

```bash
# update rules repo
cd rules/aws_cloudtrail
git pull origin main

# restart iota to reload rules
kubectl rollout restart deployment/iota
```

or maintain your own fork:

```bash
# fork this repo
gh repo fork bilals12/iota

# add your custom rules
echo "def rule(event): return event.get('eventName') == 'DeleteBucket'" > rules/aws_cloudtrail/my_rule.py

# deploy your fork
kubectl set image deployment/iota iota=your-registry/iota:custom
```

### threat coverage

rules cover all 14 MITRE ATT&CK tactics:

- Initial Access (console logins, failed attempts)
- Persistence (IAM users, EC2 modifications, SSM sessions)
- Privilege Escalation (admin policy attachments, role assumptions)
- Defense Evasion (logging disabled, unusual user agents)
- Credential Access (EC2 user data, secrets access)
- Discovery (reconnaissance via AccessDenied)
- Execution (SSM Run Command, Lambda modifications)
- Lateral Movement (security groups, network ACLs, routes)
- Collection (logging disabled, user data access)
- Exfiltration (public snapshots, gateway changes)
- Impact (data deletion, KMS key deletion)

## architecture

see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

key components:

- **reader**: streams jsonl cloudtrail events
- **engine**: orchestrates python rule execution
- **rules**: python detection logic
- **alerts**: json output for downstream routing

## development

see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development setup.

```bash
# run tests
go test ./...

# build
go build -o bin/iota ./cmd/iota

# add integration test
go test ./internal/reader -run TestReaderWithRealCloudTrail -v
```

## security considerations

- **no network egress required** (optional for alerting)
- **read-only cloudtrail access**
- **rules run in isolated python subprocess**
- **no credential storage** (uses iam roles)
- **audit logs** via cloudtrail (iota operations logged)

## license

mit license. see LICENSE file.

## support

- issues: https://github.com/bilals12/iota/issues
- security: report via github security advisories

---

**status**: beta - core detection engine working, event-driven processing with SNS/SQS, data lake and deduplication implemented

**architecture**: event-driven processing with SNS/SQS pipeline, health check endpoints, terraform module for infrastructure

**compatibility**: tested with aws cloudtrail (organization trails, single account trails, s3 event format)
