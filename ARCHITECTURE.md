# iota Architecture for Turo Deployment

## Design Principles

1. **Lightweight**: No complex infrastructure, minimal components
2. **Self-hosted**: All data stays within Turo AWS accounts
3. **Simple**: Direct S3 access, no SNS/SQS pipelines
4. **Performant**: Efficient polling, state tracking prevents reprocessing

## Architecture Comparison

### Panther (Complex SaaS)

```
CloudTrail → S3 → SNS Topic → SQS Queue → Lambda (polls SQS)
                                            ↓
                                    AssumeRole to customer account
                                            ↓
                                    Download + Parse S3 objects
                                            ↓
                                    Store in Panther S3 + Glue
                                            ↓
                                    Rules Engine Lambda
                                            ↓
                                    Alerts
```

### iota (Lightweight Self-Hosted)

```
CloudTrail → S3 (turo-org-cloudtrail in it-sec-prod)
              ↓
         iota pod (in test-subaccount-2)
         • Uses IRSA (IAM role)
         • Polls S3 every 5 min (ListObjects)
         • Downloads new files (GetObject)
         • Parses CloudTrail JSON
         • Runs 39 detection rules (Python)
         • Tracks processed files (SQLite)
         • Sends alerts (Slack)
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Turo AWS Organization                        │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  it-sec-prod (471112705274)                                 │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  CloudTrail (Organizational)                          │  │ │
│  │  │  - Logs all AWS API calls                             │  │ │
│  │  │  - Writes to S3 every ~5 minutes                      │  │ │
│  │  └─────────────────┬────────────────────────────────────┘  │ │
│  │                    ▼                                         │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  S3 Bucket: turo-org-cloudtrail                       │  │ │
│  │  │  - Path: AWSLogs/{account}/CloudTrail/{region}/...   │  │ │
│  │  │  - KMS encrypted                                       │  │ │
│  │  │  - Object format: YYYY/MM/DD/*.json.gz                │  │ │
│  │  └─────────────────┬────────────────────────────────────┘  │ │
│  └────────────────────│─────────────────────────────────────────┘ │
│                       │                                           │
│                       │ S3 Access via IRSA                        │
│                       │ (IAM role: test-eks-iota)                 │
│                       ▼                                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  test-subaccount-2 (382128918722)                          │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │  EKS Cluster                                          │  │ │
│  │  │  ┌────────────────────────────────────────────────┐  │  │ │
│  │  │  │  iota Deployment (Kustomize)                   │  │  │ │
│  │  │  │                                                 │  │  │ │
│  │  │  │  Pod Spec:                                      │  │  │ │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │  │ │
│  │  │  │  │  Container: iota                          │  │  │ │  │
│  │  │  │  │  Image: {ECR}/iota:v0.1.0                │  │  │ │  │
│  │  │  │  │                                           │  │  │ │  │
│  │  │  │  │  Command:                                 │  │  │ │  │
│  │  │  │  │    /app/iota                             │  │  │ │  │
│  │  │  │  │    --mode=s3-poll                         │  │  │ │  │
│  │  │  │  │    --s3-bucket=turo-org-cloudtrail       │  │  │ │  │
│  │  │  │  │    --s3-prefix=AWSLogs/*/CloudTrail/     │  │  │ │  │
│  │  │  │  │    --poll-interval=5m                     │  │  │ │  │
│  │  │  │  │    --rules=/app/rules/aws_cloudtrail     │  │  │ │  │
│  │  │  │  │    --state=/data/state.db                │  │  │ │  │
│  │  │  │  │                                           │  │  │ │  │
│  │  │  │  │  Process:                                 │  │  │ │  │
│  │  │  │  │  1. List S3 objects (new files)          │  │  │ │  │
│  │  │  │  │  2. Download .json.gz files              │  │  │ │  │
│  │  │  │  │  3. Decompress + parse JSON              │  │  │ │  │
│  │  │  │  │  4. Run 39 detection rules               │  │  │ │  │
│  │  │  │  │  5. Send alerts if match                 │  │  │ │  │
│  │  │  │  │  6. Update state DB                      │  │  │ │  │
│  │  │  │  │  7. Sleep 5 minutes, repeat              │  │  │ │  │
│  │  │  │  └───────────────────────────────────────────┘  │  │ │  │
│  │  │  │                                                 │  │  │ │
│  │  │  │  Volumes:                                       │  │  │ │
│  │  │  │  • /data/state.db → PVC (SQLite)              │  │  │ │
│  │  │  │  • /app/rules → ConfigMap (39 rules)          │  │  │ │
│  │  │  │                                                 │  │  │ │
│  │  │  │  ServiceAccount:                                │  │  │ │
│  │  │  │  • Name: iota                                   │  │  │ │
│  │  │  │  • Annotation: eks.amazonaws.com/role-arn       │  │  │ │
│  │  │  │    = arn:aws:iam::382128918722:role/test-eks-iota │
│  │  │  └────────────────────────────────────────────────┘  │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  │                                                              │ │
│  │  IAM Role: test-eks-iota                                   │ │
│  │  • Trust: EKS OIDC provider                                │ │
│  │  • Permissions:                                             │ │
│  │    - s3:ListBucket on turo-org-cloudtrail                 │ │
│  │    - s3:GetObject on turo-org-cloudtrail/*                │ │
│  │    - kms:Decrypt on CloudTrail KMS key                     │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS POST
                            ▼
                    ┌───────────────┐
                    │ Slack Webhook │
                    │ #security-    │
                    │  testing      │
                    └───────────────┘
```

## Key Design Decisions

### 1. No Log Shipper Needed

**Decision**: iota directly reads from S3
**Rationale**:

- Simpler architecture
- No intermediate storage
- No sync jobs or cron needed
- IRSA provides secure S3 access

### 2. Polling vs Event-Driven

**Decision**: Poll S3 every 5 minutes
**Rationale**:

- CloudTrail writes files every ~5 min anyway
- 5-minute detection latency is acceptable
- Avoids SNS/SQS infrastructure complexity
- State DB prevents duplicate processing

### 3. State Management

**Decision**: SQLite on persistent volume
**Rationale**:

- Tracks which S3 objects already processed
- Prevents duplicate alerts
- Simple, no external database
- Small footprint (< 1MB)

### 4. Rule Deployment

**Decision**: ConfigMap with 39 rules
**Rationale**:

- Rules embedded in Kubernetes manifests
- No git-sync sidecar needed
- Rules rarely change
- Easy to update via kubectl/Kustomize

### 5. Single Deployment vs DaemonSet

**Decision**: Deployment (1-2 replicas) not DaemonSet
**Rationale**:

- Not monitoring workloads (like Lacework/Wiz)
- Reading centralized CloudTrail logs
- State DB must be shared (ReadWriteOnce PVC)
- Only need 1-2 pods for redundancy

## Performance Characteristics

### Resource Usage (estimated)

- **CPU**: 100m request, 500m limit
- **Memory**: 256Mi request, 1Gi limit
- **Storage**: 1Gi PVC for state DB
- **Network**: ~100MB/hr CloudTrail download (varies by activity)

### Processing Capacity

- **CloudTrail volume**: ~1-10GB/day (Turo estimate)
- **Events per file**: ~100-1000 events
- **Detection speed**: ~10,000 events/sec (Go + Python)
- **Latency**: 5-10 minutes (poll interval + processing time)

### Scaling

- **Vertical**: Increase CPU/memory for higher volume
- **Horizontal**: NOT SUPPORTED (shared state DB with RWO PVC)
- **If needed**: Switch to RWX PVC or external state DB (PostgreSQL)

## Security Model

### Data Flow Security

1. **CloudTrail encrypted at rest** (KMS) in it-sec-prod
2. **In-flight encryption** (TLS) for S3 downloads
3. **iota processes in-memory** - no persistent storage of logs
4. **Alerts sent via HTTPS** to Slack webhook
5. **State DB contains only S3 object keys** - no sensitive data

### IAM Permissions (Least Privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::turo-org-cloudtrail"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::turo-org-cloudtrail/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:471112705274:key/*"
    }
  ]
}
```

### Network Security

- **Egress only**: iota only makes outbound connections
- **No ingress**: No LoadBalancer/Ingress needed
- **Destinations**:
  - S3 (VPC endpoints recommended)
  - Slack webhook (hooks.slack.com)

## Deployment Process

### Prerequisites

1. EKS cluster in test-subaccount-2 (382128918722)
2. CloudTrail bucket access granted (S3 + KMS policies)
3. Slack webhook URL for #security-testing
4. ECR repository for iota image

### Deployment Steps

1. **Build Docker image**

   ```bash
   cd /path/to/iota
   make docker-build
   docker tag iota:latest {ECR}/iota:v0.1.0
   docker push {ECR}/iota:v0.1.0
   ```

2. **Apply Terraform (create IAM role)**

   ```bash
   cd terraform/workspaces/test-subaccount-2
   terraform init
   terraform apply
   # Creates IAM role: test-eks-iota with IRSA
   ```

3. **Deploy via Kustomize**

   ```bash
   kubectl apply -k deployments/kubernetes/overlays/test-subaccount-2
   ```

4. **Verify**
   ```bash
   kubectl get pods -n security
   kubectl logs -n security -l app=iota -f
   ```

## Monitoring

### Health Checks

- **Liveness**: Process running
- **Readiness**: Can reach S3
- **Logs**: Structured JSON to stdout

### Metrics (via logs)

- Files processed
- Events analyzed
- Detections fired
- Processing latency

### Alerts

- Pod crashes → PagerDuty (if configured)
- Detection alerts → Slack #security-testing
- Processing errors → CloudWatch Logs

## Future Enhancements

### Phase 2 (Optional)

1. **SNS/SQS for real-time**: Reduce 5-min latency to seconds
2. **Prometheus metrics**: Better observability
3. **Horizontal scaling**: Use PostgreSQL for state
4. **Multiple log sources**: VPC Flow, GuardDuty, etc.

### Not Needed

- ❌ Log shipper (iota reads S3 directly)
- ❌ Data lake (no long-term storage)
- ❌ Web UI (alerts are the output)
- ❌ Correlation engine (single-event detection only)
