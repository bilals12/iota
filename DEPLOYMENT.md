# iota Deployment Guide

Complete deployment guide for getting iota running in your AWS environment.

## Quick Start

```bash
# 1. Build and push Docker image
make build
make docker-build
make docker-push IMAGE_REPO=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota IMAGE_TAG=v0.1.0

# 2. Deploy with Terraform
cd terraform/examples/complete
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform apply

# 3. Verify deployment
kubectl get pods -n security
kubectl logs -n security -l app.kubernetes.io/name=iota -f
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Account                              │
│                                                                  │
│  ┌──────────────┐                                               │
│  │ CloudTrail   │                                               │
│  │   Bucket     │                                               │
│  └──────┬───────┘                                               │
│         │ S3                                                    │
│         ▼                                                       │
│  ┌──────────────┐      JSONL      ┌─────────────────────┐     │
│  │ Log Shipper  │─────────────────▶│  Shared PVC         │     │
│  │ (gocloudtrail│                  │  /data/events       │     │
│  │  or similar) │                  └──────────┬──────────┘     │
│  └──────────────┘                             │                 │
│                                                │ ReadWriteMany   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              EKS Cluster (security namespace)            │   │
│  │                                                           │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │  iota Deployment (2 replicas)                      │ │   │
│  │  │                                                     │ │   │
│  │  │  ┌──────────────┐         ┌──────────────┐       │ │   │
│  │  │  │ Main         │         │ git-sync     │       │ │   │
│  │  │  │ Container    │         │ Sidecar      │       │ │   │
│  │  │  │              │         │              │       │ │   │
│  │  │  │ • iota       │         │ • Sync rules │       │ │   │
│  │  │  │ • watch mode │         │   from Git   │       │ │   │
│  │  │  │ • detect     │         │ • Every 5m   │       │ │   │
│  │  │  │ • alert      │         │              │       │ │   │
│  │  │  └──────────────┘         └──────────────┘       │ │   │
│  │  │                                                     │ │   │
│  │  │  Volumes:                                          │ │   │
│  │  │  • /data/events (shared PVC, ReadOnly)            │ │   │
│  │  │  • /data/rules (emptyDir, git-synced)             │ │   │
│  │  │  • /data/state (PVC, SQLite DB)                   │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │  ServiceAccount (IRSA)                             │ │   │
│  │  │  • IAM role for S3 CloudTrail read                │ │   │
│  │  │  • Temporary credentials via token                 │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  IAM Role: {cluster-name}-iota                                 │
│  • s3:GetObject, s3:ListBucket on CloudTrail bucket           │
│  • Trust policy: EKS OIDC provider                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS POST
                            ▼
                    ┌───────────────┐
                    │ Slack Webhook │
                    └───────────────┘
```

## Prerequisites

1. **EKS Cluster** with IRSA enabled
2. **CloudTrail** configured and writing to S3
3. **Docker registry** (ECR recommended)
4. **Git repository** for detection rules
5. **Slack webhook** (optional, for alerts)
6. **Tools installed**:
   - kubectl
   - helm 3.2+
   - terraform 1.0+
   - aws-cli
   - docker

## Step-by-Step Deployment

### 1. Prepare Detection Rules Repository

iota ships with 39 production-grade CloudTrail detection rules in `rules/aws_cloudtrail/`. You can use these directly or create your own Git repository:

**Option A: Use included rules** (recommended for quick start):
```bash
# Rules are already in the repository at rules/aws_cloudtrail/
# Includes 39 rules covering all MITRE ATT&CK cloud tactics
```

**Option B: Create custom rules repository**:
```bash
mkdir iota-rules
cd iota-rules

# Copy included rules as a starting point
cp -r /path/to/iota/rules .

# Or create your own custom rule
cat > rules/aws_cloudtrail/custom_s3_access.py <<'EOF'
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context

def rule(event):
    return (
        event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") in ["GetBucketAcl", "GetBucketPolicy"]
    )

def title(event):
    bucket = deep_get(event, "requestParameters", "bucketName", default="unknown")
    return f"S3 bucket access: {event.get('eventName')} on {bucket}"

def severity():
    return "INFO"
EOF

# Commit and push
git init
git add .
git commit -m "Initial rules based on iota 39-rule catalog"
git remote add origin https://github.com/your-org/iota-rules.git
git push -u origin main
```

### 2. Build and Push Docker Image

```bash
cd /path/to/iota

# Build
make build
make docker-build

# Tag and push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

make docker-push \
  IMAGE_REPO=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota \
  IMAGE_TAG=v0.1.0
```

### 3. Deploy with Terraform

```bash
cd terraform/examples/complete

# Copy example
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
vim terraform.tfvars
```

Example `terraform.tfvars`:

```hcl
region            = "us-east-1"
environment       = "production"
cluster_name      = "production-eks"
oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABCD1234"
cloudtrail_bucket = "my-org-cloudtrail-logs"

image_repository  = "123456789012.dkr.ecr.us-east-1.amazonaws.com/iota"
image_tag         = "v0.1.0"

rules_repo        = "https://github.com/my-org/iota-rules.git"
slack_webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Deploy:

```bash
# Initialize
terraform init

# Plan
terraform plan

# Apply
terraform apply
```

### 4. Verify Deployment

```bash
# Check pods
kubectl get pods -n security

# Should see:
# NAME                    READY   STATUS    RESTARTS   AGE
# iota-5f7b8c9d6-abc12   2/2     Running   0          2m
# iota-5f7b8c9d6-def34   2/2     Running   0          2m

# Check logs
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=50

# Should see:
# starting watcher on /data/events
# watcher started, press ctrl+c to stop
# processing file: /data/events/2024-11-27.jsonl
# processed 100 events, 5 matches
```

### 5. Test Detection

Create a test CloudTrail event:

```bash
# Copy test file to events directory
kubectl exec -n security iota-5f7b8c9d6-abc12 -c iota -- \
  sh -c 'echo "{\"eventName\":\"GetBucketAcl\",...}" > /data/events/test.jsonl'

# Check logs for detection
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=20

# Should see alert JSON + Slack notification
```

## Manual Deployment (Helm only)

If you want to deploy with Helm directly (without Terraform):

```bash
# Create namespace
kubectl create namespace security

# Create Slack webhook secret
kubectl create secret generic iota-slack-webhook \
  --from-literal=webhook-url=https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -n security

# Install Helm chart
helm install iota ./helm/iota \
  --namespace security \
  --set image.repository=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota \
  --set image.tag=v0.1.0 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/iota-role \
  --set detection.rules.repo=https://github.com/my-org/iota-rules.git \
  --set slack.enabled=true \
  --set persistence.events.existingClaim=cloudtrail-events-pvc
```

## Configuration

### Detection Rules

Rules are automatically synced from Git every 5 minutes. To update:

```bash
# Commit new rules to Git
cd iota-rules
vim rules/new_rule.py
git add rules/new_rule.py
git commit -m "Add new detection rule"
git push

# Rules will sync automatically within 5 minutes
# Or trigger immediate restart:
kubectl rollout restart deployment/iota -n security
```

### Slack Alerts

Format:

```
[Header] Rule Title
Severity: HIGH
Rule: AWS.S3.BucketAccess
Dedup: principal-GetBucketAcl

Event Details:
• Event Name: GetBucketAcl
• Event Source: s3.amazonaws.com
• Source IP: 192.0.2.1
• Region: us-east-1
• User Identity: IAMUser
• Account ID: 123456789012
```

### Resource Tuning

Edit Helm values or Terraform variables:

```hcl
# Terraform
cpu_request    = "500m"
cpu_limit      = "2000m"
memory_request = "512Mi"
memory_limit   = "2Gi"
replicas       = 3
```

```yaml
# Helm values
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

## Monitoring

### Metrics

iota logs to stdout. Key log lines:

```
starting watcher on /data/events
processing file: /data/events/2024-11-27.jsonl
processed 100 events, 5 matches
sent alert to slack: S3 bucket access
```

### Health Checks

```bash
# Check pod status
kubectl get pods -n security -l app.kubernetes.io/name=iota

# Check recent logs
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=100

# Check events
kubectl get events -n security --sort-by='.lastTimestamp'

# Check PVCs
kubectl get pvc -n security

# Check ServiceAccount
kubectl describe sa iota -n security
```

### Troubleshooting

**No events being processed:**

```bash
# Check events PVC
kubectl exec -n security iota-xxx -c iota -- ls -la /data/events

# Check file watcher
kubectl logs -n security iota-xxx -c iota | grep "starting watcher"

# Check log shipper (if separate)
kubectl get pods -n security | grep shipper
```

**Rules not loading:**

```bash
# Check git-sync logs
kubectl logs -n security iota-xxx -c git-sync

# Check rules directory
kubectl exec -n security iota-xxx -c iota -- ls -la /data/rules

# Test git clone manually
kubectl exec -n security iota-xxx -c git-sync -- \
  git clone https://github.com/your-org/iota-rules.git /tmp/test
```

**Slack alerts not working:**

```bash
# Check secret
kubectl get secret -n security iota-slack-webhook
kubectl get secret -n security iota-slack-webhook -o jsonpath='{.data.webhook-url}' | base64 -d

# Check environment variable
kubectl exec -n security iota-xxx -c iota -- env | grep SLACK

# Test webhook manually
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test from iota"}' \
  YOUR_WEBHOOK_URL
```

## Upgrading

```bash
# Build new image
make docker-build
make docker-push IMAGE_REPO=... IMAGE_TAG=v0.2.0

# Update Terraform
cd terraform/examples/complete
vim terraform.tfvars  # Update image_tag = "v0.2.0"
terraform apply

# Or update Helm
helm upgrade iota ./helm/iota \
  --namespace security \
  --set image.tag=v0.2.0 \
  --reuse-values
```

## Uninstalling

```bash
# Terraform
cd terraform/examples/complete
terraform destroy

# Helm (if deployed manually)
helm uninstall iota --namespace security
kubectl delete namespace security
```

## Production Checklist

- [ ] CloudTrail configured and writing to S3
- [ ] EKS cluster with IRSA enabled
- [ ] Docker image built and pushed to ECR
- [ ] Detection rules repository created
- [ ] Slack webhook URL obtained
- [ ] Terraform variables configured
- [ ] IAM role created with S3 read permissions
- [ ] Shared PVC for CloudTrail events created
- [ ] Log shipper deployed (gocloudtrail or similar)
- [ ] Deployment verified with test event
- [ ] Alerts received in Slack
- [ ] Monitoring/logging configured
- [ ] Runbook documented for on-call

## Security Considerations

1. **IAM permissions**: Scoped to specific CloudTrail bucket only
2. **IRSA**: Uses temporary credentials, no long-lived keys
3. **PVC encryption**: Enable encryption at rest
4. **Network policies**: Consider restricting egress to Slack only
5. **Slack webhook**: Rotate periodically, store in secrets manager
6. **Detection rules**: Review before deploying, test in non-prod first
7. **Container security**: Scan images with Trivy/Snyk
8. **RBAC**: Limit who can deploy/modify iota resources
