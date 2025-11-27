# iota Helm Chart

Deploy iota CloudTrail detection engine to Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PVC provisioner support in the underlying infrastructure
- IAM role with CloudTrail read access (for EKS IRSA)
- Slack webhook URL (optional, for alerts)

## Installation

### 1. Create Slack webhook secret (optional)

```bash
kubectl create secret generic iota-slack-webhook \
  --from-literal=webhook-url=https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -n security
```

Or use sealed secrets:

```bash
echo -n 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' | \
  kubeseal --raw --from-file=/dev/stdin --namespace security \
  --name iota-slack-webhook --key webhook-url
```

### 2. Configure values

Create a `values-custom.yaml` file:

```yaml
image:
  repository: your-registry/iota
  tag: "0.1.0"

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/iota-cloudtrail-reader

detection:
  rules:
    repo: https://github.com/your-org/iota-rules.git
    branch: main
    path: rules

slack:
  enabled: true
  secretName: iota-slack-webhook

persistence:
  events:
    existingClaim: cloudtrail-events-pvc
```

### 3. Install the chart

```bash
helm install iota ./helm/iota \
  --namespace security \
  --create-namespace \
  --values values-custom.yaml
```

### 4. Verify deployment

```bash
kubectl get pods -n security
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=100
```

## Configuration

### Core Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `iota` |
| `image.tag` | Image tag | `""` (uses chart appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Detection Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `detection.mode` | Operation mode (once/watch) | `watch` |
| `detection.python` | Python executable path | `python3` |
| `detection.enginePath` | Path to engine.py | `/app/engines/iota/engine.py` |
| `detection.eventsDir` | Events directory mount path | `/data/events` |
| `detection.stateFile` | SQLite state database path | `/data/state/iota.db` |
| `detection.rules.repo` | Git repo for detection rules | `""` |
| `detection.rules.branch` | Git branch | `main` |
| `detection.rules.path` | Path to rules within repo | `rules` |
| `detection.rules.syncInterval` | How often to sync rules | `5m` |

### Slack Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `slack.enabled` | Enable Slack alerts | `false` |
| `slack.secretName` | Secret containing webhook URL | `iota-slack-webhook` |
| `slack.secretKey` | Key in secret for webhook URL | `webhook-url` |

### Persistence Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.events.enabled` | Enable events PVC | `true` |
| `persistence.events.existingClaim` | Use existing PVC (shared with log shipper) | `""` |
| `persistence.events.storageClass` | Storage class | `""` |
| `persistence.events.accessMode` | Access mode | `ReadWriteMany` |
| `persistence.events.size` | PVC size | `10Gi` |
| `persistence.state.enabled` | Enable state PVC | `true` |
| `persistence.state.storageClass` | Storage class | `""` |
| `persistence.state.accessMode` | Access mode | `ReadWriteOnce` |
| `persistence.state.size` | PVC size | `1Gi` |

### ServiceAccount Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.annotations` | Annotations (e.g., IRSA role) | `{}` |
| `serviceAccount.name` | Service account name | `""` (uses chart fullname) |

## Architecture

iota runs as a Deployment with:

1. **Main container**: Runs iota in watch mode, continuously processing CloudTrail events
2. **git-sync sidecar** (optional): Continuously pulls latest detection rules from Git repo
3. **Shared volumes**:
   - `events`: ReadWriteMany PVC shared with CloudTrail log shipper
   - `rules`: EmptyDir populated by git-sync
   - `state`: ReadWriteOnce PVC for SQLite database

## Integration with CloudTrail Log Shipper

iota expects CloudTrail logs in JSONL format. The recommended setup:

1. Deploy a log shipper that:
   - Reads CloudTrail logs from S3
   - Converts to JSONL format
   - Writes to shared PVC at `/data/events`

2. Configure iota to:
   - Mount the same PVC at `/data/events`
   - Run in watch mode to continuously process new files

Example log shipper deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloudtrail-shipper
spec:
  template:
    spec:
      containers:
      - name: shipper
        image: your-registry/gocloudtrail:latest
        volumeMounts:
        - name: events
          mountPath: /data/events
      volumes:
      - name: events
        persistentVolumeClaim:
          claimName: cloudtrail-events-pvc
```

## IAM Requirements

The ServiceAccount needs permissions to read CloudTrail logs if the log shipper runs in the same pod/namespace:

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

## Monitoring

iota logs to stdout. Use standard Kubernetes logging:

```bash
# View recent logs
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=100

# Follow logs
kubectl logs -n security -l app.kubernetes.io/name=iota -f

# View logs from specific pod
kubectl logs -n security iota-<pod-id>
```

## Upgrading

```bash
helm upgrade iota ./helm/iota \
  --namespace security \
  --values values-custom.yaml
```

## Uninstalling

```bash
helm uninstall iota --namespace security
```

Note: PVCs are not deleted automatically. Delete manually if needed:

```bash
kubectl delete pvc -n security iota-state
```

## Troubleshooting

### No events being processed

1. Check events directory has files:
```bash
kubectl exec -n security -it iota-<pod-id> -- ls -la /data/events
```

2. Check file watcher is running:
```bash
kubectl logs -n security iota-<pod-id> | grep "starting watcher"
```

3. Verify PVC is mounted:
```bash
kubectl describe pod -n security iota-<pod-id>
```

### Rules not loading

1. Check git-sync sidecar logs:
```bash
kubectl logs -n security iota-<pod-id> -c git-sync
```

2. Check rules directory:
```bash
kubectl exec -n security -it iota-<pod-id> -- ls -la /data/rules
```

3. Check rules repo URL is accessible:
```bash
kubectl exec -n security -it iota-<pod-id> -c git-sync -- git ls-remote <repo-url>
```

### Slack alerts not working

1. Verify secret exists:
```bash
kubectl get secret -n security iota-slack-webhook
```

2. Check webhook URL is valid:
```bash
kubectl exec -n security -it iota-<pod-id> -- env | grep SLACK
```

3. Check alert logs:
```bash
kubectl logs -n security iota-<pod-id> | grep "sent alert to slack"
```
