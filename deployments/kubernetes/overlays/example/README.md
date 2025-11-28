# iota Kubernetes Deployment - Example Overlay

Example Kustomize overlay showing how to deploy iota to your EKS cluster with CloudTrail access.

## Prerequisites

1. **ECR Image**: Build and push iota image to your ECR
   ```bash
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
   docker build -t iota:v0.1.0 .
   docker tag iota:v0.1.0 YOUR_AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iota:v0.1.0
   docker push YOUR_AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iota:v0.1.0
   ```

2. **IAM Role**: Apply Terraform to create IRSA role
   ```bash
   cd terraform/workspaces/your-workspace
   terraform init
   terraform apply
   # Creates: arn:aws:iam::YOUR_AWS_ACCOUNT:role/your-eks-cluster-iota
   ```

3. **Slack Webhook** (optional): Create sealed secret
   ```bash
   kubectl create secret generic iota-slack-webhook \
     --from-literal=webhook-url=https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
     --dry-run=client -o yaml | \
     kubeseal --format=yaml > iota-slack-sealed-secret.yaml

   # Then replace secretGenerator in kustomization.yaml with:
   # resources:
   #   - iota-slack-sealed-secret.yaml
   ```

## Configuration

### Customization Required

Before deploying, update these files:

#### 1. serviceaccount-patch.yaml
Replace `arn:aws:iam::123456789012:role/your-eks-cluster-iota` with your IAM role ARN from Terraform output.

#### 2. deployment-patch.yaml
Replace `your-org-cloudtrail` with your CloudTrail S3 bucket name.

#### 3. kustomization.yaml
- Replace `YOUR_AWS_ACCOUNT` with your AWS account ID
- Update ECR repository URL and image tag
- Replace Slack webhook URL (or remove secretGenerator if not using Slack)

### Environment Variables

| Variable | Value | Description |
|----------|-------|-------------|
| S3_BUCKET | your-org-cloudtrail | CloudTrail bucket name |
| S3_PREFIX | AWSLogs/ | CloudTrail object prefix |
| POLL_INTERVAL | 5m | How often to poll S3 |
| AWS_REGION | us-east-1 | AWS region |

## Deployment

```bash
# Verify configuration
kubectl kustomize deployments/kubernetes/overlays/example

# Apply to cluster
kubectl apply -k deployments/kubernetes/overlays/example

# Check deployment
kubectl get pods -n security
kubectl logs -n security -l app=iota -f
```

## Verification

```bash
# Check pod is running
kubectl get pods -n security

# Check IRSA annotation
kubectl describe sa iota -n security | grep eks.amazonaws.com/role-arn

# Check logs for S3 polling
kubectl logs -n security -l app=iota --tail=100

# Expected logs:
# polling S3 bucket: your-org-cloudtrail with prefix: AWSLogs/
# found 25 new CloudTrail files
# processing file: AWSLogs/123456789012/CloudTrail/us-east-1/2024/11/28/...
# processed 150 events, 2 detections
# sent alert to Slack: AWS root login detected
```

## Troubleshooting

### Pod not starting
```bash
kubectl describe pod -n security -l app=iota
# Check image pull errors, IRSA issues
```

### S3 access denied
```bash
# Verify IAM role
aws iam get-role --role-name your-eks-cluster-iota

# Check trust policy allows EKS OIDC
aws iam get-role --role-name your-eks-cluster-iota --query 'Role.AssumeRolePolicyDocument'
```

### No detections
```bash
# Check if CloudTrail is writing to S3
aws s3 ls s3://your-org-cloudtrail/AWSLogs/ --recursive | tail -20

# Check iota logs for processing
kubectl logs -n security -l app=iota | grep "processed.*events"
```

## Cleanup

```bash
kubectl delete -k deployments/kubernetes/overlays/example
```
