# iota Terraform Module

Deploy iota CloudTrail detection engine to EKS with IAM roles, PVCs, and Helm chart.

## Usage

```hcl
module "iota" {
  source = "./terraform"

  cluster_name       = "production-eks"
  oidc_provider_arn  = module.eks.oidc_provider_arn
  cloudtrail_bucket  = "company-cloudtrail-logs"

  namespace              = "security"
  service_account_name   = "iota"

  image_repository = "123456789012.dkr.ecr.us-east-1.amazonaws.com/iota"
  image_tag       = "v0.1.0"
  replicas        = 2

  rules_repo   = "https://github.com/your-org/iota-rules.git"
  rules_branch = "main"
  rules_path   = "rules"

  slack_webhook_url = var.slack_webhook_url

  create_events_pvc = true
  events_pvc_size   = "100Gi"
  state_pvc_size    = "5Gi"
  storage_class     = "gp3"

  cpu_request    = "250m"
  cpu_limit      = "1000m"
  memory_request = "256Mi"
  memory_limit   = "1Gi"

  tags = {
    Environment = "production"
    Team        = "security"
    ManagedBy   = "terraform"
  }
}
```

## Example with Existing PVC

If you already have a PVC for CloudTrail events (shared with log shipper):

```hcl
module "iota" {
  source = "./terraform"

  cluster_name       = "production-eks"
  oidc_provider_arn  = module.eks.oidc_provider_arn
  cloudtrail_bucket  = "company-cloudtrail-logs"

  namespace            = "security"
  create_events_pvc    = false
  existing_events_pvc  = "cloudtrail-events-pvc"

  rules_repo = "https://github.com/your-org/iota-rules.git"

  slack_webhook_url = var.slack_webhook_url
}
```

## Complete Example with EKS

```hcl
# EKS cluster (using terraform-aws-modules/eks/aws)
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = "production-eks"
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  # ... other EKS configuration
}

# CloudTrail bucket
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "company-cloudtrail-logs"
}

# iota deployment
module "iota" {
  source = "./terraform"

  cluster_name       = module.eks.cluster_name
  oidc_provider_arn  = module.eks.oidc_provider_arn
  cloudtrail_bucket  = aws_s3_bucket.cloudtrail.id

  rules_repo        = "https://github.com/your-org/iota-rules.git"
  slack_webhook_url = var.slack_webhook_url
}

# Outputs
output "iota_iam_role_arn" {
  value = module.iota.iam_role_arn
}

output "iota_namespace" {
  value = module.iota.namespace
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| cluster_name | Name of the EKS cluster | string | - | yes |
| oidc_provider_arn | ARN of the OIDC provider for EKS IRSA | string | - | yes |
| cloudtrail_bucket | S3 bucket containing CloudTrail logs | string | - | yes |
| namespace | Kubernetes namespace for iota | string | "security" | no |
| create_namespace | Whether to create the namespace | bool | true | no |
| service_account_name | Name of the Kubernetes ServiceAccount | string | "iota" | no |
| image_repository | Docker image repository | string | "iota" | no |
| image_tag | Docker image tag | string | "latest" | no |
| replicas | Number of iota replicas | number | 2 | no |
| rules_repo | Git repository URL for detection rules | string | - | yes |
| rules_branch | Git branch for detection rules | string | "main" | no |
| rules_path | Path to rules within the git repository | string | "rules" | no |
| slack_webhook_url | Slack webhook URL for alerts | string | "" | no |
| create_events_pvc | Whether to create the events PVC | bool | true | no |
| existing_events_pvc | Name of existing PVC for events | string | "" | no |
| events_pvc_size | Size of the events PVC | string | "100Gi" | no |
| state_pvc_size | Size of the state PVC | string | "5Gi" | no |
| storage_class | Kubernetes storage class | string | "gp3" | no |
| helm_chart_path | Path to Helm chart | string | "../helm/iota" | no |
| helm_chart_version | Helm chart version | string | "0.1.0" | no |
| cpu_request | CPU request | string | "250m" | no |
| cpu_limit | CPU limit | string | "1000m" | no |
| memory_request | Memory request | string | "256Mi" | no |
| memory_limit | Memory limit | string | "1Gi" | no |
| tags | Tags to apply to AWS resources | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| iam_role_arn | ARN of the IAM role for iota ServiceAccount |
| iam_role_name | Name of the IAM role |
| namespace | Kubernetes namespace where iota is deployed |
| service_account_name | Name of the Kubernetes ServiceAccount |
| helm_release_name | Name of the Helm release |
| helm_release_version | Version of the Helm release |
| events_pvc_name | Name of the events PVC |

## Prerequisites

1. **EKS cluster** with IRSA enabled
2. **CloudTrail bucket** with logs
3. **kubectl** configured with cluster access
4. **Helm** 3.2.0+
5. **Terraform** 1.0+

## Provider Configuration

```hcl
provider "aws" {
  region = "us-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name
    ]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        module.eks.cluster_name
      ]
    }
  }
}
```

## IAM Permissions

The module creates an IAM role with the following permissions:

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

This allows iota to read CloudTrail logs from S3.

## Security Considerations

1. **Slack webhook URL**: Pass as a variable, store in Terraform Cloud/remote backend
2. **IAM role**: Scoped to specific CloudTrail bucket only
3. **ServiceAccount**: Uses IRSA for temporary credentials
4. **Network policies**: Consider adding network policies to restrict egress
5. **PVC encryption**: Enable encryption at rest for storage class

## Deployment

```bash
# Initialize
terraform init

# Plan
terraform plan -var-file=production.tfvars

# Apply
terraform apply -var-file=production.tfvars

# Verify
kubectl get pods -n security
kubectl logs -n security -l app.kubernetes.io/name=iota
```

## Updating Rules

Rules are automatically synced from Git every 5 minutes. To trigger immediate sync:

```bash
kubectl rollout restart deployment/iota -n security
```

## Monitoring

Check deployment status:

```bash
# Pods
kubectl get pods -n security -l app.kubernetes.io/name=iota

# Logs
kubectl logs -n security -l app.kubernetes.io/name=iota --tail=100 -f

# Events
kubectl get events -n security --field-selector involvedObject.name=iota

# Describe
kubectl describe deployment iota -n security
```

## Troubleshooting

### IAM role not working

Check IRSA configuration:

```bash
kubectl describe sa iota -n security
kubectl get pods -n security -l app.kubernetes.io/name=iota -o yaml | grep -A 5 serviceAccountName
```

Verify trust relationship on IAM role:

```bash
aws iam get-role --role-name production-eks-iota
```

### PVC not mounting

Check PVC status:

```bash
kubectl get pvc -n security
kubectl describe pvc cloudtrail-events-pvc -n security
```

Verify storage class exists:

```bash
kubectl get storageclass
```

### Helm release failed

Check Helm status:

```bash
helm list -n security
helm status iota -n security
helm get values iota -n security
```

View Helm logs:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=helm
```

## Cleanup

```bash
terraform destroy -var-file=production.tfvars
```

Note: PVCs may need manual cleanup if `prevent_destroy` lifecycle is set.
