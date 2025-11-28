# iota-system Terraform Module

This module creates the IAM role and policies required for the iota CloudTrail detection engine to run in EKS using IRSA (IAM Roles for Service Accounts).

## Overview

The module creates:
- **IAM Role** with IRSA trust policy for EKS ServiceAccount
- **S3 Access Policy** for reading CloudTrail logs
- **KMS Decrypt Policy** for decrypting encrypted CloudTrail logs
- **SNS Policy** (optional) for real-time CloudTrail notifications

## Usage

```hcl
module "iota_role" {
  source = "../../system-modules/iota-system"

  cluster_name              = "production-eks"
  eks_oidc_provider_arn     = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABCD1234"
  cloudtrail_bucket_name    = "turo-org-cloudtrail"
  cloudtrail_kms_key_arn    = "arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab"
  cloudtrail_sns_topic_arn  = "arn:aws:sns:us-east-1:123456789012:cloudtrail-notifications"

  namespace                 = "security"
  service_account_name      = "iota"
  enable_sns_notifications  = false

  tags = {
    Environment = "production"
    Team        = "security"
  }
}
```

## Cross-Account CloudTrail Access

When CloudTrail is in a different AWS account (e.g., it-sec-prod), you need to:

1. **Apply this module in the account where iota runs** (e.g., test-subaccount-2)
2. **Grant cross-account access in the CloudTrail account** by adding the IAM role to the S3 bucket policy and KMS key policy

### Example: S3 Bucket Policy (in it-sec-prod)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowIotaReadAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::382128918722:role/test-eks-iota"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::turo-org-cloudtrail",
        "arn:aws:s3:::turo-org-cloudtrail/*"
      ]
    }
  ]
}
```

### Example: KMS Key Policy (in it-sec-prod)

```json
{
  "Sid": "AllowIotaDecrypt",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::382128918722:role/test-eks-iota"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| cluster_name | Name of the EKS cluster | string | - | yes |
| eks_oidc_provider_arn | ARN of the EKS OIDC provider | string | - | yes |
| cloudtrail_bucket_name | Name of the CloudTrail S3 bucket | string | - | yes |
| cloudtrail_kms_key_arn | ARN of the CloudTrail KMS key | string | - | yes |
| cloudtrail_sns_topic_arn | ARN of the CloudTrail SNS topic | string | "" | no |
| namespace | Kubernetes namespace for iota | string | "security" | no |
| service_account_name | Kubernetes ServiceAccount name | string | "iota" | no |
| enable_sns_notifications | Enable SNS notifications | bool | false | no |
| tags | Additional resource tags | map(string) | {} | no |

## Outputs

| Name | Description |
|------|-------------|
| role_arn | ARN of the IAM role (use for IRSA annotation) |
| role_name | Name of the IAM role |
| role_id | Unique ID of the IAM role |
| service_account_annotation | Annotation for Kubernetes ServiceAccount |

## IRSA Setup

After applying this module, use the `role_arn` output in your Kubernetes ServiceAccount:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: iota
  namespace: security
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/production-eks-iota
```

Or in Helm values:

```yaml
serviceAccount:
  create: true
  name: iota
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/production-eks-iota
```

## Permissions

The IAM role grants the following permissions:

**S3 Permissions:**
- `s3:ListBucket` - List objects in CloudTrail bucket
- `s3:GetBucketLocation` - Get bucket region
- `s3:GetObject` - Read CloudTrail log files
- `s3:GetObjectVersion` - Read specific versions

**KMS Permissions:**
- `kms:Decrypt` - Decrypt CloudTrail logs
- `kms:DescribeKey` - Get key metadata

**SNS Permissions (if enabled):**
- `sns:Subscribe` - Subscribe to CloudTrail notifications
- `sns:Receive` - Receive notification messages

## Security Considerations

1. **Least Privilege**: Role only has read access to CloudTrail bucket, no write permissions
2. **Scoped Access**: S3 access is limited to the specific CloudTrail bucket
3. **IRSA**: Uses temporary credentials, no long-lived access keys
4. **Trust Policy**: Role can only be assumed by the specific ServiceAccount in the specific namespace
5. **Cross-Account**: For cross-account access, ensure bucket/KMS policies are properly configured

## Testing

Validate the module:

```bash
cd terraform/system-modules/iota-system
terraform init
terraform validate
```

## Related

- [iota Deployment Guide](../../../DEPLOYMENT.md)
- [Helm Chart](../../../helm/iota/)
- [OpenSpec Proposal](../../../openspec/changes/deploy-iota-to-turo-aws/proposal.md)
