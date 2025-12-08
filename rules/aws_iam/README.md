# AWS IAM Detection Rules

Detection rules based on the [IAM dataset](https://github.com/redteamtools/iam-dataset) categorization of AWS IAM actions by security impact.

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `aws_iam_credential_exposure` | Detects actions that expose or create credentials | HIGH-CRITICAL |
| `aws_iam_privilege_escalation` | Detects privilege escalation attempts | MEDIUM-CRITICAL |
| `aws_iam_resource_exposure` | Detects resource policy modifications that could expose resources | MEDIUM-CRITICAL |
| `aws_iam_high_risk_action` | Detects high-risk IAM modifications (non-automated) | INFO-HIGH |
| `aws_iam_assume_role_cross_account` | Detects cross-account role assumption | INFO |
| `aws_iam_root_activity` | Detects any root account activity | MEDIUM-CRITICAL |
| `aws_iam_mfa_deactivated` | Detects MFA device deactivation | HIGH |
| `aws_iam_saml_provider_modified` | Detects identity provider modifications | MEDIUM-CRITICAL |

## Action Categories

### CredentialExposure
Actions that return or create credentials:
- `iam:CreateAccessKey`
- `iam:CreateLoginProfile`
- `sts:AssumeRole*`
- `ec2:GetPasswordData`
- `ssm:GetParameter*`

### PrivEsc
Actions enabling privilege escalation:
- `iam:AttachUserPolicy`
- `iam:AttachRolePolicy`
- `iam:PassRole`
- `iam:UpdateAssumeRolePolicy`
- `iam:CreatePolicyVersion`

### ResourceExposure
Actions that modify resource-based policies:
- `s3:PutBucketPolicy`
- `lambda:AddPermission`
- `kms:PutKeyPolicy`
- `sns:AddPermission`
- `sqs:AddPermission`

## Allowlisting

Each rule supports allowlisting via sets defined at the top of the rule file:

```python
ALLOWLISTED_PRINCIPALS = {
    "arn:aws:iam::123456789012:role/TerraformRole",
}
```

The `aws_iam_high_risk_action` rule also allowlists common automation user agents by default.

## Log Source

CloudTrail management events with `eventSource: iam.amazonaws.com` or `sts.amazonaws.com`.
