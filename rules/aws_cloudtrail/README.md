# AWS CloudTrail Detection Rules

This directory contains production-grade detection rules for AWS CloudTrail logs. Rules are organized by threat category and severity.

## Rules Summary (39 total)

### Critical Severity (4 rules)

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `aws_console_root_login.py` | Root user console access detected | T1078.004 (Valid Accounts: Cloud Accounts) |
| `aws_root_access_key_created.py` | Root user access key created (should NEVER happen) | T1098 (Account Manipulation) |
| `aws_rds_snapshot_shared_publicly.py` | RDS snapshot shared publicly (data exposure) | T1530 (Data from Cloud Storage) |
| `aws_ec2_snapshot_made_public.py` | EBS snapshot made public (data exposure) | T1530 (Data from Cloud Storage) |

### High Severity (18 rules)

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `aws_iam_attach_admin_user_policy.py` | AdministratorAccess policy attached to user | T1098 (Account Manipulation) |
| `aws_iam_user_key_created.py` | One user created API keys for another user | T1078.004 (Valid Accounts: Cloud Accounts) |
| `aws_iam_backdoor_users.py` | IAM user created by assumed role/service (backdoor) | T1136.003 (Create Account: Cloud Account) |
| `aws_cloudtrail_stopped.py` | CloudTrail logging disabled or deleted | T1562.008 (Impair Defenses: Disable Cloud Logs) |
| `aws_s3_bucket_public_access.py` | S3 bucket made publicly accessible | T1530 (Data from Cloud Storage) |
| `aws_s3_bucket_deleted.py` | S3 bucket deleted (data destruction) | T1485 (Data Destruction) |
| `aws_s3_object_lock_disabled.py` | S3 Object Lock disabled (ransomware prep) | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| `aws_ec2_security_group_modified.py` | Risky security group rule (0.0.0.0/0 on sensitive ports) | T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall) |
| `aws_ec2_download_instance_user_data.py` | EC2 user data downloaded (credential theft) | T1552.001 (Unsecured Credentials) |
| `aws_ec2_startup_script_changed.py` | EC2 instance user data modified (persistence) | T1525 (Implant Internal Image) |
| `aws_config_service_disabled.py` | AWS Config disabled or deleted | T1562.008 (Impair Defenses: Disable Cloud Logs) |
| `aws_guardduty_disabled.py` | GuardDuty detector disabled or deleted | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| `aws_kms_key_disabled_or_scheduled_deletion.py` | KMS key disabled or scheduled for deletion | T1486 (Data Encrypted for Impact) |
| `aws_vpc_flow_logs_disabled.py` | VPC Flow Logs disabled or deleted | T1562.008 (Impair Defenses: Disable Cloud Logs) |
| `aws_lambda_function_modified.py` | Lambda function code or configuration changed | T1525 (Implant Internal Image) |
| `aws_rds_snapshot_deleted.py` | RDS snapshot deleted (data destruction) | T1485 (Data Destruction) |
| `aws_ebs_snapshot_deleted.py` | EBS snapshot deleted (data destruction) | T1485 (Data Destruction) |
| `aws_ssm_send_command.py` | SSM Run Command executed (remote code execution) | T1651 (Cloud Administration Command) |

### Medium Severity (15 rules)

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `aws_iam_user_created.py` | New IAM user created (should use roles instead) | T1136.003 (Create Account: Cloud Account) |
| `aws_iam_policy_modified.py` | IAM policy modified (inline or managed) | T1098 (Account Manipulation) |
| `aws_iam_assume_role_blacklist.py` | Sensitive role assumption detected | T1548.002 (Abuse Elevation Control: Bypass User Account Control) |
| `aws_iam_user_login_profile_modified.py` | Login profile created/modified (potential takeover) | T1098 (Account Manipulation) |
| `aws_iam_entity_creation_by_new_user.py` | New user creating IAM entities (compromise spread) | T1136.003 (Create Account: Cloud Account) |
| `aws_iam_unusual_user_agent.py` | IAM changes with unusual user agent | T1087.004 (Account Discovery: Cloud Account) |
| `aws_console_login_without_mfa.py` | Console login without MFA | T1078.004 (Valid Accounts: Cloud Accounts) |
| `aws_ec2_instance_modified_for_persistence.py` | EC2 instance attributes modified | T1525 (Implant Internal Image) |
| `aws_ec2_network_acl_modified.py` | Network ACL entry created or modified | T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall) |
| `aws_ec2_vpc_route_table_modified.py` | VPC route table modified (exfiltration path) | T1599.001 (Network Boundary Bridging: Network Address Translation Traversal) |
| `aws_ec2_gateway_modified.py` | Internet/NAT gateway created or attached | T1599.001 (Network Boundary Bridging) |
| `aws_s3_access_logging_disabled.py` | S3 access logging disabled (defense evasion) | T1562.008 (Impair Defenses: Disable Cloud Logs) |
| `aws_ssm_session_started.py` | SSM Session Manager session started | T1651 (Cloud Administration Command) |

### Info/Low Severity (2 rules)

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `aws_secrets_manager_secret_accessed.py` | Secrets Manager secret accessed | T1552.001 (Unsecured Credentials: Credentials In Files) |
| `aws_unauthorized_api_call.py` | AccessDenied errors (reconnaissance activity) | T1580 (Cloud Infrastructure Discovery) |
| `aws_console_login_failed.py` | Failed console login attempts | T1110 (Brute Force) |
| `aws_ecr_image_pushed.py` | Container image pushed to ECR | T1525 (Implant Internal Image) |

## Threat Coverage

### Initial Access
- Root account login detection
- Console login without MFA
- Failed console login attempts (brute force)
- Unauthorized API calls

### Persistence
- IAM user creation (by assumed roles/services)
- IAM access key creation (cross-user)
- EC2 instance modification (user data changes)
- Lambda function backdoors
- SSM Session Manager sessions

### Privilege Escalation
- Admin policy attachments
- IAM policy modifications
- Cross-user key creation
- Sensitive role assumption
- Login profile modifications (password resets)

### Defense Evasion
- CloudTrail disabled
- GuardDuty disabled
- AWS Config disabled
- VPC Flow Logs disabled
- S3 access logging disabled
- S3 Object Lock disabled
- KMS key deletion
- Unusual user agent strings

### Credential Access
- Root access key creation
- Secrets Manager access tracking
- EC2 user data downloads
- EC2 startup script changes

### Discovery
- AccessDenied errors (recon attempts)
- Unusual IAM operations

### Execution
- SSM Run Command (remote code execution)
- Lambda function modifications

### Lateral Movement
- Security group modifications
- Network ACL changes
- VPC route table changes
- Internet/NAT gateway attachments

### Collection
- S3 access logging disabled
- EC2 user data access

### Exfiltration
- S3 bucket public exposure
- RDS snapshot public sharing
- EBS snapshot public exposure
- Gateway modifications (data egress paths)

### Impact
- KMS key deletion (ransomware preparation)
- S3 bucket deletion
- RDS snapshot deletion
- EBS snapshot deletion
- S3 Object Lock disabled

## Usage

### Test a Single Rule

```bash
./bin/iota --mode=once \
  --jsonl=testdata/events/root-login.jsonl \
  --rules=rules/aws_cloudtrail \
  --python=python3 \
  --engine=engines/iota/engine.py
```

### Watch Mode (Production)

```bash
./bin/iota --mode=watch \
  --events-dir=/mnt/cloudtrail \
  --rules=rules/aws_cloudtrail \
  --python=python3 \
  --engine=engines/iota/engine.py \
  --state=/var/lib/iota/state.db \
  --slack-webhook=https://hooks.slack.com/...
```

## Rule Development

### Writing New Rules

Every rule must implement at minimum:

```python
def rule(event):
    """Detection logic - returns True if event matches"""
    return event.get("eventName") == "SomeEvent"
```

Optional functions:

```python
def title(event):
    """Dynamic alert title with context"""
    return f"Alert: {event.get('eventName')}"

def severity():
    """Static severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"""
    return "HIGH"

def alert_context(event):
    """Additional context for SOC analysts"""
    return {
        "actor": event.get("userIdentity", {}).get("arn"),
        "time": event.get("eventTime")
    }
```

### Using Helpers

```python
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context

def rule(event):
    # Safe nested field access
    user_type = deep_get(event, "userIdentity", "type")

    # Check if API call succeeded
    if not is_successful(event):
        return False

    # Your detection logic
    return user_type == "Root"
```

### Testing Rules

Create a test event file:

```jsonl
{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"responseElements":{"ConsoleLogin":"Success"}}
```

Run:

```bash
./bin/iota --mode=once --jsonl=test_event.jsonl --rules=rules/aws_cloudtrail
```

## Tuning False Positives

### By IP Address

Add to your rule:

```python
KNOWN_IPS = ["203.0.113.1", "198.51.100.42"]

def rule(event):
    if event.get("sourceIPAddress") in KNOWN_IPS:
        return False
    # ... rest of detection logic
```

### By Principal ARN

```python
ALLOWED_ARNS = [
    "arn:aws:iam::123456789012:role/TerraformRole",
    "arn:aws:iam::123456789012:user/admin"
]

def rule(event):
    actor_arn = deep_get(event, "userIdentity", "arn", default="")
    if any(allowed in actor_arn for allowed in ALLOWED_ARNS):
        return False
    # ... rest of detection logic
```

### By Time Window

```python
from datetime import datetime, time

def rule(event):
    # Only alert outside business hours
    event_time = datetime.fromisoformat(event.get("eventTime").replace("Z", "+00:00"))
    if time(8, 0) <= event_time.time() <= time(18, 0):  # 8 AM - 6 PM
        return False
    # ... rest of detection logic
```

## Rule Maintenance

### Regular Updates

- Review new CloudTrail event types quarterly
- Adjust severity based on alert fatigue
- Add tuning for known false positives
- Update threat intelligence indicators

### Community Contributions

Ported from [panther-analysis](https://github.com/panther-labs/panther-analysis) open-source detection rules.

To contribute new rules:
1. Write the rule following the template above
2. Test with sample CloudTrail events
3. Document the threat scenario
4. Add MITRE ATT&CK mapping
5. Submit a pull request

## Future Enhancements

- [ ] Add rule unit tests
- [ ] Implement correlation (multi-step attacks)
- [ ] Add machine learning anomaly detection
- [ ] Support custom severity functions
- [ ] Add automatic remediation actions
- [x] Port critical CloudTrail rules from panther-analysis (39/107 ported)
- [ ] Add Okta detection rules
- [ ] Add Azure AD detection rules
- [ ] Add Google Workspace detection rules

## References

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Panther Detection Rules](https://github.com/panther-labs/panther-analysis)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
