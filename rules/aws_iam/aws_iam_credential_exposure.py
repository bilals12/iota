import sys

sys.path.append("..")
from helpers.iam_actions import (
    is_credential_exposure,
    get_action,
)

ALLOWLISTED_PRINCIPALS = set()
ALLOWLISTED_SOURCE_IPS = set()

CRITICAL_ACTIONS = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreateServiceSpecificCredential",
    "ec2:GetPasswordData",
    "lightsail:GetRelationalDatabaseMasterUserPassword",
    "redshift:GetClusterCredentials",
}

HIGH_ACTIONS = {
    "iam:UpdateAccessKey",
    "iam:ResetServiceSpecificCredential",
    "ec2-instance-connect:SendSSHPublicKey",
    "ecr:GetAuthorizationToken",
    "ecr-public:GetAuthorizationToken",
    "codeartifact:GetAuthorizationToken",
    "cognito-identity:GetCredentialsForIdentity",
    "cognito-identity:GetOpenIdToken",
    "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
}


def rule(event):
    if event.get("errorCode"):
        return False
    if not is_credential_exposure(event):
        return False
    principal = event.get("userIdentity", {}).get("arn", "")
    if principal in ALLOWLISTED_PRINCIPALS:
        return False
    source_ip = event.get("sourceIPAddress", "")
    if source_ip in ALLOWLISTED_SOURCE_IPS:
        return False
    return True


def title(event):
    action = get_action(event)
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    return f"Credential exposure action {action} by {principal}"


def severity(event):
    action = get_action(event)
    if action in CRITICAL_ACTIONS:
        return "CRITICAL"
    if action in HIGH_ACTIONS:
        return "HIGH"
    if action.startswith("sts:"):
        return "INFO"
    return "MEDIUM"


def dedup(event):
    return get_action(event)


def alert_context(event):
    return {
        "action": get_action(event),
        "principal": event.get("userIdentity", {}).get("arn"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "awsRegion": event.get("awsRegion"),
        "requestParameters": event.get("requestParameters"),
    }
