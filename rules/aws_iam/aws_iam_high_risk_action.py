import sys

sys.path.append("..")
from helpers.iam_actions import is_high_risk_iam, get_action

ALLOWLISTED_PRINCIPALS = set()
ALLOWLISTED_AUTOMATION_USER_AGENTS = {
    "Terraform",
    "CloudFormation",
    "aws-sdk-go",
    "Boto3",
}


def rule(event):
    if event.get("errorCode"):
        return False
    if not is_high_risk_iam(event):
        return False
    principal = event.get("userIdentity", {}).get("arn", "")
    if principal in ALLOWLISTED_PRINCIPALS:
        return False
    user_agent = event.get("userAgent", "")
    for allowed in ALLOWLISTED_AUTOMATION_USER_AGENTS:
        if allowed.lower() in user_agent.lower():
            return False
    return True


def title(event):
    action = get_action(event)
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    target = _get_target(event)
    return f"High-risk IAM action: {action} on {target} by {principal}"


def _get_target(event):
    params = event.get("requestParameters", {})
    return (
        params.get("userName")
        or params.get("roleName")
        or params.get("groupName")
        or params.get("policyArn")
        or params.get("policyName")
        or "unknown"
    )


def severity(event):
    action = get_action(event)
    if action in {
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateAssumeRolePolicy",
        "iam:PassRole",
    }:
        return "HIGH"
    if action.startswith("iam:Delete"):
        return "MEDIUM"
    return "INFO"


def dedup(event):
    return f"{get_action(event)}:{_get_target(event)}"


def alert_context(event):
    return {
        "action": get_action(event),
        "principal": event.get("userIdentity", {}).get("arn"),
        "target": _get_target(event),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "requestParameters": event.get("requestParameters"),
    }
