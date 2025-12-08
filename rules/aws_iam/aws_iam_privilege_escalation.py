import sys

sys.path.append("..")
from helpers.iam_actions import is_privesc, get_action

ALLOWLISTED_PRINCIPALS = set()
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


def rule(event):
    if event.get("errorCode"):
        return False
    if not is_privesc(event):
        return False
    principal = event.get("userIdentity", {}).get("arn", "")
    if principal in ALLOWLISTED_PRINCIPALS:
        return False
    return True


def title(event):
    action = get_action(event)
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    target = _get_target(event)
    return f"Privilege escalation: {action} on {target} by {principal}"


def _get_target(event):
    params = event.get("requestParameters", {})
    return (
        params.get("userName")
        or params.get("roleName")
        or params.get("groupName")
        or params.get("policyArn")
        or "unknown"
    )


def severity(event):
    action = get_action(event)
    params = event.get("requestParameters", {})
    policy_arn = params.get("policyArn", "")
    if policy_arn in ADMIN_POLICY_ARNS:
        return "CRITICAL"
    if action in {
        "iam:PassRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreatePolicyVersion",
    }:
        return "CRITICAL"
    if action.startswith("iam:Attach") or action.startswith("iam:Put"):
        return "HIGH"
    return "MEDIUM"


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
