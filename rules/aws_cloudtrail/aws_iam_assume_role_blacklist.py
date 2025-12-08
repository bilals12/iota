"""
Detect AssumeRole from suspicious principals or to sensitive roles.

Monitor role assumptions that could indicate privilege escalation or lateral movement.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context

# Customize these for your environment
SENSITIVE_ROLE_PATTERNS = [
    "Admin",
    "PowerUser",
    "OrganizationAccountAccess",
    "Production",
]

# Add suspicious external account IDs
EXTERNAL_ACCOUNT_WATCHLIST = []


def rule(event):
    """Detect suspicious AssumeRole calls"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "AssumeRole":
        return False

    # Check if assuming a sensitive role
    role_arn = deep_get(event, "requestParameters", "roleArn", default="")
    for pattern in SENSITIVE_ROLE_PATTERNS:
        if pattern in role_arn:
            return True

    # Check if assumed by external account
    assuming_account = deep_get(event, "userIdentity", "accountId", default="")
    target_account = event.get("recipientAccountId", "")

    # Cross-account assumption
    if assuming_account != target_account:
        # Check watchlist
        if assuming_account in EXTERNAL_ACCOUNT_WATCHLIST:
            return True

    return False


def title(event):
    """Generate alert title"""
    role_arn = deep_get(event, "requestParameters", "roleArn", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Sensitive role [{role_arn}] assumed by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["roleArn"] = deep_get(event, "requestParameters", "roleArn")
    context["roleSessionName"] = deep_get(event, "requestParameters", "roleSessionName")
    context["assumingAccountId"] = deep_get(event, "userIdentity", "accountId")
    context["targetAccountId"] = event.get("recipientAccountId")
    return context
