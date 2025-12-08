"""
Detect when one user creates API keys for another user.

This can indicate privilege escalation or unauthorized key creation.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect cross-user access key creation"""
    if not is_successful(event):
        return False

    if event.get("eventSource") != "iam.amazonaws.com":
        return False

    if event.get("eventName") != "CreateAccessKey":
        return False

    # Check if the creator is different from the key owner
    creator_arn = deep_get(event, "userIdentity", "arn", default="")
    key_owner = deep_get(event, "responseElements", "accessKey", "userName", default="")

    # Alert if creator ARN doesn't match the user receiving the key
    return not creator_arn.endswith(f"user/{key_owner}")


def title(event):
    """Generate alert title"""
    creator = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    key_owner = deep_get(
        event, "responseElements", "accessKey", "userName", default="UNKNOWN"
    )
    return f"[{creator}] created API keys for [{key_owner}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["keyOwner"] = deep_get(event, "responseElements", "accessKey", "userName")
    context["accessKeyId"] = deep_get(
        event, "responseElements", "accessKey", "accessKeyId"
    )
    context["creator"] = deep_get(event, "userIdentity", "arn")
    return context
