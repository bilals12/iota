"""
Detect IAM user creation.

IAM users should be rare in modern AWS - most access should use federated identities or roles.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect CreateUser API call"""
    return is_successful(event) and event.get("eventName") == "CreateUser"


def title(event):
    """Generate alert title"""
    username = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"IAM user [{username}] created by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["newUsername"] = deep_get(
        event, "requestParameters", "userName", default="USERNAME_NOT_FOUND"
    )
    return context
