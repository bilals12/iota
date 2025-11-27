"""
Detect root user access key creation.

Root access keys should NEVER exist. This is a critical security risk.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, aws_rule_context


def rule(event):
    """Detect root user creating access keys"""
    # Only check access key creation events
    if event.get("eventName") != "CreateAccessKey":
        return False

    # Only root can create root access keys
    if deep_get(event, "userIdentity", "type") != "Root":
        return False

    # Only alert if the root user is creating an access key for itself
    return event.get("requestParameters") is None


def title(event):
    """Generate alert title"""
    account = deep_get(event, "recipientAccountId", default="UNKNOWN")
    return f"ROOT ACCESS KEY CREATED in account [{account}] - IMMEDIATE ACTION REQUIRED"


def severity():
    """Return alert severity"""
    return "CRITICAL"


def alert_context(event):
    """Additional context for the alert"""
    return aws_rule_context(event)
