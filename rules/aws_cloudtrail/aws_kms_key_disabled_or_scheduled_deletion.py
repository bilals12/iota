"""
Detect KMS keys being disabled or scheduled for deletion.

This can be ransomware or data destruction activity.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect KMS key disable or deletion"""
    return is_successful(event) and event.get("eventName") in [
        "DisableKey",
        "ScheduleKeyDeletion",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    key_id = deep_get(event, "requestParameters", "keyId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"KMS key [{key_id}] {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["keyId"] = deep_get(event, "requestParameters", "keyId")
    context["pendingWindowInDays"] = deep_get(
        event, "requestParameters", "pendingWindowInDays"
    )
    return context
