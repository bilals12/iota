"""
Detect EBS snapshot deletion.

Snapshot deletion can indicate data destruction or ransomware preparation.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect EBS snapshot deletion"""
    if not is_successful(event):
        return False

    return event.get("eventName") == "DeleteSnapshot"


def title(event):
    """Generate alert title"""
    snapshot_id = deep_get(event, "requestParameters", "snapshotId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"EBS snapshot [{snapshot_id}] deleted by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["snapshotId"] = deep_get(event, "requestParameters", "snapshotId")
    return context
