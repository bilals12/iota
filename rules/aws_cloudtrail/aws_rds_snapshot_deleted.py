"""
Detect RDS snapshot deletion.

Snapshot deletion can indicate data destruction or ransomware preparation.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect RDS snapshot deletion"""
    if not is_successful(event):
        return False

    event_name = event.get("eventName")
    return event_name in ["DeleteDBSnapshot", "DeleteDBClusterSnapshot"]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")

    if event_name == "DeleteDBSnapshot":
        snapshot_id = deep_get(
            event, "requestParameters", "dBSnapshotIdentifier", default="UNKNOWN"
        )
    else:  # DeleteDBClusterSnapshot
        snapshot_id = deep_get(
            event, "requestParameters", "dBClusterSnapshotIdentifier", default="UNKNOWN"
        )

    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"RDS snapshot [{snapshot_id}] deleted by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["snapshotIdentifier"] = deep_get(
        event, "requestParameters", "dBSnapshotIdentifier"
    ) or deep_get(event, "requestParameters", "dBClusterSnapshotIdentifier")
    return context
