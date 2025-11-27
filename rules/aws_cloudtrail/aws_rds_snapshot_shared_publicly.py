"""
Detect RDS snapshots being shared publicly.

Public RDS snapshots can expose sensitive database data.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect RDS snapshots shared publicly"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "ModifyDBSnapshotAttribute":
        return False

    # Check if snapshot is being shared with "all" (public)
    values_to_add = deep_get(
        event, "requestParameters", "valuesToAdd", default=[]
    )

    return "all" in values_to_add


def title(event):
    """Generate alert title"""
    snapshot_id = deep_get(
        event, "requestParameters", "dBSnapshotIdentifier", default="UNKNOWN"
    )
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"RDS snapshot [{snapshot_id}] shared publicly by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "CRITICAL"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["snapshotId"] = deep_get(
        event, "requestParameters", "dBSnapshotIdentifier"
    )
    context["attributeName"] = deep_get(
        event, "requestParameters", "attributeName"
    )
    context["valuesToAdd"] = deep_get(
        event, "requestParameters", "valuesToAdd"
    )
    return context
