"""
Detect EC2 snapshots being made public.

Public snapshots can expose sensitive data volumes.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect EBS snapshot made public"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "ModifySnapshotAttribute":
        return False

    # Check if createVolumePermission was modified to add "all" group
    add_group = deep_get(
        event,
        "requestParameters",
        "createVolumePermission",
        "add",
        "items",
        default=[]
    )

    # Check if "all" group was added
    for item in add_group:
        if item.get("group") == "all":
            return True

    return False


def title(event):
    """Generate alert title"""
    snapshot_id = deep_get(event, "requestParameters", "snapshotId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"EBS snapshot [{snapshot_id}] made public by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "CRITICAL"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["snapshotId"] = deep_get(event, "requestParameters", "snapshotId")
    context["createVolumePermission"] = deep_get(
        event, "requestParameters", "createVolumePermission"
    )
    return context
