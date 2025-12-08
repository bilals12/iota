"""
Detect GuardDuty being disabled or deleted.

Attackers often disable security services to avoid detection.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect GuardDuty being disabled"""
    return is_successful(event) and event.get("eventName") in [
        "DeleteDetector",
        "DeleteMembers",
        "DisassociateFromMasterAccount",
        "DisassociateMembers",
        "StopMonitoringMembers",
        "UpdateDetector",  # Can disable GuardDuty
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"GuardDuty {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["detectorId"] = deep_get(event, "requestParameters", "detectorId")
    # Check if UpdateDetector disabled it
    if event.get("eventName") == "UpdateDetector":
        context["enable"] = deep_get(event, "requestParameters", "enable")
    return context
