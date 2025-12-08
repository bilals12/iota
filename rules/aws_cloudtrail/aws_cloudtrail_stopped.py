"""
Detect CloudTrail being stopped or deleted.

Attackers often disable logging to cover their tracks. This detects CloudTrail modifications.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect CloudTrail Stop/Delete operations"""
    return is_successful(event) and event.get("eventName") in [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    trail_name = deep_get(event, "requestParameters", "name", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"CloudTrail [{trail_name}] {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["trailName"] = deep_get(event, "requestParameters", "name")
    return context
