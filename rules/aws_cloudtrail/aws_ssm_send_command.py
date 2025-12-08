"""
Detect SSM Run Command being executed.

SSM Run Command allows remote code execution on EC2 instances - critical to monitor.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect SendCommand API calls"""
    if not is_successful(event):
        return False

    return event.get("eventName") == "SendCommand"


def title(event):
    """Generate alert title"""
    document = deep_get(event, "requestParameters", "documentName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    # Get instance IDs
    instance_ids = deep_get(event, "requestParameters", "instanceIds", default=[])
    if instance_ids:
        targets = f"{len(instance_ids)} instance(s)"
    else:
        targets = "target(s)"

    return f"SSM Run Command [{document}] executed on [{targets}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["documentName"] = deep_get(event, "requestParameters", "documentName")
    context["instanceIds"] = deep_get(event, "requestParameters", "instanceIds")
    context["targets"] = deep_get(event, "requestParameters", "targets")
    context["parameters"] = deep_get(event, "requestParameters", "parameters")
    context["commandId"] = deep_get(event, "responseElements", "command", "commandId")
    return context
