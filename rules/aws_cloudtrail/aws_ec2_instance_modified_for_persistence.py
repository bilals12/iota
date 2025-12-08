"""
Detect EC2 instance user data modification.

User data can be used to establish persistence on instances.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect EC2 instance user data modification"""
    return is_successful(event) and event.get("eventName") == "ModifyInstanceAttribute"


def title(event):
    """Generate alert title"""
    instance_id = deep_get(event, "requestParameters", "instanceId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"EC2 instance [{instance_id}] attributes modified by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["instanceId"] = deep_get(event, "requestParameters", "instanceId")
    context["attribute"] = deep_get(event, "requestParameters", "attribute")
    return context
