"""
Detect downloading EC2 instance user data.

User data often contains credentials and secrets - downloading it is suspicious.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect DescribeInstanceAttribute with userData"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "DescribeInstanceAttribute":
        return False

    # Check if attribute requested was userData
    attribute = deep_get(event, "requestParameters", "attribute")
    return attribute == "userData"


def title(event):
    """Generate alert title"""
    instance_id = deep_get(event, "requestParameters", "instanceId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"EC2 user data downloaded for instance [{instance_id}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["instanceId"] = deep_get(event, "requestParameters", "instanceId")
    context["attribute"] = deep_get(event, "requestParameters", "attribute")
    return context
