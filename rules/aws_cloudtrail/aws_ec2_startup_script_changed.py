"""
Detect EC2 instance user data (startup script) modifications.

User data often contains credentials - modifications can indicate persistence or backdoor attempts.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect ModifyInstanceAttribute with userData"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "ModifyInstanceAttribute":
        return False

    # Check if userData attribute was modified
    user_data = deep_get(event, "requestParameters", "userData")
    return user_data is not None


def title(event):
    """Generate alert title"""
    instance_id = deep_get(event, "requestParameters", "instanceId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"EC2 startup script (userData) modified for [{instance_id}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["instanceId"] = deep_get(event, "requestParameters", "instanceId")
    # Don't include actual userData value (may contain secrets)
    context["userDataModified"] = True
    return context
