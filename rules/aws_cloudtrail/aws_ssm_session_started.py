"""
Detect SSM Session Manager sessions being started.

SSM Session Manager provides remote shell access to EC2 instances - monitor for unauthorized access.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect StartSession API calls"""
    if not is_successful(event):
        return False

    return event.get("eventName") == "StartSession"


def title(event):
    """Generate alert title"""
    target = deep_get(event, "requestParameters", "target", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"SSM Session started on [{target}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["target"] = deep_get(event, "requestParameters", "target")
    context["documentName"] = deep_get(event, "requestParameters", "documentName")
    context["sessionId"] = deep_get(event, "responseElements", "sessionId")
    return context
