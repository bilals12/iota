"""
Detect unauthorized API calls (AccessDenied errors).

Multiple AccessDenied errors can indicate reconnaissance or privilege escalation attempts.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, aws_rule_context


def rule(event):
    """Detect AccessDenied errors"""
    error_code = event.get("errorCode")
    return error_code in [
        "AccessDenied",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Unauthorized {event_name} attempted by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "LOW"  # Low by default, but pattern analysis can elevate


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["errorCode"] = event.get("errorCode")
    context["errorMessage"] = event.get("errorMessage")
    return context
