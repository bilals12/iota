"""
Detect failed AWS console login attempts.

Failed logins can indicate brute force attacks or credential stuffing.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, aws_rule_context


def rule(event):
    """Detect failed console logins"""
    if event.get("eventName") != "ConsoleLogin":
        return False

    # Check for failed login
    response = event.get("responseElements", {})
    return response.get("ConsoleLogin") == "Failure"


def title(event):
    """Generate alert title"""
    user_type = deep_get(event, "userIdentity", "type", default="Unknown")
    if user_type == "Root":
        user = "root user"
    else:
        user = deep_get(event, "userIdentity", "userName", default="UNKNOWN")

    source_ip = event.get("sourceIPAddress", "UNKNOWN")
    return f"Failed console login for [{user}] from [{source_ip}]"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["loginResult"] = deep_get(event, "responseElements", "ConsoleLogin")
    context["errorMessage"] = event.get("errorMessage")
    context["mfaUsed"] = deep_get(event, "additionalEventData", "MFAUsed")
    return context
