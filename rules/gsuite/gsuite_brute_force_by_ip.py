"""
Detect brute force login attempts against Google Workspace.

Alerts when failed logins from a single IP exceed a threshold.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gsuite_helpers import gsuite_alert_context, is_gsuite_login_failure


def rule(event):
    """Detect failed login attempts"""
    return is_gsuite_login_failure(event)


def title(event):
    """Generate alert title"""
    ip_address = event.get("ipAddress", "<UNKNOWN_IP>")
    return f"GSuite: Failed login attempts from IP [{ip_address}] exceeded threshold"


def severity():
    """Return alert severity"""
    return "INFO"


def dedup(event):
    """Dedup by source IP"""
    return event.get("ipAddress", "<UNKNOWN_IP>")


def threshold():
    """Number of events before alert triggers"""
    return 20


def alert_context(event):
    """Additional context for the alert"""
    context = gsuite_alert_context(event)
    context["actorEmail"] = deep_get(event, "actor", "email")
    return context
