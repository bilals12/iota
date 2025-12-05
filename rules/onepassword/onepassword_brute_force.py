"""
Detect brute force login attempts against 1Password.

Alerts when failed sign-in attempts from a single IP exceed a threshold.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from onepassword_helpers import onepassword_alert_context, is_onepassword_failure


def rule(event):
    """Detect failed sign-in attempts"""
    return is_onepassword_failure(event)


def title(event):
    """Generate alert title"""
    ip_address = deep_get(event, "client", "ip_address", default="<UNKNOWN_IP>")
    return f"1Password: Failed login attempts from IP [{ip_address}] exceeded threshold"


def severity():
    """Return alert severity"""
    return "INFO"


def dedup(event):
    """Dedup by source IP"""
    return deep_get(event, "client", "ip_address", default="<UNKNOWN_IP>")


def threshold():
    """Number of events before alert triggers"""
    return 20


def alert_context(event):
    """Additional context for the alert"""
    context = onepassword_alert_context(event)
    context["failureCategory"] = event.get("category")
    context["failureType"] = event.get("type")
    context["targetUser"] = deep_get(event, "target_user", "email")
    return context
