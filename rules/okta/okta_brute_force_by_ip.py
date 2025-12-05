"""
Detect brute force login attempts from a single IP in Okta.

Alerts when failed logins from a single IP exceed a threshold.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context, is_okta_failure


def rule(event):
    """Detect failed login attempts"""
    if event.get("eventType") != "user.session.start":
        return False

    return is_okta_failure(event)


def title(event):
    """Generate alert title"""
    ip_address = deep_get(event, "client", "ipAddress", default="<UNKNOWN_IP>")
    return f"Okta: Failed login attempts from IP [{ip_address}] exceeded threshold"


def severity():
    """Return alert severity"""
    return "INFO"


def dedup(event):
    """Dedup by source IP"""
    return deep_get(event, "client", "ipAddress", default="<UNKNOWN_IP>")


def threshold():
    """Number of events before alert triggers"""
    return 20


def alert_context(event):
    """Additional context for the alert"""
    context = okta_alert_context(event)
    context["failureReason"] = deep_get(event, "outcome", "reason")
    return context
