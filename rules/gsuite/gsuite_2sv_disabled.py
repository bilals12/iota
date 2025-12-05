"""
Detect 2-Step Verification disabled in Google Workspace.

Alerts when a user disables 2-Step Verification (MFA).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gsuite_helpers import (
    gsuite_alert_context,
    get_gsuite_event_name,
    is_gsuite_login_event,
)


def rule(event):
    """Detect 2SV disabled"""
    if not is_gsuite_login_event(event):
        return False

    event_name = get_gsuite_event_name(event)
    return event_name == "2sv_disable"


def title(event):
    """Generate alert title"""
    actor_email = deep_get(event, "actor", "email", default="<UNKNOWN_USER>")
    return f"GSuite: 2-Step Verification disabled for [{actor_email}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    return gsuite_alert_context(event)
