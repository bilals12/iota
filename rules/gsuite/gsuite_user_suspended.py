"""
Detect user suspension in Google Workspace.

Alerts when an admin suspends a user account.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gsuite_helpers import (
    gsuite_alert_context,
    get_gsuite_event_name,
    is_gsuite_admin_event,
)


def rule(event):
    """Detect user suspension"""
    if not is_gsuite_admin_event(event):
        return False

    event_name = get_gsuite_event_name(event)
    return event_name == "SUSPEND_USER"


def title(event):
    """Generate alert title"""
    actor_email = deep_get(event, "actor", "email", default="<UNKNOWN_ACTOR>")
    return f"GSuite: User suspended by [{actor_email}]"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    return gsuite_alert_context(event)
