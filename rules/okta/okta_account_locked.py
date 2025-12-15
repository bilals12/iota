"""
Detect Okta user account lockouts.

Account lockouts can indicate brute force attacks or credential stuffing.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import okta_alert_context, get_actor_user


def rule(event):
    """Detect account lockout events."""
    event_type = event.get("eventType", "")
    return event_type in ("user.account.lock", "user.account.lock.limit")


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    message = event.get("displayMessage", "account has been locked")
    return f"Okta account locked: [{actor}] - {message}"


def severity(event):
    """Return alert severity."""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
