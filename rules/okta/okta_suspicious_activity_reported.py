"""
Detect user-reported suspicious activity in Okta.

When users report suspicious activity, it may indicate an ongoing attack
or compromised credentials.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import okta_alert_context, get_actor_user


def rule(event):
    """Detect user-reported suspicious activity."""
    return (
        event.get("eventType") == "user.account.report_suspicious_activity_by_enduser"
    )


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    return f"Okta: User [{actor}] reported suspicious activity"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
