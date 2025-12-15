"""
Detect Okta system-wide MFA being disabled by an admin.

Disabling MFA across the organization significantly weakens security posture.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import okta_alert_context, get_actor_user


def rule(event):
    """Detect system-wide MFA being disabled."""
    return event.get("eventType") == "system.mfa.factor.deactivate"


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    return f"Okta system-wide MFA disabled by admin [{actor}]"


def severity(event):
    """Return alert severity."""
    return "CRITICAL"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
