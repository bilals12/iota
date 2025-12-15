"""
Detect Okta MFA factor suspension.

MFA factor suspension can weaken account security and may indicate
an attacker preparing for account takeover.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import (
    okta_alert_context,
    get_actor_user,
    get_okta_target_users,
    is_okta_success,
)


def rule(event):
    """Detect MFA factor suspension."""
    if event.get("eventType") != "user.mfa.factor.suspend":
        return False

    return is_okta_success(event)


def title(event):
    """Generate alert title."""
    target_users = get_okta_target_users(event)
    target = target_users[0] if target_users else "<UNKNOWN>"
    actor = get_actor_user(event)
    return f"Okta MFA factor suspended for [{target}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
