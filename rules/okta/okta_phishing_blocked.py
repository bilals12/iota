"""
Detect Okta FastPass blocking a phishing attempt.

FastPass can detect and block phishing attempts when the authentication
context doesn't match expected parameters.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import okta_alert_context, get_actor_user


def rule(event):
    """Detect FastPass blocking phishing."""
    if event.get("eventType") != "user.authentication.auth_via_mfa":
        return False

    outcome = event.get("outcome", {})
    if outcome.get("result") != "FAILURE":
        return False

    return outcome.get("reason") == "FastPass declined phishing attempt"


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    return f"Okta FastPass blocked phishing attempt for [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
