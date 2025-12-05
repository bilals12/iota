"""
Detect MFA factor reset in Okta.

Alerts when a user resets one of their own MFA factors.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context


def rule(event):
    """Detect MFA factor deactivation"""
    return event.get("eventType") == "user.mfa.factor.deactivate"


def title(event):
    """Generate alert title"""
    # Extract which factor was reset from outcome reason
    outcome_reason = deep_get(event, "outcome", "reason", default="")
    try:
        which_factor = (
            outcome_reason.split()[2] if outcome_reason else "<FACTOR_NOT_FOUND>"
        )
    except IndexError:
        which_factor = "<FACTOR_NOT_FOUND>"

    target = event.get("target", [{}])
    target_id = (
        target[0].get("alternateId", "<id-not-found>") if target else "<id-not-found>"
    )
    actor_id = deep_get(event, "actor", "alternateId", default="<id-not-found>")

    return f"Okta: MFA factor [{which_factor}] reset for [{target_id}] by [{actor_id}]"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    context = okta_alert_context(event)
    context["factorReset"] = deep_get(event, "outcome", "reason")
    return context
