"""
Detect API token creation in Okta.

Alerts when a user creates an API key, which could be used for programmatic access.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from iota_helpers import okta_alert_context, is_okta_success


def rule(event):
    """Detect API token creation"""
    if event.get("eventType") != "system.api_token.create":
        return False

    return is_okta_success(event)


def title(event):
    """Generate alert title"""
    target = event.get("target", [{}])
    key_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME")
        if target
        else "MISSING TARGET"
    )
    actor_name = deep_get(event, "actor", "displayName", default="<UNKNOWN>")
    actor_id = deep_get(event, "actor", "alternateId", default="<UNKNOWN>")

    return f"{actor_name} <{actor_id}> created API key: {key_name}"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    return okta_alert_context(event)
