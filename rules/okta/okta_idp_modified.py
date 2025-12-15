"""
Detect Okta Identity Provider creation or modification.

Identity Provider modifications can indicate an attacker attempting to
establish persistent access via federated authentication.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import okta_alert_context, get_actor_user


def rule(event):
    """Detect IDP lifecycle events."""
    event_type = event.get("eventType", "")
    return "system.idp.lifecycle" in event_type


def title(event):
    """Generate alert title."""
    event_type = event.get("eventType", "")
    action = event_type.split(".")[-1] if event_type else "modified"
    actor = get_actor_user(event)

    # Get target IDP name
    targets = event.get("target", [])
    idp_name = "<UNKNOWN>"
    for target in targets:
        if target.get("displayName"):
            idp_name = target.get("displayName")
            break

    return f"Okta Identity Provider [{idp_name}] {action}d by [{actor}]"


def severity(event):
    """Return alert severity based on action."""
    event_type = event.get("eventType", "")
    if "create" in event_type:
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert."""
    return okta_alert_context(event)
