"""
Detect admin role assignment in Okta.

Alerts when a user is granted administrative privileges. Higher severity for Super Administrator.
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context, is_okta_success

ADMIN_PATTERN = re.compile(r"[aA]dministrator")


def rule(event):
    """Detect admin privilege grant"""
    if event.get("eventType") != "user.account.privilege.grant":
        return False

    if not is_okta_success(event):
        return False

    privilege_granted = deep_get(
        event, "debugContext", "debugData", "privilegeGranted", default=""
    )
    return bool(ADMIN_PATTERN.search(privilege_granted))


def title(event):
    """Generate alert title"""
    target = event.get("target", [{}])
    display_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME") if target else ""
    )
    alternate_id = (
        target[0].get("alternateId", "MISSING ALTERNATE ID") if target else ""
    )
    privilege = deep_get(
        event,
        "debugContext",
        "debugData",
        "privilegeGranted",
        default="<UNKNOWN_PRIVILEGE>",
    )
    actor_name = deep_get(event, "actor", "displayName", default="<UNKNOWN>")
    actor_id = deep_get(event, "actor", "alternateId", default="<UNKNOWN>")

    return f"{actor_name} <{actor_id}> granted [{privilege}] to {display_name} <{alternate_id}>"


def severity(event):
    """Dynamic severity based on privilege granted"""
    privilege = deep_get(
        event, "debugContext", "debugData", "privilegeGranted", default=""
    )
    if "Super administrator" in privilege:
        return "HIGH"
    return "INFO"


def dedup(event):
    """Dedup by request ID"""
    return deep_get(
        event, "debugContext", "debugData", "requestId", default="<UNKNOWN_REQUEST_ID>"
    )


def alert_context(event):
    """Additional context for the alert"""
    context = okta_alert_context(event)
    context["privilegeGranted"] = deep_get(
        event, "debugContext", "debugData", "privilegeGranted"
    )
    return context
