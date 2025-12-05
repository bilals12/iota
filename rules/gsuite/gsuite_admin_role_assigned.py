"""
Detect admin role assignment in Google Workspace.

Alerts when a user is granted admin privileges.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from gsuite_helpers import (
    gsuite_alert_context,
    get_gsuite_event_name,
    get_gsuite_parameter,
    is_gsuite_admin_event,
)


def rule(event):
    """Detect admin role assignment"""
    if not is_gsuite_admin_event(event):
        return False

    event_name = get_gsuite_event_name(event)
    return event_name == "ASSIGN_ROLE"


def title(event):
    """Generate alert title"""
    actor_email = deep_get(event, "actor", "email", default="<UNKNOWN_ACTOR>")
    role_name = get_gsuite_parameter(event, "ROLE_NAME") or "<UNKNOWN_ROLE>"
    user_email = get_gsuite_parameter(event, "USER_EMAIL") or "<UNKNOWN_USER>"

    return f"GSuite: [{role_name}] role assigned to [{user_email}] by [{actor_email}]"


def severity(event):
    """Dynamic severity based on role"""
    role_name = get_gsuite_parameter(event, "ROLE_NAME") or ""
    if "super" in role_name.lower() or "admin" in role_name.lower():
        return "HIGH"
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    context = gsuite_alert_context(event)
    context["roleName"] = get_gsuite_parameter(event, "ROLE_NAME")
    context["targetUser"] = get_gsuite_parameter(event, "USER_EMAIL")
    return context
