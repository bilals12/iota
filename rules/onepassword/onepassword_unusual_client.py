"""
Detect unusual 1Password client access.

Alerts when non-standard 1Password clients connect to the account.
Run a query to baseline your environment's clients before enabling.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from onepassword_helpers import onepassword_alert_context

# Standard 1Password clients - customize for your environment
CLIENT_ALLOWLIST = [
    "1Password CLI",
    "1Password for Web",
    "1Password for Mac",
    "1Password SCIM Bridge",
    "1Password for Windows",
    "1Password for iOS",
    "1Password Browser Extension",
    "1Password for Android",
    "1Password for Linux",
    "1Password SDK",
]


def rule(event):
    """Detect unusual client access"""
    client_name = deep_get(event, "client", "app_name")
    if not client_name:
        return False
    return client_name not in CLIENT_ALLOWLIST


def title(event):
    """Generate alert title"""
    client_name = deep_get(event, "client", "app_name", default="<UNKNOWN_CLIENT>")
    return f"1Password: Unusual client detected - {client_name}"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = onepassword_alert_context(event)
    context["user"] = deep_get(event, "target_user", "name", default="UNKNOWN_USER")
    context["userEmail"] = deep_get(event, "target_user", "email")
    context["client"] = deep_get(event, "client", "app_name", default="UNKNOWN_CLIENT")
    context["os"] = deep_get(event, "client", "os_name", default="UNKNOWN_OS")
    context["loginResult"] = event.get("category")
    return context
