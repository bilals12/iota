"""
Detect 1Password login from unusual country.

Alerts on successful logins from countries not in the allowlist.
Customize COUNTRY_ALLOWLIST for your organization.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from onepassword_helpers import onepassword_alert_context, is_onepassword_success

# Customize for your organization's expected countries
COUNTRY_ALLOWLIST = [
    "US",
    "CA",
    "GB",
    "DE",
    "FR",
    # Add countries where your employees are located
]


def rule(event):
    """Detect login from unusual country"""
    if not is_onepassword_success(event):
        return False

    country = event.get("country")
    if not country:
        return False

    return country not in COUNTRY_ALLOWLIST


def title(event):
    """Generate alert title"""
    country = event.get("country", "<UNKNOWN_COUNTRY>")
    user_email = deep_get(event, "target_user", "email", default="<UNKNOWN_USER>")
    return f"1Password: Login from [{country}] by [{user_email}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = onepassword_alert_context(event)
    context["country"] = event.get("country")
    context["userEmail"] = deep_get(event, "target_user", "email")
    return context
