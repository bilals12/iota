"""
Detect accessing another user's password in Okta.

This can indicate credential theft or privilege abuse.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, okta_alert_context, get_actor_user


def _get_target_users(event):
    """Extract target users from event."""
    targets = event.get("target", [])
    users = set()
    for target in targets:
        if target.get("type") == "User":
            user_id = target.get("alternateId")
            if user_id:
                users.add(user_id)
    return users


def _get_target_apps(event):
    """Extract target applications from event."""
    targets = event.get("target", [])
    apps = set()
    for target in targets:
        if target.get("type") == "AppInstance":
            app_id = target.get("alternateId")
            if app_id:
                apps.add(app_id)
    return apps


def rule(event):
    """Detect password access for another user."""
    if event.get("eventType") != "application.user_membership.show_password":
        return False

    actor = deep_get(event, "actor", "alternateId", default="")
    target_users = _get_target_users(event)

    # Alert if actor is accessing someone else's password
    return actor not in target_users


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    target_users = _get_target_users(event)
    target_apps = _get_target_apps(event)
    return f"Okta: [{actor}] accessed password for [{target_users}] in [{target_apps}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def dedup(event):
    """Custom deduplication key."""
    actor = deep_get(event, "actor", "alternateId", default="")
    target_users = _get_target_users(event)
    target_apps = _get_target_apps(event)
    return f"{actor}:{target_users}:{target_apps}"


def alert_context(event):
    """Additional context for the alert."""
    context = okta_alert_context(event)
    context["targetUsers"] = list(_get_target_users(event))
    context["targetApps"] = list(_get_target_apps(event))
    return context
