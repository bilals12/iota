"""
Detect IAM entity creation by newly created users.

Newly created users creating more users/roles may indicate account compromise spreading.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect new users creating IAM entities"""
    if not is_successful(event):
        return False

    # Check if creating IAM users or roles
    event_name = event.get("eventName")
    if event_name not in ["CreateUser", "CreateRole", "CreateAccessKey"]:
        return False

    # Check if actor is an IAM user (not role/service)
    actor_type = deep_get(event, "userIdentity", "type", default="")
    if actor_type != "IAMUser":
        return False

    # This is a simplified check - in production you'd maintain user creation timestamps
    # For demo purposes, we'll alert on any IAM user creating these resources
    # Customize this logic based on your environment
    return True


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")
    actor_user = deep_get(event, "userIdentity", "userName", default="UNKNOWN")

    if event_name == "CreateUser":
        target = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
        action = f"created user [{target}]"
    elif event_name == "CreateRole":
        target = deep_get(event, "requestParameters", "roleName", default="UNKNOWN")
        action = f"created role [{target}]"
    else:  # CreateAccessKey
        target = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
        action = f"created access key for [{target}]"

    return f"IAM user [{actor_user}] {action}"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["actorUserName"] = deep_get(event, "userIdentity", "userName")
    context["principalId"] = deep_get(event, "userIdentity", "principalId")

    # Add target entity details
    event_name = event.get("eventName")
    if event_name == "CreateUser":
        context["targetUserName"] = deep_get(event, "requestParameters", "userName")
    elif event_name == "CreateRole":
        context["targetRoleName"] = deep_get(event, "requestParameters", "roleName")
    else:  # CreateAccessKey
        context["targetUserName"] = deep_get(event, "requestParameters", "userName")

    return context
