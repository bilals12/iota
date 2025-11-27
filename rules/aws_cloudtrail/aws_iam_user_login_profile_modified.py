"""
Detect IAM user login profile modifications.

Modifying login profiles can enable console access or reset passwords - potential account takeover.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect login profile creation or updates"""
    if not is_successful(event):
        return False

    event_name = event.get("eventName")
    if event_name not in ["CreateLoginProfile", "UpdateLoginProfile"]:
        return False

    # Alert if one user is modifying another user's login profile
    actor_name = deep_get(event, "userIdentity", "userName")
    target_name = deep_get(event, "requestParameters", "userName")

    # If actor is a role/federated user, get the session name
    if not actor_name:
        actor_name = deep_get(
            event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
        )

    # Alert if actor is modifying someone else's profile
    if actor_name and target_name and actor_name != target_name:
        return True

    return False


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")
    target_user = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    action = "created" if event_name == "CreateLoginProfile" else "modified"
    return f"Login profile {action} for user [{target_user}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["targetUserName"] = deep_get(event, "requestParameters", "userName")
    context["actorUserName"] = deep_get(event, "userIdentity", "userName")
    context["passwordResetRequired"] = deep_get(
        event, "requestParameters", "passwordResetRequired"
    )
    return context
