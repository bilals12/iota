"""
Detect suspicious IAM user creation patterns.

Monitors for IAM users created by non-human entities (roles/services) which may indicate backdoor accounts.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect IAM user created by assumed role or service"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "CreateUser":
        return False

    # Alert if user was created by AssumedRole or AWSService
    user_type = deep_get(event, "userIdentity", "type", default="")
    return user_type in ["AssumedRole", "AWSService"]


def title(event):
    """Generate alert title"""
    new_user = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    actor_type = deep_get(event, "userIdentity", "type", default="UNKNOWN")

    return f"IAM user [{new_user}] created by [{actor_type}]: [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["newUserName"] = deep_get(event, "requestParameters", "userName")
    context["actorType"] = deep_get(event, "userIdentity", "type")
    context["actorSessionName"] = deep_get(
        event, "userIdentity", "sessionContext", "sessionIssuer", "userName"
    )
    return context
