"""
Detect when AdministratorAccess policy is attached to a user.

This is a privilege escalation risk - users should receive permissions through roles, not direct policy attachment.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect AttachUserPolicy with AdministratorAccess"""
    if not is_successful(event) or event.get("eventName") != "AttachUserPolicy":
        return False

    policy_arn = deep_get(event, "requestParameters", "policyArn", default="")
    return policy_arn.endswith("AdministratorAccess")


def title(event):
    """Generate alert title"""
    username = deep_get(event, "requestParameters", "userName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"AdministratorAccess policy attached to user [{username}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["targetUsername"] = deep_get(
        event, "requestParameters", "userName", default="USERNAME_NOT_FOUND"
    )
    context["policyArn"] = deep_get(
        event, "requestParameters", "policyArn", default="POLICY_NOT_FOUND"
    )
    return context
