"""
Detect IAM policy modifications.

Policy changes can grant excessive permissions.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect IAM policy modifications"""
    return is_successful(event) and event.get("eventName") in [
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    # Extract the target entity
    target = (
        deep_get(event, "requestParameters", "userName")
        or deep_get(event, "requestParameters", "roleName")
        or deep_get(event, "requestParameters", "groupName")
        or deep_get(event, "requestParameters", "policyArn")
        or "UNKNOWN"
    )

    return f"IAM policy {event_name} on [{target}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["policyDocument"] = deep_get(event, "requestParameters", "policyDocument")
    context["policyName"] = deep_get(event, "requestParameters", "policyName")
    context["policyArn"] = deep_get(event, "requestParameters", "policyArn")
    return context
