"""
Detect unusual user agents making IAM changes.

Unusual user agents can indicate tool usage by attackers or automation gone rogue.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context

# Known good automation tools/services
ALLOWED_USER_AGENTS = [
    "aws-cli",
    "Boto3",
    "aws-sdk",
    "terraform",
    "Pulumi",
    "CloudFormation",
    "console.aws.amazon.com",
]

# IAM events to monitor
SENSITIVE_IAM_EVENTS = [
    "CreateUser",
    "CreateRole",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "UpdateAccessKey",
]


def rule(event):
    """Detect sensitive IAM operations with unusual user agents"""
    if not is_successful(event):
        return False

    # Check if it's a sensitive IAM event
    if event.get("eventName") not in SENSITIVE_IAM_EVENTS:
        return False

    # Get user agent
    user_agent = event.get("userAgent", "")

    # Check if user agent is known/allowed
    for allowed in ALLOWED_USER_AGENTS:
        if allowed.lower() in user_agent.lower():
            return False

    # Alert on unusual user agents
    return True


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")
    user_agent = event.get("userAgent", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    return f"Sensitive IAM operation [{event_name}] by [{actor_arn}] with unusual user agent: [{user_agent}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    # userAgent already in aws_rule_context
    return context
