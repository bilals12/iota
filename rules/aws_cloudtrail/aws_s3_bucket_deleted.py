"""
Detect S3 bucket deletion.

Bucket deletion can indicate data destruction attacks or account cleanup by adversaries.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect S3 bucket deletion"""
    if not is_successful(event):
        return False

    return event.get("eventName") == "DeleteBucket"


def title(event):
    """Generate alert title"""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"S3 bucket [{bucket}] deleted by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
