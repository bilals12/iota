"""
Detect deletion of S3 bucket public access block.

Removing public access blocks can expose buckets to unauthorized access
and is often a precursor to data exfiltration.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def rule(event):
    """Detect public access block deletion."""
    if event.get("eventName") != "DeleteBucketPublicAccessBlock":
        return False

    return is_successful(event)


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor = get_actor_user(event)
    return f"S3 public access block deleted on bucket [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
