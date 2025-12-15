"""
Detect deletion of S3 bucket replication configuration.

Removing replication is a ransomware preparation technique that prevents
recovery from replicated copies.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def rule(event):
    """Detect bucket replication deletion."""
    if event.get("eventName") != "DeleteBucketReplication":
        return False

    return is_successful(event)


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor = get_actor_user(event)
    return f"S3 bucket replication deleted on [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
