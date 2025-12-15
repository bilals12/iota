"""
Detect S3 bucket versioning suspension.

Suspending versioning is a common ransomware preparation technique that prevents
recovery of deleted or encrypted objects.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def rule(event):
    """Detect versioning suspension on S3 buckets."""
    if event.get("eventName") != "PutBucketVersioning":
        return False

    if not is_successful(event):
        return False

    status = deep_get(
        event, "requestParameters", "VersioningConfiguration", "Status", default=""
    )
    return status in ("Suspended", "Disabled")


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor = get_actor_user(event)
    return f"S3 bucket versioning suspended on [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    context["versioningStatus"] = deep_get(
        event, "requestParameters", "VersioningConfiguration", "Status"
    )
    return context
