"""
Detect unauthenticated access to S3 buckets.

Checks for S3 access attempts where the requester is not an authenticated AWS user.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context

AUTH_BUCKETS = set()


def rule(event):
    """Detect unauthenticated S3 access"""
    bucket = event.get("bucket")
    if bucket not in AUTH_BUCKETS:
        return False

    requester = event.get("requester")
    return not requester


def title(event):
    """Generate alert title"""
    bucket = event.get("bucket", "<UNKNOWN_BUCKET>")
    return f"Unauthenticated access to S3 Bucket [{bucket}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucket"] = event.get("bucket")
    context["key"] = event.get("key")
    context["remoteip"] = event.get("remoteIP")
    context["operation"] = event.get("operation")
    return context
