"""
Detect S3 access errors.

Checks for errors during S3 Object access.
This could be due to insufficient access permissions, non-existent buckets, or other reasons.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import pattern_match, aws_rule_context

HTTP_STATUS_CODES_TO_MONITOR = {
    403,
    405,
}


def rule(event):
    """Detect S3 access errors"""
    user_agent = event.get("userAgent", "")
    if user_agent.startswith("aws-internal"):
        return False

    operation = event.get("operation", "")
    if not pattern_match(operation, ["REST.*.OBJECT"]):
        return False

    http_status = event.get("httpStatus")
    return http_status in HTTP_STATUS_CODES_TO_MONITOR


def title(event):
    """Generate alert title"""
    http_status = event.get("httpStatus", "UNKNOWN")
    bucket = event.get("bucket", "<UNKNOWN_BUCKET>")
    return f"{http_status} errors found to S3 Bucket [{bucket}]"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucket"] = event.get("bucket")
    context["key"] = event.get("key")
    context["requester"] = event.get("requester")
    context["remoteip"] = event.get("remoteIP")
    context["operation"] = event.get("operation")
    context["errorCode"] = event.get("errorCode")
    context["httpStatus"] = event.get("httpStatus")
    return context
