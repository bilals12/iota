"""
Detect S3 server access logging being disabled.

Disabling access logs is a defense evasion technique to hide data exfiltration.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect S3 logging being disabled"""
    if not is_successful(event):
        return False

    if event.get("eventName") != "PutBucketLogging":
        return False

    # Check if logging is being disabled (empty logging configuration)
    logging_config = deep_get(
        event, "requestParameters", "BucketLoggingStatus", "LoggingEnabled"
    )

    # If LoggingEnabled is None/absent, logging is being disabled
    return logging_config is None


def title(event):
    """Generate alert title"""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"S3 access logging disabled for bucket [{bucket}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    context["loggingConfiguration"] = deep_get(
        event, "requestParameters", "BucketLoggingStatus"
    )
    return context
