"""
Detect disabling of S3 bucket logging.

Disabling logging is an anti-forensics technique used to hide
malicious activity.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def rule(event):
    """Detect bucket logging being disabled."""
    if event.get("eventName") != "PutBucketLogging":
        return False

    if not is_successful(event):
        return False

    # Check if logging is being disabled (no target bucket specified)
    logging_config = deep_get(
        event, "requestParameters", "BucketLoggingStatus", default={}
    )
    logging_enabled = deep_get(logging_config, "LoggingEnabled", default=None)

    # If LoggingEnabled is empty/None, logging is being disabled
    return logging_enabled is None or logging_enabled == {}


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor = get_actor_user(event)
    return f"S3 bucket logging disabled on [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
