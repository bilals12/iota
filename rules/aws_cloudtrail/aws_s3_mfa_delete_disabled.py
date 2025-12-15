"""
Detect disabling of MFA Delete on S3 buckets.

MFA Delete prevents accidental or malicious deletion of objects.
Disabling it is a common ransomware preparation technique.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def rule(event):
    """Detect MFA delete being disabled."""
    if event.get("eventName") != "PutBucketVersioning":
        return False

    if not is_successful(event):
        return False

    mfa_delete = deep_get(
        event, "requestParameters", "VersioningConfiguration", "MfaDelete", default=""
    )
    return mfa_delete in ("Disabled", "false", False)


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor = get_actor_user(event)
    return f"MFA Delete disabled on S3 bucket [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
