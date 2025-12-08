"""
Detect S3 Object Lock being disabled or retention reduced.

Object Lock protects against ransomware - disabling it can indicate preparation for data destruction.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect Object Lock configuration changes"""
    if not is_successful(event):
        return False

    event_name = event.get("eventName")

    # Monitor Object Lock and retention policy changes
    if event_name == "PutObjectLockConfiguration":
        # Check if being disabled
        enabled = deep_get(
            event,
            "requestParameters",
            "ObjectLockConfiguration",
            "ObjectLockEnabled",
            default="",
        )
        return enabled == "Disabled" or enabled == ""

    # Monitor retention policy being removed
    if event_name == "PutBucketVersioning":
        mfa_delete = deep_get(
            event,
            "requestParameters",
            "VersioningConfiguration",
            "MfaDelete",
            default="",
        )
        # Alert if MFA delete is being disabled
        return mfa_delete == "Disabled"

    return False


def title(event):
    """Generate alert title"""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    event_name = event.get("eventName")

    if event_name == "PutObjectLockConfiguration":
        action = "Object Lock disabled"
    else:
        action = "MFA Delete disabled"

    return f"S3 {action} for bucket [{bucket}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")

    if event.get("eventName") == "PutObjectLockConfiguration":
        context["objectLockConfiguration"] = deep_get(
            event, "requestParameters", "ObjectLockConfiguration"
        )
    else:
        context["versioningConfiguration"] = deep_get(
            event, "requestParameters", "VersioningConfiguration"
        )

    return context
