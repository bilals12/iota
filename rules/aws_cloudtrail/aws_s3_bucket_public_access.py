"""
Detect S3 bucket made publicly accessible.

Detects when S3 buckets are configured to allow public access.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect S3 bucket public access changes"""
    if not is_successful(event):
        return False

    # Check for public access operations
    if event.get("eventName") in ["PutBucketAcl", "PutBucketPolicy"]:
        # Check for AllUsers or AuthenticatedUsers grants
        acl = deep_get(event, "requestParameters", "AccessControlPolicy", "AccessControlList", "Grant", default=[])
        if isinstance(acl, list):
            for grant in acl:
                grantee_uri = deep_get(grant, "Grantee", "URI", default="")
                if "AllUsers" in grantee_uri or "AuthenticatedUsers" in grantee_uri:
                    return True

    # Check for public access block being disabled
    if event.get("eventName") == "PutPublicAccessBlock":
        config = deep_get(event, "requestParameters", "PublicAccessBlockConfiguration", default={})
        # Alert if any protection is disabled
        if not config.get("BlockPublicAcls") or not config.get("BlockPublicPolicy"):
            return True

    return False


def title(event):
    """Generate alert title"""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    event_name = event.get("eventName", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"S3 bucket [{bucket}] public access change via {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    return context
