"""
Detect S3 object copies to external AWS accounts.

Cross-account copies can indicate data exfiltration when objects are
copied to buckets owned by different AWS accounts.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user


def _extract_bucket_accounts(event):
    """Extract bucket names and their account IDs from resources."""
    resources = event.get("resources", [])
    bucket_accounts = {}

    for resource in resources:
        if resource.get("type") == "AWS::S3::Bucket":
            bucket_name = resource.get("arn", "").split(":::")[-1]
            account_id = resource.get("accountId", "")
            if bucket_name and account_id:
                bucket_accounts[bucket_name] = account_id

    return bucket_accounts


def rule(event):
    """Detect cross-account S3 copies."""
    if event.get("eventName") != "CopyObject":
        return False

    if not is_successful(event):
        return False

    bucket_accounts = _extract_bucket_accounts(event)

    # Need at least 2 buckets with different accounts
    if len(bucket_accounts) < 2:
        return False

    account_ids = set(bucket_accounts.values())
    return len(account_ids) > 1


def title(event):
    """Generate alert title."""
    dest_bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    source = deep_get(
        event, "requestParameters", "x-amz-copy-source", default="UNKNOWN"
    )
    source_bucket = source.split("/")[0] if "/" in source else source
    actor = get_actor_user(event)
    return (
        f"S3 cross-account copy from [{source_bucket}] to [{dest_bucket}] by [{actor}]"
    )


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketAccounts"] = _extract_bucket_accounts(event)
    context["destinationBucket"] = deep_get(event, "requestParameters", "bucketName")
    source = deep_get(event, "requestParameters", "x-amz-copy-source", default="")
    context["sourcePath"] = source
    context["sourceBucket"] = source.split("/")[0] if "/" in source else source
    return context
