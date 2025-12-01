"""
Detect insecure (HTTP) access to S3 buckets.

Checks if HTTP (unencrypted) was used to access objects in an S3 bucket,
as opposed to HTTPS (encrypted).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import pattern_match, aws_rule_context


def rule(event):
    """Detect insecure S3 access"""
    operation = event.get("operation", "")
    if not pattern_match(operation, ["REST.*.OBJECT"]):
        return False

    ciphersuite = event.get("ciphersuite")
    tls_version = event.get("tlsVersion")

    return not ciphersuite or not tls_version


def title(event):
    """Generate alert title"""
    bucket = event.get("bucket", "<UNKNOWN_BUCKET>")
    return f"Insecure access to S3 Bucket [{bucket}]"


def severity():
    """Return alert severity"""
    return "LOW"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["bucket"] = event.get("bucket")
    context["key"] = event.get("key")
    context["operation"] = event.get("operation")
    context["remoteip"] = event.get("remoteIP")
    context["userAgent"] = event.get("userAgent")
    return context
