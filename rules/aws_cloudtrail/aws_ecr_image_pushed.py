"""
Detect container images pushed to ECR.

Monitor for unauthorized image pushes which could indicate supply chain attacks.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect PutImage API calls to ECR"""
    if not is_successful(event):
        return False

    return event.get("eventName") == "PutImage"


def title(event):
    """Generate alert title"""
    repo = deep_get(event, "requestParameters", "repositoryName", default="UNKNOWN")
    image_tag = deep_get(event, "requestParameters", "imageTag", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Container image [{image_tag}] pushed to ECR repo [{repo}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "INFO"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["repositoryName"] = deep_get(event, "requestParameters", "repositoryName")
    context["imageTag"] = deep_get(event, "requestParameters", "imageTag")
    context["imageDigest"] = deep_get(event, "requestParameters", "imageDigest")
    context["registryId"] = deep_get(event, "requestParameters", "registryId")
    return context
