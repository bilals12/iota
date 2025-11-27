"""
Detect Network ACL modifications.

NACL changes can expose resources or block legitimate traffic.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect NACL modifications"""
    return is_successful(event) and event.get("eventName") in [
        "CreateNetworkAclEntry",
        "ReplaceNetworkAclEntry",
        "DeleteNetworkAclEntry",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    nacl_id = deep_get(event, "requestParameters", "networkAclId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Network ACL [{nacl_id}] {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["networkAclId"] = deep_get(event, "requestParameters", "networkAclId")
    context["ruleNumber"] = deep_get(event, "requestParameters", "ruleNumber")
    context["cidrBlock"] = deep_get(event, "requestParameters", "cidrBlock")
    context["egress"] = deep_get(event, "requestParameters", "egress")
    return context
