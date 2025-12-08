"""
Detect EC2 security group modifications that add risky ingress rules.

Detects when security groups are modified to allow wide-open access (0.0.0.0/0).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect risky security group modifications"""
    if (
        not is_successful(event)
        or event.get("eventName") != "AuthorizeSecurityGroupIngress"
    ):
        return False

    # Check for 0.0.0.0/0 CIDR blocks
    ip_permissions = deep_get(
        event, "requestParameters", "ipPermissions", "items", default=[]
    )
    for permission in ip_permissions:
        ip_ranges = permission.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            if ip_range.get("cidrIp") == "0.0.0.0/0":
                # Check if it's a sensitive port
                from_port = permission.get("fromPort")
                if from_port in [
                    22,
                    3389,
                    3306,
                    5432,
                    1433,
                    27017,
                ]:  # SSH, RDP, databases
                    return True

    return False


def title(event):
    """Generate alert title"""
    group_id = deep_get(event, "requestParameters", "groupId", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Risky security group rule added to [{group_id}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["groupId"] = deep_get(event, "requestParameters", "groupId")
    context["ipPermissions"] = deep_get(event, "requestParameters", "ipPermissions")
    return context
