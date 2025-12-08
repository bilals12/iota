"""
Detect VPC route table modifications.

Route table changes can enable network exfiltration or lateral movement paths.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect route table modifications"""
    if not is_successful(event):
        return False

    # Monitor route creation/replacement/deletion
    event_name = event.get("eventName")
    return event_name in [
        "CreateRoute",
        "ReplaceRoute",
        "DeleteRoute",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")
    route_table_id = deep_get(
        event, "requestParameters", "routeTableId", default="UNKNOWN"
    )
    destination = deep_get(
        event, "requestParameters", "destinationCidrBlock", default="UNKNOWN"
    )
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    action = event_name.replace("Route", " route").lower()
    return f"VPC route table [{route_table_id}] modified: {action} for [{destination}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["routeTableId"] = deep_get(event, "requestParameters", "routeTableId")
    context["destinationCidrBlock"] = deep_get(
        event, "requestParameters", "destinationCidrBlock"
    )
    context["destinationIpv6CidrBlock"] = deep_get(
        event, "requestParameters", "destinationIpv6CidrBlock"
    )
    context["gatewayId"] = deep_get(event, "requestParameters", "gatewayId")
    context["natGatewayId"] = deep_get(event, "requestParameters", "natGatewayId")
    context["instanceId"] = deep_get(event, "requestParameters", "instanceId")
    return context
