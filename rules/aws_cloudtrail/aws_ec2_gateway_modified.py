"""
Detect VPC gateway modifications (internet/NAT gateways).

Gateway changes can enable data exfiltration from isolated networks.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect gateway creation or attachment"""
    if not is_successful(event):
        return False

    # Monitor internet gateway and NAT gateway operations
    event_name = event.get("eventName")
    return event_name in [
        "CreateInternetGateway",
        "AttachInternetGateway",
        "CreateNatGateway",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")

    if "InternetGateway" in event_name:
        gateway_id = deep_get(
            event, "responseElements", "internetGateway", "internetGatewayId",
            default=deep_get(event, "requestParameters", "internetGatewayId", default="UNKNOWN")
        )
        vpc_id = deep_get(event, "requestParameters", "vpcId", default="N/A")
        gateway_type = "Internet Gateway"
    else:  # NAT Gateway
        gateway_id = deep_get(
            event, "responseElements", "natGateway", "natGatewayId", default="UNKNOWN"
        )
        vpc_id = deep_get(
            event, "responseElements", "natGateway", "vpcId", default="N/A"
        )
        gateway_type = "NAT Gateway"

    action = event_name.replace("InternetGateway", "").replace("NatGateway", "")
    return f"{gateway_type} [{gateway_id}] {action.lower()}d in VPC [{vpc_id}] by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)

    # Extract based on gateway type
    if "InternetGateway" in event.get("eventName"):
        context["internetGatewayId"] = deep_get(
            event, "responseElements", "internetGateway", "internetGatewayId"
        ) or deep_get(event, "requestParameters", "internetGatewayId")
        context["vpcId"] = deep_get(event, "requestParameters", "vpcId")
    else:
        context["natGatewayId"] = deep_get(
            event, "responseElements", "natGateway", "natGatewayId"
        )
        context["subnetId"] = deep_get(event, "requestParameters", "subnetId")
        context["allocationId"] = deep_get(event, "requestParameters", "allocationId")

    return context
