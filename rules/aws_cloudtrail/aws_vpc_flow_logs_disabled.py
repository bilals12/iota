"""
Detect VPC Flow Logs being disabled or deleted.

Flow logs are critical for network forensics - disabling them is suspicious.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect VPC Flow Logs being disabled"""
    return is_successful(event) and event.get("eventName") == "DeleteFlowLogs"


def title(event):
    """Generate alert title"""
    flow_log_ids = deep_get(
        event, "requestParameters", "DeleteFlowLogsRequest", "FlowLogId", default=[]
    )
    if isinstance(flow_log_ids, list):
        flow_log_str = ", ".join(flow_log_ids[:3])  # Show first 3
        if len(flow_log_ids) > 3:
            flow_log_str += f" (and {len(flow_log_ids) - 3} more)"
    else:
        flow_log_str = str(flow_log_ids)

    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"VPC Flow Logs [{flow_log_str}] deleted by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["flowLogIds"] = deep_get(
        event, "requestParameters", "DeleteFlowLogsRequest", "FlowLogId"
    )
    return context
