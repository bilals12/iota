"""
Detect Okta support access to tenant.

Alerts when Okta support accesses the organization's tenant.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from iota_helpers import okta_alert_context


def rule(event):
    """Detect support access events"""
    return event.get("eventType") in [
        "user.session.impersonation.grant",
        "user.session.impersonation.initiate",
    ]


def title(event):
    """Generate alert title"""
    event_type = event.get("eventType", "")
    actor_id = deep_get(event, "actor", "alternateId", default="<UNKNOWN>")

    if "grant" in event_type:
        return f"Okta: Support access granted by [{actor_id}]"
    return f"Okta: Support access initiated by [{actor_id}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    return okta_alert_context(event)
