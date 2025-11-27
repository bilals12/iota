"""
Detect console login without MFA.

MFA should be required for all console access - this detects non-MFA logins.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, aws_rule_context

# Set to True if you use external IdP with role assumption
ROLES_VIA_EXTERNAL_IDP = False


def rule(event):
    """Detect console login without MFA"""
    if event.get("eventName") != "ConsoleLogin":
        return False

    additional_event_data = event.get("additionalEventData", {})
    response_elements = event.get("responseElements", {})
    user_identity_type = deep_get(event, "userIdentity", "type", default="")

    # Skip if using external IdP with role assumption
    if ROLES_VIA_EXTERNAL_IDP and user_identity_type == "AssumedRole":
        return False

    # Skip if using AWS SSO or SAML provider
    user_arn = deep_get(event, "userIdentity", "arn", default="")
    saml_provider = additional_event_data.get("SamlProviderArn")
    if "AWSReservedSSO" in user_arn or saml_provider is not None:
        return False

    # Check if login was successful
    if response_elements.get("ConsoleLogin") != "Success":
        return False

    # Check MFA usage (inverted logic because second condition can be None)
    mfa_used = additional_event_data.get("MFAUsed") != "Yes"
    mfa_authenticated = deep_get(
        event, "userIdentity", "sessionContext", "attributes", "mfaAuthenticated"
    ) != "true"

    return mfa_used and mfa_authenticated


def title(event):
    """Generate alert title"""
    if deep_get(event, "userIdentity", "type") == "Root":
        user_string = "the root user"
    else:
        user = deep_get(event, "userIdentity", "userName") or deep_get(
            event, "userIdentity", "sessionContext", "sessionIssuer", "userName", default="UNKNOWN"
        )
        user_type = deep_get(
            event, "userIdentity", "sessionContext", "sessionIssuer", "type", default="user"
        ).lower()
        user_string = f"{user_type} {user}"

    account_id = event.get("recipientAccountId", "UNKNOWN")
    return f"AWS login detected without MFA for [{user_string}] in [{account_id}]"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["mfaUsed"] = deep_get(event, "additionalEventData", "MFAUsed")
    context["loginTo"] = deep_get(event, "additionalEventData", "LoginTo")
    return context
