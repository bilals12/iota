"""
iota helper functions for standalone detection
"""


def deep_get(dictionary, *keys, default=None):
    """
    Safely access nested dictionary values.

    Example:
        deep_get(event, 'userIdentity', 'type') returns event['userIdentity']['type']
        or default if any key doesn't exist
    """
    result = dictionary
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
            if result is None:
                return default
        else:
            return default
    return result


def aws_rule_context(event):
    """
    Generate standard AWS CloudTrail context for alerts.
    """
    return {
        "eventName": event.get("eventName"),
        "eventTime": event.get("eventTime"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "recipientAccountId": event.get("recipientAccountId"),
        "userIdentity": event.get("userIdentity", {}),
        "requestParameters": event.get("requestParameters", {}),
        "responseElements": event.get("responseElements", {}),
    }


def is_assume_role_event(event):
    """Check if event is an AssumeRole action"""
    return event.get("eventName") == "AssumeRole"


def is_console_login(event):
    """Check if event is a console login"""
    return event.get("eventName") == "ConsoleLogin"


def is_root_user(event):
    """Check if event was performed by root user"""
    return deep_get(event, "userIdentity", "type") == "Root"


def is_successful(event):
    """Check if event was successful"""
    error_code = event.get("errorCode")
    error_message = event.get("errorMessage")
    return not error_code and not error_message


def get_account_id(event):
    """Extract account ID from event"""
    return event.get("recipientAccountId") or deep_get(
        event, "userIdentity", "accountId"
    )


def get_user_identity_arn(event):
    """Extract user identity ARN"""
    return deep_get(event, "userIdentity", "arn", default="<UNKNOWN_ARN>")


def get_principal_id(event):
    """Extract principal ID"""
    return deep_get(event, "userIdentity", "principalId", default="<UNKNOWN_PRINCIPAL>")


def aws_guardduty_context(event):
    """Generate context for GuardDuty findings"""
    return {
        "severity": deep_get(event, "severity"),
        "type": deep_get(event, "type"),
        "title": deep_get(event, "title"),
        "description": deep_get(event, "description"),
        "accountId": deep_get(event, "accountId"),
        "region": deep_get(event, "region"),
    }


def pattern_match(string_to_check, pattern_list):
    """
    Check if a string matches any pattern in a list (case-insensitive contains).
    """
    if not string_to_check or not pattern_list:
        return False

    string_lower = str(string_to_check).lower()
    return any(pattern.lower() in string_lower for pattern in pattern_list)


def pattern_match_list(strings_to_check, pattern_list):
    """
    Check if any string in a list matches any pattern (case-insensitive contains).
    """
    if not strings_to_check or not pattern_list:
        return False

    for string in strings_to_check:
        if pattern_match(string, pattern_list):
            return True
    return False
