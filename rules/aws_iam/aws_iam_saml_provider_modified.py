def rule(event):
    if event.get("eventName") not in {
        "CreateSAMLProvider",
        "UpdateSAMLProvider",
        "DeleteSAMLProvider",
        "CreateOpenIDConnectProvider",
        "DeleteOpenIDConnectProvider",
        "AddClientIDToOpenIDConnectProvider",
        "RemoveClientIDFromOpenIDConnectProvider",
    }:
        return False
    if event.get("errorCode"):
        return False
    return True


def title(event):
    action = event.get("eventName", "unknown")
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    provider = _get_provider(event)
    return f"Identity provider modified: {action} on {provider} by {principal}"


def _get_provider(event):
    params = event.get("requestParameters", {})
    return (
        params.get("name")
        or params.get("sAMLProviderArn")
        or params.get("openIDConnectProviderArn")
        or "unknown"
    )


def severity(event):
    action = event.get("eventName", "")
    if action.startswith("Create"):
        return "HIGH"
    if action.startswith("Delete"):
        return "CRITICAL"
    return "MEDIUM"


def dedup(event):
    return f"{event.get('eventName')}:{_get_provider(event)}"


def alert_context(event):
    return {
        "eventName": event.get("eventName"),
        "provider": _get_provider(event),
        "principal": event.get("userIdentity", {}).get("arn"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "requestParameters": event.get("requestParameters"),
    }
