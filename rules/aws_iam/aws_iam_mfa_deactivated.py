def rule(event):
    if event.get("eventName") not in {"DeactivateMFADevice", "DeleteVirtualMFADevice"}:
        return False
    if event.get("errorCode"):
        return False
    return True


def title(event):
    params = event.get("requestParameters", {})
    user_name = params.get("userName", "unknown")
    action = event.get("eventName", "unknown")
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    return f"MFA {action} for {user_name} by {principal}"


def severity(event):
    return "HIGH"


def dedup(event):
    params = event.get("requestParameters", {})
    return params.get("userName", "")


def alert_context(event):
    params = event.get("requestParameters", {})
    return {
        "eventName": event.get("eventName"),
        "userName": params.get("userName"),
        "serialNumber": params.get("serialNumber"),
        "principal": event.get("userIdentity", {}).get("arn"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
    }
