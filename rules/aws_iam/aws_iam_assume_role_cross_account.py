def rule(event):
    if event.get("eventName") != "AssumeRole":
        return False
    if event.get("errorCode"):
        return False
    params = event.get("requestParameters", {})
    role_arn = params.get("roleArn", "")
    if not role_arn:
        return False
    caller_account = event.get("recipientAccountId", "")
    if not caller_account:
        return False
    role_account = _extract_account_from_arn(role_arn)
    if not role_account:
        return False
    return caller_account != role_account


def _extract_account_from_arn(arn):
    parts = arn.split(":")
    if len(parts) >= 5:
        return parts[4]
    return ""


def title(event):
    params = event.get("requestParameters", {})
    role_arn = params.get("roleArn", "unknown")
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    return f"Cross-account AssumeRole to {role_arn} by {principal}"


def severity(event):
    return "INFO"


def dedup(event):
    params = event.get("requestParameters", {})
    return params.get("roleArn", "")


def alert_context(event):
    params = event.get("requestParameters", {})
    return {
        "roleArn": params.get("roleArn"),
        "roleSessionName": params.get("roleSessionName"),
        "principal": event.get("userIdentity", {}).get("arn"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "callerAccount": event.get("recipientAccountId"),
        "targetAccount": _extract_account_from_arn(params.get("roleArn", "")),
    }
