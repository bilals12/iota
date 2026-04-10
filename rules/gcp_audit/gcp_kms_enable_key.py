import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get


def rule(event):
    method_name = deep_get(event, "protoPayload", "methodName")
    service_name = deep_get(event, "protoPayload", "serviceName")
    status_code = deep_get(event, "protoPayload", "status", "code")

    # Pre-filter
    # return False if any basic condition fails
    if any(
        [
            method_name != "SetIamPolicy",
            service_name != "cloudkms.googleapis.com",
            status_code,  # Operation failed
        ]
    ):
        return False

    # Extract the policy bindings from the request
    bindings = deep_get(
        event, "protoPayload", "request", "policy", "bindings", default=[]
    )

    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])

        # Check if granting KMS encryption/decryption permissions
        role_lower = role.lower()
        if "cryptokey" in role_lower and (
            "encrypt" in role_lower or "decrypt" in role_lower
        ):
            for member in members:
                # Alert if granting to GCS service account
                if "gs-project-accounts.iam.gserviceaccount.com" in member:
                    return True

    return False


def title(event):
    actor = deep_get(
        event, "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )
    kms_key = deep_get(event, "protoPayload", "resourceName", default="Unknown")
    return f"GCP KMS key [{kms_key}] granted encryption permissions by [{actor}]"


def alert_context(event):
    bindings = deep_get(
        event, "protoPayload", "request", "policy", "bindings", default=[]
    )
    return {
        "actor": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail"
        ),
        "kms_key": deep_get(event, "protoPayload", "resourceName"),
        "source_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIp"),
        "project": deep_get(event, "resource", "labels", "project_id"),
        "bindings": bindings,
    }
