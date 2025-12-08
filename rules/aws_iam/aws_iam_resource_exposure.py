import sys

sys.path.append("..")
from helpers.iam_actions import is_resource_exposure, get_action

ALLOWLISTED_PRINCIPALS = set()

CRITICAL_ACTIONS = {
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutAccountPublicAccessBlock",
    "s3:DeleteBucketPolicy",
    "ec2:ModifySnapshotAttribute",
    "ec2:DisableImageBlockPublicAccess",
    "kms:PutKeyPolicy",
    "kms:CreateGrant",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateRole",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "lambda:AddPermission",
    "sns:AddPermission",
    "sns:SetTopicAttributes",
    "sqs:AddPermission",
    "sqs:SetQueueAttributes",
    "ecr:SetRepositoryPolicy",
    "secretsmanager:PutResourcePolicy",
    "glue:PutResourcePolicy",
    "lakeformation:PutDataLakeSettings",
    "ram:CreateResourceShare",
    "ram:AssociateResourceShare",
}

HIGH_ACTIONS = {
    "s3:PutObjectAcl",
    "s3:PutAccessPointPolicy",
    "ec2:ModifyVpcEndpointServicePermissions",
    "ec2:CreateNetworkInterfacePermission",
    "lambda:AddLayerVersionPermission",
    "ssm:ModifyDocumentPermission",
    "es:UpdateElasticsearchDomainConfig",
    "es:CreateElasticsearchDomain",
    "elasticfilesystem:PutFileSystemPolicy",
    "glacier:SetVaultAccessPolicy",
    "logs:PutResourcePolicy",
    "backup:PutBackupVaultAccessPolicy",
    "codeartifact:DeleteDomainPermissionsPolicy",
    "codeartifact:DeleteRepositoryPermissionsPolicy",
    "codebuild:PutResourcePolicy",
    "sso:CreatePermissionSet",
    "sso:UpdatePermissionSet",
}


def rule(event):
    if event.get("errorCode"):
        return False
    if not is_resource_exposure(event):
        return False
    principal = event.get("userIdentity", {}).get("arn", "")
    if principal in ALLOWLISTED_PRINCIPALS:
        return False
    return True


def title(event):
    action = get_action(event)
    principal = event.get("userIdentity", {}).get("arn", "unknown")
    resource = _get_resource(event)
    return f"Resource exposure: {action} on {resource} by {principal}"


def _get_resource(event):
    params = event.get("requestParameters", {}) or {}
    return (
        params.get("bucketName")
        or params.get("functionName")
        or params.get("topicArn")
        or params.get("queueUrl")
        or params.get("keyId")
        or params.get("repositoryName")
        or params.get("roleName")
        or params.get("policyArn")
        or params.get("domainName")
        or params.get("resourceShareArn")
        or params.get("fileSystemId")
        or params.get("vaultName")
        or params.get("snapshotId")
        or "unknown"
    )


def severity(event):
    action = get_action(event)
    if action in CRITICAL_ACTIONS:
        return "CRITICAL"
    if action in HIGH_ACTIONS:
        return "HIGH"
    return "MEDIUM"


def dedup(event):
    return f"{get_action(event)}:{_get_resource(event)}"


def alert_context(event):
    return {
        "action": get_action(event),
        "principal": event.get("userIdentity", {}).get("arn"),
        "resource": _get_resource(event),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "requestParameters": event.get("requestParameters"),
    }
