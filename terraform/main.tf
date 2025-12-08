terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.1"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.17.0"
    }
  }
}

# IAM role for iota ServiceAccount (IRSA)
resource "aws_iam_role" "iota" {
  name               = "${var.cluster_name}-iota"
  assume_role_policy = data.aws_iam_policy_document.iota_assume_role.json

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-iota"
    }
  )
}

data "aws_iam_policy_document" "iota_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_arn, "/^(.*provider/)/", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# IAM policy for CloudTrail S3 access
resource "aws_iam_role_policy" "iota_cloudtrail_read" {
  name   = "cloudtrail-read"
  role   = aws_iam_role.iota.id
  policy = data.aws_iam_policy_document.cloudtrail_read.json
}

data "aws_iam_policy_document" "cloudtrail_read" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      "arn:aws:s3:::${var.cloudtrail_bucket}",
      "arn:aws:s3:::${var.cloudtrail_bucket}/*"
    ]
  }
}

# Kubernetes namespace
resource "kubernetes_namespace" "iota" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace

    labels = {
      name = var.namespace
    }
  }
}

# Sealed secret for Slack webhook (if webhook_url provided)
resource "kubernetes_secret" "slack_webhook" {
  count = var.slack_webhook_url != "" ? 1 : 0

  metadata {
    name      = "iota-slack-webhook"
    namespace = var.namespace
  }

  data = {
    webhook-url = var.slack_webhook_url
  }

  type = "Opaque"

  depends_on = [kubernetes_namespace.iota]
}

# Shared PVC for CloudTrail events
resource "kubernetes_persistent_volume_claim" "events" {
  count = var.create_events_pvc ? 1 : 0

  metadata {
    name      = "cloudtrail-events-pvc"
    namespace = var.namespace
  }

  spec {
    access_modes = ["ReadWriteMany"]

    resources {
      requests = {
        storage = var.events_pvc_size
      }
    }

    storage_class_name = var.storage_class
  }

  depends_on = [kubernetes_namespace.iota]
}

# Helm release
resource "helm_release" "iota" {
  name      = "iota"
  namespace = var.namespace
  chart     = var.helm_chart_path
  version   = var.helm_chart_version

  values = [
    templatefile("${path.module}/values.yaml.tpl", {
      image_repository = var.image_repository
      image_tag        = var.image_tag
      replicas         = var.replicas
      iam_role_arn     = aws_iam_role.iota.arn
      service_account  = var.service_account_name
      rules_repo       = var.rules_repo
      rules_branch     = var.rules_branch
      rules_path       = var.rules_path
      slack_enabled    = var.slack_webhook_url != ""
      events_pvc       = var.create_events_pvc ? kubernetes_persistent_volume_claim.events[0].metadata[0].name : var.existing_events_pvc
      state_pvc_size   = var.state_pvc_size
      storage_class    = var.storage_class
      cpu_request      = var.cpu_request
      cpu_limit        = var.cpu_limit
      memory_request   = var.memory_request
      memory_limit     = var.memory_limit
    })
  ]

  depends_on = [
    kubernetes_namespace.iota,
    kubernetes_secret.slack_webhook,
    kubernetes_persistent_volume_claim.events
  ]
}
