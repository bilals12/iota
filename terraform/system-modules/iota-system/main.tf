terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.82.2"
    }
  }
}

# IAM role for iota service account using IRSA (IAM Roles for Service Accounts)
resource "aws_iam_role" "iota" {
  name        = "${var.cluster_name}-iota"
  description = "IAM role for iota CloudTrail detection engine with IRSA"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.eks_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(var.eks_oidc_provider_arn, "/^(.*provider/)/", "")}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
            "${replace(var.eks_oidc_provider_arn, "/^(.*provider/)/", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.cluster_name}-iota"
      ManagedBy   = "terraform"
      Component   = "iota"
      Description = "IRSA role for iota CloudTrail detection"
    }
  )
}

# Policy for reading CloudTrail logs from S3
resource "aws_iam_role_policy" "cloudtrail_s3_access" {
  name = "cloudtrail-s3-access"
  role = aws_iam_role.iota.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListCloudTrailBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::${var.cloudtrail_bucket_name}"
      },
      {
        Sid    = "ReadCloudTrailObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "arn:aws:s3:::${var.cloudtrail_bucket_name}/*"
      }
    ]
  })
}

# Policy for decrypting CloudTrail logs (KMS encrypted)
resource "aws_iam_role_policy" "cloudtrail_kms_decrypt" {
  name = "cloudtrail-kms-decrypt"
  role = aws_iam_role.iota.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DecryptCloudTrailLogs"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = var.cloudtrail_kms_key_arn
      }
    ]
  })
}

# SQS Queue for CloudTrail notifications
resource "aws_sqs_queue" "cloudtrail_notifications" {
  name                       = var.sqs_queue_name != "" ? var.sqs_queue_name : "${var.cluster_name}-iota-cloudtrail-queue"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cloudtrail_notifications_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(
    var.tags,
    {
      Name      = var.sqs_queue_name != "" ? var.sqs_queue_name : "${var.cluster_name}-iota-cloudtrail-queue"
      ManagedBy = "terraform"
      Component = "iota"
    }
  )
}

# Dead Letter Queue
resource "aws_sqs_queue" "cloudtrail_notifications_dlq" {
  name                      = var.sqs_queue_name != "" ? "${var.sqs_queue_name}-dlq" : "${var.cluster_name}-iota-cloudtrail-queue-dlq"
  message_retention_seconds = 1209600

  tags = merge(
    var.tags,
    {
      Name      = var.sqs_queue_name != "" ? "${var.sqs_queue_name}-dlq" : "${var.cluster_name}-iota-cloudtrail-queue-dlq"
      ManagedBy = "terraform"
      Component = "iota"
    }
  )
}

# SQS Queue Policy for SNS subscription
resource "aws_sqs_queue_policy" "cloudtrail_notifications" {
  count     = var.cloudtrail_sns_topic_arn != "" ? 1 : 0
  queue_url = aws_sqs_queue.cloudtrail_notifications.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.cloudtrail_notifications.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = var.cloudtrail_sns_topic_arn
          }
        }
      }
    ]
  })
}

# SQS permissions for iota IAM role
resource "aws_iam_role_policy" "sqs_access" {
  name = "sqs-access"
  role = aws_iam_role.iota.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl"
        ]
        Resource = aws_sqs_queue.cloudtrail_notifications.arn
      }
    ]
  })
}

# Optional: SNS subscription for real-time CloudTrail notifications
resource "aws_iam_role_policy" "cloudtrail_sns_subscribe" {
  count = var.enable_sns_notifications ? 1 : 0

  name = "cloudtrail-sns-subscribe"
  role = aws_iam_role.iota.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReceiveCloudTrailNotifications"
        Effect = "Allow"
        Action = [
          "sns:Subscribe",
          "sns:Receive"
        ]
        Resource = var.cloudtrail_sns_topic_arn
      }
    ]
  })
}
