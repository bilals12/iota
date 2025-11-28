output "role_arn" {
  description = "ARN of the IAM role for iota (use this for IRSA annotation on ServiceAccount)"
  value       = aws_iam_role.iota.arn
}

output "role_name" {
  description = "Name of the IAM role for iota"
  value       = aws_iam_role.iota.name
}

output "role_id" {
  description = "Unique ID of the IAM role for iota"
  value       = aws_iam_role.iota.id
}

output "service_account_annotation" {
  description = "Annotation to add to the Kubernetes ServiceAccount for IRSA"
  value = {
    "eks.amazonaws.com/role-arn" = aws_iam_role.iota.arn
  }
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for CloudTrail notifications"
  value       = aws_sqs_queue.cloudtrail_notifications.url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue for CloudTrail notifications"
  value       = aws_sqs_queue.cloudtrail_notifications.arn
}

output "sqs_dlq_url" {
  description = "URL of the SQS dead letter queue"
  value       = aws_sqs_queue.cloudtrail_notifications_dlq.url
}

output "sqs_dlq_arn" {
  description = "ARN of the SQS dead letter queue"
  value       = aws_sqs_queue.cloudtrail_notifications_dlq.arn
}
