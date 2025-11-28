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
