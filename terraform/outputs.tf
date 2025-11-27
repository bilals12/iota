output "iam_role_arn" {
  description = "ARN of the IAM role for iota ServiceAccount"
  value       = aws_iam_role.iota.arn
}

output "iam_role_name" {
  description = "Name of the IAM role"
  value       = aws_iam_role.iota.name
}

output "namespace" {
  description = "Kubernetes namespace where iota is deployed"
  value       = var.namespace
}

output "service_account_name" {
  description = "Name of the Kubernetes ServiceAccount"
  value       = var.service_account_name
}

output "helm_release_name" {
  description = "Name of the Helm release"
  value       = helm_release.iota.name
}

output "helm_release_version" {
  description = "Version of the Helm release"
  value       = helm_release.iota.version
}

output "events_pvc_name" {
  description = "Name of the events PVC"
  value       = var.create_events_pvc ? kubernetes_persistent_volume_claim.events[0].metadata[0].name : var.existing_events_pvc
}
