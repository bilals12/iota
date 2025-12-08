output "iota_iam_role_arn" {
  description = "IAM role ARN for iota ServiceAccount"
  value       = module.iota.iam_role_arn
}

output "iota_namespace" {
  description = "Namespace where iota is deployed"
  value       = module.iota.namespace
}

output "iota_service_account" {
  description = "ServiceAccount name"
  value       = module.iota.service_account_name
}

output "events_pvc_name" {
  description = "Name of the events PVC"
  value       = module.iota.events_pvc_name
}
