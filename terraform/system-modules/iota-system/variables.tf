variable "cluster_name" {
  description = "Name of the EKS cluster where iota will be deployed"
  type        = string
}

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider for IRSA (e.g., arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABCD1234)"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket containing CloudTrail logs (e.g., turo-org-cloudtrail)"
  type        = string
}

variable "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key used to encrypt CloudTrail logs"
  type        = string
}

variable "cloudtrail_sns_topic_arn" {
  description = "ARN of the SNS topic for CloudTrail notifications (optional)"
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Kubernetes namespace where iota will be deployed"
  type        = string
  default     = "security"
}

variable "service_account_name" {
  description = "Name of the Kubernetes ServiceAccount for iota"
  type        = string
  default     = "iota"
}

variable "enable_sns_notifications" {
  description = "Enable SNS notifications for real-time CloudTrail processing"
  type        = bool
  default     = false
}

variable "sqs_queue_name" {
  description = "Name for SQS queue (optional, defaults to cluster-name-iota-cloudtrail-queue)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
