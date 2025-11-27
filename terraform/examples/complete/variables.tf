variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "oidc_provider_arn" {
  description = "ARN of the OIDC provider for EKS IRSA"
  type        = string
}

variable "cloudtrail_bucket" {
  description = "S3 bucket containing CloudTrail logs"
  type        = string
}

variable "image_repository" {
  description = "Docker image repository for iota"
  type        = string
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "rules_repo" {
  description = "Git repository URL for detection rules"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts"
  type        = string
  sensitive   = true
}
