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

variable "namespace" {
  description = "Kubernetes namespace for iota"
  type        = string
  default     = "security"
}

variable "create_namespace" {
  description = "Whether to create the namespace"
  type        = bool
  default     = true
}

variable "service_account_name" {
  description = "Name of the Kubernetes ServiceAccount"
  type        = string
  default     = "iota"
}

variable "image_repository" {
  description = "Docker image repository"
  type        = string
  default     = "iota"
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "replicas" {
  description = "Number of iota replicas"
  type        = number
  default     = 2
}

variable "rules_repo" {
  description = "Git repository URL for detection rules"
  type        = string
}

variable "rules_branch" {
  description = "Git branch for detection rules"
  type        = string
  default     = "main"
}

variable "rules_path" {
  description = "Path to rules within the git repository"
  type        = string
  default     = "rules"
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts (leave empty to disable)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "create_events_pvc" {
  description = "Whether to create the events PVC (false if using existing)"
  type        = bool
  default     = true
}

variable "existing_events_pvc" {
  description = "Name of existing PVC for events (used if create_events_pvc is false)"
  type        = string
  default     = ""
}

variable "events_pvc_size" {
  description = "Size of the events PVC"
  type        = string
  default     = "100Gi"
}

variable "state_pvc_size" {
  description = "Size of the state PVC"
  type        = string
  default     = "5Gi"
}

variable "storage_class" {
  description = "Kubernetes storage class"
  type        = string
  default     = "gp3"
}

variable "helm_chart_path" {
  description = "Path to Helm chart (local or remote)"
  type        = string
  default     = "../helm/iota"
}

variable "helm_chart_version" {
  description = "Helm chart version"
  type        = string
  default     = "0.1.0"
}

variable "cpu_request" {
  description = "CPU request"
  type        = string
  default     = "250m"
}

variable "cpu_limit" {
  description = "CPU limit"
  type        = string
  default     = "1000m"
}

variable "memory_request" {
  description = "Memory request"
  type        = string
  default     = "256Mi"
}

variable "memory_limit" {
  description = "Memory limit"
  type        = string
  default     = "1Gi"
}

variable "tags" {
  description = "Tags to apply to AWS resources"
  type        = map(string)
  default     = {}
}
