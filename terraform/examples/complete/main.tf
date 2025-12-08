terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.0.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Data sources for existing resources
data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.cluster_name
}

# Kubernetes provider configuration
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

# Deploy iota
module "iota" {
  source = "../.."

  cluster_name      = var.cluster_name
  oidc_provider_arn = var.oidc_provider_arn
  cloudtrail_bucket = var.cloudtrail_bucket

  namespace            = "security"
  service_account_name = "iota"

  image_repository = var.image_repository
  image_tag        = var.image_tag
  replicas         = 2

  rules_repo   = var.rules_repo
  rules_branch = "main"
  rules_path   = "rules"

  slack_webhook_url = var.slack_webhook_url

  create_events_pvc = true
  events_pvc_size   = "100Gi"
  state_pvc_size    = "5Gi"
  storage_class     = "gp3"

  cpu_request    = "250m"
  cpu_limit      = "1000m"
  memory_request = "256Mi"
  memory_limit   = "1Gi"

  tags = {
    Environment = var.environment
    Team        = "security"
    ManagedBy   = "terraform"
  }
}
