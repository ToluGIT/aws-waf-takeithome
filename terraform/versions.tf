terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Remote state management
  backend "s3" {
    # Configuration provided via -backend-config in workflows
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "owasp-juice-shop"
      Environment = var.environment
      Owner       = "security-team"
      ManagedBy   = "terraform"
    }
  }
}
