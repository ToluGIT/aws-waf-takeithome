variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "juice-shop"
}

variable "container_port" {
  description = "Port that the Juice Shop container listens on"
  type        = number
  default     = 3000
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 2
}

variable "cpu" {
  description = "CPU units for the ECS task"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Memory for the ECS task"
  type        = number
  default     = 1024
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to Kinesis Data Firehose"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the application"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this for production
}

variable "ssl_certificate_arn" {
  description = "ARN of the SSL certificate for HTTPS (optional)"
  type        = string
  default     = null
}

variable "enable_https_redirect" {
  description = "Enable HTTP to HTTPS redirect"
  type        = bool
  default     = true
}

# Rate limiting threshold used by the WAF module
variable "rate_limit_per_5_minutes" {
  description = "Max requests per IP in 5 minutes before WAF blocks"
  type        = number
  # Keep this modest so the smoke test can observe rate limiting.
  # Tune higher for production traffic patterns.
  default = 50
}
