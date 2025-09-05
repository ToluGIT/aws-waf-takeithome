variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "alb_arn" {
  description = "ARN of the Application Load Balancer to associate with WAF"
  type        = string
}

variable "enable_logging" {
  description = "Enable WAF logging"
  type        = bool
  default     = true
}

variable "kinesis_firehose_arn" {
  description = "ARN of the Kinesis Data Firehose delivery stream for WAF logs"
  type        = string
  default     = null
}

variable "rate_limit_per_5_minutes" {
  description = "Rate limit per 5 minutes per IP"
  type        = number
  default     = 50 # Lowered for better testing of rate limiting
}

variable "allowed_countries" {
  description = "List of allowed country codes (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = ["US", "CA", "GB", "AU", "DE", "FR", "JP"]
}

variable "blocked_ips" {
  description = "List of IP addresses/CIDR blocks to block"
  type        = list(string)
  default     = []
}

variable "juice_shop_sql_injection_priority" {
  description = "Priority for the Juice Shop SQL injection rule"
  type        = number
  default     = 100
}

variable "rate_limit_priority" {
  description = "Priority for the rate limiting rule"
  type        = number
  default     = 200
}

variable "geo_restriction_priority" {
  description = "Priority for the geographic restriction rule"
  type        = number
  default     = 300
}

variable "ip_reputation_priority" {
  description = "Priority for the IP reputation rule"
  type        = number
  default     = 400
}

variable "common_ruleset_priority" {
  description = "Priority for the AWS Common RuleSet"
  type        = number
  default     = 500
}

variable "sqli_ruleset_priority" {
  description = "Priority for the AWS SQLi RuleSet"
  type        = number
  default     = 600
}

variable "aws_region" {
  description = "AWS region for CloudWatch dashboard"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}