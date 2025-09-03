output "web_acl_id" {
  description = "ID of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.id
}

output "web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_name" {
  description = "Name of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.name
}

output "web_acl_capacity" {
  description = "Web ACL capacity units used"
  value       = aws_wafv2_web_acl.main.capacity
}

output "ip_set_arn" {
  description = "ARN of the IP set for blocked IPs"
  value       = aws_wafv2_ip_set.blocked_ips.arn
}

output "juice_shop_rule_name" {
  description = "Name of the Juice Shop SQL injection rule"
  value       = "JuiceShopSQLiRule"
}

output "logging_configuration_arn" {
  description = "ARN of the WAF logging configuration"
  value       = var.enable_logging ? aws_wafv2_web_acl_logging_configuration.main[0].resource_arn : null
}
