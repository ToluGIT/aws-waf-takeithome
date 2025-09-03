output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.main.zone_id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "juice_shop_url" {
  description = "URL to access the OWASP Juice Shop application"
  value = format("%s://%s",
    var.ssl_certificate_arn != null ? "https" : "http",
    aws_lb.main.dns_name
  )
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.juice_shop.name
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF WebACL"
  value       = module.edge_waf.web_acl_arn
}

output "waf_web_acl_id" {
  description = "ID of the WAF WebACL"
  value       = module.edge_waf.web_acl_id
}

output "s3_waf_logs_bucket" {
  description = "S3 bucket for WAF logs"
  value       = aws_s3_bucket.waf_logs.bucket
}

output "kinesis_firehose_delivery_stream" {
  description = "Kinesis Data Firehose delivery stream for WAF logs"
  value       = var.enable_waf_logging ? aws_kinesis_firehose_delivery_stream.waf_logs[0].name : null
}
