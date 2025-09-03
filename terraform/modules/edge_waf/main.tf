# IP Set for blocked IPs (dynamic blocking support)
resource "aws_wafv2_ip_set" "blocked_ips" {
  name  = "${var.project_name}-blocked-ips"
  scope = "REGIONAL"

  ip_address_version = "IPV4"
  addresses          = var.blocked_ips

  tags = merge(var.tags, {
    Name = "${var.project_name}-blocked-ips"
  })
}

# WAF WebACL with comprehensive security rules
resource "aws_wafv2_web_acl" "main" {
  name  = "${var.project_name}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 2b: Remote File Inclusion (RFI) Protection
  rule {
    name     = "RFIProtectionRule"
    priority = 145

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "http://"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "https://"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RFIProtectionRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 1: Block specific Juice Shop SQL injection payload
  rule {
    name     = "JuiceShopSQLiRule"
    priority = var.juice_shop_sql_injection_priority

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string = "' OR 1=1--"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "/rest/products/search"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
            positional_constraint = "EXACTLY"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "JuiceShopSQLiRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3b: Oversized Header Protection
  rule {
    name     = "LargeHeaderRule"
    priority = 160

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 4096

        field_to_match {
          headers {
            match_scope       = "ALL"
            oversize_handling = "MATCH"
            match_pattern {
              all {}
            }
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LargeHeaderRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Path Traversal Protection
  rule {
    name     = "PathTraversalRule"
    priority = 140

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "../"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "/etc/passwd"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PathTraversalRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Command Injection Protection
  rule {
    name     = "CommandInjectionRule"
    priority = 150

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "; cat"
            field_to_match {
              all_query_arguments {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "; ls"
            field_to_match {
              all_query_arguments {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "| cat"
            field_to_match {
              all_query_arguments {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
        statement {
          byte_match_statement {
            search_string = "& whoami"
            field_to_match {
              all_query_arguments {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommandInjectionRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Rate limiting per IP
  rule {
    name     = "RateLimitRule"
    priority = var.rate_limit_priority

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5_minutes
        aggregate_key_type = "IP"

        scope_down_statement {
          not_statement {
            statement {
              byte_match_statement {
                search_string = "healthcheck"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 1
                  type     = "LOWERCASE"
                }
                positional_constraint = "CONTAINS"
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Geographic restriction (if configured)
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 ? [1] : []
    content {
      name     = "GeoRestrictionRule"
      priority = var.geo_restriction_priority

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allowed_countries
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoRestrictionRule"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 6: Block known bad IPs
  dynamic "rule" {
    for_each = length(var.blocked_ips) > 0 ? [1] : []
    content {
      name     = "IPReputationRule"
      priority = var.ip_reputation_priority

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked_ips.arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "IPReputationRule"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 7: AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = var.common_ruleset_priority

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Keep SizeRestrictions_BODY in count mode for Juice Shop functionality
        # Remove both overrides to enable blocking of attacks
        rule_action_override {
          action_to_use {
            count {}
          }
          name = "SizeRestrictions_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 8: AWS Managed Rules - SQL Injection Rule Set
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = var.sqli_ruleset_priority

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"

        # Remove SQLi_QUERYARGUMENTS override to enable blocking of classic SQL injection
        # This will fix the 500 error issue and properly block SQL injection attempts
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-web-acl"
  })

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}WebACL"
    sampled_requests_enabled   = true
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  # Count must be known at plan time; rely only on enable_logging.
  # The Firehose ARN may be unknown during plan but will resolve at apply.
  count                   = var.enable_logging ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [var.kinesis_firehose_arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "COUNT"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "DROP"
      condition {
        action_condition {
          action = "ALLOW"
        }
      }
      requirement = "MEETS_ALL"
    }
  }
}

# CloudWatch Dashboard for WAF Metrics (Optional)
resource "aws_cloudwatch_dashboard" "waf_dashboard" {
  dashboard_name = "${var.project_name}-waf-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.aws_region, "Rule", "ALL"],
            [".", "BlockedRequests", ".", ".", ".", ".", ".", "."],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "WAF Requests Overview"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.aws_region, "Rule", "JuiceShopSQLiRule"],
            [".", ".", ".", ".", ".", ".", ".", "RateLimitRule"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesCommonRuleSet"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesSQLiRuleSet"],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Blocked Requests by Rule"
          period  = 300
        }
      }
    ]
  })
}
