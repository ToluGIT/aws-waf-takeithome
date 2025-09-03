-- WAF KPI Metrics (single statement, honest among-logged percentages)
-- Reports CORE_METRICS first and Top 5 attack vectors below it.

WITH base AS (
  SELECT action, terminatingruleid
  FROM waf_logs
  WHERE from_unixtime(timestamp/1000) >= current_timestamp - interval '1' day
    AND from_unixtime(timestamp/1000) <= current_timestamp
    -- Partition pruning for speed (today and yesterday)
    AND year IN (
      date_format(current_timestamp, '%Y'),
      date_format(current_timestamp - interval '1' day, '%Y')
    )
    AND month IN (
      date_format(current_timestamp, '%m'),
      date_format(current_timestamp - interval '1' day, '%m')
    )
    AND day IN (
      date_format(current_timestamp, '%d'),
      date_format(current_timestamp - interval '1' day, '%d')
    )
),
metrics AS (
  SELECT
    COUNT(*) AS total_logged_requests,
    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_requests,
    SUM(CASE WHEN action = 'COUNT' THEN 1 ELSE 0 END) AS counted_requests,
    ROUND(100.0 * SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) AS percent_blocked_among_logged
  FROM base
),
top AS (
  SELECT
    COALESCE(
      CASE
        WHEN terminatingruleid = 'JuiceShopSQLiRule' THEN 'SQL Injection (Juice Shop)'
        WHEN terminatingruleid LIKE '%SQLi%' THEN 'SQL Injection (AWS Managed)'
        WHEN terminatingruleid LIKE '%XSS%' THEN 'Cross-Site Scripting'
        WHEN terminatingruleid = 'RateLimitRule' THEN 'Rate Limiting'
        WHEN terminatingruleid = 'GeoRestrictionRule' THEN 'Geographic Restriction'
        WHEN terminatingruleid = 'IPReputationRule' THEN 'IP Reputation Block'
        WHEN terminatingruleid LIKE '%Common%' THEN 'Common Attack Patterns'
        WHEN terminatingruleid LIKE '%Emergency%' THEN 'Emergency Block Rule'
        WHEN terminatingruleid LIKE '%AWSManagedRulesCommonRuleSet%' THEN 'AWS Common Rules'
        WHEN terminatingruleid LIKE '%AWSManagedRulesSQLiRuleSet%' THEN 'AWS SQLi Rules'
        ELSE terminatingruleid
      END,
      'Unknown'
    ) AS rule_name,
    COUNT(*) AS rule_block_count
  FROM base
  WHERE action = 'BLOCK'
  GROUP BY terminatingruleid
  ORDER BY rule_block_count DESC
  LIMIT 5
)
SELECT metric_type, total_requests, blocked_requests, percent_blocked, rule_name, rule_block_count
FROM (
  SELECT
    'CORE_METRICS' AS metric_type,
    total_logged_requests AS total_requests,
    blocked_requests,
    percent_blocked_among_logged AS percent_blocked,
    'logged_counts' AS rule_name,
    counted_requests AS rule_block_count,
    0 AS sort_key,
    0 AS sort_score
  FROM metrics

  UNION ALL

  SELECT
    'TOP_ATTACK_VECTORS' AS metric_type,
    0 AS total_requests,
    0 AS blocked_requests,
    0 AS percent_blocked,
    rule_name,
    rule_block_count,
    1 AS sort_key,
    rule_block_count AS sort_score
  FROM top
)
ORDER BY sort_key ASC, sort_score DESC;
