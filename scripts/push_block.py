#!/usr/bin/env python3
"""
Emergency WAF Rule Deployment Script
====================================

Rapidly deploy emergency blocking rules to AWS WAF WebACL for incident response.
Designed to execute in under 60 seconds for critical security incidents.

Usage Examples:
    # Block specific IP address
    python push_block.py --ip 192.0.2.44 --web-acl-id arn:aws:wafv2:...

    # Block CIDR range
    python push_block.py --ip 192.0.2.0/24 --web-acl-id arn:aws:wafv2:...

    # Block URI pattern
    python push_block.py --uri-pattern "admin/backdoor" --web-acl-id arn:aws:wafv2:...

    # Block with custom rule name and dry run
    python push_block.py --ip 10.0.0.0/8 --web-acl-id arn:aws:wafv2:... --rule-name "Internal-Network-Block" --dry-run

Author: Security Engineering Team
Version: 1.0
"""

import argparse
import boto3
import json
import sys
import time
import random
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import logging
import re
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class WAFEmergencyBlocker:
    """Emergency WAF rule deployment class with safety features."""
    
    def __init__(self, region: str = 'us-east-1'):
        """Initialize WAF client and configuration."""
        self.wafv2_client = boto3.client('wafv2', region_name=region)
        self.region = region
        self.emergency_rule_priority = 50  # High priority for emergency rules
        
    def validate_inputs(self, web_acl_id: str, ip_address: Optional[str] = None, 
                       uri_pattern: Optional[str] = None) -> bool:
        """Validate input parameters for security and correctness."""
        try:
            # Validate WebACL ID format
            if not web_acl_id or not web_acl_id.startswith('arn:aws:wafv2:'):
                logger.error("Invalid WebACL ARN format")
                return False
                
            if ip_address:
                # Validate IP address or CIDR format
                ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$'
                if not re.match(ip_pattern, ip_address):
                    logger.error(f"Invalid IP address or CIDR format: {ip_address}")
                    return False
                    
                # Prevent blocking critical infrastructure
                dangerous_ranges = [
                    '0.0.0.0/0',      # All traffic
                    '127.0.0.0/8',    # Loopback
                    '169.254.0.0/16', # Link-local
                    '224.0.0.0/4',    # Multicast
                ]
                
                for dangerous in dangerous_ranges:
                    if ip_address == dangerous:
                        logger.error(f"Refusing to block dangerous range: {ip_address}")
                        return False
                        
            if uri_pattern:
                # Basic URI pattern validation
                if len(uri_pattern) < 2 or len(uri_pattern) > 200:
                    logger.error("URI pattern must be between 2 and 200 characters")
                    return False
                    
                # Prevent overly broad patterns
                dangerous_patterns = ['/', '*', '.*', '.+']
                if uri_pattern in dangerous_patterns:
                    logger.error(f"Refusing to block overly broad pattern: {uri_pattern}")
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}")
            return False
    
    def get_web_acl_info(self, web_acl_id: str) -> Tuple[Dict, str, str]:
        """Retrieve WebACL information and lock token.

        Returns a tuple of (WebACL, LockToken, Scope), where Scope is either
        'REGIONAL' or 'CLOUDFRONT' inferred from the ARN.
        """
        try:
            # Extract WebACL name and ID from ARN
            arn_parts = web_acl_id.split('/')
            if len(arn_parts) < 4:
                raise ValueError("Invalid WebACL ARN format")

            # arn:aws:wafv2:<region>:<account>:regional/webacl/<name>/<id>
            # or arn:aws:wafv2:us-east-1:<account>:global/webacl/<name>/<id>
            scope_segment = arn_parts[0]
            if scope_segment.endswith(':regional'):
                scope = 'REGIONAL'
            elif scope_segment.endswith(':global'):
                scope = 'CLOUDFRONT'
            else:
                # Default to REGIONAL if not clearly specified
                scope = 'REGIONAL'

            web_acl_name = arn_parts[2]
            web_acl_uuid = arn_parts[3]

            response = self.wafv2_client.get_web_acl(
                Scope=scope,
                Id=web_acl_uuid,
                Name=web_acl_name
            )

            return response['WebACL'], response['LockToken'], scope

        except Exception as e:
            logger.error(f"Failed to retrieve WebACL info: {str(e)}")
            raise
    
    def find_available_priority(self, web_acl: Dict) -> int:
        """Find the next available priority for emergency rules."""
        used_priorities = set()
        
        for rule in web_acl.get('Rules', []):
            used_priorities.add(rule['Priority'])
            
        # Start from emergency rule priority and find first available
        priority = self.emergency_rule_priority
        while priority in used_priorities:
            priority -= 1
            if priority < 1:
                priority = self.emergency_rule_priority + 1
                while priority in used_priorities:
                    priority += 1
                break
                
        return priority
    
    def create_ip_block_rule(self, ip_address: str, rule_name: str, priority: int) -> Dict:
        """Create IP blocking rule configuration."""
        return {
            'Name': rule_name,
            'Priority': priority,
            'Statement': {
                'IPSetReferenceStatement': {
                    'ARN': f'arn:aws:wafv2:{self.region}:*:regional/ipset/{rule_name}-ipset/*'
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_name
            }
        }
    
    def create_uri_block_rule(self, uri_pattern: str, rule_name: str, priority: int) -> Dict:
        """Create URI pattern blocking rule configuration."""
        return {
            'Name': rule_name,
            'Priority': priority,
            'Statement': {
                'ByteMatchStatement': {
                    # AWS WAFv2 expects bytes for SearchString
                    'SearchString': uri_pattern.encode('utf-8'),
                    'FieldToMatch': {
                        'UriPath': {}
                    },
                    'TextTransformations': [
                        {
                            'Priority': 1,
                            'Type': 'URL_DECODE'
                        },
                        {
                            'Priority': 2,
                            'Type': 'LOWERCASE'
                        }
                    ],
                    'PositionalConstraint': 'CONTAINS'
                }
            },
            'Action': {
                'Block': {}
            },
            'VisibilityConfig': {
                'SampledRequestsEnabled': True,
                'CloudWatchMetricsEnabled': True,
                'MetricName': rule_name
            }
        }
    
    def create_ip_set(self, ip_address: str, ip_set_name: str, scope: str) -> str:
        """Create IP set for IP-based blocking using the provided scope (REGIONAL or CLOUDFRONT)."""
        try:
            response = self.wafv2_client.create_ip_set(
                Scope=scope,
                Name=ip_set_name,
                Description=f'Emergency block for {ip_address} - Created {datetime.now(timezone.utc).isoformat()}',
                IPAddressVersion='IPV4',
                Addresses=[ip_address],
                Tags=[
                    {
                        'Key': 'CreatedBy',
                        'Value': 'EmergencyBlockScript'
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': datetime.now(timezone.utc).isoformat()
                    },
                    {
                        'Key': 'Purpose',
                        'Value': 'EmergencySecurityResponse'
                    }
                ]
            )
            
            logger.info(f"Created IP set: {ip_set_name}")
            return response['Summary']['ARN']
            
        except self.wafv2_client.exceptions.WAFDuplicateItemException:
            # IP set already exists, find its ID and get ARN
            ip_sets = self.wafv2_client.list_ip_sets(Scope=scope)
            for ip_set in ip_sets['IPSets']:
                if ip_set['Name'] == ip_set_name:
                    response = self.wafv2_client.get_ip_set(
                        Scope=scope,
                        Id=ip_set['Id'],
                        Name=ip_set['Name']
                    )
                    return response['IPSet']['ARN']
            # If we get here, something went wrong
            raise Exception(f"IP set {ip_set_name} exists but couldn't be found")
            
        except Exception as e:
            logger.error(f"Failed to create IP set: {str(e)}")
            raise
    
    def deploy_emergency_rule(self, web_acl_id: str, rule_name: str, 
                            ip_address: Optional[str] = None, 
                            uri_pattern: Optional[str] = None,
                            dry_run: bool = False) -> Dict:
        """Deploy emergency blocking rule to WebACL."""
        start_time = time.time()
        
        try:
            # Get current WebACL configuration
            web_acl, lock_token, scope = self.get_web_acl_info(web_acl_id)
            logger.info(f"Retrieved WebACL: {web_acl['Name']} (Scope: {scope})")
            
            # Find available priority
            priority = self.find_available_priority(web_acl)
            logger.info(f"Using priority: {priority}")
            
            # Create rule based on type
            new_rule = None
            ip_set_arn = None
            
            if ip_address:
                # Normalize single IPv4 to /32 for WAF IP set requirement
                ip_cidr = ip_address if '/' in ip_address else f"{ip_address}/32"
                if not dry_run:
                    # Create IP set first
                    ip_set_name = f"{rule_name}-ipset"
                    ip_set_arn = self.create_ip_set(ip_cidr, ip_set_name, scope)
                else:
                    # Generate placeholder ARN for dry run (scope-aware)
                    scope_segment = 'regional' if scope == 'REGIONAL' else 'global'
                    region_for_arn = 'us-east-1' if scope == 'CLOUDFRONT' else self.region
                    ip_set_arn = f'arn:aws:wafv2:{region_for_arn}:*:{scope_segment}/ipset/{rule_name}-ipset/*'
                
                new_rule = {
                    'Name': rule_name,
                    'Priority': priority,
                    'Statement': {
                        'IPSetReferenceStatement': {
                            'ARN': ip_set_arn
                        }
                    },
                    'Action': {
                        'Block': {}
                    },
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': rule_name
                    }
                }
                logger.info(f"Created IP blocking rule for: {ip_address}")
                
            elif uri_pattern:
                new_rule = self.create_uri_block_rule(uri_pattern, rule_name, priority)
                logger.info(f"Created URI blocking rule for pattern: {uri_pattern}")
            
            if new_rule is None:
                raise ValueError("Must specify either ip_address or uri_pattern")
            
            if dry_run:
                logger.info("DRY RUN: Would deploy the following rule:")
                logger.info(json.dumps(new_rule, indent=2))
                return {
                    'success': True,
                    'message': 'Dry run completed successfully',
                    'rule': new_rule,
                    'execution_time': time.time() - start_time
                }
            
            # Add new rule to WebACL
            updated_rules = web_acl['Rules'] + [new_rule]
            
            # Update WebACL (omit empty Description to satisfy API min length)
            update_params = {
                'Scope': scope,
                'Id': web_acl['Id'],
                'Name': web_acl['Name'],
                'DefaultAction': web_acl['DefaultAction'],
                'Rules': updated_rules,
                'VisibilityConfig': web_acl['VisibilityConfig'],
                'LockToken': lock_token
            }
            if web_acl.get('Description'):
                update_params['Description'] = web_acl['Description']

            # If we just created an IP set, give WAF a brief moment before first update
            if ip_address and not dry_run:
                time.sleep(0.5)

            # Retry loop for UpdateWebACL to handle propagation/lock issues
            max_attempts = 7
            base_sleep = 0.5
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    self.wafv2_client.update_web_acl(**update_params)
                    execution_time = time.time() - start_time
                    logger.info(f"Successfully deployed emergency rule: {rule_name}")
                    logger.info(f"Execution time: {execution_time:.2f} seconds")
                    return {
                        'success': True,
                        'message': f'Emergency rule {rule_name} deployed successfully',
                        'rule_name': rule_name,
                        'priority': priority,
                        'execution_time': execution_time,
                        'web_acl_id': web_acl['Id']
                    }
                except self.wafv2_client.exceptions.WAFUnavailableEntityException as e:
                    last_exc = e
                    sleep_for = min(base_sleep * (2 ** (attempt - 1)), 5.0) + random.uniform(0, 0.2)
                    logger.warning(f"UpdateWebACL attempt {attempt}/{max_attempts} failed with WAFUnavailableEntityException; retrying in {sleep_for:.2f}s")
                    time.sleep(sleep_for)
                    continue
                except self.wafv2_client.exceptions.WAFOptimisticLockException as e:
                    last_exc = e
                    logger.warning(f"Optimistic lock encountered on attempt {attempt}/{max_attempts}; refreshing LockToken and retrying")
                    # Refresh WebACL and LockToken, rebuild update_params and updated_rules idempotently
                    web_acl, lock_token, scope = self.get_web_acl_info(web_acl_id)
                    # Only add the rule if it doesn't already exist
                    existing_rule_names = {r['Name'] for r in web_acl.get('Rules', [])}
                    if rule_name not in existing_rule_names:
                        updated_rules = web_acl['Rules'] + [new_rule]
                    else:
                        logger.info(f"Rule {rule_name} already present after refresh; reusing existing rules")
                        updated_rules = web_acl['Rules']
                    update_params = {
                        'Scope': scope,
                        'Id': web_acl['Id'],
                        'Name': web_acl['Name'],
                        'DefaultAction': web_acl['DefaultAction'],
                        'Rules': updated_rules,
                        'VisibilityConfig': web_acl['VisibilityConfig'],
                        'LockToken': lock_token
                    }
                    if web_acl.get('Description'):
                        update_params['Description'] = web_acl['Description']
                    sleep_for = min(base_sleep * (2 ** (attempt - 1)), 5.0) + random.uniform(0, 0.2)
                    time.sleep(sleep_for)
                    continue
                except ClientError as e:
                    last_exc = e
                    code = e.response.get('Error', {}).get('Code', '')
                    if code in ('ThrottlingException', 'WAFInternalErrorException', 'ServiceUnavailableException'):
                        sleep_for = min(base_sleep * (2 ** (attempt - 1)), 5.0) + random.uniform(0, 0.2)
                        logger.warning(f"UpdateWebACL attempt {attempt}/{max_attempts} failed with {code}; retrying in {sleep_for:.2f}s")
                        time.sleep(sleep_for)
                        continue
                    else:
                        raise

            # If we exhausted retries, raise last exception to be caught by outer handler
            raise last_exc if last_exc else Exception("UpdateWebACL failed after retries")
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed to deploy emergency rule: {str(e)}")
            logger.error(f"Execution time: {execution_time:.2f} seconds")
            return {
                'success': False,
                'error': str(e),
                'execution_time': execution_time
            }
    
    def list_emergency_rules(self, web_acl_id: str) -> List[Dict]:
        """List all emergency rules in the WebACL."""
        try:
            web_acl, _, _ = self.get_web_acl_info(web_acl_id)
            
            emergency_rules = []
            for rule in web_acl.get('Rules', []):
                if (rule['Priority'] <= self.emergency_rule_priority + 50 and 
                    'Emergency' in rule['Name']):
                    emergency_rules.append({
                        'name': rule['Name'],
                        'priority': rule['Priority'],
                        'action': list(rule['Action'].keys())[0],
                        'metric_name': rule['VisibilityConfig']['MetricName']
                    })
            
            return emergency_rules
            
        except Exception as e:
            logger.error(f"Failed to list emergency rules: {str(e)}")
            return []

def main():
    """Main function for command-line execution."""
    parser = argparse.ArgumentParser(
        description='Deploy emergency WAF blocking rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Block IP address
  python push_block.py --ip 192.0.2.44 --web-acl-id arn:aws:wafv2:us-east-1:123456789012:regional/webacl/juice-shop-web-acl/12345678

  # Block CIDR range
  python push_block.py --ip 192.0.2.0/24 --web-acl-id arn:aws:wafv2:us-east-1:123456789012:regional/webacl/juice-shop-web-acl/12345678

  # Block URI pattern
  python push_block.py --uri-pattern "admin/backdoor" --web-acl-id arn:aws:wafv2:us-east-1:123456789012:regional/webacl/juice-shop-web-acl/12345678

  # Dry run
  python push_block.py --ip 10.0.0.0/8 --web-acl-id arn:aws:wafv2:us-east-1:123456789012:regional/webacl/juice-shop-web-acl/12345678 --dry-run
        """
    )
    
    parser.add_argument('--web-acl-id', required=True, 
                       help='WebACL ARN to update')
    parser.add_argument('--ip', 
                       help='IP address or CIDR range to block')
    parser.add_argument('--uri-pattern', 
                       help='URI pattern to block')
    parser.add_argument('--rule-name', 
                       help='Custom rule name (auto-generated if not provided)')
    parser.add_argument('--region', default='us-east-1',
                       help='AWS region (default: us-east-1)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--list-rules', action='store_true',
                       help='List existing emergency rules')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize blocker
    blocker = WAFEmergencyBlocker(region=args.region)
    
    # List rules if requested
    if args.list_rules:
        rules = blocker.list_emergency_rules(args.web_acl_id)
        if rules:
            print("\nExisting Emergency Rules:")
            print("-" * 50)
            for rule in rules:
                print(f"Name: {rule['name']}")
                print(f"Priority: {rule['priority']}")
                print(f"Action: {rule['action']}")
                print(f"Metric: {rule['metric_name']}")
                print("-" * 30)
        else:
            print("No emergency rules found.")
        return
    
    # Validate inputs
    if not args.ip and not args.uri_pattern:
        parser.error("Must specify either --ip or --uri-pattern")
    
    if args.ip and args.uri_pattern:
        parser.error("Cannot specify both --ip and --uri-pattern")
    
    if not blocker.validate_inputs(args.web_acl_id, args.ip, args.uri_pattern):
        sys.exit(1)
    
    # Generate rule name if not provided
    if not args.rule_name:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if args.ip:
            safe_ip = args.ip.replace('/', '-').replace('.', '-')
            args.rule_name = f"Emergency-IP-Block-{safe_ip}-{timestamp}"
        else:
            safe_pattern = re.sub(r'[^a-zA-Z0-9-]', '-', args.uri_pattern)[:20]
            args.rule_name = f"Emergency-URI-Block-{safe_pattern}-{timestamp}"
    
    # Deploy rule
    result = blocker.deploy_emergency_rule(
        web_acl_id=args.web_acl_id,
        rule_name=args.rule_name,
        ip_address=args.ip,
        uri_pattern=args.uri_pattern,
        dry_run=args.dry_run
    )
    
    # Print results
    if result['success']:
        print(f"\nSUCCESS: {result['message']}")
        if not args.dry_run:
            print(f"Rule Name: {result['rule_name']}")
            print(f"Priority: {result['priority']}")
        print(f"Execution Time: {result['execution_time']:.2f} seconds")
        
        if result['execution_time'] > 60:
            print("WARNING: Execution exceeded 60-second target!")
        
    else:
        print(f"\nERROR: Failed to deploy rule: {result['error']}")
        print(f"Execution Time: {result['execution_time']:.2f} seconds")
        sys.exit(1)

if __name__ == '__main__':
    main()
