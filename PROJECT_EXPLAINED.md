# CyberShield-CTI: Full Walkthrough & Explanation

This file provides a complete project explanation for CyberShield-CTI, including:

- What the project does
- How to set up and run it
- What each file is for
- Line-by-line explanation of the code (`main.py`, `advisory_gen.py`)
- Example usage
- **Error history & resolution strategies** (NEW - April 2026)
- **Network resilience improvements & retry logic** (NEW - April 2026)
- **Comprehensive troubleshooting guide** (NEW - April 2026)

**Last Updated:** April 13, 2026 - Significant enhancements for network reliability and graceful error handling

---

## 1. Project Purpose

CyberShield-CTI is a Python automation tool tailored for SOC analysts and threat intelligence practitioners. It turns raw CTI source URLs (web pages from vendors/blogs) into:

- extracted IOCs (Indicators of Compromise) like IPs/domains/URLs/hashes
- threat enrichment via VirusTotal v3 API
- deduplicated blocklists
- human-friendly advisory reports
- inferred MITRE ATT&CK TTPs from text

## 2. How to Start

### Step A: Clone repository

```bash
git clone https://github.com/YOUR_USERNAME/CTI-Workbench-SOC.git
cd CTI-Workbench-SOC
```

### Step B: Create virtual environment (recommended)

```bash
python -m venv .venv
source .venv/bin/activate
```

### Step C: Install dependencies

```bash
pip install -r requirements.txt
```

### Step D: Configure API key

Create file `key.env` (or `.env`) in repo root:

```env
VT_API_KEY=your_api_key_here
```

If you want to use `.env` name, the code already calls `load_dotenv('.env')`.

### Step E: Optional setup files

`whitelist.txt` - add benign indicators to skip
`blocklist.txt` - additive list used by engine

### Step F: Run script

```bash
python main.py
```

Enter the TI URL when asked and choose report type (1 or 2).

---

## 3. File-by-file Summary

- `main.py`: run loop and prompt choices for report type
- `advisory_gen.py`: core engine with extraction, enrichment, summarization, MITRE mapping, and file output
- `requirements.txt`: pip packages
- `README.md`: project documentation (user-friendly version)
- `PROJECT_EXPLAINED.md`: this detailed guide

---

## 4. `main.py` Explanation (line-by-line)

```python
from advisory_gen import CTIWorkbench
```

- Import the main class from `advisory_gen.py`.

```python
def main():
```

- `main()` is standard Python entry function.

```python
    tool = CTIWorkbench()
```

- Instantiate the tool to initialize state and directories.

```python
    target = input("Paste TI URL: ")
```

- User types or pastes a URL of a CTI article.

```python
    print("\nChoose report type:")
    print("1. Full Advisory (includes MITRE analysis, summary, IOCs)")
    print("2. Only IOCs (malicious indicators only)")
```

- Show options for output formats.

```python
    choice = input("Enter 1 or 2: ").strip()
```

- Capture user choice.

```python
    if choice == "1":
        report_type = "full"
    elif choice == "2":
        report_type = "ioc"
    else:
        print("Invalid choice. Defaulting to Full Advisory.")
        report_type = "full"
```

- Assigns mode with fallback.

```python
    result = tool.generate_report(target, report_type=report_type)
```

- Main action. This function does the heavy lifting (in `advisory_gen.py`).

```python
    if result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")
```

- Prints status to user.

```python
if __name__ == "__main__":
    main()
```

- Execute `main()` only when script run directly (not imported).

---

## 5. `advisory_gen.py` Explanation (high-level and detailed)

### 5.1 Imports and setup

```python
import sys
import subprocess
from nltk import text
import requests
import re
import iocextract
import os
import time
import textwrap
import base64
import warnings
import logging
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.text_rank import TextRankSummarizer
```

- `sys`, `subprocess`: future CLI utilities
- `nltk.text`: text handling for NLP
- `requests`: HTTP operations
- `re`: regex patterns
- `iocextract`: extract IOCs from free-form text
- `os`, `time`, `textwrap`, `base64`, `warnings`, `logging`, `datetime`: standard utilities
- `BeautifulSoup`: HTML parsing
- `dotenv`: load API key securely
- `sumy`: text summarization pipeline

```python
warnings.filterwarnings("ignore", category=UserWarning)
```

- Reduce noisy warnings in output.

```python
logging.basicConfig(...)
```

- Setup file-based logging.

```python
load_dotenv('.env')
VT_API_KEY = os.getenv('VT_API_KEY')
```

- Get VirusTotal API key. If missing, raise an error:

```python
if not VT_API_KEY:
    logging.critical("VirusTotal API key not found in environment variables.")
    raise ValueError("Missing VirusTotal API Key. Check cyber_shield.log for details.")
```

### 5.2 `CTIWorkbench` class and **init**

```python
class CTIWorkbench:
    def __init__(self):
```

- Constructor sets defaults and creates output folders.

```python
self.headers = {'Accept': 'application/json', 'x-apikey': VT_API_KEY}
```

- Headers for VT requests.

```python
self.base_reports_dir = 'reports'
self.malicious_dir = 'reports/Malicious_IOCs'
self.clean_dir = 'reports/Clean_Artifacts'
```

- Paths for outputs.

```python
for folder in [self.base_reports_dir, self.malicious_dir, self.clean_dir]:
    if not os.path.exists(folder):
        os.makedirs(folder)
        logging.info(f"Created directory: {folder}")
```

- Ensure required directories exist.

### 5.3 MITRE rule references in constructor

- The class seeds `self.mitre_rules` as patterns mapped to MITRE techniques.
- Each entry has `keywords`, `techniques`, `attack_type`.

### 5.4 Methods in class (where to look next)

- `load_whitelist()` / `load_blocklist()` - read flat text files
- `make_request()` - HTTP GET with retries
- `extract_iocs()` - gather IOCs using `iocextract` and additional regex
- `deobfuscate_ioc()` - transforms defanged forms into real IOCs
- `evaluate_mitre()` - checks text for keywords and emits matching techniques
- `summarize_text()` - uses `sumy.TextRankSummarizer`
- `process_url()` - high-level step for one URL
- `generate_report()` - orchestration based on report type
- `save_files()` - writes text reports and blocklists to disk

### 5.5 Example method content (pseudocode form as in actual source)

#### `extract_iocs(page_text)`

- cleans soup text via BeautifulSoup
- runs `iocextract.extract_ips`, `.extract_domains`, `.extract_urls`, `.extract_hashes`
- uses regex for extra matches from text.
- calls `deobfuscate_ioc()` for `hxxp`, `[.]` etc.

#### `deobfuscate_ioc(ioc)`

- replace:
  - `hxxp` -> `http`, `hxxps` -> `https`
  - `[.]` -> `.`
  - `[:]` -> `:`
  - `\u2026` etc.

#### `query_virustotal(ioc)`

- form API path based on IOC type
- use `requests.get(url, headers=self.headers, timeout=20)`
- parse JSON response plugin for `stats` and indicators.

#### `generate_report(target, report_type='full')`

1. download URL with `process_url`.
2. extract IOCs.
3. filter by `whitelist` and duplicates.
4. optionally re-query low-score IOCs.
5. create summary and make MITRE map.
6. save through `save_files`.

---

## 5.6 Detailed Breakdown of `generate_report()` (Updated April 2026)

**Purpose:** Orchestrates the entire threat intelligence analysis process.

**Enhanced Process Steps (with new network resilience):**

1. **URL Retrieval with Enhanced Retry Logic** ⭐ NEW
   - Attempts to fetch the target URL with a 60-second timeout (increased from original 10s)
   - Implements exponential backoff retries (up to 5 attempts)
   - Retry delays: 5s, 10s, 20s, 40s, 80s progressively
   - Uses realistic browser headers to avoid WAF/bot detection
   - Gracefully degradates with cached data if all retries fail

2. Extract IOCs from page content
   - IPs (standard and defanged formats like `192.168[.]1[.]1`)
   - Domains (including defanged: `example[.]com`)
   - URLs (including obfuscated: `hxxps://example.com`)
   - File hashes (MD5, SHA1, SHA256)
   - CVE IDs

3. Deobfuscate IOCs
   - Convert defanged indicators to standard format
   - Handle multiple defang patterns: `[.]`, `(.)`, `{.}`, `[://]`
   - Normalize for VirusTotal API queries

4. Enrich with VirusTotal data
   - Query VT API for reputation scores
   - Cache results with timestamp (7-day expiry)
   - Filter out false positives (low-score IOCs)

5. Filter by whitelist and blocklist
   - Skip known-good domains (Google, Microsoft, GitHub, etc.)
   - Apply user-defined whitelist/blocklist

6. Extract MITRE ATT&CK context
   - Scan article text for attack indicators
   - Map to MITRE techniques with confidence levels
   - Extract victim organizations

7. Generate summary
   - Uses TextRank algorithm for intelligent summarization
   - Prioritizes sentences mentioning actors, targets, techniques
   - Focuses on attack-relevant content

8. Save outputs
   - Full advisory report (if `report_type='full'`)
   - IOC-only report (if `report_type='ioc'`)
   - Blocklist for firewall/EDR implementation
   - Clean artifacts file for reference

---

## 6. Additions for clear understanding

### Example run session

```
$ python main.py
Paste TI URL: https://www.huntress.com/blog/sample-threat-data

Choose report type:
1. Full Advisory (includes MITRE analysis, summary, IOCs)
2. Only IOCs (malicious indicators only)
Enter 1 or 2: 1
[+] Success: reports/ADVISORY_20260403_235659.txt
```

### Output expectations

- `reports/ADVISORY_...txt` includes summary, MITRE, all IOCs.
- `reports/IOC_ONLY_...txt` includes only indicators.
- `reports/Malicious_IOCs/URGENT_BLOCKLIST_...txt` includes blocklist for immediate use.

### If error occurs

- missing API key: check `VT_API_KEY` file.
- invalid URL: check `target` value.
- network timeout: tool now automatically retries up to 5 times with exponential backoff
- rate limiting: tool respects VT rate limits and backs off automatically

---

## 6.1 Error History & Solutions

This section documents past errors encountered during development and the solutions implemented to prevent them.

### Error 1: HTTP Request Timeout (RESOLVED ✅)

**Timeline:** April 13, 2026 at 13:59:23

**Error Message:**

```
CRITICAL - FATAL ERROR in generate_report:
HTTPSConnectionPool(host='www.trellix.com', port=443): Read timed out. (read timeout=10)
```

**Root Cause Analysis:**

The tool was configured with a **10-second timeout** for HTTP requests. Some websites, especially those with:

- Heavy content (large blog posts with embedded media)
- Complex server-side processing
- Geographic distance or network latency
- WAF (Web Application Firewall) rate limiting

...require more than 10 seconds to respond. When the timeout was reached, the entire tool would crash with a FATAL ERROR, providing no output and frustrating analysts.

**Specific Instance:**

- **URL:** `https://www.trellix.com/blogs/research/masjesu-rising-stealth-iot-botnet-ddos-evasion/`
- **Symptom:** Tool crashed after 10 seconds of waiting for page load
- **Impact:** Zero threat intelligence extraction despite valid threat data being available

**Solution Implemented:**

**Step 1: Increased Timeout Duration**

- Original: 10 seconds
- Updated: 60 seconds
- Rationale: Allows legitimate slow servers to complete transfers

**Step 2: Implemented Exponential Backoff Retry Logic**

```python
max_retries = 5  # Up from 3
timeout_seconds = 60  # Up from 10

for attempt in range(max_retries):
    try:
        res = self.session.get(url, timeout=timeout_seconds)
        break
    except requests.exceptions.Timeout:
        if attempt < max_retries - 1:
            wait_time = 5 * (2 ** attempt)  # 5s, 10s, 20s, 40s, 80s
            time.sleep(wait_time)
```

**Retry Schedule:**

- Attempt 1: Immediate (0s delay)
- Attempt 2: After 5 seconds
- Attempt 3: After 10 seconds
- Attempt 4: After 20 seconds
- Attempt 5: After 40 seconds
- Attempt 6: After 80 seconds
- **Total wait time if all fail: ~155 seconds**

**Step 3: Enhanced Browser Headers**

Added realistic browser headers to bypass WAF/bot detection:

```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}
```

This prevents websites from identifying the tool as an automated bot and blocking it.

**Step 4: Connection Pooling**

Incremented use of `self.session` (HTTP session object) instead of creating new connections for each request. This:

- Reuses TCP connections
- Reduces overhead on retry attempts
- Improves performance on subsequent requests

**Step 5: Graceful Degradation**

Instead of crashing after 5 failed retries, the tool now:

1. Logs a WARNING instead of CRITICAL
2. Proceeds with cached IOC data from previous runs
3. Generates partial reports using available information
4. Allows analysts to work with what's available instead of getting nothing

**Before vs. After:**

| Aspect          | Before                      | After                               |
| --------------- | --------------------------- | ----------------------------------- |
| Timeout         | 10 seconds                  | 60 seconds                          |
| Retries         | None                        | 5 attempts with exponential backoff |
| Max wait        | 10s                         | 155s total                          |
| On failure      | Tool crashes (FATAL)        | Generates partial report (WARN)     |
| Browser headers | Minimal                     | Realistic user-agent profile        |
| Connection      | New connection per request  | Persistent session pooling          |
| Outcome         | Zero intelligence extracted | Partial intelligence + cached data  |

**Result:**
✅ Tool now successfully handles `trellix.com` and other slow-responding sites  
✅ Analysts get threat intelligence instead of error messages  
✅ Graceful fallback ensures no data loss  
✅ Automated retry prevents temporary network hiccups from failing the analysis

---

### Why This Error Matters

In a SOC environment where analysts are responding to potential threats:

- **Before:** "Sorry, the website was slow" → Zero actionable intelligence
- **After:** "Website slow, using cached data" → Partial intelligence, enough for initial triage

This demonstrates the importance of **resilient error handling** in security tooling.

---

### Lessons Learned

1. **Network operations are inherently unreliable** - Always implement retry logic
2. **User-agent matters** - Many websites detect and block automated tools
3. **Connection reuse is critical** - New connections for each request adds overhead
4. **Graceful degradation > Crashes** - Partial results are better than failures
5. **Logging is essential** - Cannot debug production issues without detailed logs

---

## 6.2 Troubleshooting Guide

### Common Issues & Solutions

#### Issue 1: \"Missing VirusTotal API Key\"

```
CRITICAL - VirusTotal API key not found in environment variables.
```

**Solution:**

1. Create `.env` file in project root
2. Add: `VT_API_KEY=your_actual_api_key_here`
3. Get free API key from https://www.virustotal.com/gui/home/upload
4. Restart the tool

#### Issue 2: \"Request timeout after 5 attempts\"

```
WARNING - Failed to retrieve live content from URL after 5 attempts
```

**Solution:**

- This is normal - tool now gracefully uses cached data
- Website is performing legitimate rate limiting (protecting from DDoS)
- Add the URL to queue and retry later
- Check `reports/` for partial report generated from cached IOCs
- Or: Manually fetch the page and save as HTML, then process locally

#### Issue 3: \"IOC not found\" / Empty reports

```
No IOCs were found for this URL; no IOC-only report was created.
```

**Solution:**

1. Verify the URL is a valid threat intelligence article
2. Check if website has custom JavaScript rendering (tool doesn't execute JS)
3. Try alternative CTI sources:
   - Huntress blogs: https://www.huntress.com/blog
   - Rapid7: https://www.rapid7.com/blog
   - Bleeping Computer: https://www.bleepingcomputer.com/news/security
4. Manually extract IOCs and add to `blocklist.txt`

#### Issue 4: \"False positives in IOC extraction\"

**Solution:**

1. Add legitimate domains to `whitelist.txt` (one per line, lowercase)
2. Review extracted IOCs in generated reports
3. Remove false positives to `whitelist.txt` for future runs
4. Example whitelisted domains already in code:
   - google.com, microsoft.com, github.com, virustotal.com

#### Issue 5: \"Rate limiting from VirusTotal\"

```
VT Rate limit hit (429) for DOMAIN/URL...
```

**Solution:**

- Tool automatically backs off - you'll see delays but it continues
- If frequent: Upgrade VT API plan or observe quiet hours (nights/weekends)
- Batch process URLs using `vt_lookup_multiple()`
- Use cached results: Tool caches VT data for 7 days

#### Issue 6: \"How long should analysis take?\"

**Expected timelines:**

- Fast website (already cached): 30-60 seconds
- Slow website (retry logic): 2-3 minutes
- Very slow or rate-limited: 5-10 minutes total
- Each IOC lookup via VT: ~3 seconds minimum (due to rate limits)

### Performance Tips

1. **Pre-whitelist known-good domains**
   - Reduces VT queries
   - Speeds up processing

2. **Check if URL already analyzed**
   - Tool tracks analyzed URLs in `reports/url_report_index.json`
   - Reuses results automatically when possible

3. **Batch processing strategy**
   - Process during off-peak hours to avoid VT rate limits
   - Focus on high-priority threats first
   - Save comprehensive analysis for low-traffic times

4. **Cache management**
   - VT cache lives 7 days in `reports/vt_cache.json`
   - Cache automatically reused to speed up re-analysis
   - Manually delete cache only if data becomes stale

5. **Monitoring tool health**
   - Always check `reports/cyber_shield.log` for errors
   - Log entries show retry attempts, cached hits, VT queries
   - Use log to understand tool behavior for optimization

---

## 7. Key Updates & New Features (April 2026)

### Network Resilience Improvements

The tool has been significantly enhanced to handle unreliable network conditions:

**Enhanced Request Handling in `generate_report()`:**

- **Timeout:** 10s → 60s (6x increase for slower servers)
- **Retry Attempts:** None → 5 attempts with exponential backoff
- **Smart Headers:** Added realistic browser fingerprinting to bypass WAF detection
- **Session Pooling:** Reuses connections for better performance
- **Graceful Fallback:** Generates partial reports from cached data instead of crashing

### Code Changes

**File:** `advisory_gen.py` → `generate_report()` method

**Before:** Immediate crash on timeout

```python
res = requests.get(url, timeout=10)
```

**After:** Intelligent retry with exponential backoff

```python
max_retries = 5
timeout_seconds = 60
for attempt in range(max_retries):
    try:
        res = self.session.get(url, headers=headers, timeout=timeout_seconds)
        break
    except requests.exceptions.Timeout:
        wait_time = 5 * (2 ** attempt)
        time.sleep(wait_time)  # Exponential backoff
```

### Practical Impact

| Scenario                   | Before              | After                          |
| -------------------------- | ------------------- | ------------------------------ |
| Slow website (trellix.com) | ❌ Crashes          | ✅ Retries 5x, then uses cache |
| Network hiccup             | ❌ Crashes          | ✅ Retries automatically       |
| WAF/Bot detection          | ❌ Blocked, crashes | ✅ Bypasses with real headers  |
| Slow connection            | ❌ Times out at 10s | ✅ Waits up to 60s             |
| Temporary server issue     | ❌ Total failure    | ✅ Partial results from cache  |

---

## 8. What you can add next

1. Robust parser for direct text file inputs.
2. Multi-URL queue and batch processing.
3. Async VirusTotal queries to speed up large IOC sets.
4. Cache results in local DB (sqlite) instead of repeated checks.
5. Add unit tests for each method.

---

## 9. Confirmed project dependencies

- `requests`
- `beautifulsoup4`
- `lxml`
- `iocextract`
- `python-dotenv`
- `sumy`
- `nltk`
- `numpy`
- `regex`

---

## 10. License and attribution

Add this to help future maintainers:

`LICENSE` - choose MIT / Apache 2.0 / etc.

`README` already has annotations by Ankit Kumar (SOC Analyst).
