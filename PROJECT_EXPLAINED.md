# CyberShield-CTI: Full Walkthrough & Explanation

This file provides a complete project explanation for CyberShield-CTI, including:

- What the project does
- How to set up and run it
- What each file is for
- Line-by-line explanation of the code (`main.py`, `advisory_gen.py`)
- Example usage

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
- rate limiting: sleep and retry.

---

## 7. What you can add next

1. Robust parser for direct text file inputs.
2. Multi-URL queue and batch processing.
3. Async VirusTotal queries to speed up large IOC sets.
4. Cache results in local DB (sqlite) instead of repeated checks.
5. Add unit tests for each method.

---

## 8. Confirmed project dependencies

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

## 9. License and attribution

Add this to help future maintainers:

`LICENSE` - choose MIT / Apache 2.0 / etc.

`README` already has annotations by Ankit Kumar (SOC Analyst).
