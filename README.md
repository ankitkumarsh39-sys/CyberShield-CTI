# CyberShield-CTI

Python-based IOC extraction, enrichment, and advisory generation engine for CTI analysts.

## 🛡️ Overview

**CyberShield-CTI** (also referred to as CTI-Workbench-SOC in docs) automates translating raw threat intelligence source data into actionable outputs:

- Extracts Indicators of Compromise (IOCs): IP addresses, domains, URLs, and file hashes.
- Enriches IOCs via VirusTotal v3 API (score, analysis, metadata).
- Re-checks low-detection IOCs to capture evolving threat status.
- Deduplicates and applies whitelist filtering to reduce noise.
- Produces text advisories, blocklists, and incubation reports in `/reports`.

## 📁 Repository Structure

- `main.py`: Entry script coordinating extraction, enrichment, and report generation.
- `advisory_gen.py`: Advisory formatting and report writing logic.
- `blocklist.txt`: Example/seed blocklist storage file.
- `whitelist.txt`: Whitelisted IOCs to ignore in detection output.
- `reports/`: Output folder with generated advisory and IOC artifacts.
- `requirements.txt`: Python dependencies.
- `README.md`: Project documentation.

## ⚙️ Key Features (Detailed)

1. IOC Extraction
   - Parses URLs and text from CTI blog content.
   - Supports: IPv4, domain names, URLs, MD5/SHA variants.
   - Handles defanged IOCs (e.g., `hxxp://`) and normalizes output.

2. VirusTotal Integration
   - Queries VT v3 for threat score and metadata.
   - Automatically updates for IoCs with low detection (≤5) for latest detection data.

3. Noise Reduction
   - Deduplicates IOCs across feeds and history.
   - Applies `whitelist.txt` to exclude known benign indicators.
   - Saves incremental blocklist updates in `reports/Malicious_IOCs`.

4. Advisory Output
   - Writes human readable report files with context and IOC lists.
   - Includes “Urgent Blocklist” for SOC ingestion.

## 🔧 Quick Setup

1. Clone repo:

   ```bash
   git clone https://github.com/YOUR_USERNAME/CTI-Workbench-SOC.git
   cd CTI-Workbench-SOC
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure API key:
   - Create a file called `key.env` in repo root.
   - Add:
     ```env
     VT_API_KEY=your_api_key_here
     ```

4. Configure optional files:
   - `whitelist.txt`: one IOC per line to exclude.
   - `blocklist.txt`: persists known malicious IOCs.

## ▶️ Running the Tool

From project root:

```bash
python main.py
```

- When prompted, enter a threat intelligence blog URL or local text file path.
- The script performs extraction, enrichment, maybe a refresh for low-signal IOC, then writes outputs into `reports/`.

## 🗂️ Output Files

- `reports/ADVISORY_<timestamp>.txt`: full narrative report.
- `reports/IOC_ONLY_<timestamp>.txt`: extracted IOC list.
- `reports/Malicious_IOCs/URGENT_BLOCKLIST_<timestamp>.txt`: final blocklist for SOC tools.

## 🧪 Development Notes

- Use a test list in `blocklist.txt` to avoid repeatedly querying VirusTotal during dev.
- Local run without VT key should fail gracefully; add proper key management in future updates.

## 💡 Contribution Guidance

- Add features in modular files (`advisory_gen.py` for output formatting, `main.py` for orchestration).
- Maintain API key security; don’t commit `.env` or `key.env`.
- Run formatting/linting with `black`/`flake8` to keep style.

## 🧰 Libraries Used

- `requests`: HTTP client for fetching blog pages and VirusTotal API data.
- `beautifulsoup4` (`bs4`): HTML parser to extract clean text and IOCs.
- `lxml`: fast parser backend for BeautifulSoup.
- `iocextract`: specialized IOC extraction (IP/domain/url/hash) from text.
- `python-dotenv`: loads VT_API_KEY from environment files.
- `sumy`: generates text summary of threat intelligence content.
- `nltk`: NLP tokenizer support for summarization.
- `numpy`: utility math/array operations used in data handling.
- `regex`: advanced regex support for extracting defanged IOCs.

---

### 📌 Important: API/Privacy

- VirusTotal account may rate-limit; use test API key carefully.
- No sensitive API keys should be committed to git.
