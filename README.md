# CyberShield-CTI
Python-based IOC extraction and enrichment tool. Automates the transition from raw threat blogs to structured investigation reports with real-time VirusTotal re-analysis and summarization logic.

# 🛡️ CTI-Workbench-SOC

**CTI-Workbench-SOC** is a high-performance Python automation tool designed for Security Operations Center (SOC) analysts. It streamlines the process of extracting, deduplicating, and enriching Indicators of Compromise (IOCs) from raw Threat Intelligence (CTI) blogs and reports.

---

## 🚀 Key Features

* **Automated Extraction:** Uses advanced RegEx to pull IPs, Domains, URLs, and File Hashes from complex HTML and text.
* **VirusTotal v3 Integration:** Real-time enrichment of IOCs using the VirusTotal API.
* **Smart Re-analysis:** Automatically triggers a fresh scan for IOCs with low detection scores (≤ 5) to capture the latest threat data.
* **Intelligent Filtering:** * **Deduplication:** Prevents redundant API calls and cleaner reports.
    * **Whitelist Support:** Silently filters out "noise" (e.g., Google, Microsoft, internal domains).
    * **Zero-Score Pass:** Keeps defanged/suspicious formats (like `hxxp`) even if not yet flagged by VT.
* **Advisory Generation:** Produces professional, human-readable text reports and machine-ready blocklists.

---

## 🛠️ Technical Stack

* **Language:** Python 3.x
* **APIs:** VirusTotal v3
* **Libraries:** `requests`, `BeautifulSoup4`, `iocextract`, `sumy`, `python-dotenv`
* **Security:** Environment variable management via `.env` to protect API credentials.

---

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/CTI-Workbench-SOC.git](https://github.com/YOUR_USERNAME/CTI-Workbench-SOC.git)
   cd CTI-Workbench-SOC

   Install Dependencies:

Bash
pip install -r requirements.txt

Configure API Key:
Create a key.env file in the root directory and add your VirusTotal API key:

Plaintext
VT_API_KEY=your_api_key_here

source API_KEY = https://www.virustotal.com/gui/home/apikey

============================================================================

📖 Usage
Run the script and paste a URL from a threat intelligence blog (e.g., Huntress, Atos, BleepingComputer):

Bash
python CTIWorkbench.py
The tool will generate a full advisory in the /reports folder and an urgent blocklist in /reports/Malicious_IOCs.

----------------------------------------------------------------------------------------------

🛡️ Security Note
This project follows Secure Coding Practices. API keys are managed via environment variables and are strictly excluded from version control via .ignore.

Developed by: Ankit Kumar

Role: SOC Analyst | Cybersecurity Professional

---

### 💡 Pro-Tip: Create a `requirements.txt`
To make the "Installation" section of your README work, create a file named `requirements.txt` in your folder and paste this:

```text
requests
beautifulsoup4
iocextract
sumy
python-dotenv
lxml
