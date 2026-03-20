import sys
import subprocess
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

# --- Summarization libraries (NLP) ---
from sumy.parsers.plaintext import PlaintextParser  
from sumy.nlp.tokenizers import Tokenizer           
from sumy.summarizers.lsa import LsaSummarizer      

warnings.filterwarnings("ignore", category=UserWarning)

# --- 1. LOGGING CONFIGURATION ---
logging.basicConfig(
    filename='reports/cyber_shield.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- 2. CONFIGURATION ---
load_dotenv(".env")
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    logging.critical("VirusTotal API key not found in environment variables.")
    raise ValueError("Missing VirusTotal API Key. Check cyber_shield.log for details.")

class CTIWorkbench: 
    def __init__(self):
        """Initializes the engine, sets up directories, and loads whitelists."""
        logging.info("CyberShield-CTI Engine Initialized.")
        
        self.headers = {'Accept': 'application/json', 'x-apikey': VT_API_KEY}
        
        # Directory paths
        self.base_reports_dir = 'reports'
        self.malicious_dir = 'reports/Malicious_IOCs'
        self.clean_dir = 'reports/Clean_Artifacts'
        
        # 1. Create folders using the self-healing logic
        for folder in [self.base_reports_dir, self.malicious_dir, self.clean_dir]:
            if not os.path.exists(folder): 
                os.makedirs(folder)
                logging.info(f"Created directory: {folder}")

        # 2. Define the MITRE Map
        self.mitre_map = {
            "phishing": {"id": "T1566", "name": "Phishing"},
            "clickfix": {"id": "T1204.002", "name": "User Execution: Malicious File"},
            "win+r": {"id": "T1204", "name": "User Execution"},
            "net use": {"id": "T1135", "name": "Network Share Discovery"},
            "webdav": {"id": "T1133", "name": "External Remote Services"},
            "persistence": {"id": "T1098", "name": "Account Manipulation"},
            "c2": {"id": "T1071", "name": "Application Layer Protocol"},
            "asar injection": {"id": "T1546", "name": "Event Triggered Execution"},
            "lolbin": {"id": "T1218", "name": "System Binary Proxy Execution"},
            "fake captcha": {"id": "T1204.001", "name": "User Execution: Malicious Link"}
        }
                
        # 3. Load local text files
        self.ip_whitelist = self._load_file('whitelist.txt')
        self.manual_blocklist = self._load_file('blocklist.txt')
        self.domain_whitelist = ['google.com', 'microsoft.com', 'github.com', 'acronis.com', 'atos.net', 'huntress.com', 'virustotal.com', 'twitter.com', 'linkedin.com', 'any.run']

    def _ensure_dir(self, file_path):
        """Creates the parent directory for any file if it's missing."""
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Created missing directory: {directory}")

    def _load_file(self, filename):
        """Self-healing file loader."""
        if os.path.exists(filename):
            with open(filename, 'r', encoding="utf-8") as f:
                return [line.strip().lower() for line in f if line.strip()]
        else:
            with open(filename, 'w', encoding="utf-8") as f:
                f.write(f"# CyberShield-CTI: {filename} database\n")
            logging.info(f"Initialized missing file: {filename}")
            return []

    def _get_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # to filter out false positives and trigger re-analysis for low-score IOCs, improving accuracy.
    # This function queries the VirusTotal API for the given IOC and returns the number of malicious hits along with a status message.
    def get_vt_data(self, ioc_type, ioc_value):
        val = ioc_value.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http")
        endpoints = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
        resource_id = self._get_url_id(val) if ioc_type == "url" else val
        api_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}"
        
        try:
            time.sleep(15) 
            res = requests.get(api_url, headers=self.headers, timeout=10)
            malicious = 0
            # If the initial lookup returns 200, check the number of malicious hits. If it's 5 or fewer, trigger a re-analysis to check for updates, as some IOCs may be newly added or previously undetected.
            if res.status_code == 200:
                malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            # If the IOC has 5 or fewer malicious hits, trigger a re-analysis to check for updates, as some IOCs may be newly added or previously undetected.
            if malicious <= 5:
                logging.info(f"Triggering Re-analysis for {ioc_value}(Score: {malicious})")
                try:
                    rescan_url = f"{api_url}/analyse"
                    requests.post(rescan_url, headers=self.headers, timeout=5)# Trigger re-analysis
                    time.sleep(10) # Wait for re-analysis to complete
                    res = requests.get(api_url, headers=self.headers, timeout=5)# Re-fetch results after re-analysis
                    if res.status_code == 200:# Re-fetch results after re-analysis
                        malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                        return malicious, f"{malicious} hits (Re-analyzed)"
                except Exception as e:
                    logging.error(f"Re-analysis failed: {str(e)}")
            return malicious, f"{malicious} hits"
        except Exception as e:
            logging.error(f"Network error: {str(e)}")
            return 0, "Lookup Error"

    # The get_summary function uses the LSA summarization algorithm from the sumy library to generate a concise summary of the input text. It processes the text, extracts key sentences, and formats the summary for better readability.
    def get_summary(self, text):
        parser = PlaintextParser.from_string(' '.join(text.split()), Tokenizer("english"))
        summarizer = LsaSummarizer()
        summary = summarizer(parser.document, 3) 
        return textwrap.fill(" ".join([str(s) for s in summary]), width=80)

    # The extract_context function analyzes the input text to identify relevant MITRE ATT&CK techniques based on predefined keywords. It also attempts to extract the name of the victim organization from the text using regular expressions. The function returns a dictionary containing the detected TTPs and the identified victim.
    def extract_context(self, text):
        text_lower = text.lower()
        found_ttps = []
        for keyword, info in self.mitre_map.items():
            if keyword in text_lower:
                entry = f"{info['id']} ({info['name']})"
                if entry not in found_ttps:
                    found_ttps.append(entry)

        victim_match = re.search(r'([A-Z][\w\s]+) (?:targeted|attacked|victim|breached|researchers)', text)
        return {
            "ttps": ", ".join(found_ttps) if found_ttps else "T1204 (User Execution)",
            "victim": victim_match.group(1).strip() if victim_match else "Unspecified"
        }

    # The generate_report function orchestrates the entire process of analyzing a given URL. It scrapes the webpage, extracts relevant IOCs, checks them against VirusTotal, and compiles a comprehensive report. The report includes detected TTPs, a summary of the page content, and categorized lists of malicious IOCs. The function also handles file management for storing reports and blocklists.
    def generate_report(self, url):
        logging.info(f"Starting analysis for: {url}")
        try:
            res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = soup.get_text(separator=' ')
            context = self.extract_context(page_text)
            
#-----------------------------------------------------------------------------------------
            # Extraction logic
            # 1. Matches exactly 12 digits followed by a word boundary (no dot/char)
# 2. OR matches the 4-part IP structure with defanged separators
            found_ips = sorted(list(set(re.findall(r'\b(?:\d{12}|(?:\d{1,3}(?:\[\.\]|\.|\(\.\))){3}\d{1,3})\b', page_text))))
            raw_hashes = sorted(list(set(iocextract.extract_hashes(page_text))))
            ignored_ext = ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg', '.get']
            all_domains = sorted(list(set([d.lower() for d in re.findall(r'(?:com|org|net)s?\'[a-zA-Z0-9\-]+(?:\[\.\]|\.|\(\.\))[a-z]{2,}', page_text) 
                              if not any(ext in d.lower() for ext in ignored_ext)])))
            #  Updated RegEx to exclude common file extensions and focus on domain-like patterns
            
            # Updated RegEx to catch steamcommunity[.]com/profiles/12345...
            found_urls = sorted(list(set(re.findall(r'(?:http|hxxp)s?(?:\[\:\/\/\]|\:\/\/)[a-zA-Z0-9\-\.\[\]]+(?:(?:\/|\%2F)[\w\.\-\/\=\?\&\%\+\[\]]+)?', page_text))))

#-----------------------------------------------------------------------------------------

            mal_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
            full_list = []

            # The process_ioc function is a helper function defined within generate_report to avoid code duplication when processing different types of IOCs (IPs, domains, URLs, and file hashes). It takes a list of IOCs, their type, and category as input, performs cleaning and normalization, checks against whitelists and blocklists, queries VirusTotal for reputation data, and categorizes the results accordingly. This modular approach enhances code readability and maintainability while ensuring consistent processing across all IOC types.
            def process_ioc(ioc_list, ioc_type, cat):
                for ioc in ioc_list:
                    print(f"[*] Checking for {cat}: {ioc[:30]}...")

                    # The cleaning step normalizes the IOC by replacing common obfuscation patterns (like [.] or hxxp) with their standard forms. 
                    # This helps in accurately checking against whitelists and blocklists, as well as querying VirusTotal. By converting to lowercase, 
                    # it also ensures that the checks are case-insensitive, which is important for consistency.

                    clean_val = ioc.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http").lower()# This line  process_ioc does the "Refanging"
                    if any(w in clean_val for w in self.ip_whitelist + self.domain_whitelist):
                        continue
                    is_block = clean_val in self.manual_blocklist
                    hits, status = (1, "[!] BLOCKLIST MATCH") if is_block else self.get_vt_data(ioc_type, ioc)

                    # It acts as the final judge, deciding whether an Indicator of Compromise (IOC) is dangerous enough to be included in your Malicious_IOCs report.
                    # It uses OR logic, meaning if any one of these three conditions is true, the item is marked as a threat.
                    if hits > 0 or "\\\\" in ioc or "hxxp" in ioc.lower() or "[.]" in ioc:
                        entry = f"{cat}: {ioc.ljust(45)} | {status}"
                        full_list.append(entry)
                        mal_data[cat].append(entry)

            process_ioc(found_ips, 'ip', 'IPs')
            process_ioc(all_domains, 'domain', 'Domain')
            process_ioc(found_urls, 'url', 'URL')
            process_ioc(raw_hashes, 'hash', 'File_Hash')

            # --- EXPORT TO TEXT FILES --- 
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = f"{self.base_reports_dir}/FULL_ADVISORY_{ts}.txt"
            self._ensure_dir(report_path)

            with open(report_path, "w", encoding="utf-8") as f:
                f.write("=" *50 + "\nReport:\n" + "=" *50 + f"\n")
                f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"SOURCE URL       : {url}\n")
                f.write(f"TARGET COMPANY   : {context['victim']}\n\n")
                f.write("=" *50 + "\nMITRE ATT&CK ANALYSIS:\n" + "=" *50 + f"\nDetected TTPs    : {context['ttps']}\n\n")
                f.write(f"SUMMARY: {self.get_summary(page_text)}\n\n")
                f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} Found):\n" + "\n".join(full_list))

            if full_list:
                blocklist_path = f"{self.malicious_dir}/URGENT_BLOCKLIST_{ts}.txt"
                self._ensure_dir(blocklist_path)
                with open(blocklist_path, "w", encoding="utf-8") as f:
                    for cat, items in mal_data.items():
                        if items: 
                            f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")

            logging.info(f"Success: Report generated at {report_path}")
            return report_path

        except Exception as e:
            logging.critical(f"FATAL ERROR in generate_report: {str(e)}")
            return None

if __name__ == "__main__":
    tool = CTIWorkbench()
    target = input("Paste TI URL: ")
    result = tool.generate_report(target)
    if result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")