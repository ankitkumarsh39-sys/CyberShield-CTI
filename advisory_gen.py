import requests          # For making HTTP requests to VirusTotal and Threat Intel blogs
import re                # For Regular Expression matching (finding defanged IPs and URLs)
import iocextract        # A specialized library for extracting MD5, SHA1, and SHA256 hashes
import os                # For interacting with the Operating System (creating folders/loading files)
import time              # For managing API rate limits (pausing between VirusTotal requests)
import textwrap          # For formatting the final report text to a specific width (readability)
import base64            # To encode URLs into the ID format required by VirusTotal v3 API
import warnings          # To silence unnecessary logs from BeautifulSoup or Requests
import logging           # NEW: For creating a professional 'cyber_shield.log' audit trail
from bs4 import BeautifulSoup    # For parsing HTML and extracting clean text from web pages
from datetime import datetime    # For adding timestamps to report filenames and logs
from dotenv import load_dotenv   # To load the VT_API_KEY from a hidden .env file (Security)

# --- Summarization libraries (NLP - Natural Language Processing) ---
from sumy.parsers.plaintext import PlaintextParser  # Converts raw text into a format the AI can read
from sumy.nlp.tokenizers import Tokenizer                     # Breaks text down into individual words/sentences
from sumy.summarizers.lsa import LsaSummarizer      # Uses Latent Semantic Analysis to pick the top 3 sentences

# Suppress BeautifulSoup warnings to keep the terminal clean
warnings.filterwarnings("ignore", category=UserWarning)

# --- 1. LOGGING CONFIGURATION ---
# Configures the log file to record timestamps, severity levels, and messages
logging.basicConfig(
    filename='reports/cyber_shield.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- 2. CONFIGURATION ---
# Load the .env file containing the VT_API_KEY
load_dotenv(".env")

# Securely fetch the API key from environment variables
VT_API_KEY = os.getenv("VT_API_KEY")

# Check if the API key is available, if not log a critical error and exit
if not VT_API_KEY:
    logging.critical("VirusTotal API key not found in environment variables. Please set VT_API_KEY in .env.")
    raise ValueError("Missing VirusTotal API Key. Check cyber_shield.log for details.")

# The main class that encapsulates all the functionality of the CyberShield-CTI Engine
class CTIWorkbench: 
    def __init__(self):
        """Initializes the engine, sets up directories, and loads whitelists."""
        logging.info("CyberShield-CTI Engine Initialized.")
        
        # Define API headers (x-apikey is required for VirusTotal v3)
        self.headers = {'Accept': 'application/json', 'x-apikey': VT_API_KEY}
        
        # Directory paths for organized report storage
        self.base_reports_dir = 'reports'
        self.malicious_dir = 'reports/Malicious_IOCs'
        self.clean_dir = 'reports/Clean_Artifacts'
        
        # Create folders if they don't exist
        for folder in [self.base_reports_dir, self.malicious_dir, self.clean_dir]:
            if not os.path.exists(folder): 
                os.makedirs(folder)
                logging.info(f"Created directory: {folder}")
                
        # Load local text files into lists for filtering
        self.ip_whitelist = self._load_file('whitelist.txt')
        self.manual_blocklist = self._load_file('blocklist.txt')
        
        # Hardcoded trusted domains to avoid "False Positives" on common sites
        self.domain_whitelist = ['google.com', 'microsoft.com', 'github.com', 'acronis.com', 'atos.net', 'huntress.com']

        # Industry keywords used to identify the "How" of an attack (MITRE-like context)
        self.attack_vectors = ["Phishing", "ClickFix", "Net Use", "WebDAV", "Fake CAPTCHA", "Win+R"]
        self.techniques = ["Persistence", "C2 Beacon", "ASAR Injection", "Proxy Execution", "LOLBin"]

    def _load_file(self, filename):
        """Checks if a file exists, reads it, or creates it if missing."""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        else:
            with open(filename, 'w') as f: pass # Create empty file
            logging.info(f"Initialized empty local file: {filename}")
            return []

    def _get_url_id(self, url):
        """VirusTotal v3 requires URLs to be base64 encoded without '=' padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def get_vt_data(self, ioc_type, ioc_value):
        """Queries VirusTotal API and triggers re-analysis for low-score hits."""
        # Standardize the IOC format (Refanging)
        val = ioc_value.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http")
        endpoints = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
        
        # Determine the correct API endpoint and ID
        resource_id = self._get_url_id(val) if ioc_type == "url" else val
        api_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}"
        
        try:
            time.sleep(15) # Stay within Free Tier rate limits (4 reqs/min)
            res = requests.get(api_url, headers=self.headers, timeout=10)
            
            malicious = 0
            if res.status_code == 200:
                malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            
            # RE-ANALYSIS LOGIC: If score is low, force a new scan to get fresh Intel
            if malicious <= 5:
                logging.info(f"Triggering Re-analysis for {ioc_value} (Score: {malicious})")
                try:
                    rescan_url = f"{api_url}/analyse"
                    rescan_req = requests.post(rescan_url, headers=self.headers, timeout=10)
                    
                    if rescan_req.status_code == 200:
                        time.sleep(20) # Wait for the scan engines to finish
                        res = requests.get(api_url, headers=self.headers, timeout=10)
                        if res.status_code == 200:
                            malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                            return malicious, f"{malicious} hits (Re-analyzed)"
                except Exception as e:
                    logging.error(f"Re-analysis failed for {ioc_value}: {str(e)}")
                    return malicious, f"{malicious} hits (Skipped Re-analysis)"

            return malicious, f"{malicious} hits"
        except Exception as e:
            logging.error(f"Network error during VT lookup for {ioc_value}: {str(e)}")
            return 0, "Lookup Error (Manual Review Req)"

    def get_summary(self, text):
        """Uses NLP to generate a 3-sentence summary of the threat blog."""
        parser = PlaintextParser.from_string(' '.join(text.split()), Tokenizer("english"))
        summarizer = LsaSummarizer()
        summary = summarizer(parser.document, 3) 
        return textwrap.fill(" ".join([str(s) for s in summary]), width=80)

    def extract_context(self, text):
        """Scans the text for specific attack vectors, techniques, and victims."""
        found_vectors = [v for v in self.attack_vectors if v.lower() in text.lower()]
        found_techs = [t for t in self.techniques if t.lower() in text.lower()]
        # Regex to find potential victim company names based on context
        victim_match = re.search(r'([A-Z][\w\s]+) (?:targeted|attacked|victim|breached|researchers)', text)
        return {
            "vectors": ", ".join(found_vectors) if found_vectors else "Social Engineering",
            "techniques": ", ".join(found_techs) if found_techs else "Unknown",
            "victim": victim_match.group(1).strip() if victim_match else "Unspecified"
        }

    def generate_report(self, url):
        """Main pipeline: Scrape -> Extract -> Enrich -> Report."""
        logging.info(f"Starting analysis for target URL: {url}")
        try:
            # Download the webpage content
            res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = soup.get_text(separator=' ') # Get clean text from HTML
            context = self.extract_context(page_text)
            
            # --- DEDUPLICATED EXTRACTION ---
            # Extract IPs using RegEx that supports defanging [.]
            found_ips = sorted(list(set(re.findall(r'\b(?:\d{1,3}(?:\[\.\]|\.|\(\.\))){3}\d{1,3}\b', page_text))))
            # Extract MD5/SHA hashes using the iocextract library
            raw_hashes = sorted(list(set(iocextract.extract_hashes(page_text))))
            
            # Asset Filtering: Ignore common website files to save API quota
            ignored_ext = ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg']
            all_domains = sorted(list(set([d.lower() for d in re.findall(r'[a-zA-Z0-9\-]+(?:\[\.\]|\.|\(\.\))[a-z]{2,}', page_text) 
                              if not any(ext in d.lower() for ext in ignored_ext)])))
            
            # Extract URLs and UNC paths (\\\\server\\share)
            found_urls = sorted(list(set(re.findall(r'(?:http|hxxp)(?:\[\:\/\/\]|\:\/\/)[^\s<>"]+|\\\\(?:[\w\.\-]+)\\[\w\.\-\\]+', page_text))))

            mal_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
            full_list = []

            def process_ioc(ioc_list, ioc_type, cat):
                """Helper function to loop through IOCs and perform lookups."""
                for ioc in ioc_list:
                    print(f"[*] Processing {cat}: {ioc[:30]}...") # Progress feedback
                    clean_val = ioc.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http").lower()
                    
                    # Silently skip items found in whitelists
                    if any(w in clean_val for w in self.ip_whitelist + self.domain_whitelist):
                        logging.info(f"Skipping whitelisted IOC: {ioc}")
                        continue
                    
                    # Check if manually blocked or malicious on VT
                    is_block = clean_val in self.manual_blocklist
                    hits, status = (1, "[!] BLOCKLIST MATCH") if is_block else self.get_vt_data(ioc_type, ioc)
                    
                    # FILTER: Keep if VT flagged OR if it has suspicious formats like hxxp/UNC
                    if hits > 0 or "\\\\" in ioc or "hxxp" in ioc.lower():
                        entry = f"{cat}: {ioc.ljust(45)} | {status}"
                        full_list.append(entry)
                        mal_data[cat].append(entry)

            # Run the processing for each category
            process_ioc(found_ips, 'ip', 'IPs')
            process_ioc(all_domains, 'domain', 'Domain')
            process_ioc(found_urls, 'url', 'URL')
            process_ioc(raw_hashes, 'hash', 'File_Hash')

            # --- EXPORT TO TEXT FILES --- 
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = f"{self.base_reports_dir}/FULL_ADVISORY_{ts}.txt"
            
            # Generate the human-readable Full Advisory
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"SOURCE URL       : {url}\n")
                f.write(f"TARGET COMPANY   : {context['victim']}\n\n")
                f.write("=" *50 + "\nTHREAT SUMMARY:\n\n" + "=" *50 + f"\nAttack Vectors   : {context['vectors']}\n\nTechniques Used  : {context['techniques']}\n\n")
                f.write(f"SUMMARY: {self.get_summary(page_text)}\n\n")
                f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} Found):\n" + "\n".join(full_list))

            # Generate the machine-readable Urgent Blocklist
            if full_list:
                with open(f"{self.malicious_dir}/URGENT_BLOCKLIST_{ts}.txt", "w", encoding="utf-8") as f:
                    for cat, items in mal_data.items():
                        if items: f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")

            logging.info(f"Success: Report generated at {report_path}")
            return report_path

        except Exception as e:
            # Logs critical errors like No Internet or Website down
            logging.critical(f"FATAL ERROR in generate_report: {str(e)}")
            return None

if __name__ == "__main__":
    # Entry point for the application
    tool = CTIWorkbench()
    target = input("Paste TI URL: ")
    result = tool.generate_report(target)
    if result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")