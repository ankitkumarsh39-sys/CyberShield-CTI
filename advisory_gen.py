import requests
import re
import iocextract
import os
import time
import textwrap
import base64
import warnings
from bs4 import BeautifulSoup
from datetime import datetime
from dotenv import load_dotenv

# Summarization libraries
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

warnings.filterwarnings("ignore", category=UserWarning)

# --- CONFIGURATION ---
# This looks for the .env file in the same folder
load_dotenv("key.env")

# Securely fetch the key
VT_API_KEY = os.getenv("VT_API_KEY")

class CTIWorkbench:
    def __init__(self):
        self.headers = {'Accept': 'application/json', 'x-apikey': VT_API_KEY}
        
        # Directory setup
        self.base_reports_dir = 'reports'
        self.malicious_dir = 'reports/Malicious_IOCs'
        self.clean_dir = 'reports/Clean_Artifacts'
        
        for folder in [self.base_reports_dir, self.malicious_dir, self.clean_dir]:
            if not os.path.exists(folder): os.makedirs(folder)
                
        # Load Whitelist and Blocklist
        self.ip_whitelist = self._load_file('whitelist.txt')
        self.manual_blocklist = self._load_file('blocklist.txt')
        self.domain_whitelist = ['google.com', 'microsoft.com', 'github.com', 'acronis.com', 'atos.net']

        # Keywords for Full Advisory Context
        self.attack_vectors = ["Phishing", "ClickFix", "Net Use", "WebDAV", "Fake CAPTCHA", "Win+R"]
        self.techniques = ["Persistence", "C2 Beacon", "ASAR Injection", "Proxy Execution", "LOLBin"]

    def _load_file(self, filename):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        else:
            with open(filename, 'w') as f: pass
            return []

    def _get_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_vt_data(self, ioc_type, ioc_value):
        val = ioc_value.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http")
        endpoints = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
        
        resource_id = self._get_url_id(val) if ioc_type == "url" else val
        api_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}"
        
        try:
            time.sleep(15) 
            res = requests.get(api_url, headers=self.headers, timeout=10)
            
            malicious = 0
            if res.status_code == 200:
                malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            
            # RE-ANALYSIS LOGIC (Score <= 3)
            if malicious <= 5:
                print(f"[*] Score {malicious} low for {ioc_value}. Attempting Re-analysis...")
                try:
                    rescan_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}/analyse"
                    rescan_req = requests.post(rescan_url, headers=self.headers, timeout=10)
                    
                    if rescan_req.status_code == 200:
                        time.sleep(20) 
                        res = requests.get(api_url, headers=self.headers, timeout=10)
                        if res.status_code == 200:
                            malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                            return malicious, f"{malicious} hits (Re-analyzed)"
                except:
                    return malicious, f"{malicious} hits (Skipped Re-analysis: Manual Check Req)"

            return malicious, f"{malicious} hits"
        except:
            return 0, "Lookup Error (Manual Review Req)"
    
    # --- SUMMARIZATION ---
    def get_summary(self, text):
        parser = PlaintextParser.from_string(' '.join(text.split()), Tokenizer("english"))
        summarizer = LsaSummarizer()
        summary = summarizer(parser.document, 3) 
        return textwrap.fill(" ".join([str(s) for s in summary]), width=80)
    
    # --- FULL CONTEXT EXTRACTION ---
    def extract_context(self, text):
        found_vectors = [v for v in self.attack_vectors if v.lower() in text.lower()]
        found_techs = [t for t in self.techniques if t.lower() in text.lower()]
        victim_match = re.search(r'([A-Z][\w\s]+) (?:targeted|attacked|victim|breached|researchers)', text)
        return {
            "vectors": ", ".join(found_vectors) if found_vectors else "Social Engineering",
            "techniques": ", ".join(found_techs) if found_techs else "Unknown",
            "victim": victim_match.group(1).strip() if victim_match else "Unspecified"
        }

    # --- MAIN REPORT GENERATION ---

    def generate_report(self, url):
        print(f"[*] Analyzing: {url}")
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        page_text = soup.get_text(separator=' ')
        context = self.extract_context(page_text)
        
        # --- DEDUPLICATED EXTRACTION ---
        found_ips = sorted(list(set(re.findall(r'\b(?:\d{1,3}(?:\[\.\]|\.|\(\.\))){3}\d{1,3}\b', page_text))))
        raw_hashes = sorted(list(set(iocextract.extract_hashes(page_text))))
        
        all_domains = sorted(list(set([d.lower() for d in re.findall(r'[a-zA-Z0-9\-]+(?:\[\.\]|\.|\(\.\))[a-z]{2,}', page_text) 
                      if not any(ext in d.lower() for ext in ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg'])])))
        
        # URLs can be tricky due to obfuscation, so we use a more comprehensive regex
        found_urls = sorted(list(set(re.findall(r'(?:http|hxxp)(?:\[\:\/\/\]|\:\/\/)[^\s<>"]+|\\\\(?:[\w\.\-]+)\\[\w\.\-\\]+', page_text))))

        mal_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
        full_list = []

        # Helper for processing
        def process_ioc(ioc_list, ioc_type, cat):
            for ioc in ioc_list:
                clean_val = ioc.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http").lower()
                
                # Check Whitelist
                if any(w in clean_val for w in self.ip_whitelist + self.domain_whitelist): continue
                
                # Check Blocklist or VT
                is_block = clean_val in self.manual_blocklist
                hits, status = (1, "[!] BLOCKLIST MATCH") if is_block else self.get_vt_data(ioc_type, ioc)
                
                # FILTER: Only add if score > 0 or it's a known malicious format (WebDAV/hxxp)
                if hits > 0 or "\\\\" in ioc or "hxxp" in ioc.lower():
                    entry = f"{cat}: {ioc.ljust(45)} | {status}"
                    full_list.append(entry)
                    mal_data[cat].append(entry)

        process_ioc(found_ips, 'ip', 'IPs')
        process_ioc(all_domains, 'domain', 'Domain')
        process_ioc(found_urls, 'url', 'URL')
        process_ioc(raw_hashes, 'hash', 'File_Hash')

        # --- EXPORT --- 
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        now_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        report_path = f"{self.base_reports_dir}/FULL_ADVISORY_{ts}.txt"
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("============================================================\n")
            f.write("THREAT INTELLIGENCE ADVISORY\n")
            f.write("============================================================\n")
            f.write(f"REPORT DATE      : {now_dt}\n")
            f.write(f"SOURCE URL       : {url}\n")
            f.write(f"TARGET COMPANY   : {context['victim']}\n")
            f.write("============================================================\n\n")
            f.write(f"SUMMARY: {self.get_summary(page_text)}\n\n")
            f.write(f"VECTORS: {context['vectors']}\nTECHNIQUES: {context['techniques']}\n")
            f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} Found):\n" + "\n".join(full_list))

        if full_list:
            with open(f"{self.malicious_dir}/URGENT_BLOCKLIST_{ts}.txt", "w", encoding="utf-8") as f:
                for cat, items in mal_data.items():
                    if items: f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")

        return report_path

if __name__ == "__main__":
    tool = CTIWorkbench()
    target = input("Paste TI URL: ")
    print(f"\n[+] Success: {tool.generate_report(target)}")