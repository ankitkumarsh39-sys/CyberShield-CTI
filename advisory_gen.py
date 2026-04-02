import sys               # For handling command-line arguments (if needed in the future)
import subprocess        # For potential future use (e.g., running external tools or scripts)
from nltk import text    # For potential future use in more advanced NLP tasks (currently using sumy for summarization)
import requests          # For making HTTP requests to VirusTotal and Threat Intel blogs
import re                # For Regular Expression matching (finding defanged IPs and URLs)
import iocextract        # A specialized library for extracting MD5, SHA1, and SHA256 hashes
import os                # For interacting with the Operating System (creating folders/loading files)
import time              # For managing API rate limits (pausing between VirusTotal requests)
import textwrap          # For formatting the final report text to a specific width (readability)
import base64            # To encode URLs into the ID format required by VirusTotal v3 API
import warnings          # To silence unnecessary logs from BeautifulSoup or Requests
import logging           # For creating a professional 'cyber_shield.log' audit trail
from bs4 import BeautifulSoup    # For parsing HTML and extracting clean text from web pages
from datetime import datetime    # For adding timestamps to report filenames and logs
from dotenv import load_dotenv   # To load the VT_API_KEY from a hidden .env file (Security)

# --- Summarization libraries (NLP - Natural Language Processing) ---
from sumy.parsers.plaintext import PlaintextParser  # Converts raw text into a format the AI can read
from sumy.nlp.tokenizers import Tokenizer           # Breaks text down into individual words/sentences
from sumy.summarizers.text_rank import TextRankSummarizer  # Uses TextRank to surface the most important statements

# Suppress BeautifulSoup warnings to keep the terminal clean
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
    # The __init__ method is the constructor for the CTIWorkbench class. 
    # It initializes the engine by setting up necessary directories for reports, loading whitelists and blocklists from local text files, and defining expanded MITRE ATT&CK detection rules for behavior-based inference. 
    # This setup ensures that the engine is ready to process threat intelligence data effectively while maintaining a structured environment for storing outputs and logs.
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

        # Expanded MITRE detection rules support behavior-based inference from article text.
        # Each rule is a behavior pattern mapped to one or more ATT&CK techniques.
        # - keywords: article phrases that trigger this rule
        # - techniques: list of MITRE techniques/sub-techniques with tactic, confidence, and rationale
        # - attack_type: a high-level attack category derived from the behavior
        self.mitre_rules = [
            {
                "keywords": ["phishing", "phish", "fake documentation portal", "fake portal", "fake login page", "credential harvesting", "spearphishing", "phishing lure", "fake captcha"],
                "techniques": [
                    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "confidence": "High", "reason": "Article text explicitly describes phishing lures, fake documentation portals, and credential-harvesting pages."},
                    {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Initial Access", "confidence": "Medium", "reason": "The fake portal and user-directed clicks imply a malicious link-based social engineering vector."}
                ],
                "attack_type": "Phishing"
            },
            {
                "keywords": ["browser credential", "browser passwords", "browser logins", "saved passwords", "credential theft from browsers", "chrome password", "firefox password", "browser data", "cookies and autofill"],
                "techniques": [
                    {"id": "T1555.001", "name": "Credentials from Web Browsers", "tactic": "Credential Access", "confidence": "High", "reason": "The article clearly describes browser password and autofill theft by the malware."},
                    {"id": "T1119", "name": "Automated Collection", "tactic": "Collection", "confidence": "Medium", "reason": "Stealer behavior automates the collection of stored browser credentials, cookies, and related artifacts."}
                ],
                "attack_type": "Credential Theft"
            },
            {
                "keywords": ["stealer", "infostealer", "macos stealer", "macos stealer malware", "credential stealer", "steal credentials"],
                "techniques": [
                    {"id": "T1119", "name": "Automated Collection", "tactic": "Collection", "confidence": "High", "reason": "The article refers to stealer malware that automatically collects user data and credentials."}
                ],
                "attack_type": "Stealer"
            },
            {
                "keywords": ["c2", "command-and-control", "command and control", "web panel", "c2 infrastructure", "control server", "beacon"],
                "techniques": [
                    {"id": "T1071.001", "name": "Application Layer Protocol", "tactic": "Command and Control", "confidence": "High", "reason": "The text mentions web-based C2 panels and command-and-control infrastructure over HTTP."}
                ],
                "attack_type": "Command and Control"
            },
            {
                "keywords": ["exfiltration", "data staging", "compression using ditto", "compress stolen data", "stage data", "upload stolen data"],
                "techniques": [
                    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "confidence": "Medium", "reason": "The article describes data staging, compression, and exfiltration via the attacker’s C2 channel."}
                ],
                "attack_type": "Data Exfiltration"
            },
            {
                "keywords": ["obfuscated", "defanged", "defanging", "stealth", "conceal", "hide", "evade detection"],
                "techniques": [
                    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "confidence": "Medium", "reason": "The text describes obfuscation and defanged indicators used to evade detection."}
                ],
                "attack_type": "Defense Evasion"
            }
        ]
                
        # 3. Load local text files
        self.ip_whitelist = self._load_file('whitelist.txt')
        self.manual_blocklist = self._load_file('blocklist.txt')
        self.domain_whitelist = ['google.com', 'microsoft.com', 'github.com', 'acronis.com', 'atos.net', 'huntress.com', 'virustotal.com', 'twitter.com', 'linkedin.com', 'any.run']
    
    # The _ensure_dir function is a utility method that checks if the parent directory of a given file path exists. If it doesn't, the function creates the necessary directory structure. 
    # This is particularly useful for ensuring that when the tool attempts to write reports or blocklists, it won't encounter errors due to missing directories.
    #  By implementing this self-healing mechanism, the tool can recover gracefully from situations where directories might have been accidentally deleted or were never created in the first place.

    def _ensure_dir(self, file_path):
        """Creates the parent directory for any file if it's missing."""
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Created missing directory: {directory}")

    # The _load_file function is designed to handle both the loading and initialization of critical text files (like whitelists and blocklists) in a self-healing manner. 
    # If the specified file exists, it reads the contents into a list while stripping whitespace and converting to lowercase for consistency. 
    # If the file is missing, it creates a new file with a header comment, logs this action, and returns an empty list.
    # This approach ensures that the tool can operate smoothly even if essential files are accidentally deleted or not set up initially.

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

    #  The _get_url_id function is a helper method that takes a URL as input and encodes it into a format suitable for querying the VirusTotal v3 API.
    #  Since the API requires URLs to be represented as a base64-encoded string, this function performs the necessary encoding and formatting to ensure that the URL can be correctly processed by the API when checking for malicious activity.
    def _get_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # to filter out false positives and trigger re-analysis for low-score IOCs, improving accuracy.
    # This function queries the VirusTotal API for the given IOC and returns the number of malicious hits along with a status message.
    def get_vt_data(self, ioc_type, ioc_value):

        def deobfuscate(ioc_value):
            val = ioc_value.strip()
        # Common defanging replacements
            replacements = {
                "[.]": ".",
                "(.)": ".",
                "{.}": ".",
                "[://]": "://",
                "hxxp://": "http://",
                "hxxps://": "https://",
                "hxxp": "http",
                "fxp": "ftp"
            }
            
            # If the value contains common defanging patterns, perform replacements; otherwise, return the original value

            for k, v in replacements.items():# This loop iterates through the defined replacements and applies them to the input value, effectively 
                #"refanging" any obfuscated IOCs back to their standard format for accurate processing.
                    val = val.replace(k, v)
            return val
        
        # The deobfuscate function is called to clean the IOC value by replacing common obfuscation patterns with their standard forms. 
        # This ensures that the IOC is in the correct format for querying VirusTotal and checking against whitelists and blocklists.
        val = deobfuscate(ioc_value)

        # --- Validate and Refang the IOC and type of IOC ---
        endpoints = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "url": "urls"
        }

        #--- Validate the IOC type against supported endpoints. If the type is not recognized, log an error and return a failure status.
        #  This check prevents unnecessary API calls with invalid types and ensures that the function only processes known IOC categories.
        if ioc_type not in endpoints:
            logging.error(f"Unsupported IOC type: {ioc_type}")
            return 0, f"Unsupported IOC Type: {ioc_type}"
        
        # For URLs, we need to convert them to the specific ID format required by the VirusTotal v3 API, which involves base64 encoding. 
        # For other IOC types, we can use the cleaned value directly.
        
        resource_id = self._get_url_id(val) if ioc_type == "url" else val
        api_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}"
        
        malicious = 0# Initial malicious count is set to 0, and will be updated based on the API response. This variable is crucial for determining whether to trigger a re-analysis for low-score IOCs.    
        logging.info(f"Querying VT for {ioc_type.upper()}: {val[:100]}...")# Log the query action with the type of IOC and a truncated version of the value for readability in the logs.")   

        try:

            # optional: small sleep to respect API rate limits, especially if processing many IOCs in a loop. Adjust the duration as needed based on VT's guidelines and your usage patterns.
            time.sleep(20) # Pause to respect API rate limits
            res = requests.get(api_url, headers=self.headers, timeout=10)

            # Rate limit handling: 
            # If we hit a rate limit (e.g., 429 Too Many Requests), we can log this event and return a specific status message.
            # If the initial lookup returns 200, check the number of malicious hits. If it's 3 or fewer, trigger a re-analysis to check for updates, as some IOCs may be newly added or previously undetected.
            if res.status_code == 429:
                logging.warning(f" VT Rate limit hit(429) for {ioc_type.upper()}: {val[:200]}... Waiting sleeping for 20 seconds before retrying.")
                time.sleep(20) # Wait before retrying
                res = requests.get(api_url, headers=self.headers, timeout=10) # Retry the API call after waiting

            # If the initial lookup returns 200, check the number of malicious hits
            if res.status_code == 200:

                try:
                    malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
    
                # return malicious count and status message. If the expected keys are not found in the response, log an error and return a failure status.
                except KeyError:
                    logging.error("Unexpected response format from VirusTotal API")
                    return 0, f" VT Lookup Failed (Status Code: {res.status_code}): {res.json()}"
        
            # If the IOC has 5 or fewer malicious hits, trigger a re-analysis to check for updates, as some IOCs may be newly added or previously undetected.
            if malicious <= 5: # Threshold for low-score IOCs that may benefit from re-analysis

                logging.info(f"Triggering Re-analysis for {ioc_type.upper()}: {val[:200]} (Score: {malicious})")
                try:
                    rescan_url = f"{api_url}/analyse"

                    # store post response and check it
                    post_res = requests.post(rescan_url, headers=self.headers, timeout=10)# Trigger re-analysis
                    
                    # Accept common successful response codes (200 OK, 202 Accepted) for the re-analysis request. 
                    # If the response indicates that the re-analysis was accepted, we can proceed to wait and then re-fetch the results. 
                    if post_res.status_code in (200, 201, 202):# Re-fetch results after re-analysis
                        time.sleep(20) # Wait for re-analysis to complete

                        res = requests.get(api_url, headers=self.headers, timeout=10)# Re-fetch results after re-analysis
                        
                        if res.status_code == 200:# Check results again after re-analysis
                            malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                            return malicious, f"{malicious} hits (Re-analyzed)"
                        
                        # if fatch failed after successfull POST
                        # if the re-fetch after re-analysis fails, log the error and return the original malicious count with a note that re-analysis was attempted but failed.
                        return malicious, f"{malicious} hits (Re-analysis attempted but failed): {res.status_code})"

                    #if re-analysis POST fails (e.g., due to network issues or API errors), log the error and return the original malicious count with a note that re-analysis was skipped.
                    return malicious, f"{malicious} hits (Re-analysis attempted but failed): {post_res.status_code})"
                
                except Exception as e:# if re_analysis failed logg the error
                    logging.error(f"Re-analysis error for {ioc_type.upper()} try manual analysis: {str(e)}")
                    return malicious, f"{malicious} hits (Re-analysis failed)"

        except Exception as e:
            logging.error(f"Network error during VT lookup for {ioc_type.upper()}: {str(e)}")
            return 0, "Lookup Error"
        return malicious, f"{malicious} hits"
                
    def vt_lookup_multiple(self, ioc_list, ioc_type, base_sleep=5, max_retries=3):
        results = []

        for i, ioc in enumerate(ioc_list, start=1):
            logging.info(f"[{i}/{len(ioc_list)}] VT starting Lookup for {ioc_type.upper()}: {str(ioc)[:200]}...")

            retries = 0
            while retries <= max_retries:
                score, msg = self.get_vt_data(ioc_type, ioc)

            # If your get_vt_data returns "Lookup Error" or indicates rate limit in msg,
            # retry with backoff. (If you already handle 429 inside get_vt_data, this becomes extra safety.)

                if "rate limit" in msg.lower() or "429" in msg:
                    wait_time = base_sleep * (2 ** retries)  # Exponential backoff
                    logging.warning(f"Rate limit hit for {ioc_type.upper()} Retrying in {retries+1}/{max_retries} after waiting {wait_time} seconds.")
                    time.sleep(wait_time)
                    retries += 1
                continue

            # succes and non-reate limit failed  -> break retry loop
            break
        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "score": score,
            "message": msg
        })

        # sleep between IOCs to avoid 429 
        time.sleep(base_sleep)
        return results

    # The get_summary function uses the TextRank summarization algorithm from the sumy library to generate a detailed, attack-focused summary.
    # It also prioritizes sentences that mention actors, targets, techniques, and campaign behavior.
    def get_summary(self, text):
        parser = PlaintextParser.from_string(' '.join(text.split()), Tokenizer("english"))
        summarizer = TextRankSummarizer()
        sentence_count = min(15, len(parser.document.sentences))
        if sentence_count == 0:
            return "No meaningful summary could be generated from the source text."

        ranked_summary = [str(s) for s in summarizer(parser.document, sentence_count)]
        keywords = [
            "attack", "campaign", "target", "targeted", "malware", "exploit", "threat actor",
            "actor", "payload", "c2", "command", "control", "ransom", "steal", "credential",
            "phishing", "infection", "vulnerability", "backdoor", "persistence"
        ]
        sentences = re.split(r'(?<=[\.\?\!])\s+', text)
        keyword_sentences = []
        for sent in sentences:
            lower_sent = sent.lower()
            if any(keyword in lower_sent for keyword in keywords):
                sent = sent.strip()
                if sent and sent not in keyword_sentences:
                    keyword_sentences.append(sent)
                    if len(keyword_sentences) >= sentence_count:
                        break

        combined = []
        for sent in ranked_summary + keyword_sentences:
            if sent not in combined:
                combined.append(sent)
                if len(combined) >= sentence_count:
                    break

        summary_text = " ".join(combined)
        return textwrap.fill(summary_text, width=80)

    # Added to improve summary quality by extracting relevant content from HTML pages.
    # This method removes non-content elements (scripts, styles, headers, etc.) and prioritizes article text for better summarization.
    def extract_page_content(self, soup):
        """Extracts better article content for summarization."""
        for tag in soup(["script", "style", "noscript", "header", "footer", "aside", "nav", "form", "svg"]):
            tag.decompose()

        content_parts = []
        if soup.title and soup.title.string:
            content_parts.append(soup.title.string)

        meta_desc = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
        if meta_desc and meta_desc.get("content"):
            content_parts.append(meta_desc.get("content"))

        for selector in ["article", "main", "section", "div", "p"]:
            for elem in soup.select(selector):
                text = elem.get_text(separator=' ', strip=True)
                if text and len(text.split()) > 8:
                    content_parts.append(text)

        if not content_parts:
            content_parts.append(soup.get_text(separator=' ', strip=True))

        combined = ' '.join(content_parts)
        return re.sub(r'\s+', ' ', combined)

    # The extract_context function analyzes the input text to identify relevant MITRE ATT&CK techniques based on predefined keywords. 
    # It also attempts to extract the name of the victim organization from the text using regular expressions. The function returns a dictionary containing the detected TTPs and the identified victim.
    def extract_context(self, text):
        """
        Analyze article text and return MITRE ATT&CK context.

        This function performs the following steps:
        1. Normalize the input text to lowercase for keyword matching.
        2. Iterate through each behavior rule in self.mitre_rules.
        3. If any rule keyword appears in the text, collect the rule's attack type,
           the mapped techniques, and the corresponding MITRE tactic.
        4. If no explicit rule matches, use a fallback for obvious phishing indicators.
        5. Extract any victim organizations mentioned with targeted/attacked language.
        6. Build a deduplicated list of detected TTPs and a set of attack types/tactics.
        7. Return a structured dictionary with all inferred MITRE context.
        """

        victims = []
        text_lower = text.lower()
        found_ttps = []
        found_details = []
        attack_types = set()
        tactics = set()

        for rule in self.mitre_rules:
            # If any rule keyword is present in the article, mark that behavior as seen.
            if any(keyword in text_lower for keyword in rule["keywords"]):
                if rule.get("attack_type"):
                    attack_types.add(rule["attack_type"])
                for tech in rule["techniques"]:
                    # Avoid duplicate technique entries by checking the technique ID.
                    if tech["id"] not in {d["id"] for d in found_details}:
                        found_details.append(tech)
                        tactics.add(tech["tactic"])

        # Fallback to a basic phishing detection if no rule matched but phishing-like text is present.
        if not found_details:
            if "phishing" in text_lower or "fake portal" in text_lower or "credential harvesting" in text_lower:
                found_details.append({
                    "id": "T1566",
                    "name": "Phishing",
                    "tactic": "Initial Access",
                    "confidence": "Medium",
                    "reason": "The article shows a phishing-style engagement even though explicit keywords were limited."
                })
                tactics.add("Initial Access")
                attack_types.add("Phishing")

        # Extract victim organizations from text using improved patterns that handle
        # various phrasing like "Company X was targeted", "victims include X", or "X breached".
        # This uses multiple regex patterns for better coverage and deduplicates results.
        victim_patterns = [
            re.compile(
                r'\b([A-Z][A-Za-z0-9&.,\- ]{2,60}?)\b\s+(?:was\s+)?'
                r'(?:targeted|attacked|breached|compromised|hacked|hit|affected|exploited|infected)',
                re.IGNORECASE
            ),
            re.compile(
                r'(?:victims?|targets?|affected)\s+(?:include|are|were|:\s*)\s*([A-Z][A-Za-z0-9&.,\- ]{2,60}?(?:,\s*[A-Z][A-Za-z0-9&.,\- ]{2,60}?)*)',
                re.IGNORECASE
            ),
            re.compile(
                r'\b([A-Z][A-Za-z0-9&.,\- ]{2,60}?)\b\s+(?:company|organization|firm|corp|inc|llc|group)\s+(?:was\s+)?'
                r'(?:targeted|attacked|breached|compromised|hacked)',
                re.IGNORECASE
            )
        ]
        
        victims_set = set()
        for pattern in victim_patterns:
            matches = pattern.findall(text)
            for match in matches:
                # Handle comma-separated lists in the second pattern
                if ',' in match:
                    sub_matches = [m.strip() for m in match.split(',') if m.strip()]
                    victims_set.update(sub_matches)
                else:
                    victims_set.add(match.strip())
        
        # Filter out common false positives (e.g., generic terms, short words)
        filtered_victims = [
            v for v in victims_set 
            if len(v) > 3 and not any(word in v.lower() for word in ['the', 'and', 'but', 'for', 'with', 'this', 'that', 'these', 'those'])
        ]
        
        victims = sorted(filtered_victims) if filtered_victims else ["Unspecified"]

        for detail in found_details:
            entry = f"{detail['id']} ({detail['name']})"
            if entry not in found_ttps:
                found_ttps.append(entry)

        if not found_ttps:
            # If nothing matches, default to the generic user execution technique,
            # because most articles still describe some form of execution-based compromise.
            found_ttps = ["T1204 (User Execution)"]
            attack_types.add("Unknown")
            tactics.add("Initial Access")

        # Format the technique details so the report can show confidence and reasoning.
        detail_lines = [
            f"- {d['id']} ({d['name']}) [{d['confidence']}]: {d['reason']}"
            for d in found_details
        ]

        return {
            "ttps": ", ".join(found_ttps),
            "victims": victims if victims else ["Unspecified"],
            "attack_types": ", ".join(sorted(attack_types)) if attack_types else "Unknown",
            "tactics": ", ".join(sorted(tactics)) if tactics else "Unknown",
            "mitre_details": detail_lines
        }

    # The generate_report function or   `chestrates the entire process of analyzing a given URL. It scrapes the webpage, extracts relevant IOCs, checks them against VirusTotal, and compiles a comprehensive report. 
    # The report includes detected TTPs, a summary of the page content, and categorized lists of malicious IOCs. The function also handles file management for storing reports and blocklists.
    def generate_report(self, url):
        logging.info(f"Starting analysis for: {url}")
        try:
            res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = soup.get_text(separator=' ')
            # Use extracted content for better summarization and context extraction (improved from raw page_text)
            content_for_summary = self.extract_page_content(soup)
            # Updated to use content_for_summary instead of raw page_text for more accurate TTP and victim detection
            context = self.extract_context(content_for_summary)
            
#----------------------------------------------------------------------------------------------------------------------------------------------------------
            # Extraction logic
            # 1. Matches exactly 12 digits followed by a word boundary (no dot/char)
            # 2. OR matches the 4-part IP structure with defanged separators
            found_ips = sorted(list(set(re.findall(r'\b(?:\d{12}|(?:\d{1,3}(?:\[\.\]|\.|\(\.\))){3}\d{1,3})\b', page_text))))
            def normalize_ip(ip):# This function takes an IP address that may be defanged (e.g., using [.] or (.) instead of .) and normalizes it back to the standard format.
                ip = ip.replace("[.]", ".").replace("(.)", ".")# By replacing common defanging patterns with a standard dot, this function ensures that all IP addresses are in a consistent format for further processing and analysis.
                return ip
            found_ips = sorted(set(normalize_ip(ip) for ip in found_ips))# This line applies the normalize_ip function to each found IP address, ensuring that all IPs are in a consistent format. The sorted and set functions are used to remove duplicates and maintain an ordered list of unique IP addresses.

            raw_hashes = sorted(list(set(iocextract.extract_hashes(page_text))))

             # To reduce false positives, we exclude common file extensions that are unlikely to be domains. 
             # This helps focus the domain extraction on more relevant patterns, improving the accuracy of the report.
            ignored_ext = ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg', '.get']

            all_domains = sorted(
                set(
                    d.lower()
                    for d in re.findall(
                        r'\b[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.)(?:[a-z]{2,})(?:\/[^\s]*)?\b',
                        page_text,
                        re.IGNORECASE
                    )
                    if not any(ext in d.lower() for ext in ignored_ext)
                )
            )

            # Updated RegEx to exclude common file extensions and focus on domain-like patterns
            # Updated RegEx to catch steamcommunity[.]com/profiles/12345...
            found_urls = sorted(list(set(re.findall(r'(?:http|hxxp)s?(?:\[\:\/\/\]|\:\/\/)[a-zA-Z0-9\-\.\[\]]+(?:(?:\/|\%2F)[\w\.\-\/\=\?\&\%\+\[\]]+)?', page_text))))
            
            raw_cves = re.findall(
                r'\bCVE[\s\-_–—]?(\d{4})[\s\-_–—]?(\d{4,7})\b',
                page_text,
                re.IGNORECASE
                )
            found_cves = sorted(list(set(f"CVE-{y}-{n}".upper() for y, n in raw_cves)))
            logging.info(f"Extracted counts of IOCs-> IPs: {len(found_ips)}, Domains: {len(all_domains)}, URLs: {len(found_urls)}, Hashes: {len(raw_hashes)}, CVE: {len(found_cves)}")
            
#-----------------------------------------------------------------------------------------------------------------------------------------------------------

            mal_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
            full_list = []

            # The process_ioc function is a helper function defined within generate_report to avoid code duplication when processing different types of IOCs (IPs, domains, URLs, and file hashes). 
            # It takes a list of IOCs, their type, and category as input, performs cleaning and normalization, checks against whitelists and blocklists, queries VirusTotal for reputation data, 
            # and categorizes the results accordingly. This modular approach enhances code readability and maintainability while ensuring consistent processing across all IOC types.
            def process_ioc(ioc_list, ioc_type, cat):
                for ioc in ioc_list:
                    print(f"[*] Checking for {cat}: {ioc[:80]}...")

                    # The cleaning step normalizes the IOC by replacing common obfuscation patterns (like [.] or hxxp) with their standard forms. 
                    # This helps in accurately checking against whitelists and blocklists, as well as querying VirusTotal. By converting to lowercase, 
                    # it also ensures that the checks are case-insensitive, which is important for consistency.
                    clean_val = ioc.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://").replace("hxxp", "http").lower()# This line process_ioc does the "Refanging"
                    if any(w in clean_val for w in self.ip_whitelist + self.domain_whitelist):
                        continue
                    is_block = clean_val in self.manual_blocklist

                    logging.info(f"Processing {ioc_type.upper()} IOC: raw={ioc[:80]} Malicious_IOC={clean_val[:80]}")
                    # The vt_result variable is assigned a tuple based on whether the IOC is found in the manual blocklist. 
                    # If it is a blocklisted item, it is immediately categorized as a threat with a message indicating a blocklist match.
                    
                    vt_result = (1, "[!] BLOCKLIST MATCH") if is_block else self.get_vt_data(ioc_type, ioc)
                    if not vt_result:
                        vt_result = (0, "VT returned None (check get_vt_data returns)")
                    hits, status = vt_result

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

#----------------------------------------------------------------------------------------------------------------------------------------------

            # --- EXPORT TO TEXT FILES ---
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = f"{self.base_reports_dir}/ADVISORY_{ts}.txt"
            self._ensure_dir(report_path)

            with open(report_path, "w", encoding="utf-8") as f:
                f.write("=" *50 + "\nReport:\n" + "=" *50 + f"\n")
                f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"SOURCE URL       : {url}\n")
                f.write(f"TARGET COMPANY   : {', '.join(context['victims'])}\n\n")
                # Write the MITRE ATT&CK section with all inferred context:
                # - Detected TTPs: concatenated technique IDs and names
                # - Attack Type: high-level behavior classification
                # - MITRE Tactic(s): inferred stage(s) of the attack lifecycle
                f.write("=" *50 + "\nMITRE ATT&CK ANALYSIS:\n" + "=" *50 + f"\nDetected TTPs: {context['ttps']}\n")
                f.write(f"Attack Type      : {context.get('attack_types', 'Unknown')}\n")
                f.write(f"MITRE Tactic(s)  : {context.get('tactics', 'Unknown')}\n\n")
                if context.get('mitre_details'):
                    # Add per-technique confidence and reasoning.
                    f.write("Technique findings:\n")
                    f.write("\n".join(context['mitre_details']) + "\n\n")
                # Updated to use content_for_summary for better summary quality (improved from raw page_text)
                f.write("SUMMARY:\n")
                f.write(self.get_summary(content_for_summary) + "\n\n")
                f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} IOC_Found):\n\n" + "\n".join(full_list) + "\n\n")
                f.write("=" * 50 + "\nCVE REFERENCES:\n" + "=" * 50 + "\n\n")
                f.write("Detected CVEs :\n" + ("\n".join(found_cves) if found_cves else "None"))
                logging.info(f"Report generated with {len(full_list)} malicious IOCs found.")

            # If any malicious IOCs were found, also create a separate blocklist file for immediate use in defenses like firewalls or EDRs. 
            # This provides a quick reference for security teams to implement blocks without having to sift through the full report.
            if full_list:
                blocklist_path = f"{self.malicious_dir}/URGENT_BLOCKLIST_{ts}.txt" # NEW: Separate blocklist file for quick defensive action
                self._ensure_dir(blocklist_path) # Ensure the directory exists before writing the blocklist
                with open(blocklist_path, "w", encoding="utf-8") as f: # Write only the raw IOCs to the blocklist for easy import into security tools
                    for cat, items in mal_data.items(): # Iterate through each category (IPs, Domains, URLs, File Hashes)
                        if items: # Only write categories that have malicious IOCs
                            f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")

            logging.info(f"Success: Report generated at {report_path}\n{'='*60}")
            return report_path

        except Exception as e:
            logging.critical(f"FATAL ERROR in generate_report: {str(e)}")
            return None