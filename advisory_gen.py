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
import json              # For caching VT lookups and URL report metadata
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

# --- 2. CONFIGURATION --- intigreating .env for API key management, improving security by keeping sensitive information out of the codebase and logs.
# VT is use for reputation checks and to filter out false positives and trigger re-analysis for low-score IOCs, improving accuracy.
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

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.cache_dir = self.base_reports_dir
        self.vt_cache_path = os.path.join(self.cache_dir, 'vt_cache.json')
        self.url_report_index_path = os.path.join(self.cache_dir, 'url_report_index.json')
        self.vt_cache_max_age_seconds = 7 * 24 * 60 * 60  # one week for zero-score cache reuse
        self.vt_cache = self._load_json(self.vt_cache_path)
        self.url_report_index = self._load_json(self.url_report_index_path)

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

    def _load_json(self, file_path):
        """Self-healing JSON loader for cache/index files."""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                logging.warning(f"Corrupt JSON in {file_path}; rebuilding.")
                return {}
        else:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump({}, f, indent=2)
            logging.info(f"Initialized missing JSON file: {file_path}")
            return {}

    def _save_json(self, file_path, data):
        """Persist JSON data safely."""
        self._ensure_dir(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    #  The _get_url_id function is a helper method that takes a URL as input and encodes it into a format suitable for querying the VirusTotal v3 API.
    #  Since the API requires URLs to be represented as a base64-encoded string, this function performs the necessary encoding and formatting to ensure that the URL can be correctly processed by the API when checking for malicious activity.
    def _get_url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _normalize_url(self, url):
        if not url:
            return url
        normalized = url.split('#', 1)[0].strip()
        if normalized.endswith('/'):
            normalized = normalized[:-1]
        return normalized

    # to filter out false positives and trigger re-analysis for low-score IOCs, improving accuracy.
    # This function queries the VirusTotal API for the given IOC and returns the number of malicious hits along with a status message.
    def get_vt_data(self, ioc_type, ioc_value, force_reanalysis=False):

        def deobfuscate(ioc_value):
            val = ioc_value.strip()
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
            for k, v in replacements.items():
                val = val.replace(k, v)
            return val

        val = deobfuscate(ioc_value)
        cache_key = f"{ioc_type}:{val}"
        cache_entry = self.vt_cache.get(cache_key)

        if cache_entry and not force_reanalysis:
            cache_age = 0
            try:
                cache_age = (datetime.now() - datetime.fromisoformat(cache_entry.get('last_checked'))).total_seconds()
            except Exception:
                cache_age = 0

            if cache_entry.get('score') is not None:
                score = cache_entry['score']
                status = cache_entry.get('status', f"{score} hits (cached)")
                if score > 0 or cache_age < self.vt_cache_max_age_seconds:
                    logging.info(f"Using cached VT result for {ioc_type.upper()} {val}: {status} (age {int(cache_age)}s)")
                    return score, status

        endpoints = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "url": "urls"
        }

        if ioc_type not in endpoints:
            logging.error(f"Unsupported IOC type: {ioc_type}")
            return 0, f"Unsupported IOC Type: {ioc_type}"

        resource_id = self._get_url_id(val) if ioc_type == "url" else val
        api_url = f"https://www.virustotal.com/api/v3/{endpoints.get(ioc_type)}/{resource_id}"
        malicious = 0

        try:
            time.sleep(2)
            try:
                res = self.session.get(api_url, timeout=10)
            except requests.exceptions.SSLError as ssl_err:
                logging.warning(f"SSL verification failed for VT lookup on {val}: {ssl_err}. Retrying with verify=False.")
                res = self.session.get(api_url, timeout=10, verify=False)

            if res.status_code == 429:
                logging.warning(f"VT Rate limit hit(429) for {ioc_type.upper()}: {val[:200]}... waiting before retrying.")
                time.sleep(5)
                try:
                    res = self.session.get(api_url, timeout=10)
                except requests.exceptions.SSLError:
                    res = self.session.get(api_url, timeout=10, verify=False)

            if res.status_code == 200:
                try:
                    malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except KeyError:
                    logging.error("Unexpected response format from VirusTotal API")
                    return 0, f"VT Lookup Failed (Status Code: {res.status_code}): {res.json()}"

            status = f"{malicious} hits"
            cache_payload = {
                'score': malicious,
                'status': status,
                'last_checked': datetime.now().isoformat()
            }
            self.vt_cache[cache_key] = cache_payload
            self._save_json(self.vt_cache_path, self.vt_cache)

            if malicious <= 5:
                logging.info(f"Triggering re-analysis for {ioc_type.upper()}: {val[:200]} (Score: {malicious})")
                try:
                    rescan_url = f"{api_url}/analyse"
                    try:
                        post_res = self.session.post(rescan_url, timeout=10)
                    except requests.exceptions.SSLError:
                        post_res = self.session.post(rescan_url, timeout=10, verify=False)
                    if post_res.status_code in (200, 201, 202):
                        time.sleep(3)
                        try:
                            res = self.session.get(api_url, timeout=10)
                        except requests.exceptions.SSLError:
                            res = self.session.get(api_url, timeout=10, verify=False)
                        if res.status_code == 200:
                            malicious = res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                            status = f"{malicious} hits (Re-analyzed)"
                            cache_payload['score'] = malicious
                            cache_payload['status'] = status
                            cache_payload['last_checked'] = datetime.now().isoformat()
                            self.vt_cache[cache_key] = cache_payload
                            self._save_json(self.vt_cache_path, self.vt_cache)
                            return malicious, status
                        return malicious, f"{malicious} hits (Re-analysis attempted but failed): {res.status_code}"
                    return malicious, f"{malicious} hits (Re-analysis attempted but failed): {post_res.status_code}"
                except Exception as e:
                    logging.error(f"Re-analysis error for {ioc_type.upper()}: {str(e)}")
                    return malicious, f"{malicious} hits (Re-analysis failed)"

        except Exception as e:
            logging.error(f"Network error during VT lookup for {ioc_type.upper()}: {str(e)}")
            return 0, "Lookup Error"

        return malicious, status
                
    def vt_lookup_multiple(self, ioc_list, ioc_type, base_sleep=5, max_retries=3):
        results = []

        for i, ioc in enumerate(ioc_list, start=1):
            logging.info(f"[{i}/{len(ioc_list)}] VT starting Lookup for {ioc_type.upper()}: {str(ioc)[:200]}...")
            retries = 0
            while retries <= max_retries:
                score, msg = self.get_vt_data(ioc_type, ioc)
                if "rate limit" in msg.lower() or "429" in msg:
                    wait_time = base_sleep * (2 ** retries)
                    logging.warning(f"Rate limit hit for {ioc_type.upper()}. Retrying {retries+1}/{max_retries} after waiting {wait_time} seconds.")
                    time.sleep(wait_time)
                    retries += 1
                    continue
                break

            results.append({
                "ioc": ioc,
                "type": ioc_type,
                "score": score,
                "message": msg
            })
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

    def _remove_iocs_from_text(self, text):
        """Remove standalone IOC patterns before generating the summary."""
        if not text:
            return text

        patterns = [
            r'\\b[A-Fa-f0-9]{32}\\b',
            r'\\b[A-Fa-f0-9]{40}\\b',
            r'\\b[A-Fa-f0-9]{64}\\b',
            r'\\bCVE[\s\-_–—]?\d{4}[\s\-_–—]?\d{4,7}\\b',
            r'(?:hxxps?|https?):\\/\\/[^\s]+',
            r'\\b(?:\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3})\\b',
            r'\\b[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.)[a-zA-Z0-9-.]+\\b',
            r'\\bIoC\\b',
        ]

        cleaned = text
        for pat in patterns:
            cleaned = re.sub(pat, ' ', cleaned, flags=re.IGNORECASE)

        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

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

        explicit_mitre = sorted(set(match.upper() for match in re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text, re.IGNORECASE)))

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
            "matched_mitre_codes": ", ".join(explicit_mitre) if explicit_mitre else "None",
            "victims": victims if victims else ["Unspecified"],
            "attack_types": ", ".join(sorted(attack_types)) if attack_types else "Unknown",
            "tactics": ", ".join(sorted(tactics)) if tactics else "Unknown",
            "mitre_details": detail_lines
        }

    # The generate_report function orchestrates the entire process of analyzing a given URL. It scrapes the webpage, extracts relevant IOCs, checks them against VirusTotal, and compiles a comprehensive report. 
    # The report includes detected TTPs, a summary of the page content, and categorized lists of malicious IOCs. The function also handles file management for storing reports and blocklists.
    # Added report_type parameter: "full" for complete report, "ioc" for IOCs only.
    def generate_report(self, url, report_type="full", reuse_choice=None):
        logging.info(f"Starting analysis for: {url} (Report Type: {report_type})")
        norm_url = self._normalize_url(url)
        report_entry = self.url_report_index.get(norm_url, {})
        existing_report = report_entry.get("reports", {}).get(report_type)
        force_vt_reanalysis = False
        analysis_note = ""

        if existing_report and os.path.exists(existing_report):
            if reuse_choice == "1":
                logging.info(f"Reusing existing report for URL: {norm_url}")
                return existing_report
            elif reuse_choice == "2":
                analysis_note = "Previous URL analysis exists; report regenerated using cached VirusTotal data."
            elif reuse_choice == "3":
                force_vt_reanalysis = True
                analysis_note = "Previous URL analysis exists; report regenerated with forced VirusTotal re-analysis."
            else:
                analysis_note = "Previous URL analysis exists; report regenerated using cached VirusTotal data."
        

        try:
            res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = soup.get_text(separator=' ')
            # Use extracted content for better summarization and context extraction (improved from raw page_text)
            content_for_summary = self.extract_page_content(soup)
            summary_for_report = self._remove_iocs_from_text(content_for_summary)
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
            def normalize_ioc(ioc):
                return (
                    ioc.replace("[.]", ".")
                       .replace("(.)", ".")
                       .replace("[://]", "://")
                       .replace("hxxps://", "https://")
                       .replace("hxxp://", "http://")
                       .replace("hxxps", "https://")
                       .replace("hxxp", "http")
                       .replace("fxp", "ftp")
                       .strip()
                       .lower()
                )
            found_ips = sorted(set(normalize_ip(ip) for ip in found_ips))# This line applies the normalize_ip function to each found IP address, ensuring that all IPs are in a consistent format. The sorted and set functions are used to remove duplicates and maintain an ordered list of unique IP addresses.

            raw_hashes = sorted(list(set(iocextract.extract_hashes(page_text))))

             # To reduce false positives, we exclude common file extensions that are unlikely to be domains. 
             # This helps focus the domain extraction on more relevant patterns, improving the accuracy of the report.
            ignored_ext = ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg', '.get']

            all_domains = sorted(
                set(
                    normalize_ioc(d)
                    for d in re.findall(
                        r'\b[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.)(?:[a-z]{2,})(?:\/[^\s]*)?\b',
                        page_text,
                        re.IGNORECASE
                    )
                    if not any(ext in normalize_ioc(d) for ext in ignored_ext)
                )
            )

            # Updated RegEx to exclude common file extensions and focus on domain-like patterns
            # Updated RegEx to catch steamcommunity[.]com/profiles/12345...
            found_urls = sorted(list(set(re.findall(r'(?:http|hxxp)s?(?:\[\:\/\/\]|\:\/\/)[a-zA-Z0-9\-\.\[\]]+(?:(?:\/|\%2F)[\w\.\-\/\=\?\&\%\+\[\]]+)?', page_text))))
            
            cve_source = None
            article_tag = soup.find('article')
            main_tag = soup.find('main')
            if article_tag:
                cve_source = article_tag.get_text(separator=' ', strip=True)
            elif main_tag:
                cve_source = main_tag.get_text(separator=' ', strip=True)
            else:
                cve_source = content_for_summary

            raw_cves = re.findall(
                r'\bCVE[\s\-_–—]?(\d{4})[\s\-_–—]?(\d{4,7})\b',
                cve_source,
                re.IGNORECASE
                )
            found_cves = sorted(list(set(f"CVE-{y}-{n}".upper() for y, n in raw_cves)))
            logging.info(f"Extracted counts of IOCs-> IPs: {len(found_ips)}, Domains: {len(all_domains)}, URLs: {len(found_urls)}, Hashes: {len(raw_hashes)}, CVE: {len(found_cves)}")
            
#-----------------------------------------------------------------------------------------------------------------------------------------------------------

            mal_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
            clean_data = {"File_Hash": [], "Domain": [], "URL": [], "IPs": []}
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
                    clean_val = normalize_ioc(ioc)# This line process_ioc does the "Refanging"
                    if any(w in clean_val for w in self.ip_whitelist + self.domain_whitelist):
                        continue
                    is_block = clean_val in self.manual_blocklist

                    logging.info(f"Processing {ioc_type.upper()} IOC: raw={ioc[:80]} Malicious_IOC={clean_val[:80]}")
                    # The vt_result variable is assigned a tuple based on whether the IOC is found in the manual blocklist. 
                    # If it is a blocklisted item, it is immediately categorized as a threat with a message indicating a blocklist match.
                    
                    vt_result = (1, "[!] BLOCKLIST MATCH") if is_block else self.get_vt_data(ioc_type, clean_val, force_reanalysis=force_vt_reanalysis)
                    if not vt_result:
                        vt_result = (0, "VT returned None (check get_vt_data returns)")
                    hits, status = vt_result

                    # It acts as the final judge, deciding whether an Indicator of Compromise (IOC) is dangerous enough to be included in your Malicious_IOCs report.
                    # It uses OR logic, meaning if any one of these three conditions is true, the item is marked as a threat.
                    if hits > 0 or "\\\\" in ioc or "hxxp" in ioc.lower() or "[.]" in ioc:
                        entry = f"{cat}: {clean_val.ljust(45)} | {status}"
                        full_list.append(entry)
                        mal_data[cat].append(entry)
                    else:
                        # Collect clean IOCs (score 0, no malicious indicators)
                        entry = f"{cat}: {clean_val.ljust(45)} | {status}"
                        clean_data[cat].append(entry)

            process_ioc(found_ips, 'ip', 'IPs')# This line processes the list of found IP addresses by calling the process_ioc function with the appropriate parameters for IPs. It checks each IP against whitelists, blocklists, and VirusTotal, and categorizes them accordingly in the report.
            process_ioc(all_domains, 'domain', 'Domain')# This line processes the list of found domains by calling the process_ioc function with the appropriate parameters for domains. It checks each domain against whitelists, blocklists, and VirusTotal, and categorizes them accordingly in the report.
            process_ioc(found_urls, 'url', 'URL')# This line processes the list of found URLs by calling the process_ioc function with the appropriate parameters for URLs. It checks each URL against whitelists, blocklists, and VirusTotal, and categorizes them accordingly in the report.
            process_ioc(raw_hashes, 'hash', 'File_Hash')# This line processes the list of found file hashes by calling the process_ioc function with the appropriate parameters for file hashes. It checks each hash against whitelists, blocklists, and VirusTotal, and categorizes them accordingly in the report.

#----------------------------------------------------------------------------------------------------------------------------------------------

            clean_list = [item for sublist in clean_data.values() for item in sublist]

            # --- EXPORT TO TEXT FILES ---
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            if report_type == "ioc" and not full_list:
                logging.info(f"No IOCs found for {url}; IOC-only report will not be created.")
                return "NO IOC Found"

            if report_type == "ioc":
                report_path = f"{self.base_reports_dir}/IOC_ONLY_{ts}.txt"
            else:
                report_path = f"{self.base_reports_dir}/ADVISORY_{ts}.txt"
            self._ensure_dir(report_path)

            with open(report_path, "w", encoding="utf-8") as f:
                if report_type == "full":
                    f.write("=" *50 + "\nReport:\n" + "=" *50 + f"\n")
                    f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"SOURCE URL       : {url}\n\n")
                    if analysis_note:
                        f.write(f"ANALYSIS NOTE    : {analysis_note}\n\n")
                    f.write(f"TARGET COMPANY   : {', '.join(context['victims'])}\n\n")
                    # Write the MITRE ATT&CK section with all inferred context:
                    # - Detected TTPs: concatenated technique IDs and names
                    # - Attack Type: high-level behavior classification
                    # - MITRE Tactic(s): inferred stage(s) of the attack lifecycle
                    f.write("=" *50 + "\nMITRE ATT&CK ANALYSIS:\n" + "=" *50 + f"\n\nDetected TTPs    : {context['ttps']}\n")
                    f.write(f"Matched MITRE Codes: {context.get('matched_mitre_codes', 'None')}\n")
                    f.write(f"Attack Type      : {context.get('attack_types', 'Unknown')}\n")
                    f.write(f"MITRE Tactic(s)  : {context.get('tactics', 'Unknown')}\n\n")
                    if context.get('mitre_details'):
                        # Add per-technique confidence and reasoning.
                        f.write("Technique findings:\n")
                        f.write("\n".join(context['mitre_details']) + "\n\n")
                    # Updated to use content_for_summary for better summary quality (improved from raw page_text)
                    f.write("=" *50 + "\nSUMMARY:\n" + "=" *50 + f"\n\n")
                    f.write(self.get_summary(summary_for_report) + "\n\n")
                    f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} IOC_Found), IPs: {len(found_ips)}, Domains: {len(all_domains)}, URLs: {len(found_urls)}, Hashes: {len(raw_hashes)}, CVE: {len(found_cves)}" "\n\n" + "\n".join(full_list) + "\n\n")
                    f.write("=" * 50 + "\nCVE REFERENCES:\n" + "=" * 50 + "\n\n")
                    f.write("Detected CVEs :\n" + ("\n".join(found_cves) if found_cves else "None"))
                else:  # report_type == "ioc"
                    f.write("=" *50 + "\nIOC Report:\n" + "=" *50 + f"\n")
                    f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"SOURCE URL       : {url}\n\n")
                    if analysis_note:
                        f.write(f"ANALYSIS NOTE    : {analysis_note}\n\n")
                    f.write("-" * 50 + f"\nMALICIOUS IOCs ({len(full_list)} IOC_Found), IPs: {len(found_ips)}, Domains: {len(all_domains)}, URLs: {len(found_urls)}, Hashes: {len(raw_hashes)}, CVE: {len(found_cves)}" "\n\n" + "\n".join(full_list) + "\n\n")
                logging.info(f"Report generated with {len(full_list)} malicious IOCs and {len(clean_list)} clean IOCs found.")

            # If any malicious IOCs were found, also create a separate blocklist file for immediate use in defenses like firewalls or EDRs. 
            # This provides a quick reference for security teams to implement blocks without having to sift through the full report.
            if full_list:
                blocklist_path = f"{self.malicious_dir}/URGENT_BLOCKLIST_{ts}.txt" # NEW: Separate blocklist file for quick defensive action
                self._ensure_dir(blocklist_path) # Ensure the directory exists before writing the blocklist
                with open(blocklist_path, "w", encoding="utf-8") as f: # Write only the raw IOCs to the blocklist for easy import into security tools
                    for cat, items in mal_data.items(): # Iterate through each category (IPs, Domains, URLs, File Hashes)
                        if items: # Only write categories that have malicious IOCs
                            f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")

            # If any clean IOCs were found, create a separate clean artifacts file for reference.
            if clean_list:
                clean_path = f"{self.clean_dir}/CLEAN_ARTIFACTS_{ts}.txt"
                self._ensure_dir(clean_path)
                with open(clean_path, "w", encoding="utf-8") as f:
                    f.write("=" *50 + "\nClean Artifacts Report:\n" + "=" *50 + f"\n")
                    f.write(f"REPORT DATE      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"SOURCE URL       : {url}\n\n")
                    f.write(f"Clean IOCs ({len(clean_list)} found)\n\n")
                    for cat, items in clean_data.items():
                        if items:
                            f.write(f"[{cat}]\n" + "\n".join(items) + "\n\n")
                logging.info(f"Clean artifacts saved to {clean_path}")

            logging.info(f"Success: Report generated at {report_path}\n{'='*60}")

            index = self.url_report_index.setdefault(norm_url, {"reports": {}, "last_analyzed": None})
            index["reports"][report_type] = report_path
            index["last_analyzed"] = datetime.now().isoformat()
            self._save_json(self.url_report_index_path, self.url_report_index)

            return report_path

        except Exception as e:
            logging.critical(f"FATAL ERROR in generate_report: {str(e)}")
            return None