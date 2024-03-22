from typing import Any
from bs4 import BeautifulSoup
import re as regex
from urllib.parse import urlparse, parse_qs, unquote
from pprint import pprint
from typing import Dict, List
import whois
from datetime import datetime
import os 
from analysis_template import Reason, Report
from spellchecker import SpellChecker

# NOTE
# Reason ctor (name: str, val, reason: str, score_incr: int)
# Report ctor (type: str, who: str) type is what type of analysis was done, who is the entity analyzed

class EmailDetails:
    def __init__(self, email) -> None:
        self.obj = email
        self.sender_addr = email.SenderEmailAddress
        self.subject = email.Subject
        self.header = email.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
        self.body = email.Body
        self.body_info = BodyInfo(self.body)
        self.auth_results = AuthResults(self.header)
        self.whois_info = WhoIsInfo(self.sender_addr)
        
    
    


class WhoIsInfo:
    def query_whois(self, domain) -> dict:
        if not self._can_query(domain):
            print(f"[!] Cannot query WHOIS data for { domain } as it is not a .com, .org, or .net domain... [!]")
            return None
        try:
            return whois.whois(domain.split("@")[1])
        except Exception as e:
            print(f"Failed to fetch WHOIS data: { e }")
            return None
    
    def _can_query(self, domain) -> bool:
        domain = domain.lower()
        if domain.endswith(".com") or domain.endswith(".org") or domain.endswith(".net"):
            return True
        return False
    
    def most_recent(self, dates) -> datetime:
        if dates is None:
            return "UNKNOWN"
        
        if isinstance(dates, list):
            return dates[0]
        
        return dates
    
    def set_data(self):
        self.domain_name = self.whois_info.domain_name
        self.registrant = self.whois_info.registrant_name
        self.registrar = self.whois_info.registrar
        self.creation_date = self.most_recent(self.whois_info.creation_date)
        self.expiration_date = self.most_recent(self.whois_info.expiration_date)
        self.set_age()
    
    def __init__(self, domain_name):
        self.whois_info = self.query_whois(domain_name)
        if self.whois_info is None:
            print(f"[!] Failed to fetch WHOIS data for { domain_name }")
            self.did_query = False
        else:
            self.did_query = True
            self.set_data()
    
    
    def set_age(self):
        if not self.creation_date == "UNKNOWN":
            self.age = (datetime.now() - self.creation_date).days
        else:
            self.age = "UNKNOWN"
    
    def till_expiration(self):
        if not self.expiration_date == "UNKNOWN":
            self.expir_days = (self.expiration_date - datetime.now()).days
        self.expir_days = "UNKNOWN"
    
    
    def __str__(self) -> whois.str:
        return f'Domain Name: { self.domain_name }\nRegistrant: { self.registrant }\nRegistrar: { self.registrar }\nCreation Date: { self.creation_date }\nExpiration Date: { self.expiration_date }\nDomain Age: { self.age } days\n'


class WhoIsAnalyzer:
    def __init__(self, data: WhoIsInfo) -> None:
        if not data.did_query:
            print("[!] Failed to fetch WHOIS data... [!]")
            return
        
        self.data = data
        self.MALICIOUS_REGSTRARS = {
            "NameCheap, Inc.": 77,
            "NameSilo, LLC": 88,
            "GoDaddy.com, LLC": 40,
            "PDR Ltd. d/b/a PublicDomainRegistry.com": 64,
            "Tucows Domains Inc.": 66,
            "Google LLC": 68,
            "Chengdu West Dimension Digital Technology Co., Ltd.": 88,
            "ALIBABA.COM SINGAPORE E-COMMERCE PRIVATE LIMITED": 48,
            "Wild West Domains, LLC": 65,
            "Shinjiru Technology Sdn Bhd": 96,
            "Hosting Concepts B.V. d/b/a Openprovider": 91,
            "Jiangsu Bangning Science & technology Co. Ltd.": 89,
            "Name.com, Inc.": 72,
            "Registrar of Domain Names REG.RU LLC": 88,
            "eNom, LLC": 50,
            "Wix.com Ltd.": 98,
            "GMO Internet, Inc. d/b/a Onamae.com": 78,
            "Web Commerce Communications Limited dba WebNic.cc": 84,
            "OnlineNIC, Inc.": 80,
            "Register.com, Inc.": 79
        }
        self.Report = Report("WHOIS", self.data.domain_name)
    
    def domain_analysis(self):
        EXPLAINATION = "The program uses a list of known malicious/comprimised domain names to check if the domain name is present in the list"
        domain_names = self.data.domain_name
        if domain_names is None:
            return Reason("Domain Names", "UNKNOWN", "Failed to get Data", 0)
        score_incr = self.analyze_domain_names(domain_names)
        self.Report.add_reason(
            Reason("Domain Name Analysis", domain_names, EXPLAINATION, score_incr)
        )
    
    def analyze_domain_names(self, domain_names) -> int:
        if domain_names is None:
            return 0
        
        file_path = r'analysis_data\domain_data.txt'
        if not os.path.exists(file_path):
            print("[!] Compromised Domain Name File Data was not found... [!]")
            return 0    
        
        data = []
        with open(file_path, 'r') as file:
            data = file.read().splitlines()
        
        if not data:
            print("[!] No data was found in the compromised domain name file... [!]")
            return 0
        
        if filter(lambda name: name in data, domain_names):
            return 5
        
        return 0
        
    def analyze_domain_age(self):
        age = self.data.age
        score_incr = 0
        if not age is None and age != "UNKNOWN" and age < 365:
            score_incr = 5
            
        explain = "Threat actors often use newly registered domains to avoid blacklists and reputation systems. \nOlder domains are more likely to be legitimate."
        self.Report.add_reason(
            Reason("Domain Age Analysis", age, explain, score_incr)
        )
    
    def analyze_expriation_date(self):
        EXPLAIN = "Short expiration dates for domain names imply that a domain is fraudlent and are almost always a sign of a scam"
        days = self.data.expir_days
        score_incr = 0
        if days is None or days == "UNKNOWN":
            score_incr = 0
        elif days < 90:
            score_incr = 10
        elif days < 180:
            score_incr = 5
        elif days < 365:
            score_incr = 4
        else:
            score_incr = 0
        return self.Report.add_reason(
            Reason("Domain Expiration Analysis", days, EXPLAIN, score_incr)
        )

    def analyze_registrar(self):
        EXPLAIN = "The program has list of known malicious registrars if the domain name is known to be malicious the field will be >0"
        registrar = self.data.registrar
        score_incr = 0  
        if registrar and registrar in self.MALICIOUS_REGSTRARS:
            score_incr = 5
        self.Report.add_reason(
            Reason("Registrar Analysis", registrar, EXPLAIN, score_incr)
        )    
        
    
    def is_privacy_protected(self):
        registrant_name = self.data.registrant
        score_incr = 0
        if registrant_name and "privacy" in registrant_name.lower():
            score_incr = 5
        EXPLAIN = "Privacy protection is often used by threat actors to hide their identity and avoid detection"
        self.Report.add_reason(
            Reason("Privacy Protection Analysis", registrant_name, EXPLAIN, score_incr)
        )
    
    def generate_report(self):
        print("[ Analyzing Domain Name Data... ]")
        self.domain_analysis()
        print("[ Analyzing Domain Age... ]")    
        self.analyze_domain_age()
        print("[ Analyzing Domain Expiration Date... ]")
        self.analyze_expriation_date()
        print("[ Analyzing Registrar... ]")
        self.analyze_registrar()
        print("[ Checking Privacy Protection... ]")
        self.is_privacy_protected()
        print("[ Analysis & Report Complete ]")
    

class BodyInfo:
    def __init__(self, body_text):
        self.body = body_text
        self.urls = self.extract_urls(body_text)
        
    
    def extract_urls(self, email_body):
        urls = []
        soup = BeautifulSoup(email_body, 'html.parser')
        
        for link in soup.find_all('a'):
            href = link.get('href')
            if not href:
                continue
            url = self.parse_safelink(href)
            urls.append(url)
            link.replace_with('[ REMOVED URL ]')
        
        clean_body = str(soup)
        url_pattern = url_pattern = regex.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        matches = url_pattern.findall(clean_body)
        
        for match in matches:
            url = self.parse_safelink(match)
            urls.append(url)
        # update the body so we can it for mispelled words
        self.body = url_pattern.sub('[ REMOVED URL ]', clean_body)
        return list(set(urls))
    
    def parse_safelink(url):
        parsed_url = urlparse(url)
        if not 'safelinks.protection.outlook.com' in parsed_url.netloc:
            return url    
        query_params = parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        if not original_url:
            return url
        return unquote(original_url)
    
    def view(self):
        print(self.body)
    
    def view_urls(self):
        if not self.urls:
            print("[!] No URLs were found in the email body... [!]")
            return
        print("[ URLs Found in Email Body ]")
        for url in self.urls:
            print(f'\t[>] { url }\n')
    
                
class BodyAnalyzer:
    def __init__(self, data: BodyInfo, sender: str, scanURLs: bool) -> None:
        self.data = data
        self.report = Report("Body", sender)
        urgency_words = [
        "urgent", "immediate", "action", "now", "limited", "offer",
        "expire", "risk", "danger", "warning", "critical", "alert",
        "important", "immediately", "confirm", "validate", "require",
        "deadline", "final", "notice", "threat", "security", "protect",
        "act", "priority", "attention", "secure", "emergency", "verify",
        "account", "confidential", "mandatory", "protect", "resolve",
        "response", "safety", "serious", "solve", "stop", "suspend",
        "verify", "warning", "without delay", "apply", "available",
        "avoid", "bonus", "caution", "certify", "chance", "claim",
        "clearance", "deal", "discount", "do not delay", "exclusive",
        "expiration", "exposed", "hurry", "instantly", "limited time",
        "new", "offer ends", "once", "only", "order now", "prevent",
        "protection", "quick", "report", "rush", "safeguard", "save",
        "scam", "special", "steal", "subscribe", "today", "top priority",
        "unauthorized", "unlock", "while supplies last", "win", "within",
        "breach", "crackdown", "enforcement", "click here", "apply now", "click"
        "buy now", "call now", "claim now", "click below", "click now",
        "click to get", "click to remove", "collect now", "contact us",
        "download now", "enroll now", "find out more", "get it now",
        ]
        self.URGNCY_WRDS: set = set(urgency_words)
        self.find_urgency()
        self.find_mispelled_words()
        
    def find_mispelled_words(self):
        spell = SpellChecker()
        words = self.data.body.split()
        self.misspelled_words = spell.unknown(words)
    
    def find_keywords(self, body):
        return list(lambda wrds: wrds.strip(".,!?:;") in self.URGNCY_WRDS, body)
        
    def find_urgency(self):
        words = self.data.body.lower().split()
        self.urg_words = self.find_keywords(words)
    
    def generate_report(self):
        EXPLAIN_URG = "Threat actors often use a sense of urgency to provoke fear and panic in their victims. \nThis is a common tactic used in phishing emails to get the victim to act without thinking."
        EXPLAIN_MIS = "Mispelled words are often used in phishing emails either by accident or to avoid detection by spam filters. \nThey are also used to target victims who may not be as attentive to detail."
        self.report.add_reason(
            Reason("Urgency Analysis", self.urg_words, EXPLAIN_URG, len(self.urg_words))
        )
        self.report.add_reason(
            Reason("Mispelled Word Analysis", self.misspelled_words, EXPLAIN_MIS, len(self.misspelled_words))
        )
    
        
class AuthResults:
    def __init__(self, header: str) -> None:
        self.results = self.get_authentication_results(header)
        self.spf = None
        self.dkim = None
        self.dmarc = None
        [setattr(self, key, value) for key, value in self.results.items()]
        
    def get_authentication_results(self, email_header) -> Dict[str, str]:
        patterns = {
            'spf': r'spf=(\w+)',
            'dkim': r'dkim=(\w+)',
            'dmarc': r'dmarc=(\w+)'
        }
        auth_results = {}
        for key, pattern in patterns.items():
            match = regex.search(pattern, email_header, regex.IGNORECASE)
            
            if match:
                auth_results[key] = match.group(1)
                continue
            
            auth_results[key] = "UNKNOWN"
        return auth_results
        
            

    def __str__(self) -> str:
        return f"[ AUTHENTICATION RESULTS ]\n SPF: { self.spf } \n DKIM: { self.dkim } \n DMARC: { self.dmarc }"
        
    def score(self) -> int:
        score = 0
        for value in self.results.values():
            if value != 'pass':
                score += 5
        return score
        

    
    
    
    
    





    
if __name__ == "__main__":
    pass
    # main()