from typing import Any
from bs4 import BeautifulSoup
import re as regex
from urllib.parse import urlparse, parse_qs, unquote
from pprint import pprint
from typing import Dict, List
import whois
from datetime import datetime
import os 
import requests


        

class Email:
    def __init__(self, email):        
        self.data = email
        self.sender = email.SenderEmailAddress

    def menu_view(self) -> str:
        return f"""
        * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
        | Subject Line: { self.data.Subject }                                                |
        | From: { self.sender }                                                               | 
        | Date: { self.data.SentOn }                                                         |
        * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
    """       
        
        
class DetailedEmail(Email):
    def __init__(self, data):
        super().__init__(data)
        self.header = data.PropertyAccessor.GetProperty(
            "http://schemas.microsoft.com/mapi/proptag/0x007D001E"
        )
        self.urls = self.extract_urls(self.data.body)
        self.auth_results = AuthResults(self.header)
    
    
    
    def analyze_body(self):
        body = BodyAnalyzer(self.data.body)
        return body.score()
    
    def analyze_domain(self):
        domain = self.sender.split('@')[1]
        domain_analyzer = WhoIsAnalyzer(domain)
        return domain_analyzer.score()
    

        
   
    
    

class BodyAnalyzer:
    def __init__(self, email_body: str) -> None:
        self.body = email_body
        self.urls = self.extract_urls()
        self.report = {}
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
        self.URGNCY_WRDS = set(urgency_words)
        
    def score(self):
        words = self.body.lower().split()
        return len(self.find_keywords(words))
    
    def find_keywords(self, body):
        return list(lambda wrds: wrds.strip(".,!?:;") in self.URGNCY_WRDS, body)
    
    def extract_urls(self, email_body):
        urls = []
        soup = BeautifulSoup(email_body, 'html.parser')
        
        for link in soup.find_all('a'):
            href = link.get('href')
            if not href:
                continue
            url = self.parse_safelink(href)
            urls.append(url)
        
        # for urls in the email body not in tags
        url_pattern = regex.compile(r'https?://\S+')
        matches = url_pattern.findall(str(soup))
        for match in matches:
            url = self.parse_safelink(match)
            urls.append(url)
        
        return list(set(urls))  
    
    
    def parse_safelink(url):
        parsed_url = urlparse(url)
        if 'safelinks.protection.outlook.com' in parsed_url.netloc:
            query_params = parse_qs(parsed_url.query)
            original_url = query_params.get('url', [None])[0]
            if original_url:
                return unquote(original_url)
        return url
        
        
class AuthResults:
    def __init__(self, header: str) -> None:
        self.results = self.parse_authentication_results(header)
        self.spf = None
        self.dkim = None
        self.dmarc = None
        self._set_attrs()
        
    def parse_authentication_results(self, email_header) -> Dict[str, str]:
        """
            Extracts the authentication results from the data header.
        """
        patterns = {
            'spf': r'spf=(\w+)',
            'dkim': r'dkim=(\w+)',
            'dmarc': r'dmarc=(\w+)'
        }
        auth_results = {}
        for key, pattern in patterns.items():
            match = regex.search(pattern, email_header, regex.IGNORECASE)
            if not match:
                continue
            auth_results[key] = match.group(1)
        return auth_results
    
    def _set_attrs(self):
        for key, value in self.results.items():
            setattr(self, key, value)

    def __str__(self) -> str:
        return f"""
        [ AUTHENTICATION RESULTS ] 
        SPF: { self.spf } 
        DKIM: { self.dkim }
        DMARC: { self.dmarc }
        """
        
    def score(self) -> int:
        for value in self.results.values():
            if value != 'pass':
                score += 5
        return score
        
class WhoIsAnalyzer:
    def __init__(self, domain_name: str) -> None:
        self.domain_name = domain_name
        self.whois_info = self.fetch_whois_info()
        if self.whois_info is None:
            print(f"[!] Failed to fetch WHOIS data for { self.domain_name }")
            return
        
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
        self.report = {}

    def fetch_whois_info(self) -> Dict[str, Any]:
       
        try:
            return whois.whois(self.domain_name)
        
        except Exception as e:
            print(f"Failed to fetch WHOIS data: { e }")
            return None
    
    def analyze_domain_names(self):
        domain_names = self.whois_info.domain_name
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
        
        if not any(name in data for name in domain_names):
            return 0
        
        return 5
        
    def get_domain_age(self):
        if not self.whois_info:
            return None
        
        creation_date = self.whois_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
       
        if creation_date:
            return (datetime.now() - creation_date).days
        
        return None
    
    def analyze_domain_age(self):
        age = self.get_domain_age()
        
        if age is None or age > 365:
            return 0
        
        if age < 365:
            return 5
        
        return 0
    
    def analyze_expriation_date(self):
        expiration_date = self.whois_info.expiration_date
        
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        if not expiration_date:
            return 0
        
        days = (expiration_date - datetime.now()).days
       
        if days < 90:
            return 10

        elif days < 180:
            return 5

        elif days < 365:
            return 2

        else:
            return 0

    def analyze_registrar(self):
        registrar = self.whois_info.registrar
        if registrar and registrar in self.MALICIOUS_REGSTRARS:
            percentage = self.MALICIOUS_REGSTRARS[registrar]
            return (percentage / 100 ) * 2
        return 0
    
    def privacy_protected(self):
        registrant_name = self.whois_info.registrant_name
        if registrant_name and "privacy" in registrant_name.lower():
            return 5
        
        return 0
    
    
    def generate_report(self):
        self.report = {
            "Domain Age Score": self.analyze_domain_age(),
            "Suspicious Domain Names Score": self.analyze_domain_names(),
            "Short Expiration Date Score": self.analyze_expriation_date(),
            "Malicious Registrar": self.analyze_registrar(),
            "Uses Privacy Protection Score": self.privacy_protected()
        }
        return self.report
    
    def score(self):
        if not self.report:
            self.generate_report()
        return sum(self.report.values())
    
    def rank_score(self):
        score = self.score()
        if score > 10:
            return "High"
        
        elif score > 5:
            return "Medium"
        
        else:
            return "Low"
    
    def save_report(self):
        if not self.report:
            self.generate_report()
        file_path = r'analysis_data\whois_reports.txt'
        with open(file_path, 'a') as file:
            file.write(f"Summary of: { self.domain_name }")
            file.write(f"Score: { self.score() }\n")
            file.write(f"Risk Level: {self.rank_score()}")
            file.write(f"Report: { self.report }")
    
    def score_guide(self):
        return """
        [ Score Guide ]
        0 - 5: Low Risk
        6 - 9: Medium Risk
        11 - 15: High Risk
        """
    
    
    
    
    





    
if __name__ == "__main__":
    pass
    # main()