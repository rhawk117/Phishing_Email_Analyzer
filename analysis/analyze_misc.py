from typing import Any
from bs4 import BeautifulSoup
import re as regex
from urllib.parse import urlparse, parse_qs, unquote
import whois
from datetime import datetime
import os 
from analysis_template import Reason, Report
from spellchecker import SpellChecker
from domain_checker import DomainDB
# NOTE
# Reason ctor (name: str, val, reason: str, risk: int)
# Report ctor (type: str, who: str) type is what type of analysis was done, who is the entity analyzed


        


class WhoIsInfo:
    def __init__(self, domain_name):
        self.whois_info = self.query_whois(domain_name)
        if self.whois_info is None:
            print(f"[!] Failed to fetch WHOIS whois_data for { domain_name }")
            self.did_query = False
        else:
            self.did_query = True
            self.set_data()
    
    def query_whois(self, domain) -> dict:
        if not self._can_query(domain):
            print(f"[!] Cannot query WHOIS whois_data for { domain } as it is not a .com, .org, or .net domain... [!]")
            return None
        try:
            return whois.whois(domain.split("@")[1])
        except Exception as e:
            print(f"Failed to fetch WHOIS whois_data: { e }")
            return None
    
    def _can_query(self, domain) -> bool:
        domain = domain.lower()
        if domain.endswith(".com") or domain.endswith(".org") or domain.endswith(".net"):
            return True
        return False
    
    def most_recent(self, dates) -> datetime:
        if dates is None:
            return "Not Found"
        
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
    
    
    
    def set_age(self):
        if not self.creation_date == "Not Found":
            self.age = (datetime.now() - self.creation_date).days
        else:
            self.age = "Not Found"
    
    def till_expiration(self):
        if not self.expiration_date == "Not Found":
            self.expir_days = (self.expiration_date - datetime.now()).days
        else:
            self.expir_days = "Not Found"
    
    
    def __str__(self) -> whois.str:
        return f'Domain Name: { self.domain_name }\nRegistrant: { self.registrant }\nRegistrar: { self.registrar }\nCreation Date: { self.creation_date }\nExpiration Date: { self.expiration_date }\nDomain Age: { self.age } days\n'


class WhoIsAnalyzer:
    
    @staticmethod
    def analyze(whois_data: WhoIsInfo) -> Report:
        if not whois_data.did_query:
            return None
        report = Report(f"WhoIs Report of { whois_data.domain_name }")
        WhoIsAnalyzer.domain_analysis(report, whois_data)
        WhoIsAnalyzer.analyze_domain_age(report, whois_data)
        WhoIsAnalyzer.analyze_expriation_date(report, whois_data)
        WhoIsAnalyzer.analyze_registrar(report, whois_data)
        WhoIsAnalyzer.is_privacy_protected(report, whois_data)
        return report
    
    @staticmethod
    def domain_analysis(report: Report, whois_data: WhoIsInfo):
        EXPLAINATION = "The program uses a list of known malicious/comprimised domain names to check if the domain name is present in the list"
        domain_names = whois_data.domain_name
        if domain_names is None:
            report.add_reason(Reason("Domain Name Blacklist Check", EXPLAINATION, "N/A", domain_names))
            
        domain_db = DomainDB()
        for domains in domain_names:
            if domain_db.query(domains):
                report.add_reason(
                    Reason("Domain Name Blacklist Check", EXPLAINATION, "High", domains)
                )
                
    @staticmethod
    def analyze_domain_age(report: Report, whois_data: WhoIsInfo):
        age = whois_data.age
        EXPLAIN = "Threat actors often use newly registered domains to avoid blacklists and reputation systems. \nOlder domains are more likely to be legitimate."
        if not age is None or age == "Not Found":
            report.add_reason(
                Reason("Domain Age Analysis", EXPLAIN, "N/A", age)
            )
        elif age > 365:
            report.add_reason(
                Reason("Domain Age Analysis", EXPLAIN, "N/A", age)
            )
        else:
            report.add_reason(
                Reason("Domain Age Analysis", EXPLAIN, "High", age)
            )
        
    @staticmethod
    def analyze_expriation_date(report: Report, whois_data: WhoIsInfo):
        EXPLAIN = "Short expiration dates for domain names imply that a domain is fraudlent and are almost always a sign of a scam"
        days = whois_data.expir_days
        risk = "High"
        if days is None or days == "Not Found" or days > 365:
            risk = "N/A"
        report.add_reason(
                Reason("Domain Expiration Date Analysis", EXPLAIN, risk, days)
            )
        
    @staticmethod
    def analyze_registrar(report: Report, whois_data: WhoIsInfo):
        EXPLAIN = "The program has list of known malicious registrars if the domain name is known to be malicious the field will be >0"
        registrar = whois_data.registrar
        risk = "N/A"
        MALICIOUS_REGSTRARS = {
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
        if registrar and registrar in MALICIOUS_REGSTRARS:
            risk = "High"
        report.add_reason(
            Reason("Registrar Analysis", EXPLAIN, risk, registrar)
        )    
        
    @staticmethod
    def is_privacy_protected(report: Report, whois_data: WhoIsInfo):
        registrant_name = whois_data.registrant
        risk = "N/A"
        EXPLAIN = "Privacy protection is often used by threat actors to hide their identity and avoid detection"
        if registrant_name and "privacy" in registrant_name.lower():
            risk = "Medium" 
        report.add_reason(
            Reason("Privacy Protection Analysis",EXPLAIN, risk, registrant_name)
        )
    
    

class BodyInfo:
    def __init__(self, email):
        self.email = email
        self.body = email.Body
        self.urls = self.extract_urls(self.body)
        
    
    def extract_urls(self, email_body) -> list:
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
        url_pattern = regex.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        matches = url_pattern.findall(clean_body)
        
        for match in matches:
            url = self.parse_safelink(match)
            urls.append(url)
            
        # update the body so we can search it for mispelled words
        self.body = url_pattern.sub('[ REMOVED URL ]', clean_body)
        return list(set(urls))
    
    def parse_safelink(url) -> str:
        parsed_url = urlparse(url)
        if not 'safelinks.protection.outlook.com' in parsed_url.netloc:
            return url    
        query_params = parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        if not original_url:
            return url
        return unquote(original_url)
    
    def view_body(self):
        print(f"Subject: { self.email.Subject }")
        print(f"From: { self.email.SenderName } ({ self.email.SenderEmailAddress })")
        print(f"Date: { self.email.ReceivedTime }")
        print(f"{'*' * 60}\n{ self.body } \n{'*' * 60}")
    
    def view_urls(self):
        if not self.urls:
            print("[!] No URLs were found in the email body... [!]")
            return
        print("[ URLs Found in Email Body ]")
        for url in self.urls:
            print(f'\t[>] { url }\n')
    
                
class BodyAnalyzer:
    def __init__(self, body_info: BodyInfo, sender: str) -> None:
        self.body_info = body_info
        self.report = Report("Body", sender)
        
        
        self.find_urgency()
        self.find_mispelled_words()
    
    @staticmethod    
    def find_mispelled_words(report, body_info: BodyInfo):
        spell = SpellChecker()
        words = body_info.body.split()
        misspelled_words = spell.unknown(words)
        return misspelled_words
    
    @staticmethod
    def analyze_words(report: Report, body_info: BodyInfo):
        EXPLAIN = "Mispelled words are often used in phishing emails either by accident or to avoid detection by spam filters. \nThey are also used to target victims who may not be as attentive to detail."
        wrd_list = BodyAnalyzer.find_mispelled_words(body_info)
        risk_lvl = "Low"
        if not wrd_list: 
            risk_lvl = "N/A"
        elif len(wrd_list) > 10: 
            risk_lvl = "Medium"
        elif len(wrd_list) > 20:
            risk_lvl = "High"
        report.add_reason(
            Reason("Mispelled Word Analysis",EXPLAIN, risk_lvl, len(wrd_list))
        )
        
    
    def find_keywords(self, wrd_list: list, body: str):
        return list(lambda wrds: wrds.strip(".,!?:;") in wrd_list, body)
        
    def find_urgency(self):
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
        words = self.body_info.body.lower().split()
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
        
    def get_authentication_results(self, email_header) -> dict:
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
            auth_results[key] = "Not Found"
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