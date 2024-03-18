from client_manager import Client
from email_parse import Email, DetailedEmail

from datetime import datetime
import whois
from dataclasses import dataclass
import os 

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
        self.Report = Report()
    
    
    def analyze_domain_names(self):
        domain_names = data.domain_name
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
        
    def analyze_domain_age(self):
        age = self.data.age
        score_incr = 0
        if age is None or age > 365:
            score_incr = 0
        explain = "Threat actors often use newly registered domains to avoid blacklists and reputation systems. Older domains are more likely to be legitimate."
        
    
    def analyze_expriation_date(self):
        days = self.data.expir_days
        score_incr = 0
        if days < 90:
            score_incr = 10

        elif days < 180:
            score_incr = 5

        elif days < 365:
            score_incr = 2

        else:
            score_incr = 0
        
        

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
    
    
  
    
    






def main():
    client = Client()
    if not client.safe_load():
        return 
    email = client.emails
    for i in email:
        info = WhoIsInfo(i.SenderEmailAddress)
        if info.whois_info is None:
            continue
        print(info)
        print("\n\n\n")
        input("Press Enter to continue...")
    
    

if __name__ == "__main__":
    main()