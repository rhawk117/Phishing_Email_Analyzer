from client_manager import Client
from datetime import datetime
import whois
from dataclasses import dataclass
import re
from pprint import pprint
from email.parser import HeaderParser
from analysis_template import Report

class HeaderExtractor:
    def __init__(self, header_str: str) -> None:
        self.header_txt = header_str
        if not self.safe_parse():
            raise ValueError("[!] Failed to parse the email header [!]")
        self.parse_fields()
    
    def safe_parse(self):
        try:
            self.parser = HeaderParser().parsestr(self.header_txt)
            return True
        except HeaderParser.ParserError:
            print(f'[!] Failed to parse the provided email  header: {self.header_txt}')
            return False
    
    def parse_fields(self):
        pass
    
    def fetch(self, field):
        return self.parser.get(field, "Not Found")
    
    def fetch_all(self, field):
        return self.parser.get_all(field, "Not Found")
    
    def field_is_unset(self, field):
        return field == "Not Found"
    
    def display(self):
        pprint(self.data(), indent=4) 
    
    def data(self) -> dict:
        pass
    
    def analyze(self) -> Report:
        pass
    

@dataclass
class AntiSpamMailboxDelivery:
    ucf: str # user confidence field if 0 it passes (at least from what I have seen)
    jmr: str # junk mail reason if 0 it passes (at least from what I have seen)
    auth: str # authentication if 0 it passes (at least from what I have seen)
    raw: dict # dictionary dump of fields 

    def __str__(self) -> str:
        return f"UCF: { self.ucf }\n JMR: { self.jmr }\n AUTH: { self.auth}\n"


@dataclass
class MS_AntiSpam_Report:
    cip: str # => "Connecting IP Address" - use to determine if the IP is blacklisted (yay more work)
    ctry: str # => "Country" - use to determine if the country is blacklisted (yay more work) 
    ipv: str # => "IP Version" - use to determine if the IP is blacklisted (similar to CIP but more specific)
    raw: dict
    
    def __str__(self):
        return f"\nCIP: {self.cip}\n CTRY: {self.ctry}\n IPV: {self.ipv}\n"


class XSplicer:
    
    @staticmethod
    def fetch(self, data: dict, srch_val:str):
        return self.data.get(srch_val, "Not Found")
    
    @staticmethod 
    def splice_antispam_delievery(anti_spam_str) -> AntiSpamMailboxDelivery:
        data = XSplicer.splice_fields(anti_spam_str)
        return AntiSpamMailboxDelivery(
            ucf=XSplicer.fetch(data, "ucf"),
            jmr=XSplicer.fetch(data, "jmr"),
            auth=XSplicer.fetch(data, "auth"),
            raw=data
        )
        
    @staticmethod 
    def splice_spam_report(spam_report_str) -> MS_AntiSpam_Report:
        data = XSplicer.splice_fields(spam_report_str)
        return MS_AntiSpam_Report(
            cip=XSplicer.fetch(data,"cip"),
            ctry=XSplicer.fetch(data,"ctry"),
            ipv=XSplicer.fetch(data,"ipv"), 
            raw=data
        )
    
    @staticmethod
    def splice_fields(field_val) -> dict | str:
        if field_val == "Not Found":
            return field_val
        
        data = {}
        for fields in field_val.split(";"):
            key, val = fields.split(":")
            data[key] = val
            
        return data




 
class XHeaderInfo(HeaderExtractor):
    def __init__(self, header_str: str) -> None:
        super().__init__(header_str)
    
    def parse_fields(self) -> None:        
        self.ms_exchange_org_scl = self.fetch("X-MS-Exchange-Organization-SCL")
        self.ms_anti_spam = self.fetch("X-Microsoft-Antispam")
        
        # X-Microsoft-Antispam-Mailbox-Delivery, X-Forefront-Antispam-Report
        self.set_spam_fields() 
        
        self.auth_as = self.fetch("X-MS-Exchange-Organization-AuthAs")
    
    def set_spam_fields(self):
        self.anti_spam_report = XSplicer.splice_spam_report(
            self.fetch("X-Forefront-Antispam-Report")
        )
        
        self.anti_spam_mbox = XSplicer.splice_antispam_delievery(
            self.fetch("X-Microsoft-Antispam-Mailbox-Delivery")
        )    
    
    
    def data(self) -> dict:
        return {
            "X-Forefront-Antispam-Report": self.anti_spam_report,
            "X-MS-Exchange-Organization-SCL": self.ms_exchange_org_scl,
            "X-Microsoft-Antispam": self.ms_anti_spam,
            "X-Microsoft-Antispam-Mailbox-Delivery": self.anti_spam_mb,
            "X-MS-Exchange-Organization-AuthAs": self.auth_as
        }
    def __str__(self) -> str:
        return "[ X-Header Information ]\n" + \
                f"X-Forefront-Antispam-Report\n {self.anti_spam_report}\n" + \
                f"X-MS-Exchange-Organization-SCL: {self.ms_exchange_org_scl}\n" + \
                f"X-Microsoft-Antispam: {self.ms_anti_spam}\n" + \
                f"X-Microsoft-Antispam-Mailbox-Delivery\n {self.anti_spam_mbox}\n" + \
                f"X-MS-Exchange-Organization-AuthAs: {self.auth_as}\n" \
                
    
    
class HeaderInfo(HeaderExtractor):
    def __init__(self, header_str: str) -> None:
        super().__init__(header_str)
        
    def parse_fields(self) -> None:
        self.return_path = self.fetch("Return-Path")
        self.msg_from = self.fetch("From")
        self.reply_to = self.fetch("Reply-To")
    
    def data(self) -> dict:
        return {
            "Return-Path": self.return_path,
            "From": self.msg_from,
            "Reply-To": self.reply_to
        }
        
        
    def __str__(self) -> str:
        return  f"\n[ Header Information ]\n Return-Path: {self.return_path}\n From: {self.msg_from}\n Reply-To: {self.reply_to}\n" 


class AuthResults(HeaderExtractor):
    def __init__(self, header_str: str) -> None:
        self.spf = None
        self.dkim = None
        self.dmarc = None
        self.compauth = None
        super.__init__(header_str)

    def parse_fields(self) -> None:
        self.parse_auth_results()
    
    def parse_auth_results(self) -> None:
        patterns = {
            'spf': r'spf=(\w+)',
            'dkim': r'dkim=(\w+)',
            'dmarc': r'dmarc=(\w+)',
            'compauth': r'compauth=(\w+)',
        }
        
        auth_results = self.fetch("Authentication-Results")
        if not auth_results:
            print("[!] No Authentication Results Header Field Found")
            return 
        
        for key, pattern in patterns.items():
            match = re.search(pattern, auth_results)
            if match:
                setattr(self, key, match.group(1))
            else:
                setattr(self, key, "Not Found") 
                
    def data(self) -> dict:
        return {
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "compauth": self.compauth,            
        }
    
    def __str__(self) -> str:
        return f"\n[ Authentication Results ]" + \
            f"SPF: {self.spf}\n DKIM: {self.dkim}\n" + \
            f"DMARC: {self.dmarc}\n CompAuth: {self.compauth}\n"


        




def main() -> None:
    pass
    


if __name__ == "__main__":
    main()    