from client_manager import Client
from datetime import datetime
import whois
from dataclasses import dataclass
import os 
import re
from pprint import pprint
from email.parser import HeaderParser



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
        
class XHeaderInfo(HeaderExtractor):
    def __init__(self, header_str: str) -> None:
        super().__init__(header_str)
    
    def parse_fields(self) -> None:
        self.x_mailer = self.fetch("X-Mailer")
        self.forefront_antispam_report = self.fetch("X-Forefront-Antispam-Report")
        self.ms_exchange_org_scl = self.fetch("X-MS-Exchange-Organization-SCL")
        self.ms_anti_spam = self.fetch("X-Microsoft-Antispam")
        self.ms_antispam_mailbox_delivery = self.fetch("X-Microsoft-Antispam-Mailbox-Delivery")
        self.ms_atp_properties = self.fetch("X-MS-Exchange-AtpMessageProperties")
        self.ms_auth_source = self.fetch("X-MS-Exchange-Organization-AuthSource")
        self.ms_auth_as = self.fetch("X-MS-Exchange-Organization-AuthAs")
    
    def data(self) -> dict:
        return {
            "X-Mailer": self.x_mailer,
            "X-Forefront-Antispam-Report": self.forefront_antispam_report,
            "X-MS-Exchange-Organization-SCL": self.ms_exchange_org_scl,
            "X-Microsoft-Antispam": self.ms_anti_spam,
            "X-Microsoft-Antispam-Mailbox-Delivery": self.ms_antispam_mailbox_delivery,
            "X-MS-Exchange-AtpMessageProperties": self.ms_atp_properties,
            "X-MS-Exchange-Organization-AuthSource": self.ms_auth_source,
            "X-MS-Exchange-Organization-AuthAs": self.ms_auth_as
        }
    def __str__(self) -> str:
        return "[ X-Header Information ]\n" + str(self.view())
    
    
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
    def __str__(self) -> whois.str:
        return  "\n[ Header Information ]\n" + str(self.view())


class AuthResults(HeaderExtractor):
    def __init__(self, header_str: str) -> None:
        self.spf = None
        self.dkim = None
        self.dmarc = None
        self.compauth = None
        super.__init__(header_str)
        self.parse_fields()

    def parse_fields(self) -> None:
        self.parse_auth_results()
    
    def parse_auth_results(self):
        patterns = {
            'spf': r'spf=(\w+)',
            'dkim': r'dkim=(\w+)',
            'dmarc': r'dmarc=(\w+)',
            'compauth': r'compauth=(\w+)',
            'reason': r'reason=(\w+)'
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
            "Spf": self.spf,
            "Dkim": self.dkim,
            "Dmarc": self.dmarc,
            "CompAuth": self.compauth,
            "Reason": self.reason
        }




def main() -> None:
    pass

if __name__ == "__main__":
    main()    