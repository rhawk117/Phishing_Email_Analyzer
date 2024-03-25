from dataclasses import dataclass



# FIELDS 

# X-Microsoft-Antispam-Mailbox-Delivery

# all should be 0
# ucf - user confidence field 
# jmr - junk mail reason
# auth - authentication 


@dataclass
class AntiSpamMailboxDelivery:
    ucf: str # user confidence field if 0 it passes (at least from what I have seen)
    jmr: str # junk mail reason if 0 it passes (at least from what I have seen)
    auth: str # authentication if 0 it passes (at least from what I have seen)
    raw: dict # dictionary dump of fields 

    def __str__(self) -> str:
        return f"UCF: { self.ucf }\n JMR: { self.jmr }\n AUTH: { self.auth }\n"


@dataclass
class MS_AntiSpam_Report:
    cip: str # => "Connecting IP Address" - use to determine if the IP is blacklisted (yay more work)
    ctry: str # => "Country" - use to determine if the country is blacklisted (yay more work) 
    ipv: str # => "IP Version" - use to determine if the IP is blacklisted (similar to CIP but more specific)
    raw: dict
    
    def __str__(self):
        return f"\nCIP: {self.cip}\n CTRY: {self.ctry}\n IPV: {self.ipv}\n"

@staticmethod
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


