
from dataclasses import dataclass



# FIELDS 

# X-Microsoft-Antispam-Mailbox-Delivery

# all should be 0
# ucf - user confidence field 
# jmr - junk mail reason
# auth - authentication 


# 

@dataclass
class X_MS_AntiSpam_MailboxDelivery:
    ucf: str # user confidence field if 0 it passes (at least from what I have seen)
    jmr: str # junk mail reason if 0 it passes (at least from what I have seen)
    auth: str # authentication if 0 it passes (at least from what I have seen)
    raw: dict # dictionary dump of fields 


# sample 
# CIP:5.61.117.83; => "Connecting IP Address"
# CTRY:IE; => "Country"
# LANG:en;
# SCL:-1; => "Spam Confidence Level"

@dataclass
class MS_AntiSpam_Report:
    cip: str
    ctry: str
    ipv: str
    raw: dict
    


@staticmethod
class XSplicer:
    def fetch(self, data: dict, srch_val:str):
        return self.data.get(srch_val, "Not Found")
    
    @staticmethod
    def splice_antispam_delievery(anti_spam_str):
        data = XSplicer.splice_fields(anti_spam_str)
        return X_MS_AntiSpam_MailboxDelivery(
            ucf=XSplicer.fetch(data, "ucf"),
            jmr=XSplicer.fetch(data, "jmr"),
            auth=XSplicer.fetch(data, "auth"),
            raw=data
        )
    def splice_spam_report(spam_report_str):
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


