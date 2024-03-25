from header_parser import AuthResults, HeaderInfo, HeaderExtractor, XHeaderInfo, EmailData
from analysis_template import Reason, Report


NOT_FOUND = "The parser failed to fetch results for this field or it was not included in the email header"

class AnalyzeAuth:
    
    @staticmethod
    def analyze_auth_results(self, auth_results: AuthResults):
        SPF_FAILED = "SPF or Sender Policy Framework is an email authentication method that detects forged sender addresses during the delivery of the email. If the SPF check fails, it means the email is not from the domain it claims to be from. This is a common technique used by phishers to trick users into thinking the email is from a legitimate source."
        DKIM_FAILED = "DKIM or DomainKeys Identified Mail is an email authentication method that verifies the authenticity of the email. If the DKIM check fails, it means the email has been tampered with or is not from the domain it claims to be from. This is a common technique used by phishers to trick users into thinking the email is from a legitimate source."
        DMARC_FAILED = "DMARC or Domain-based Message Authentication, Reporting, and Conformance is an email authentication method that helps prevent email spoofing. If the DMARC check fails, it means the email is not from the domain it claims to be from. This is a common technique used by phishers to trick users into thinking the email is from a legitimate source."
        COMP_AUTH_FAILED = "CompAuth or Composite Authentication is an email authentication method that combines multiple authentication methods to verify the authenticity of the email. If the COMP_AUTH check fails, it means the email is not from the domain it claims to be from. This is a common indicator of a phishing email and is a technique used by phishers to trick users into thinking the email is from a legitimate source."
        report = Report("Authentication Results")
        data_set = auth_results.data()
        explain = {
            "spf": SPF_FAILED,
            "dkim": DKIM_FAILED,
            "dmarc": DMARC_FAILED,
            "compauth": COMP_AUTH_FAILED
        }
        for key, value in data_set.items():
            if value == "Not Found":
                report.add_reason(Reason(key, NOT_FOUND, "N/A", value))
            elif value.lower() == "pass":
                continue
            else:
                report.add_reason(
                    Reason(f"{ key } did not pass", explain[key], self.ascribe_risk(value), value)
                )
            return report
                
    @staticmethod
    def ascribe_risk(self, value) -> str:
        if value == "fail":
            return "High"
        elif value in ["softfail", "neutral"]:
            return "Medium"
        else:
            return "Low"

class AnalyzeXHeaders:
    
    @staticmethod
    def analyze_x_headers(self, x_header_data: XHeaderInfo):
        report = Report("X-Header Analysis")
        AnalyzeXHeaders.analyze_anti_spam_report(
            x_header_data.anti_spam_report, report
        )
        AnalyzeXHeaders.analyze_mb_delievery(
            x_header_data.mb_delievery, report
        )
        AnalyzeXHeaders.anti_spam(report, x_header_data)
        AnalyzeXHeaders.auth_as(report, x_header_data)
        
    
    @staticmethod
    def analyze_anti_spam_report(anti_spam_report, report: Report) -> None:
        CTRY_EXPL = "The country of the connecting IP address was a Country known for malicious activity."
        IPV_EXPL = "The IP validation of the connecting IP address (CIP) was known for malicious activity and has been previously blacklisted. The IPV field has the following values for the field, NLI (No List Information), CAL (Checked And Allowed), BL (Blacklisted), BLI (Block List Information), and WL (Whitelisted)."
        blacklisted_ctry = ["RU", "CN", "IR", "KP", "SY", "CU", "PK", "VN", "VE", "IQ", "RO", "NG", "IN"]
        
        if anti_spam_report.ctry in blacklisted_ctry:
            report.add_reason(
                Reason("Blacklisted Country", CTRY_EXPL, "Medium", anti_spam_report.ctry)
            )
        if anti_spam_report.ipv == "NLI":
            report.add_reason(
                Reason("No List Information for IPV field", IPV_EXPL, "Low", anti_spam_report.ipv)
            )
        elif anti_spam_report.ipv == "BL":
            report.add_reason(
                Reason("Blacklisted IP Address", IPV_EXPL, "High", anti_spam_report.ipv)
            )
        elif anti_spam_report.ipv == "BLI":
            report.add_reason(
                Reason("Block List Information for IPV field", IPV_EXPL, "Medium", anti_spam_report.ipv)
            )
        
    @staticmethod
    def analyze_mb_delievery(mb_delievery, report) -> None:
        
        EXPLAIN_UCF = "The UCF field is the User Confidence Field and is used to determine the confidence of the user in the email. The JMR field is the Junk Mail Reason field and is used to determine if the email is junk mail. The AUTH field is the Authentication field and is used to determine if the email is authenticated."
        EXPLAIN_JMR = "The JMR field is the Junk Mail Reason field and is used to determine if the email is junk mail. If the JMR field is 0, it passes this check."
        EXPLAIN_AUTH = "The AUTH field is the Authentication field and is used to determine if the email is authenticated. If the AUTH field is 0, it passes this check."
        
        explain = {
            "ucf": EXPLAIN_UCF,
            "jmr": EXPLAIN_JMR,
            "auth": EXPLAIN_AUTH
        }
        data = mb_delievery.raw
        
        for key, val in explain.items():
            risk = AnalyzeXHeaders.ascribe_risk(data.get(key, "N/A"))
            if risk == "N/A":
                continue
            report.add_reason( Reason(
                 f"{ key } was greater than 0.", explain[key], risk, data[key]
                    )
                )
    
    @staticmethod
    def anti_spam(report: Report, xheader_data: XHeaderInfo) -> None:
        
        EXPLAIN = "The BCL field is the Bulk Complaint Level field and is used to determine the level of complaints against the email. The BCL field is a value between 0 and 9, with 0 being the lowest level of complaints and 9 being the highest level of complaints. A high BCL value indicates that the email has received a high number of complaints and is likely to be spam. A low BCL value indicates that the email has received a low number of complaints and is likely to be legitimate."
        fields = xheader_data.ms_anti_spam
        try:
            bcl = fields.split("BCL:")[1].split(";")[0]
        except IndexError:
            report.add_reason(
                Reason("BCL Field", NOT_FOUND, "N/A", "Not Found")
            )
            return 
        bcl_risk = AnalyzeXHeaders.ascribe_risk(bcl)
        if bcl_risk != "N/A":
            report.add_reason(
                Reason("Bulk Complaint Level was high ", EXPLAIN, bcl_risk, bcl)
            )    

    
    @staticmethod
    def auth_as(report: Report, xheader_data: XHeaderInfo):
        ANON_EXPL = "The Auth As field is set to Anonymous, which indicates that the email is not authenticated. This is a common indicator of a phishing email and is a technique used by phishers to trick users into thinking the email is from a legitimate source."
        if xheader_data.auth_as == "Not Found":
            report.add_reason(
                Reason("Auth As Field", NOT_FOUND, "N/A", "Not Found")
            )
        elif xheader_data.auth_as == "Anonymous":
            report.add_reason(
                Reason("Auth As Field", ANON_EXPL , "Low", "Anonymous")
            )
    
    
    @staticmethod
    def ascribe_risk(value) -> str:
        if value == "Not Found":
            return "N/A"
        else:
            try:            
                value = int(value)
            except ValueError:
                return "N/A"
             
            if value == 0:
                return "N/A"

            elif value > 6:
                return "High"

            elif value > 3:
                return "Medium"

            else:
                return "Low"

        
    
        
        
        
        
    

