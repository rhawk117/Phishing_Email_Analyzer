from analyze_header import AnalyzeMaster
from analysis_template import Report
from header_parser import XHeaderInfo, HeaderInfo, AuthResults
from analyze_misc import WhoIsInfo, WhoIsAnalyzer, BodyInfo, BodyAnalyzer, URLAnalysis
from pathlib import Path
import sys 

class EmailData:
    
    # when analyze all is selected we need an object to keep track of everything
    def __init__(self, email_object) -> None:
        
        self.xheader_report, self.auth_report = EmailData.analyze_headers(email_object)
        
        self.whois_report = EmailData.analyze_whois(email_object)
        self.body_report = EmailData.analyze_body(email_object)
        self.url_report = EmailData.analyze_urls(email_object)

    
    @staticmethod
    def analyze_headers(email_object) -> tuple:
        header_str = EmailData.get_header(email_object)
        
        xheader_report = EmailData.analyze_xheaders(email_object, header_str)
        auth_report = EmailData.analyze_auth(email_object, header_str)
        return (xheader_report, auth_report)
        
    @staticmethod
    def analyze_xheaders(email_object, header="") -> Report:
        if header == "":
            header = EmailData.get_header(email_object)
        info = XHeaderInfo(header)
        return AnalyzeMaster.analyze_xheaders(info)

    @staticmethod
    def get_header(email) -> str:
        return email.PropertyAccessor.GetProperty(
            "http://schemas.microsoft.com/mapi/proptag/0x007D001E"
        )
    
    @staticmethod
    def analyze_auth(email_object, header="") -> Report:
        if header == "":
            header = EmailData.get_header(email_object)
            
        header = EmailData.get_header(email_object)
        info = AuthResults(header)
        return AnalyzeMaster.analyze_auth_results(info)
        
    def analyze_all(self) -> list[Report]:
        return [
            self.xheader_report,
            self.auth_report,
            self.body_report,
            self.url_report,
            self.whois_report
        ]
        
    @staticmethod
    def analyze_whois(email_object) -> Report:
        sender = email_object.SenderEmailAddress
        whois_data = WhoIsInfo(sender)
        if not whois_data.did_query():
            return None
        return WhoIsAnalyzer.analyze(whois_data)
    
    @staticmethod
    def analyze_body(email_object) -> Report:
        info = BodyInfo(email_object.Body)
        return BodyAnalyzer.analyze(info)
    
    @staticmethod
    def analyze_urls(email_object):
        info = BodyInfo(email_object.Body)
        if not info.urls:
            print("[!] No URLs were found in the body to analyze..")
            return None 
        return URLAnalysis.analyze_all(info)
    
class Output:
    
    @staticmethod 
    def console_output(report: Report):
        Output.iter_reports(report)

    
    @staticmethod
    def iter_reports(self, report):
        if not isinstance(report, list):
            Output.console_output(report)
            return
        for r in report:
            if not isinstance(report, list):
                Output.console_output(r)
                continue
            Output.iter_reports(r)
    
    @staticmethod 
    def export(report: Report | list[Report]):
        exe_path = Path(sys.argv[0]).parent.absolute()
        Report.export(report, exe_path)
    
    
        
        

