from dataclasses import dataclass
import os 
from datetime import datetime as dt

@dataclass
class Reason:
    title: str
    explain: str
    risk_level: str
    value: str

    def score_risk(self) -> int:    
        if self.risk_level == "N/A":
            return 0
        
        elif self.risk_level == "Low":
            return 1
        
        elif self.risk_level == "Medium":
            return 2
        
        else:
            return 3
        
        
    def __str__(self) -> str:
        return f"\n[>] { self.name } | { self.risk_level } [<]\n[i] REASON: { self.explain }\n"


  

class Report:
    def __init__(self, type: str) -> None:
        self.reasons: list[Reason] = []
        self.score: int = 0
        self.title = f"{ type }_report"
    
    def add_reason(self, reason: Reason):
        self.reasons.append(reason)
        self.score += reason.score_risk()
    
    @staticmethod
    def export_path_checks(report, output_path: str) -> bool:
        if not os.path.exists(output_path):
            os.mkdir(output_path)
            
        file_n = f"{ report.title }_{ dt.now() }.txt"
        path = os.path.join(output_path, file_n)
        return path
    
    @staticmethod
    def export(report, output_path: str) -> bool:
        path = Report.export_path_checks(report, output_path)
        content = ""
        if isinstance(report, list):
            content = [f'{ r }\n\n' for r in report]
        else:
            content = str(report)
        try:
            Report._export(path, content)
        except Exception as e:
            print(f"[!] Error exporting report: { e }")
            
        
    def _export(self, path, content):
        with open(path, "w") as file:
            file.write(content)
    
    
    def console_report(self):
        total = len(self.reasons * 3)
        print(f"*** { self.title } ***\nTotal Score: { self.score } / { total }\n")
        for reason in self.reasons:
            input(f"{ reason } \n[ Press Enter to Continue ]")
    
    def __str__(self) -> str:
        report = ""
        for reason in self.reasons:
            report += f"\n { reason } {'-' * 50 }\n"
        return report
     
