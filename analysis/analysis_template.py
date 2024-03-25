
from dataclasses import dataclass

@dataclass
class Reason:
    title: str
    explain: str
    risk_level: str
    value: str

    def score_risk(self):    
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
    
    def export_report(self):
        file_name = f"{ self.title }.txt"
        with open(file_name, 'w') as file:
            file.write(str(self))
    
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
     
