


class Reason:
    def __init__(self, name: str, val, reason: str, score_incr: int) -> None:
        self.field_name = name
        self.field_value = val
        if self.none_reason(reason):
            return
        self.score_amm: int = score_incr
        self.detr_risk()
    
    def none_reason(self, rzn):
        if self.field_value is None:
            self.reason = f"ERROR: Failed to get Data for { self.field_name }"
            self.score_amm = 0
            self.risk_level = "Low"
            return True
        else:
            self.reason = rzn
            return False
            
    
    def detr_risk(self):
        if self.score_amm <= 1:
            self.risk_level = "Low"

        elif self.score_amm <= 3:
            self.risk_level = "Medium"

        else:
            self.risk_level = "High"
    
    def __str__(self) -> str:
        return f"{ self.field_name } - { self.field_value }\n[+] Score Increase: {self.score_amm}\n[>] Reason: { self.reason }\n[!] Risk Level: { self.risk_level }\n"
        

class Report:
    def __init__(self, type: str, who: str) -> None:
        self.reasons: list[Reason] = []
        self.score: int = 0
        self.title = f"{ type }_report_of_{ who }"
    
    def add_reason(self, reason: Reason):
        self.reasons.append(reason)
        self.score += reason.score_amm
    
    def export_report(self):
        file_name = f"{ self.title }.txt"
        with open(file_name, 'w') as file:
            file.write(str(self))
    
    def short_report(self):
        print(f"*** { self.title } ***\nTotal Score: { self.score }\n")
        for reason in self.reasons:
            print(f"{ reason.field_name } - { reason.score_amm } [ { reason.risk_level } ]")
            print("\n")
            input("[ Press Enter to Continue ]")
            
    def __str__(self) -> str:
        report = ""
        for reason in self.reasons:
            report += f"\n { reason } {'-' * 50 }\n"
        return report
     
