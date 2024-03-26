import os 
import ui_components as UI
from client_manager import Client
import analysis.analysis_results as Analyzer
import analysis.analyze_misc as MiscData
from analysis.analysis_results import EmailData as Results


class App:
    def __init__(self) -> None:
        self.ui = UIComponents()
    
    def run(self) -> None:
        pass

class UIComponents:
    def __init__(self, client):
        self.main_menu: UI.MainMenu = UI.MainMenu(self)
        self.email_menu: UI.EmailMenu = None
        self.email_viewer: UI.EmailViewer = None
        self.folder_viewer: UI.FolderViewer = None
        self.layer: UI.MenuUI = None
        self.user_agent: Client = None
        
    def start(self):
       choice = self.main_menu.run()
       self.main_menu_hndler(choice)
        
    def main_menu_hndler(self, choice):
        if choice == "[ Load Outlook ]":
            self.ol_flow_control()
            
        elif choice == "[ Help / Tutorial ]":
            self.main_menu.help_handler()
                    
        elif choice == "[ Exit Program ]":
            self.main_menu.exit_hndler()
    
    def get_client(self):
        if self.user_agent is None:
            self.user_agent = Client()
            return self.user_agent.safe_load()
        return True
    
    def folder_select(self, client: Client):
        folder_map = client.clientFolders
        self.folder_select = UI.FolderSelect(folder_map)
        return self.folder_select.run()
    
    def get_folder(self):
        if not self.get_client():
            print("[!] Failed to Load Outlook Client")
            return False
        user_folder = self.folder_select(self.user_client)
        if user_folder == "back":
            return False 
        folder_contents = self.user_client.get_folder_emails(user_folder)
        self.email_menu = UI.EmailMenu(folder_contents)
        
        
    def ol_flow_control(self):
        if not self.get_folder():
            self.start()
        else:
            self.email_flow_control()
    
    
    def email_flow_control(self):
        email = self.email_menu.run()
        if email == "back":
            self.ol_flow_control()
        else:
            pass
    
    def email_actions(self, email):
        self.email_viewer = UI.EmailActions(email)
        choice = self.email_viewer.run()
        if choice == "back":
            self.email_flow_control()
            
        elif choice == "views":
            self.view_control(email)
            
        elif choice == "anlyze":
            self.analyze_control(email)
            
    def view_control(self, email, body_info: MiscData.BodyInfo = None):
        self.viewer = UI.ViewerUI(email)
        choice = self.viewer.run()
        if choice == "back":
            self.email_actions(email)
        else:
            if body_info is None:
                body_info = MiscData.BodyInfo(email)
            self.viewer_hndler(
                choice, body_info
            )
    
    def viewer_hndler(self, choice: str, body_info: MiscData.BodyInfo) -> None:
        if choice == "body":
            body_info.view_body()
            
        elif choice == "header":
            hdr = self.user_agent.get_header(body_info.email)
            body_info.view_header(hdr)
            
        elif choice == "urls":
            body_info.view_urls()
            
        input("[ Press Enter to Continue ]")
        self.view_control(body_info.email, body_info)
        
    def analyze_control(self, email):
        analyze = UI.AnalyzeUI(email)
        choice = analyze.run()
        if choice == "back":
            self.view_control()
        else:
            self.report_control(
                self.handle_analysis(choice, email)
                , email
            )
             
        
    def handle_analysis(self, choice: str, email):
        print(f"[i] Performing a { choice.title() } analysis and generating a report...")
        if choice == "body":
            report = Results.analyze_body(email)

        elif choice == "header":
            report = Results.analyze_headers(email)

        elif choice == "domain":
            report = Results.analyze_whois(email)

        elif choice == "url":
            report = Results.analyze_urls(email)

        elif choice == "all":
            report = Results(email).analyze_all()
            
        return report
    
    def report_control(self, report, email) -> None:
        reportUI = UI.ReportUI()
        choice = reportUI.run()
        if choice == "back":
            self.analyze_control(email)
            
        elif choice == "view":
            
        elif choice == "save":
            pass
    
    def report_types(self, report):
        if isinstance(report, list):
            pass
        else:
            
            
    
            
        
    
    
        
            
    

        