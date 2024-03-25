import os 
import ui_components as UI
from client_manager import Client


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
        
        
    def start(self):
       choice = self.main_menu.run()
       self.main_menu_hndler(choice)
        
    def main_menu_hndler(self, choice):
        if choice == "[ Load Outlook ]":
            self.outlook_interactions()
            
        elif choice == "[ Help / Tutorial ]":
            self.main_menu.help_handler()
                    
        elif choice == "[ Exit Program ]":
            self.main_menu.exit_hndler()
    
    def get_client(self):
        self.user_agent = Client()
        return self.user_agent.safe_load()
    
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
            self.email_menu.run()
            
    
        
        
        
    
    
        
            
    

        