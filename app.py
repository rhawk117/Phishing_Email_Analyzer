import os 
from ui_components import MainMenu, EmailMenu, EmailViewer
from client_manager import Client


class App:
    def __init__(self) -> None:
        self.ui = UIComponents()
    
    def run(self) -> None:
        pass

class UIComponents:
    def __init__(self, client):
        self.main_menu: MainMenu = MainMenu(self)
        self.email_menu: EmailMenu = None
        self.email_viewer: EmailViewer = None

    def start(self):
       choice = self.main_menu.run()
       self.main_menu_hndler(choice)
        
        
        
    def main_menu_hndler(self, choice):
        if choice == "[ Load Outlook Inbox ]":
            self.get_client()

        elif choice == "[ Paste Email Header ]":
            raise NotImplementedError

        elif choice == "[ Help / Tutorial ]":
            raise NotImplementedError
        
        elif choice == "[ Exit Program ]":
            self.main_menu.exit_hndler()
    
    def get_client(self):
        user_agent = Client()
        did_load = user_agent.safe_load()
        if did_load:
            self.user_client = user_agent
            self.render_emailMenu()
        else:
            print("[!] Failed to load user client, returning to main menu...")
            self.start()
            
    def set_email_menu(self):
        prompt = "[i] Select an Email To Analyze [i]"
        self.email_menu = EmailMenu(prompt, self.user_client.emails)
    
    def render_emailMenu(self):
        self.set_email_menu()
        action = self.email_menu.run()
        if action is None:
            self.start()
        else:
            pass
    
    def render_emailViewer(self, email_to_load):
        pass

# generic base class containing all the data and methods needed for the UI for paste & load client
class UIBackend:
    def __init__(self):
        self.domain_db = DomainDB()
    
        
        

        