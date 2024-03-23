from client_manager import Client
from questionary import Choice, prompt
import sys
from time import sleep



class MenuUI:
    def __init__(self, prompt: str, choices:list) -> None:
        self.prompt = prompt
        self.choices = choices
            
    def _ask(self):
        question = [
            {
                "type": "select",
                "name": "choice",
                "message": self.prompt,
                "choices": self.choices
            }
        ]
        answer = prompt(question)
        return answer["choice"]
    
    def run(self):
        return self._ask()
         
        
class MainMenu(MenuUI):
    TITLE_TEXT = """
***********************************************************************
        _     _     _     _                         _                 
  _ __ | |__ (_)___| |__ (_)_ __   __ _   ___ _ __ (_)_ __   ___ _ __ 
 | '_ \| '_ \| / __| '_ \| | '_ \ / _` | / __| '_ \| | '_ \ / _ \ '__|
 | |_) | | | | \__ \ | | | | | | | (_| | \__ \ | | | | |_) |  __/ |   
 | .__/|_| |_|_|___/_| |_|_|_| |_|\__, | |___/_| |_|_| .__/ \___|_|   
 |_|                              |___/              |_|             
    
                    made by: @rhawk117
        
***********************************************************************
    
"""
    def __init__(self) -> None:
        CHOICES = [
            "[ Load Outlook Inbox ]",
            "[ Analysis Tools ]",
            "[ Help / Tutorial ]",
            "[ Exit Program ]"
        ]
        super().__init__(
            " << Welcome to Phish Sniper, Select an Option To Continue >>",
            CHOICES
        )
        
    def exit_hndler(self) -> None:
       print("[i] Exiting Program... [i]")
       sys.exit()
       
    def help_hndler(self):
        pass
    
    def help_text(self, text: str) -> None:
        print(f'[i] { text } [i]')
        sleep(5)

class FolderMenu(MenuUI):
    def __init__(self, folder_map: dict) -> None:
        self.choices = [Choice(title=f"[ { folder } ]", value=folder) for folder in folder_map.keys()]
        self.prompt = "[ Select a Folder from Outlook to Analyze ]"
        super().__init__(self.prompt, self.choices)



class EmailMenu(MenuUI):
    def __init__(self, emails: list):
        self.current_page: int = 0
        self.page_size: int = 10
        self.num_pages: int = (len(emails)) // self.page_size
        
        self.prompt: str = f'Select an Email From your Inbox (Page {self.current_page + 1}/{self.num_pages})'
        self.emails: list = emails
        self.choices: list = []
    
    def page_options(self):
        if self.current_page > 0:
            self.choices.append(Choice(title="Go Back", value="back"))
            
        if self.current_page < self.num_pages:
            self.choices.append(Choice(title="Next Page", value="next"))
            
        self.choices.append(Choice(title="Return to Main Menu", value="main_menu"))

    def _render_page(self):
        ''''
            Generates a page of the next 10 emails to display
            (god this took so long to figure out...)
        '''

        start_index = self.current_page * self.page_size
        end_index = min(start_index + self.page_size, len(self.emails))
        # COM Objecs are read only, can't slice a list with them
        page_emails = [self.emails[i] for i in range(start_index, end_index)]
        self.map_options(page_emails)
        self.page_options()
        self.prompt: str = f'Select an Email From your Inbox (Page {self.current_page + 1}/{self.num_pages})'

    def map_options(self, page_emails: list):
        self.choices = [Choice(title=self.menu_view(email), value=email) for email in page_emails]

    def menu_view(self, email):
        return f"[ Subject: { email.Subject } | From: { email.SenderEmailAddress } ]"
        

    def _pager(self, choice):
        if choice is None:
            return False # choice should only be None on first iter
        
        if choice == "next":
            self.current_page += 1
            return False

        elif choice == "back":
            self.current_page -= 1
            return False
        
        else: 
            return True
                    
    def run(self):
        choice = None
        while self._pager(choice) == False:
            self._render_page()
            choice = self._ask()
        if choice == "main_menu":
            return None
        
        return choice
    
    
    
class EmailViewer(MenuUI):
    def __init__(self, email_obj) -> None:
        CHOICES = [
            Choice(title="[ View Contents ]",  value="views"),
            Choice(title="[ Analyze Body ]",  value="urls"),
            Choice(title="[ Analyze Header ]", value="header"),
            Choice(title="[ Analyze Domain ]",  value="whois"),
            Choice(title="[ Analyze All ]", value="all"),
            Choice(title="[ Go Back ]", value="back"),
        ]
        super().__init__(
            "[ Select Analysis Action to perform on Email ]",
            CHOICES
        )
        self.email = email_obj
        
        
class Views:
    def __init__(self) -> None:
        CHOICES = [
            Choice(title="[ View Header ]", value="header"),
            Choice(title="[ View Body ]", value="body"),
            Choice(title="[ View WhoIs ]", value="whois"),
            Choice(title="[ View Email Contents ]", value="content"),
            Choice(title="[ Go Back ]", value="back")
        ]
        super().__init__(
            "[ What would you like to view ]",
            CHOICES
        )
        

        



        
    

def testMainMenu():
    mainMenu = MainMenu()
    mainMenu.run()

def testEmailMenu():
    client = Client()
    if not client.safe_load():
        print("[!] Failed to load client... [!]")
        sys.exit()
    emailMenu = EmailMenu(
        client.emails
    )
    
    email = emailMenu.run()
    print(email.Body)

# Rough Idea (rn)
'''
- have a "master" class with the list of UI components 
- have an action chain of possible user interactions 
- have a "main" function that runs the UI components with the 
  logic classes that do the analysis of emails 

NOTE
- run() method should be the entry point for the UI components
'''
def main() -> None:
    # testMainMenu()
    # testEmailMenu()
    client = Client()
    if not client.safe_load():
        print("[!] Failed to load client... [!]")
        sys.exit()
    folder_menu = FolderMenu(client.clientFolders)
    choice = folder_menu.run()
    folder_contents = client.get_folder_emails(choice)
    email_selection = EmailMenu(folder_contents)
    email = email_selection.run()
    


if __name__ == "__main__":
    main()
