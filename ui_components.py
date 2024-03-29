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
            "[ Load Outlook ]",
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
        choices = [Choice(title=f"[ { name } ]", value=val) for name, val in folder_map.items()]
        choices.append(Choice(title="[ Go Back ]", value="back"))
        prompt = "[ Select a Folder from Outlook to Open ]"
        super().__init__(prompt, choices)
        



class EmailMenu(MenuUI):
    def __init__(self, emails: list):
        self.current_page: int = 0
        self.page_size: int = 10
        self.num_pages: int = (len(emails)) // self.page_size
        
        self.prompt: str = f'[i] Select an Email From your Inbox (Page { self.current_page + 1 }/{ self.num_pages })'
        self.emails: list = emails
        self.choices: list = []
    
    def page_options(self):
        if self.current_page > 0:
            self.choices.append(Choice(title="Go Back", value="back"))
            
        if self.current_page < self.num_pages:
            self.choices.append(Choice(title="Next Page", value="next"))
            
        self.choices.append(Choice(title="Return to Folder Selection", value="folder"))

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
        if choice == "folder":
            return None
        return choice
    
    
    
class EmailActions(MenuUI):
    def __init__(self, email_obj) -> None:
        CHOICES = [
            Choice(title="[ View ]",  value="views"),
            Choice(title="[ Analyze ]", value="anlyze"),
            Choice(title="[ Go Back ]", value="back"),
        ]
        super().__init__(
            "[ Select an Action to perform on Email ]",
            CHOICES
        )
        self.email = email_obj

class ViewerUI(MenuUI):
    def __init__(self, an_email) -> None:
        self.email = an_email
        CHOICES = [
            Choice(title="[ View Body ]", value="body"),
            Choice(title="[ View Header ]", value="header"),
            Choice(title="[ View URLs ]", value="urls"),
            Choice(title="[ Go Back ]", value="back")
        ]
        super().__init__(
            "[ Select an Option to View ]",
            CHOICES
        )

        
class AnalyzeUI(MenuUI):
    def __init__(self, email_obj) -> None:
        CHOICES = [
            Choice(title="[ Body Analysis ]", value="body"),
            Choice(title="[ Header Analysis ]", value="header"),
            Choice(title="[ Domain Analysis ]", value="domain"),
            Choice(title="[ URL Analysis (limited) ]", value="url"),
            Choice(title="[ Detailed Analysis (All)]", value="all"),
            Choice(title="[ Go Back ]", value="back"),
        ]
        super().__init__(
            "[ Select an Analysis Tool ]",
            CHOICES
        )
        self.email = email_obj
        
class ReportUI(MenuUI):
    def __init__(self):
        CHOICES = [
            Choice(title="[ View Results ]", value="view"),
            Choice(title="[ Save Report ]", value="save"),
            Choice(title="[ Go Back ]", value="back")
        ]
        super().__init__(
            "[ Select an Action to perform on Email ]",
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
    from email.parser import HeaderParser
    from email.utils import parseaddr
    if not client.safe_load():
        print("[!] Failed to load client... [!]")
        sys.exit()
    inbox = client.inboxContents
    for i in inbox:
        header =  i.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")       
        parser = HeaderParser().parsestr(header)
        return_p = parser.get('Return-Path')
        if "bounce" in return_p or "*" in return_p:
            print(f"Return Path: {return_p.split("@")[1]}")
        else:
            print(f"Return Path: {return_p}")
        input()

if __name__ == "__main__":
    main()
