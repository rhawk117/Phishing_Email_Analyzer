from client_manager import Client
from email_parse import Email, DetailedEmail
import questionary

class MenuUI:
    def __init__(self, prompt, choices) -> None:
        self.prompt = prompt
        self.choices = choices
        
    
    def _get_choice(self):
        return questionary.select(
            self.prompt,
            choices=self.choices
        ).ask()
    
    def run(self):
        usrSlct = self._get_choice()
        self._hndler(usrSlct)
         
    def _hndler(self, response):
        pass

        
class MainMenu(MenuUI):
    def __init__(self) -> None:
        CHOICES = [
                "[ Load Outlook Inbox ]",
                "[ Paste Email Header ]",
                "[ Help / Tutorial ]",
                "[ Exit Program ]"
        ]
        
        super().__init__(
            "<< SELECT AN OPTION TO CONTINUE >>",
            CHOICES
        )
        
    def _hndler(self, response):
        if response == "Option 1: Do something":
            print("Doing something...")

        elif response == "Option 2: Do something else":
            print("Doing something else...")

        elif response == "Exit":
            print("Exiting...")

        else:
            print("Invalid option")



class EmailMenu(MenuUI):
    def __init__(self, prompt: str, emails: list, mainMenu: MainMenu):
        self.prompt: str = prompt
        self.emails: list = emails
        self.MainMenu: MainMenu = mainMenu
        self.current_page: int = 0
        self.page_size: int = 10
        self.num_pages: int = (len(emails)) // self.page_size
        
        self.choices: list = []
        self.menu_map: dict = {}
    
    def page_options(self):
        if self.current_page > 0:
            self.choices.append("Go Back")
            
        if self.current_page < self.num_pages:
            self.choices.append("Next Page")
            
        self.choices.append("Return to Main Menu")

    def _render_page(self):
        ''''
            Generates a page of the next 10 emails to display
            (god this took so long to figure out...)
        '''
        start_index = self.current_page * self.page_size
        end_index = min(start_index + self.page_size, len(self.emails))
        page_emails = [Email(self.emails[i]) for i in range(start_index, end_index)]
        self.choices = [email.menu_view() for email in page_emails]
        self.menu_map = dict(zip(self.choices, page_emails))
        self.page_options()


    def _hndler(self, choice):
        if choice is None:
            return False # choice should only be None on first iter
        
        if choice == "Next Page":
            self.current_page += 1
            return False

        elif choice == "Go Back":
            self.current_page -= 1
            return False
        else: # choice is an email, end pager
            return True
            

    def _bounce(self):
        '''
        ensures that we don't have a buffer overflow and
        fall into the "gap of death"
        '''
        if self.current_page == self.num_pages:
            self.current_page = 0
            
    def run(self):
        choice = None
        while self._hndler(choice) == False:
            self._render_page()
            choice = self._get_choice()
            self._bounce()
            
        # since choice isn't in the menu_map
        if choice == "Return to Main Menu":
            self.MainMenu.run() # place holder for now
            return None
        
        return self.menu_map[choice]
    
class EmailViewer(MenuUI):
    def __init__(self, email_data: Email, emailMenu: EmailMenu) -> None:
        CHOICES = [
            "[ View Contents (Body) ]", 
            "[ View URLs ]", 
            "[ View Email Header ]",
            "[ View WHOIS Information ]", 
            "[ Go Back ]"
        ]
        self.Data = DetailedEmail(email_data)
        
    def _hndler(self, response):
        if response == "View Contents (Body)":
            print(self.Data.body)
            input("Press Enter to continue...")
            
        elif response == "View URLs":
            print(self.Data.urls)
        elif response == "View Email Header":
            print(self.Data.header)
            
        elif response == "View WHOIS Information":
            print(self.Data.view_whois())
            
        elif response == "Go Back":
            print("Going back...")
        
    


    

def testMainMenu():
    mainMenu = MainMenu()
    mainMenu.run()

def testEmailMenu():
    client = Client()
    emailMenu = EmailMenu(
        "Select an email to view",
        client.emails,
        MainMenu()
    )
    
    email = emailMenu.run()
    email_viewer = EmailViewer(email, emailMenu)
    email_viewer.run()
    

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
    testEmailMenu()
    
    


if __name__ == "__main__":
    main()
