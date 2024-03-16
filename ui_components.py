import questionary
import curses
from client_manager import Client
from email_parse import ParsedEmail

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
                "Load Outlook Inbox",
                "Paste Email Header",
                "Help / Tutorial",
                "Exit Program"
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
        start_index = self.current_page * self.page_size
        end_index = min(start_index + self.page_size, len(self.emails))
        page_emails = [self.emails[i] for i in range(start_index, end_index)]
        self.choices = [self._generate_email_str(email) for email in page_emails]
        self.menu_map = dict(zip(self.choices, page_emails))
        self.page_options()
    
    

    def _generate_email_str(self, email):
        return_str = f"\n| SUBJECT: {email.Subject} ({email.SentOn})\n"
        return_str += f" | SENDER: {email.SenderName}\n"
        return_str += f" | ADDRESS: {email.SenderEmailAddress}"
        return return_str

    

    def _hndler(self, choice):
        if choice is None:
            return False
        
        if choice == "Next Page":
            self.current_page += 1
            return False

        elif choice == "Go Back":
            self.current_page -= 1
            return False
        else:
            return True
            

    def _bounce(self):
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
            self.MainMenu.run()
            return None
        
        return self.menu_map[choice]
    

class EmailViewer(MenuUI):
    def __init__(self, parser_obj: ParsedEmail, emailMenu: EmailMenu) -> None:
        self.prompt = "<< Select an Action >>"
        self.choices = ["[ View Contents (Body) ]", "[ View URLs ]", "[ View Email Header ]", "[ Go Back ]"]
        self.email_data = parser_obj
        self.email_menu = emailMenu
    
    def construct_prompt(self, email_str):
        prompt = "<< Select Desired Action On Email >>"
    
    def go_back(self):
        input("Press Enter to go back...")
        self.email_menu.run()
    
    def _hndler(self, response):
        if response == "[ View Contents (Body) ]":
            print(self.email_data.display_str())
        
        elif response == "[ View URLs ]":
            print("[i] Loading URLs... [i]")
            self.email_data.view_urls()
            
        
        elif response == "[ View Email Header ]":
            print("[i] Loading Email Header... [i]")
            self.email_data.display_header()
        
        elif response == "[ Go Back ]":
            self.email_menu.run()
        
        else:
            raise Exception("Invalid unhandled option selected!")


    

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
    parsed_email = client.parsed_email(email)
    if parsed_email is None:
        return 
    email_viewer = EmailViewer(parsed_email, emailMenu)
    email_viewer.run()
    
    
def main() -> None:
    # testMainMenu()
    testEmailMenu()
    
    


if __name__ == "__main__":
    main()
