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

class Pager:
    def __init__(self, num_options: int):
        self.page_size = 10
        self.cur_page = 0
        self.max_pages = num_options // self.page_size
    
    def Next(self):
        if self.cur_page < self.max_pages:
            self.cur_page += 1
        else:
            self.cur_page = 0

class EmailMenu(MenuUI):
    def __init__(self, prompt: str, emails: list):
        self.prompt: str = prompt
        self.emails: list = emails
        
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

    def _render_page(self):
        start_index = self.current_page * self.page_size
        end_index = min(start_index + self.page_size, len(self.emails))
        page_emails = [self.emails[i] for i in range(start_index, end_index)]
        self.choices = [self._generate_email_str(email) for email in page_emails]
        self.menu_map = dict(zip(self.choices, page_emails))
        self.page_options()
    
    

    def _generate_email_str(self, email):
        format_str = "-" * 50
        return_str = f"\n| SUBJECT: {email.Subject} ({email.SentOn})\n"
        return_str += f" | SENDER: {email.SenderName}\n"
        return_str += f" | ADDRESS: {email.SenderEmailAddress}\n{format_str}"
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
            print("[i] Loading Email.. [i]")
            return True

    def _bounce(self):
        if self.current_page == self.num_pages:
            self.current_page = 0
            
    def run(self):
        choice = None
        while self._hndler(choice) == False:
            self._render_page()
            choice = self._get_choice()
            self._hndler(choice)
            self._bounce()
            
        return self.menu_map[choice]
            
    

def testMainMenu():
    mainMenu = MainMenu()
    mainMenu.run()

def testEmailMenu():
    client = Client()
    emailMenu = EmailMenu(
        "Select an email to view",
        client.emails
    )
    email = emailMenu.run()
    msg = client.display_detailed_email(email)
    
    print(msg)
    
def main() -> None:
    # testMainMenu()
    testEmailMenu()
    
    


if __name__ == "__main__":
    main()
