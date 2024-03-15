import questionary
import curses



class MenuUI:
    def __init__(self, prompt, choices, evnt_hndler) -> None:
        self.prompt = prompt
        self.choices = choices
        self.evnt_hndler = evnt_hndler
    
    def run(self):
        choice = questionary.select(
            self.prompt,
            choices=self.choices
        ).ask()
        self.evnt_hndler(choice)
        
    
    
    
    

class MainMenu(MenuUI):
    def __init__(self) -> None:
        super().__init__(
            prompt="Main Menu:",
            options=[
                "Load Outlook Inbox",
                "Paste Email Header",
                "Help / Tutorial",
                "Exit Program"
            ]
        )
        
    def handler(self, response):
        if response == "Option 1: Do something":
            # Handle Option 1
            print("Doing something...")
        elif response == "Option 2: Do something else":
            # Handle Option 2
            print("Doing something else...")
        elif response == "Exit":
            # Exit the program
            print("Exiting...")
        else:
            print("Invalid option")


def main() -> None:
    main_menu = MainMenu()
    response = main_menu.run()
    main_menu.handler(response)


if __name__ == "__main__":
    main()
