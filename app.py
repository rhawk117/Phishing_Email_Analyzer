import os 
from ui_components import MainMenu, EmailMenu, EmailViewer



class App:
    def __init__(self) -> None:
        pass
    
    def run(self) -> None:
        pass

class UIComponents:
    def __init__(self, client):
        self.client = client
        self.main_menu = MainMenu(self)
        self.email_menu = EmailMenu(self)
        self.email_viewer = EmailViewer(self)
