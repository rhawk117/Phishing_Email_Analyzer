from typing import Any
import win32com.client
import logging


class Client:
    def __init__(self) -> None:
        self.safe_load()

    def load(self):
        self.outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        self.inbox = self.outlook.GetDefaultFolder(6)  # 6 corresponds to the Inbox
        self.emails = self.inbox.Items

    def close(self): 
        self.outlook.Quit()

    def safe_load(self):
        try:
            self.load()
            return True
        except Exception as e:
            print("[!] Failed to load Outlook, for more information check program logs.")
            return False
    


    
    
            
def main() -> None:
    client = Client()
    client.load()
    

if __name__ == "__main__":
    main()
