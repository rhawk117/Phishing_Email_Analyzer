from typing import Any
import win32com.client
import logging


class Client:
    def load(self):
        self.outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        self.inbox = self.outlook.GetDefaultFolder(6)  # 6 corresponds to the Inbox
        
    def close(self): 
        if self.outlook:
            self.outlook.Quit()

    def safe_load(self):
        try:
            self.load()
            return True
        except Exception as e:
            print("[!] Failed to load Outlook, for more information check program logs.")
            return False
    
    @property
    def inboxContents(self) -> Any | None:
        if not self.outlook:
            return None
        return self.inbox.Items
    
    @property
    def clientFolders(self) -> dict | None:
        if not self.outlook:
            return None
        folder_schema = {}
        for folders in self.outlook.Folders.Folders:
            print(folders.Name)
            folder_schema[folders.Name] = folders
        return folder_schema
    
    
    def get_folder_emails(self, folder_name: str) -> set | None:
        if not self.outlook:
            return None
        folder = self.clientFolders.get(folder_name)
        if not folder:
            return None
        return self.get_emails(folder)
        

    def get_emails(self, folder_obj) -> set | None:
        if not self.outlook or not folder_obj:
            return None
        return set(filter(lambda x: x.Class == 43, folder_obj.Items)) 


    
    
            
def main() -> None:
    client = Client()
    client.load()
    

if __name__ == "__main__":
    main()
