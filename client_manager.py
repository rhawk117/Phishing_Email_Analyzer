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
        self.folders = olHelper.get_email_folders(self)
        return olHelper.map_folders(self.folders)
    
    def get_folder_emails(self, folder_name: str) -> list | None:
        if not self.outlook:
            return None
        folder = self.clientFolders.get(folder_name)
        if not folder:
            return None
        return self.get_emails(folder)
        

    def get_emails(self, folder_obj) -> set | None:
        if not self.outlook or not folder_obj:
            return None
        return list(filter(lambda x: x.Class == 43, folder_obj.Items)) 


class olHelper:
    '''
        to anyone stumbling across this code this is the only working
        way i've found to (relatively) EFFICIENTLY retrieve all email 
        folders in outlook.
        
        there is NO documentation or methods in win32com.client to do this
        and it took me a while to figure out such a simple method you think
        would be built in. 
    '''
    
    @staticmethod
    def get_email_folders(client: Client):
        root = client.outlook.Folders.Item(1)
        return olHelper.walk_outlook(root)
        
    @staticmethod            
    def walk_outlook(folder, email_folders=None):
        
        if email_folders is None: email_folders = []
                
        email_folders.append(folder)

        for subfolder in folder.Folders:
            if not olHelper.has_email_items(subfolder):
                continue
            olHelper.walk_outlook(subfolder, email_folders)

        return email_folders    
    
    @staticmethod   
    def has_email_items(folder) -> bool:
        try:
            # restrict items to "IPM.Note" to quickly check for emails
            emails = folder.Items.Restrict("[MessageClass]='IPM.Note'")
            return emails.Count > 0
        except:
            return False
    
    @staticmethod
    def map_folders(folders) -> dict:
        return {folder.Name: folder for folder in folders}



    
    
            
def main() -> None:
    client = Client()
    client.safe_load()
    f = olHelper.get_email_folders(client)
    for i in f:
        print(i.Name)

if __name__ == "__main__":
    main()
