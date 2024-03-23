from client_manager import Client
from datetime import datetime
import whois
from dataclasses import dataclass
import os 
import re
from pprint import pprint
from email.parser import HeaderParser
import json 
  


def client_folders(client):
    root = client.outlook.Folders
    print(type(root))
    



def main():
    client = Client()
    if not client.safe_load():
        return 
    email = client.emails
    json_data = []
    client_folders(client)
        
        
        

def save_data(data):
    with open("sample.json", "w") as file:
        json.dump(data, file, indent=4)

def test_data_objects(emails):
    pass
    # for i in range(5):
    #     header = email[i].PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
    #     data = [
    #      HeaderInfo(header).data(),
    #      XHeaderInfo(header).data(),
    #      AuthResults(header).data()
    #     ]  
    #     for d in data:
    #         d.display()

if __name__ == "__main__":
    main()