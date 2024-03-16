from typing import Any
import win32com.client
import logging
from bs4 import BeautifulSoup, NavigableString, Tag
import re
import textwrap
import shutil
from urllib.parse import urlparse, parse_qs, unquote


class ParsedEmail:
    def __init__(self, emailObject) -> None:
        self.email_obj = emailObject
        self._body = emailObject.Body
        self.urls = self.extract_urls()
        self.header = self.email_obj.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")

    def decode_safelink(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        if original_url:
            return unquote(original_url)
    
    def extract_urls(self):
        soup = BeautifulSoup(self._body, "html.parser")
        for link in soup.find_all('a'):
            url = link.get('href')
            if url:
                if "safelinks.protection.outlook.com" in url:
                    url = self.decode_safelink(url)
                self.urls.append(url)


    def display_str(self):
        return f"""
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
| Subject Line: { self.email_obj.Subject }                                                |
| From: { self.email_obj.SenderEmailAddress }                                             | 
| Date: { self.email_obj.SentOn }                                                         |
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *   
   Contents 
   
   { self._body }     
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
        """
    
    
    
    def view_urls(self):
        print("\t\t\t[ URLS FOUND ]")
        for url in self.urls:
            print(f"\t=> { url }")
    
    def display_header(self):
        print(f"\t\t\t[ HEADER ]\n{ self.header }")
