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
        self._body = emailObject.HTMLBody if hasattr(emailObject, 'HTMLBody') else emailObject.Body
        self.urls = []  
        self.dirty_urls = []  
        self.clean_body = self.parse_body()   
        self.header = self.email_obj.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")

    def decode_safelink(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        original_url = query_params.get('url', [None])[0]
        if original_url:
            return unquote(original_url)

    def parse_body(self):
        rmved_html = self.strip_html(self._body)
        return self.clean_text(rmved_html)   

    def a_tag_rmver(self, a: Tag) -> str:
        url = a['href']
        self.dirty_urls.append(url)   
        
        if "safelinks.protection.outlook.com" in url:
            cleaned_url = self.decode_safelink(url)  
            self.urls.append(cleaned_url)   
            url = cleaned_url  

        if a.string:
            a.replace_with(f"{a.string} [URL: {url}]")
        else:
            a.replace_with(f"[URL: {url}]")

    def strip_html(self, html: str) -> str:
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            self.a_tag_rmver(a)
        return soup.get_text(separator="\n")

    def clean_text(self, text: str) -> str:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        replaced = "\n".join(lines)
        console_width = shutil.get_terminal_size().columns  # Use console width directly
        wrapped_text = "\n".join([textwrap.fill(line, width=console_width) for line in replaced.split('\n')])
        return wrapped_text

    def display(self):
        print("===============================================")
        print(f"[ SUBJECT: { self.email_obj.Subject } ]")  # Use .Subject
        print(f"[ FROM: { self.email_obj.SenderEmailAddress } ]")
        print(f"[ SENDER ADDRESS: { self.email_obj.SenderName } ]")
        print(f"[ RECEIVED: { self.email_obj.ReceivedTime } ]")
        print("===============================================")
        print("*** BODY ***".center(80))
        print(self.clean_body)
        print("===============================================")
        print("*** UNPARSED URLs ***".center(80))
        for url in self.dirty_urls:
            print(url)
        print("===============================================")
        print("*** PARSED URLs ***".center(80))
        for url in self.urls:  # Ensure this list is populated with clean URLs
            print(url)
