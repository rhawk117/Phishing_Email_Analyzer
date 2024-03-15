from typing import Any
import win32com.client
import logging
from bs4 import BeautifulSoup, NavigableString, Tag
import re
import textwrap
from email_parse import ParsedEmail
import shutil

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

    def _strip_html(self, html: str) -> str:
        """Convert HTML to clean text, preserving links, improving formatting, and wrapping text."""
        soup = BeautifulSoup(html, 'html.parser')

        # Process each anchor tag; replace with its text and URL
        for a in soup.find_all('a', href=True):
            href = a['href']
            if a.string:
                a.replace_with(f" {a.string} [ URL {href} ]")
            else:
                a.replace_with(href)

        # Get text from soup and normalize whitespaces
        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        clean_text = "\n".join(lines)

        # Determine console width and wrap text
        console_width = shutil.get_terminal_size((80, 20))[0]  # Default to 80 if unable to determine
        wrapped_text = "\n".join([textwrap.fill(line, width=console_width) for line in clean_text.split('\n')])

        return wrapped_text

    def display_email(self, anEmail):
        parser = ParsedEmail(anEmail)
        parser.display()

    def display_emails(self):
        for email in self.emails:
            self.display_email(email)
            input('*** Press Enter to continue ***')



def main() -> None:
    client = Client()
    if client.safe_load():
        client.display_emails()
    client.close()

if __name__ == "__main__":
    main()
