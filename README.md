# Outlook Phishing Email Analyzer
--------------------------------
Python Console UI that is directly linked to Outlook. In order for the program to work, you must be on Windows and have Outlook installed as this program uses the Python win32com.client library to directory interect
with Outlook. The project is still in development and likely will be for a while. The UI works (kinda) however I'm still working on the ranking criteria as it's too broad right now. Considering how suspicious / phishing emails tend to be non-linear 
you can really only analyze the header, x header and authentication results (DKIM, DMARC, SPF).  
