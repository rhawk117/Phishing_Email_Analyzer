from client_manager import Client
from email_parse import Email, DetailedEmail









def main():
    client = Client()
    client.load()
    emails = client.emails
    email = DetailedEmail(emails[0])
    email.view_urls()
    input("Press Enter to continue...") 
    email.view_whois()
    input("Press Enter to continue...")
    email.view_auth_results()
    input("Press Enter to continue...")

if __name__ == "__main__":
    main()