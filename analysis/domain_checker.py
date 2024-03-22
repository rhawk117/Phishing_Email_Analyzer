import sqlite3
import requests
import os 
import sys

database_fn = r'malicious_domains.db'
folder_n = 'domain_db'
class DomainDB:
    def __init__(self):
        self.db_path = self._resolve_path()
        self.connect = sqlite3.connect(database_fn)
        self.c = self.connect.cursor()
        self.initialize()
                
    def _resolve_path(self):
        path = os.path.abspath(os.path.dirname(sys.argv[0]))
        folder = os.path.join(path, folder_n)
        if not os.path.exists(folder):
            os.mkdir(folder)
            
        db_path = os.path.join(folder, database_fn)
        if not os.path.exists(db_path):
            open(db_path, 'w').close()
        
        return db_path
    
    
    def _fetch_data(self):
        url = 'https://hole.cert.pl/domains/domains.txt'
        response = requests.get(url)
        return response.text.split('\n')
    
    def initialize(self):
        self.c.execute('''CREATE TABLE IF NOT EXISTS malicious_domains
                          (domain TEXT PRIMARY KEY)''')
        self.connect.commit()
        
        self.c.execute("SELECT COUNT(*) FROM malicious_domains")
        count = self.c.fetchone()[0]
        print(f"[i] Found { count } domains in the database")
        if count == 0: 
            self._populate()
        
    def _populate(self):        
        db_data = self._fetch_data()
        if not db_data:
            print("[!] Failed to fetch domain data from the server")
            return 
        
        for domain in db_data:
            if not domain:
                continue
            self.c.execute("INSERT OR IGNORE INTO malicious_domains (domain) VALUES (?)", (domain,))
        self.connect.commit()

    def query(self, domain) -> bool:
        self.c.execute("SELECT EXISTS(SELECT 1 FROM malicious_domains WHERE domain = ?)", (domain,))
        result = self.c.fetchone()[0]
        return bool(result)
    
    def add(self, domain):
        self.c.execute("INSERT OR IGNORE INTO malicious_domains (domain) VALUES (?)", (domain,))
        self.connect.commit()
    
    def close(self):
        self.connect.close()
        
def main() -> None:
    database = DomainDB()
    domain = 'google.com'
    print(f"Checking if { domain } is in the database...")
    if database.query(domain):
        print(f"{ domain } is a malicious domain")
    else:
        print(f"{ domain } is not a malicious domain")
    

if __name__ == '__main__':
    main()