import sqlite3
import requests
import os 
import sys

DB_FILE = 'malicious_domains.db'
FOLDER_NAME = 'domain_db'
URL = 'https://hole.cert.pl/domains/domains.txt'

class DomainDB:
    def __init__(self):
        self.db_path = self._resolve_path()
        self.connect = sqlite3.connect(self.db_path)
        self.cursor = self.connect.cursor()
        self.initialize()
      
    def _resolve_path(self):
        path = os.path.abspath(os.path.dirname(sys.argv[0]))
        folder = os.path.join(path, FOLDER_NAME)
        if not os.path.exists(folder):
            os.mkdir(folder)
        return os.path.join(folder, DB_FILE)
    
    def _fetch_data(self):
        response = requests.get(URL)
        return response.text.split('\n')
    @property
    def size(self) -> int:
        self.cursor.execute("SELECT COUNT(*) FROM malicious_domains")
        return self.cursor.fetchone()[0]
        
    
    def initialize(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS malicious_domains
                          (domain TEXT PRIMARY KEY)''')
        self.connect.commit()
        
        
        if self.size == 0: 
            self._populate()
    
    def _populate(self):        
        db_data = self._fetch_data()
        if not db_data:
            print("[!] Failed to fetch domain data from the server")
            return 
        
        for domain in db_data:
            self.cursor.execute("INSERT OR IGNORE INTO malicious_domains (domain) VALUES (?)", (domain,))
        self.connect.commit()

    def query(self, domain) -> bool:
        self.cursor.execute("SELECT EXISTS(SELECT 1 FROM malicious_domains WHERE domain = ?)", (domain,))
        result = self.cursor.fetchone()[0]
        return bool(result)
    
    def add(self, domain):
        self.cursor.execute("INSERT OR IGNORE INTO malicious_domains (domain) VALUES (?)", (domain,))
        self.connect.commit()
    
    def close(self):
        self.connect.close()
        
        
        
# testing db func 
def main() -> None:
    database = DomainDB()
    
    # all_true = [
    #     "0-01x-merchandise.554217.xyz",
    #     "0-0llx.12313123.xyz",
    #     "0-0lx.1231312.xyz",
    #     "0-0lxmarket.5767435.xyz",
    #     "0-0lxmarket.8796556.xyz",
    #     "0-2lyb.sbs",
    #     "0-6n10.sbs",
    #     "0-avn0.sbs",
    #     "0-finanzierung.com",
    #     "0-lix.6900845.xyz",
    #     "0-lx-delivery.1212223.xyz",
    #     "0-lx.08453151.xyz",
    #     "0-lx.12457545.xyz",
    #     "0-lx.12store3444.xyz",
    #     "0-lx.13454317.xyz",
    #     "0-lx.1548415.xyz",
    #     "0-lx.1595411.xyz",
    #     "0-lx.1894987.xyz",
    #     "0-lx.233424257.xyz",
    #     "0-lx.26666596.xyz",
    #     "0-lx.2698488.xyz",
    #     "0-lx.3698488.xyz",
    #     "0-lx.38200021.xyz",
    #     "0-lx.38453151.xyz",
    #     "0-lx.4336451.xyz",
    #     "0-lx.4548415.xyz",
    #     "0-lx.4595411.xyz",
    #     "0-lx.45956233.xyz",
    #     "0-lx.5698488.xyz",
    #     "0-lx.58411522.xyz",
    #     "0-lx.71544512.xyz",
    #     "0-lx.8090983.xyz",
    #     "0-lx.8671216.xyz",
    #     "0-lx.86777534.xyz",
    #     "0-lx.9072531.xyz",
    #     "0-lx.9072532.xyz",
    #     "0-lx.98335151.xyz",
    # ]
    
    # for i, val in enumerate(all_true):
    #     if database.query(val):
    #         print(f"[ PASS ] - ATTEMPT { i + 1 } / { len(all_true) }")
    #     else:
    #         print(f"fuck you its broken")
    
    # database.close()
    

if __name__ == '__main__':
    main()