# This database is using dictionaries for storing clients' and files' information
# Information is also stored in sql and loaded to the RAM when server restarts

from client import *
from file_manager import *
from typing import Union
from sqlite3 import *
#No real need for locking here, since selectors were used without additional threads. but it's a good practice:)
from threading import Lock

LOCAL_DB_FILE_NAME = 'server.db' 
CREATE_USERS_SQL = """
        CREATE TABLE IF NOT EXISTS clients (
        id VARCHAR(16) PRIMARY KEY,
        client_name VARCHAR(255),
        public_key BLOB,
        last_seen VARCHAR(100),
        AES_key BLOB
        );
        """
CREATE_FILES_SQL = """ 
    CREATE TABLE IF NOT EXISTS files (
        id VARCHAR(16),
        file_name VARCHAR(255),
        path VARCHAR(255) PRIMARY KEY,
        verified BOOLEAN
    );
    """
    
class Database:
    def __init__(self)->None:
        self.clients = {}
        self.files = {}
        self.sqlite_conn = connect(LOCAL_DB_FILE_NAME, check_same_thread=False)
        self.create_tables()
        self.load_tables()
        self.lock = Lock()

    def load_tables(self)->None:
        cursor = self.sqlite_conn.cursor()
        all_clients = cursor.execute("SELECT * FROM clients").fetchall()
        cursor.close()
        self.sqlite_conn.commit()
        for client_row in all_clients:
            client_id = client_row[0]
            client_name = client_row[1]
            public_key = client_row[2]
            last_seen = client_row[3]
            aes_key = client_row[4]
            self.clients[client_id] = Client(client_name, last_seen, client_id, public_key, aes_key)
        cursor = self.sqlite_conn.cursor()    
        all_files = cursor.execute("SELECT * FROM files").fetchall()
        cursor.close()
        self.sqlite_conn.commit()
        for file_row in all_files:
            client_id = file_row[0]
            file_name = file_row[1]
            file_path = file_row[2]
            verified = file_row[3]
            self.files[file_path] = ClientFile(client_id, file_name, file_path, verified)
        print(self)

    def create_tables(self)->None:
        cursor = self.sqlite_conn.cursor()
        cursor.execute(CREATE_USERS_SQL)
        cursor.execute(CREATE_FILES_SQL)
        cursor.close()
        self.sqlite_conn.commit()


    def add_client(self, client_name:str, last_seen:str)->Union[str, None]:
        with self.lock:
            #cant have two clients with the same name
            for client in list(self.clients.values()):
                if client.client_name == client_name:
                    return None
            client = Client(client_name, last_seen)
            #for the unreasonable case that the client_id is already in use
            while client.client_id in self.clients:
                client = Client(client_name, last_seen)
            self.clients[client.client_id] = client
            cursor = self.sqlite_conn.cursor()
            cursor.execute("INSERT INTO clients (id, client_name, public_key, last_seen, AES_key) VALUES (?, ?, ?, ?, ?)",
                    [client.client_id, client_name, "", client.last_seen, ""])
            cursor.close()
            self.sqlite_conn.commit()
            print(self)
            return client.client_id
    
    def get_client(self, client_id:str, client_name:str)->Union[Client, None]:
        with self.lock:
            if client_id in self.clients:
                client = self.clients[client_id]
                if client_name == client.client_name:
                    return client
            return None  

    def client_id_exists(self, client_id:str)->bool:
        with self.lock:
            return client_id in self.clients 

    def update_public_key(self, client_id:str, public_key: bytes)->None:
        with self.lock:
            if client_id in self.clients:
                self.clients[client_id].set_public_key(public_key)
                cursor = self.sqlite_conn.cursor()
                cursor.execute("UPDATE clients SET public_key=? WHERE id=?",[public_key, client_id])
                cursor.close()
                self.sqlite_conn.commit()
                print(self)

    def get_public_key(self, client_id:str)->Union[str, None]:
        with self.lock:
            if client_id in self.clients:
                return self.clients[client_id].get_public_key()

    def update_aes_key(self, client_id:str, aes_key:bytes)->None:
        with self.lock:
            if client_id in self.clients:
                self.clients[client_id].set_aes_key(aes_key)
                cursor = self.sqlite_conn.cursor()
                cursor.execute("UPDATE clients SET AES_key=? WHERE id=?",[aes_key, client_id])
                cursor.close()
                self.sqlite_conn.commit()
                print(self)

    def get_aes_key(self, client_id:str)->Union[str, None]:
        with self.lock:
            if client_id in self.clients:
                return self.clients[client_id].get_aes_key()        
        
    def update_last_seen(self,client_id:str, last_seen:str)->None:
        with self.lock:
            if client_id in self.clients:
                self.clients[client_id].set_last_seen(last_seen)
                cursor = self.sqlite_conn.cursor()
                cursor.execute("UPDATE clients SET last_seen=? WHERE id=?",[last_seen, client_id])
                cursor.close()
                self.sqlite_conn.commit()



    def add_file(self, client_id:str, file_name:str)->Union[None, bool]:
        file_path = get_as_path(client_id, file_name)
        with self.lock:
            if client_id not in self.clients:
                return False
            self.files[file_path] = ClientFile(client_id, file_name, get_as_path(client_id, file_name))
            cursor = self.sqlite_conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO files (id, file_name, path, verified) VALUES (?, ?, ?, ?)",
                        [client_id, file_name, file_path, False])
            cursor.close()
            self.sqlite_conn.commit()
            print(self)
            return True    

    def verify_file(self, file_path: str)->None:
        with self.lock:
            if file_path in self.files:
                self.files[file_path].verify_file()
                cursor = self.sqlite_conn.cursor()
                cursor.execute("UPDATE files SET Verified=1 WHERE path=?", [file_path])
                cursor.close()
                self.sqlite_conn.commit()
                print(self) 
    
    def __str__(self) -> str:
        clients = "\n----------------------------------------\n\n\n-----------\n"
        clients+="| Clients: |"
        clients+="\n-----------\n"
        for client in list(self.clients.values()):
            clients+=str(client)
            clients+="\n------------------\n"
        files = "\n||||||||||||||||||||||||||||||||||||||||||\n\n\n----------\n"
        files+="| Files: |"
        files+="\n----------\n"
        for file in list(self.files.values()):
            files+=str(file)
            files+="\n------------------\n"  
        files+="\n---------------------------------------\n"    
        return clients+files     
      