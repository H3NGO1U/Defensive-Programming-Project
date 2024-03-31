import selectors
import socket
from protocol import *
import logging
import struct
from encryption import *
import cksum
import file_manager
import database
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

MAX_LENGTH = 1024
SERVER_VERSION = 3

      
class Server:
    def __init__(self, host: str, port: int)->None:
        self.port = port
        self.host = host
        self.sel = selectors.DefaultSelector()
        self.not_stopped = True
        self.version = SERVER_VERSION
        self.database = database.Database()

    def accept(self,sock: socket.socket, mask: int)->None:
        conn, addr = sock.accept()
        print('accepted', conn, 'from', addr)
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def accept_registration(self,conn: socket.socket)->Union[ResponseRegistrationSucceeded, ResponseDeclineRegistration]:
        data = conn.recv(SIZE_OF_CLIENT_NAME)
        client_name = remove_padding(data).decode()
        client_id = self.database.add_client(client_name, str(datetime.now()))
        print(f'{client_name} was given the id: {client_id}')
        if client_id:
            return ResponseRegistrationSucceeded(client_id)

        else:    
            return ResponseDeclineRegistration()
            
             
    def accept_login(self, conn: socket.socket, client_id: str)->Union[ResponseLoginOKSendingAES, ResponseLoginFailed]:
        self.database.update_last_seen(client_id, str(datetime.now()))
        client_name = remove_padding(conn.recv(SIZE_OF_CLIENT_NAME)).decode()
        client = self.database.get_client(client_id, client_name)
        if client:
            public_key = client.get_public_key()
            if public_key:
                self.database.update_aes_key(client_id, generate_aes_key())
                encrypted_aes_key = encrypt_with_RSA(public_key, client.get_aes_key())
                return ResponseLoginOKSendingAES(client_id, encrypted_aes_key)    
        return ResponseLoginFailed(client_id)       

    def accept_public_key(self, conn: socket.socket, client_id: str)->Union[ResponseAESKey, ResponseDeclineRegistration]:
        self.database.update_last_seen(client_id, str(datetime.now()))
        client_name = remove_padding(conn.recv(SIZE_OF_CLIENT_NAME)).decode()
        public_key = conn.recv(SIZE_OF_PUBLIC_KEY)
        client = self.database.get_client(client_id, client_name)
        if client:
            self.database.update_public_key(client_id, public_key)
            self.database.update_aes_key(client_id, generate_aes_key())
            encrypted_aes_key = encrypt_with_RSA(public_key, client.get_aes_key())
            if encrypted_aes_key:
                return ResponseAESKey(client_id, encrypted_aes_key)
        return ResponseDeclineRegistration() 

    def accept_file(self, conn: socket.socket, client_id: str, payload_size: int)->Union[ResponseFileAcceptedSendingCRC, ResponseServerFailed]:
        if self.database.client_id_exists(client_id):
            self.database.update_last_seen(client_id, str(datetime.now()))
            inner_header_data = conn.recv(SIZE_OF_INNER_HEADER)
            content_size, original_content_size, packet_number, total_packets = struct.unpack(INNER_HEADER_STRUCTURE, inner_header_data)
            print(f'{client_id}: ACCEPTING FILE packet number {packet_number}')
            file_name = conn.recv(SIZE_OF_FILE_NAME)
            size_of_file_contents = payload_size - SIZE_OF_INNER_HEADER - SIZE_OF_FILE_NAME
            if size_of_file_contents <= 0:
                print("ERROR recieving file: payload size is not a positive number")
                return ResponseServerFailed()
            else:
                file_content_encrypted = conn.recv(size_of_file_contents)
              #  decrypted_file = decrypt_aes(file_content_encrypted, client.get_aes_key())
                clean_file_name = remove_padding(file_name).decode()
                mode = "wb" if packet_number == 1 else "ab"
                file_manager.save_as_file(client_id, clean_file_name, file_content_encrypted, mode)
                if packet_number == total_packets:
                    file_path = file_manager.get_as_path(client_id, clean_file_name)
                    file_manager.decrypt_file(file_path, self.database.get_aes_key(client_id))
                    self.database.add_file(client_id, clean_file_name)
                    server_crc = cksum.calc_crc(file_path)
                    return ResponseFileAcceptedSendingCRC(client_id, content_size, file_name, server_crc)           

    def accept_crc_not_ok_final(self, conn: socket.socket, client_id: str)->ResponseMsgAccepted:
        file_name = conn.recv(SIZE_OF_FILE_NAME)
        self.database.update_last_seen(client_id, str(datetime.now()))
        return ResponseMsgAccepted(client_id, file_name)
    
    def accept_crc_not_ok(self, conn: socket.socket, client_id: str)->None:
        file_name = conn.recv(SIZE_OF_FILE_NAME)
        self.database.update_last_seen(client_id, str(datetime.now()))

    def accept_crc_ok(self, conn: socket.socket, client_id: str)->ResponseMsgAccepted:
        file_name = conn.recv(SIZE_OF_FILE_NAME)
        self.database.update_last_seen(client_id, str(datetime.now()))
        clean_file_name = remove_padding(file_name).decode()
        file_path = file_manager.get_as_path(client_id, clean_file_name)
        self.database.verify_file(file_path)
        return ResponseMsgAccepted(client_id, file_name)
    
    def read(self,conn: socket.socket, mask: int)->None:
        try:
            data = conn.recv(SIZE_OF_HEADER)
            client_id = data[:SIZE_OF_ID]
            if client_id:
                client_version, request_code, payload_size = struct.unpack(HEADER_STRUCTURE, data[SIZE_OF_ID:])
                request_type = identify_req(request_code)  
                if request_type == 0:
                    response = ResponseServerFailed()
                    conn.send(response.pack_for_sending())
                    
                else:
                    print(client_id.hex(), "sent a", request_type, "request")
                    response = None
                    if request_type=="registration":
                        response = self.accept_registration(conn)
                    elif request_type=="public_key":
                        response = self.accept_public_key(conn, client_id.hex())
                    elif request_type=="login":
                        response = self.accept_login(conn, client_id.hex())  
                    elif request_type=="send_file":
                        response = self.accept_file(conn, client_id.hex(), payload_size)
                    elif request_type=="CRC_ok":
                        response = self.accept_crc_ok(conn, client_id.hex())
                    elif request_type=="CRC_not_ok":
                        self.accept_crc_not_ok(conn, client_id.hex())
                    elif request_type=="CRC_not_ok_final":
                        response = self.accept_crc_not_ok_final(conn, client_id.hex())
                    if response:
                        conn.send(response.pack_for_sending())    
            else:
                print("One of the clients left the service") 
                print('closing', conn)
                self.sel.unregister(conn)    
                conn.close()
        except (ConnectionResetError, ConnectionAbortedError):
            print("One of the clients left the service")        
            print('closing', conn)
            self.sel.unregister(conn)    
            conn.close()

    def create_socket(self)->None:
        self.sock = socket.socket()  
        self.sock.bind((self.host, self.port))
        self.sock.listen(100)
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self.accept)

    def run(self)->None:
        self.create_socket()  
        log.debug("starting server...")  
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

              