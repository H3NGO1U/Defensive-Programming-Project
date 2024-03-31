
from enum import Enum
import struct
SERVER_VERSION = 3
SIZE_OF_ID = 16
SIZE_OF_HEADER = 23
SIZE_OF_CLIENT_NAME = 255
SIZE_OF_PUBLIC_KEY = 160
SIZE_OF_FILE_NAME = 255
SIZE_OF_FILE_SIZE_FIELD = 4
SIZE_OF_PACKET_COUNTING = 4
SIZE_OF_CRC = 4
SIZE_OF_INNER_HEADER = SIZE_OF_FILE_SIZE_FIELD * 2 + SIZE_OF_PACKET_COUNTING
HEADER_STRUCTURE = '<BHI'
INNER_HEADER_STRUCTURE = '<IIHH'

status_codes = {
        1025:"registration",
        1026:"public_key",
        1027:"login",
        1028:"send_file",
        1029:"CRC_ok",
        1030:"CRC_not_ok",
        1031:"CRC_not_ok_final"
}

class ResponseCodes(Enum):
    registration_success = 1600
    registration_failed = 1601
    sending_AES = 1602
    accepted_file = 1603
    msg_accepted = 1604
    login_ok_sending_AES = 1605
    failed_login = 1606
    server_error = 1607


       
class Header:
    def __init__(self, version: int, code: int, payload_size: int):
        self.version = version
        self.code = code
        self.payload_size = payload_size

    def pack_for_sending(self):
        return struct.pack("<BHI", self.version, self.code, self.payload_size)

# add different class to each response
class Response:
    def __init__(self, response_type: ResponseCodes, payload_size: int):
        self.header = Header(SERVER_VERSION, response_type.value, payload_size)

    def pack_for_sending(self)->bytes:
        return self.header.pack_for_sending()
    

class ResponseWithPayload(Response):
    def __init__(self, response_type: ResponseCodes, client_id:str, payload_size:int):
        super().__init__(response_type, payload_size)
        self.client_id = client_id

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()+ bytes.fromhex(self.client_id)
    
class ResponseFileAcceptedSendingCRC(ResponseWithPayload):
    def __init__(self, client_id:str, content_size:int, file_name:str, crc:int):
        print("File accepted, sending crc...")
        super().__init__(ResponseCodes.accepted_file, client_id, SIZE_OF_ID + SIZE_OF_FILE_SIZE_FIELD + SIZE_OF_FILE_NAME + SIZE_OF_CRC)
        self.content_size = content_size
        self.file_name = file_name
        self.crc = crc

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending() + struct.pack('<I', self.content_size) + self.file_name + struct.pack('<I', self.crc) 
       
class ResponseRegistrationSucceeded(ResponseWithPayload):
    def __init__(self, client_id:str):
        print("Registration succeeded, waiting for public key...")
        super().__init__(ResponseCodes.registration_success, client_id, SIZE_OF_ID)

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()
    

class ResponseAESKey(ResponseWithPayload):
    def __init__(self, client_id:str, encrypted_aes_key:bytes):
        print("Accepted public key, sending encrypted AES key...")
        super().__init__(ResponseCodes.sending_AES, client_id, SIZE_OF_ID+len(encrypted_aes_key))
        self.encrypted_aes_key = encrypted_aes_key

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()+self.encrypted_aes_key


class ResponseDeclineRegistration(Response):
    def __init__(self):
        print("Registration declined")
        super().__init__(ResponseCodes.registration_failed, 0)

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()   


class ResponseLoginOKSendingAES(ResponseWithPayload):
    def __init__(self, client_id:str, aes_key:bytes):
        print("Login accepted, sending encrypted AES key...")
        super().__init__(ResponseCodes.login_ok_sending_AES, client_id, SIZE_OF_ID+len(aes_key))
        self.aes_key = aes_key

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()+self.aes_key


class ResponseLoginFailed(ResponseWithPayload):
    def __init__(self, client_id:str):
        print("Login failed")
        super().__init__(ResponseCodes.failed_login, client_id, SIZE_OF_ID)

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()
    

class ResponseMsgAccepted(ResponseWithPayload):
    def __init__(self, client_id:str, file_name:str):
        print("Accepting client's crc message")
        super().__init__(ResponseCodes.msg_accepted, client_id, SIZE_OF_ID)
        self.file_name = file_name

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()+self.file_name
    

class ResponseServerFailed(Response):
    def __init__(self):
        print("Server failed")
        super().__init__(ResponseCodes.server_error, 0)

    def pack_for_sending(self)->bytes:
        return super().pack_for_sending()   


def identify_req(code: int)->str:
        if code in status_codes:
            return status_codes[code]
        else:
            return 0
        

def remove_padding(data: bytes)->bytes:
    end_of_info = data.find(b'\0')
    return data[:end_of_info]        

