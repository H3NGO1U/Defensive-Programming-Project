import secrets

DEFAULT_AES_KEY = b'\x00'
DEFAULT_PUBLIC_KEY = b'\x00'
UUID_LEN = 16

def create_UUID()->str:
    random_bytes = secrets.token_bytes(UUID_LEN)
    hex_string = random_bytes.hex()
    return hex_string

class Client:
    def __init__(self,client_name: str, last_seen: str, client_id: str=create_UUID(), public_key: bytes=DEFAULT_PUBLIC_KEY, aes_key:bytes=DEFAULT_AES_KEY)->None:    
        self.client_id = client_id
        self.client_name = client_name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key

    def set_public_key(self, public_key: bytes)->None:
        self.public_key = public_key

    def get_public_key(self)->bytes:
        return self.public_key

    def set_aes_key(self, aes_key: bytes)->None:
        self.aes_key = aes_key

    def get_aes_key(self)->bytes:
        return self.aes_key  
    
    def set_last_seen(self, last_seen: str)->None:
        self.last_seen = last_seen

    def __str__(self) -> str:
        public_key = "Set" if self.public_key!=DEFAULT_PUBLIC_KEY else "Not set"
        aes_key = "Set" if self.aes_key!=DEFAULT_AES_KEY else "Not set"
        return f'\nClient id: {self.client_id}\nClient name: {self.client_name}\nPublic key: {public_key}\nAES key: {aes_key}\nLast seen: {self.last_seen}'    

