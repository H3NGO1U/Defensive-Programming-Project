from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad
import secrets
from typing import Union

SIZE_OF_AES_KEY = 32

def encrypt_with_RSA(public_key: bytes, message:str)->Union[str, None]:
    try:
        cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_message = cipher.encrypt(message)
        return encrypted_message
    except ValueError:
        print("RSA key format is not supported")
        return None


#256-bit aes key
def generate_aes_key()->bytes:
    aes_key = secrets.token_bytes(SIZE_OF_AES_KEY)
    return aes_key


def decrypt_aes(ciphertext: str, key: bytes)->bytes:
    cipher = AES.new(key, AES.MODE_CBC, bytes(AES.block_size))
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


   