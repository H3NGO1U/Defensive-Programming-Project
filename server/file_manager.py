import os
import encryption


class ClientFile:
    def __init__(self, client_id: str, file_name: str, file_path: str, verified: bool=False)->None:
        self.client_id = client_id
        self.file_name = file_name
        self.file_path = file_path
        self.verified = verified

    def verify_file(self)->None:
        self.verified = True

    def __str__(self)->str:
        verified = "CRC verified" if self.verified else "CRC not verified"
        return f'\nFile belongs to {self.client_id}\nFile name: {self.file_name}\nFile path: {self.file_path}\nVerified: {verified}'

clients_files_folder_name = "clients_files_folder"

#each client has its own directory, which name is their client id
def save_as_file(client_id: str, file_name: str, file_content: bytes, mode: str)->None:
    file_name = os.path.basename(file_name) #protect from directory traversal
    os.makedirs(clients_files_folder_name, exist_ok=True)

    client_folder_name = client_id
    client_dir_path = os.path.join(clients_files_folder_name, client_folder_name)
    os.makedirs(client_dir_path, exist_ok=True)

    file_path = os.path.join(client_dir_path, file_name)
    with open(file_path,mode) as client_file:
        client_file.write(file_content)


def get_as_path(client_id: str, file_name: str):
    return os.path.join(clients_files_folder_name, client_id, file_name)


def decrypt_file(file_path :str, aes_key: bytes):
    with open(file_path, "rb") as file_to_decrypt:
        file_content = file_to_decrypt.read()
        decrypted_file_contents = encryption.decrypt_aes(file_content, aes_key)
        with open(file_path, "wb") as client_file:
            client_file.write(decrypted_file_contents)