import os
import rsa
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from getpass import getpass

from rsa import PublicKey, PrivateKey

# File to store encrypted passwords
PASSWORD_FILE = "passwords.json"
encryption_type = "0"


# Generate a Fernet encryption key based on the master password
def generate_key(master_password: str) -> bytes:
    return base64.urlsafe_b64encode(master_password.ljust(32).encode()[:32])

def derive_aes_key(master_password: str, salt: bytes) -> bytes:
    """Derives a secure AES key from the master password."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password)

# Load existing passwords from file
def load_passwords() -> dict:
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as file:
            return json.load(file)
    return {}


# Save passwords to file
def save_passwords(passwords: dict):
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file)


# Add a new password
def encrypt_with_fernet(key: bytes, service: str, password: str):
    global encryption_type
    encryption_type = "1"
    passwords = load_passwords()
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password.encode()).decode()
    passwords[service] = encrypted_password
    save_passwords(passwords)
    print(f"Password for {service} has been saved.")

def encrypt_with_rsa(key: PublicKey, service: str, password: str):
    # This generates a new public and private key with rsa
    global encryption_type
    encryption_type = "2"
    passwords = load_passwords()
    encrypted_data = rsa.encrypt(password.encode(), key)
    encrypted_password = base64.b64encode(encrypted_data).decode()
    print(type(encrypted_password))
    passwords[service] = encrypted_password
    save_passwords(passwords)
    print(f"Password for {service} has been saved.")


# AES Encryption Function
def encrypt_with_aes(master_password: str, service: str, password: str):
    global encryption_type
    encryption_type = "3"
    passwords = load_passwords()

    # Generate a salt and derive a key
    salt = os.urandom(16)
    key = derive_aes_key(master_password, salt)

    # Create a Cipher object with AES in GCM mode
    iv = os.urandom(12)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the password
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()

    # Store salt, IV, and encrypted password as a single base64-encoded string
    encrypted_data = base64.b64encode(salt + iv + encryptor.tag + encrypted_password).decode()
    passwords[service] = encrypted_data
    save_passwords(passwords)
    print(f"Password for {service} has been saved.")


def add_password(key: bytes, rsa_key: PublicKey, service: str, password: str):
    print("What type of encryption would you want?")
    print("1. With Fernet")
    print("2. With RSA")
    print("3. With AES")
    choice = input("Please choose an option: ")

    if choice == "1":
        encrypt_with_fernet(key, service, password)
        print("Encrypted with Fernet")
    elif choice == "2":
        encrypt_with_rsa(rsa_key, service, password)
        print("Encrypted with RSA")
    elif choice == "3":
        encrypt_with_aes(key, service, password)
        print("Encrypted with AES")
    else:
        print("Invalid choice. Please try again.")

# Retrieve a password
def retrieve_password(key: bytes, service: str):
    passwords = load_passwords()
    if service not in passwords:
        print(f"No password found for {service}.")
        return
    cipher = Fernet(key)
    encrypted_password = passwords[service].encode()
    try:
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        print(f"Password for {service}: {decrypted_password}")
    except Exception as e:
        print("Failed to decrypt the password. Is the master password correct?")

def retrieve_rsa_password(encrypt_key: PublicKey, decrypt_key: PrivateKey, service: str):
    passwords = load_passwords()
    if service not in passwords:
        print(f"No password found for {service}.")
        return
    encrypted_data_bytes = base64.b64decode(passwords[service])
                         #encrypt_key)
    try:
        decMessage = rsa.decrypt(encrypted_data_bytes, decrypt_key).decode()
        print(f"Password for {service}: {decMessage}")
    except Exception as e:
        print("Failed to decrypt the password. Is the master password correct?")


# AES Password Retrieval Function
def retrieve_aes_password(master_password: str, service: str):
    passwords = load_passwords()
    if service not in passwords:
        print(f"No password found for {service}.")
        return

    # Decode stored data
    encrypted_data_bytes = base64.b64decode(passwords[service])
    salt, iv, tag, encrypted_password = (
        encrypted_data_bytes[:16],  # Salt (16 bytes)
        encrypted_data_bytes[16:28],  # IV (12 bytes)
        encrypted_data_bytes[28:44],  # GCM Tag (16 bytes)
        encrypted_data_bytes[44:]  # Encrypted Password
    )

    # Derive the key
    key = derive_aes_key(master_password, salt)

    # Create a Cipher object for decryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        # Decrypt the password
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        print(f"Password for {service}: {decrypted_password.decode()}")
    except Exception as e:
        print("Failed to decrypt the password. Is the master password correct?")


# List all stored services
def list_services():
    passwords = load_passwords()
    if not passwords:
        print("No services found.")
        return
    print("Stored services:")
    for service in passwords.keys():
        print(f"- {service}")


# Main menu
def main():
    master_password = getpass("Enter the master password: ")
    key = generate_key(master_password)
    rsaPublicKey, rsaPrivateKey = rsa.newkeys(256)

    while True:
        print("\nPassword Manager")
        print("1. Add a password")
        print("2. Retrieve a password")
        print("3. List stored services")
        print("4. Exit")
        choice = input("Please choose an option: ")

        if choice == "1":
            service = input("Enter the service name: ")
            password = getpass("Enter the password: ")
            add_password(key, rsaPublicKey, service, password)
        elif choice == "2":
            service = input("Enter the service name: ")
            #retrieve_password(key, service)
            if encryption_type == "1":
                retrieve_password(key, service)
            elif encryption_type == "2":
                retrieve_rsa_password(rsaPublicKey, rsaPrivateKey, service)
        elif choice == "3":
            list_services()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()