from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

KEY_DIRECTORY = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIRECTORY, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIRECTORY, "public_key.pem")

class RSAKeyPair:
    def __init__(self):
        if not os.path.exists(KEY_DIRECTORY):
            os.makedirs(KEY_DIRECTORY)
        
        if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
            self.load_keys()
        else:
            self.generate_keys()
            self.save_keys()

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self):
        # Serialize and save the private key
        with open(PRIVATE_KEY_FILE, 'wb') as private_key_file:
            private_key_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        # Serialize and save the public key
        with open(PUBLIC_KEY_FILE, 'wb') as public_key_file:
            public_key_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def load_keys(self):
        # Load the private key
        with open(PRIVATE_KEY_FILE, 'rb') as private_key_file:
            self.private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )
        # Load the public key
        with open(PUBLIC_KEY_FILE, 'rb') as public_key_file:
            self.public_key = serialization.load_pem_public_key(
                public_key_file.read()
            )

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


class RSAEncryptor:
    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, message):
        return self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class RSADecryptor:
    def __init__(self, private_key):
        self.private_key = private_key

    def decrypt(self, ciphertext):
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()


def main():
    rsa_key_pair = RSAKeyPair()
    print("Private Key:")
    print(rsa_key_pair.serialize_private_key().decode())
    
    print("Public Key:")
    print(rsa_key_pair.serialize_public_key().decode())
    encryptor = RSAEncryptor(rsa_key_pair.public_key)
    decryptor = RSADecryptor(rsa_key_pair.private_key)

    while True:
        choice = input("Do you want to encrypt or decrypt a message? (e/d/exit): ").strip().lower()
        if choice == 'e':
            message = input("Enter the message to encrypt: ")
            ciphertext = encryptor.encrypt(message)
            print(f"Encrypted Message (bytes): {ciphertext.hex()}")
        elif choice == 'd':
            ciphertext_hex = input("Enter the message to decrypt (as hex string): ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
                decrypted_message = decryptor.decrypt(ciphertext)
                print(f"Decrypted Message: {decrypted_message}")
            except ValueError as e:
                print(f"Error: {e}. Make sure the input is a valid hex string.")
        elif choice == 'exit':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 'e' for encryption, 'd' for decryption, or 'exit' to quit.")

if __name__ == "__main__":
    main()
