from cryptography.fernet import Fernet


def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)

write_key()
key = load_key()
message = "skibidi toilet will be mine".encode()
f = Fernet(key)
encrypted = f.encrypt(message)
print(encrypted)
decrypted_encrypted = f.decrypt(encrypted)
print(decrypted_encrypted)

key = load_key()
# file name
file = "skibidi rizz.txt"
# encrypt it
test = input()
while test:
    if test:
        encrypt(file, key)
    else:
        decrypt(file, key)
