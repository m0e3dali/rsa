# RSA Cryptography Library
## This project is a encryptor-decryptor using RSA and Fernet to encrypt and decrypt, and create public and private key. Variations include the use of a password to protect the message, encryption of message and encryption of files, This was created with Python version 3.12.4 and is executed on the command line. It has dependency on cryptography library in python.
## This project can be run from the command line once it is downloaded and unzipped, assuming the python and cryptography libraries are installed in the computer
With git:
Clone the repository:

git clone https://github.com/moe3dali/rsa.git
cd rsa

## For the file-encryptor and message-encryptor, the program will guide you through the encryption/decryption (run the program name in the command prompt). For the password-protector, usage is as follows
password.py file (location of file) -s xxx -e/-d
## -s determines the salt amount of the file with the passed size, -e/-d determines wheter to encrypt or decrypt the file
## This program can be used for learning/personal purpose.
