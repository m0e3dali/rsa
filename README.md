# RSA Cryptography Program
## This project is a encryptor-decryptor using RSA and Fernet to encrypt and decrypt, and create public and private key. Variations include the use of a password to protect the message, encryption of message and encryption of files, This was created with Python version 3.12.4 and is executed on the command line. It has dependency on cryptography library in python.
## To run the file-encryption program, run fileencrypt.py in the working directory, to run the message-encryptor, run rsa.py in the working directory, to run the password-protector, run password.py in the working directory with the usage below
## For the file-encryptor and message-encryptor, the program will guide you through the encryption/decryption (run the program name in the command prompt). For the password-protector, usage is as follows
password.py file (location of file) -s xxx -e/-d
## -s determines the salt amount of the file with the passed size, -e/-d determines wheter to encrypt or decrypt the file
## Dependencies:
Python 3, cryptography library in pip https://cryptography.io/en/latest/
## Installation
With git:
Clone the repository:

git clone https://github.com/moe3dali/rsa.git
cd rsa

## This program can be used for learning/personal purpose.
