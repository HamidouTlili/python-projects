text
# Hamidou Hash and AES Encryption

## Overview

This project implements a custom hash function that combines various hashing algorithms and encrypts data using AES encryption. The nickname "Hamidou" is integrated into the hashing process using Morse code.

## Features

- Custom hash generation using MD5, SHA-256, and SHA-512.
- AES encryption and decryption with a fixed secret key.
- User-friendly command-line interface for encrypting and decrypting messages.

## Usage

1. **Run the Script**:
   ```bash
   python hamidouhash2.py

Choose an Action:
Enter E to encrypt a message.
Enter D to decrypt an encrypted message.
Enter Q to quit the program.
Enter Your Message:
For encryption, input the message you want to encrypt.
For decryption, input the encrypted hash and IV.
Secret Key
The fixed AES secret key used in this project is derived from the following byte string:
python
MY_AES_KEY = hashlib.sha256(b'1fbd8ca2fc988a452b44fed2c165606635b8adf6').digest()
