Hamidou Hash Tool
Overview
The Hamidou Hash Tool is a command-line utility that performs custom hashing and encryption using AES-256. The tool creates a unique hash by combining multiple hashing algorithms (MD5, SHA-256, and SHA-512) and integrates Morse code into the process. The hash is then encrypted using AES encryption.

Features
Custom Hash Generation: Generates a custom hash using MD5, SHA-256, and SHA-512, with Morse code integration.
AES Encryption/Decryption: Encrypts and decrypts the generated hash using AES-256 encryption.
User-Friendly Command-Line Interface: Interactively encrypt or decrypt a message.
Requirements
Python 3.x
cryptography library
Installing Dependencies
Install the required dependencies using the following command:

pip install cryptography
How It Works
Custom Hash Function:

The input message is hashed with MD5 and SHA-256.
A static string "Hamidou" is converted to Morse code and hashed with SHA-512.
The results are combined and hashed again using SHA-256 to generate the final custom hash.
AES Encryption:

The generated custom hash is encrypted using AES-256 encryption.
A random initialization vector (IV) is generated for each encryption to ensure uniqueness.
AES Decryption:

The encrypted hash can be decrypted using the AES key and IV to retrieve the original custom hash.
Usage
Running the Script

python hamidouhash2.py
Available Options:
(E)ncrypt: Encrypt a message.
(D)ecrypt: Decrypt a message.
(Q)uit: Exit the program.
Example Workflow:
Encrypt a Message:

Run the script.
Choose the E option to encrypt a message.
Enter the message you want to encrypt.
The script will display the original custom hash, the encrypted hash (in hex), and the initialization vector (IV).
Decrypt a Message:

Choose the D option to decrypt a previously encrypted message.
Enter the encrypted hash (in hex) and the IV (in hex).
The script will display the decrypted hash, which should match the original custom hash.
Example:

Would you like to (E)ncrypt or (D)ecrypt? (Q to quit): E
Enter the message to encrypt: example
Original Custom Hash: d2d2d2d2...  # shortened for clarity
Encrypted Hash (Hex): abcdabcd...
IV (Hex): 123456789...
To decrypt:


Would you like to (E)ncrypt or (D)ecrypt? (Q to quit): D
Enter the encrypted hash (in hex): abcdabcd...
Enter the IV (in hex): 123456789...
Decrypted Hash: d2d2d2d2...
License
This project is licensed under the MIT License.

