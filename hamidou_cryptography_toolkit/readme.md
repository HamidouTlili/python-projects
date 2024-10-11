Hamidou Cryptography Toolkit
Overview
The Hamidou Cryptography Toolkit is a comprehensive Python toolkit designed to handle various cryptographic functions such as AES and RSA encryption/decryption, Vigenère cipher, file hashing, EXIF metadata extraction, WHOIS lookup, and VirusTotal hash reputation check. The toolkit provides an easy-to-use command-line interface for cryptographic operations.

Features
AES Encryption/Decryption:
Encrypt and decrypt text using AES (Advanced Encryption Standard).
RSA Encryption/Decryption:
Generate RSA key pairs and perform encryption/decryption.
Supports digital signatures for message integrity.
Vigenère Cipher:
A classical cipher for text encryption and decryption.
File Hashing:
Generate SHA-256 hashes for files and list hashed files in a directory.
EXIF Metadata Extraction:
Extract and display EXIF metadata from images.
WHOIS Lookup:
Perform WHOIS lookups to gather domain information.
File Encryption/Decryption:
Encrypt and decrypt files (text and images) using AES encryption.
VirusTotal Hash Reputation:
Check the hash of a file using the VirusTotal API for reputation analysis.
Requirements
Python 3.x
cryptography library
Pillow library (for EXIF metadata extraction)
whois library
requests library (for VirusTotal API interaction)
Install the required dependencies using the following command:


pip install cryptography Pillow whois requests
How to Use
Running the Script:

Start the toolkit by running the main Python script:


python hamido-cryptography_toolkit.py
You will be presented with a menu of operations:

=== Cryptography Toolkit ===
1. AES Encryption/Decryption
2. RSA Encryption/Decryption
3. Vigenère Cipher
4. File Hashing
5. EXIF Metadata Extraction
6. WHOIS Lookup
7. File Encryption/Decryption
8. VirusTotal Hash Reputation
Choose an option by entering the corresponding number and follow the prompts.

Example Usage
AES Encryption/Decryption:

Enter text to encrypt and the toolkit will generate a random AES key and encrypt the text.
The same key will be used to decrypt the text back to its original form.
RSA Encryption/Decryption:

Generate an RSA key pair, encrypt a message using the public key, and decrypt it using the private key.
Sign and verify messages for added security.
Vigenère Cipher:

Enter text and a key to encrypt the message using the Vigenère cipher.
File Hashing:

Hash files in a directory using SHA-256 to ensure data integrity.
EXIF Metadata Extraction:

Extract metadata such as camera information, date, and geolocation from an image.
WHOIS Lookup:

Enter a domain name to retrieve registration information, expiration dates, and name servers.
File Encryption/Decryption:

Encrypt or decrypt any file using AES encryption.
VirusTotal Hash Reputation:

Check a file's hash against VirusTotal to see if it's flagged as malicious by any antivirus engines.
VirusTotal API Key
To use the VirusTotal functionality, you need to replace the existing VIRUSTOTAL_API_KEY in the script with your own API key. You can get an API key by signing up at VirusTotal.

License
This project is licensed under the MIT License.

