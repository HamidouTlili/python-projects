import os
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image
from PIL.ExifTags import TAGS
import whois

# VirusTotal API Key (Added)
VIRUSTOTAL_API_KEY = "915e7a71b85055b79d04b25afa3043b005ceeb01a57d342d2422ac182e3b79d2"

# 1. AES Encryption and Decryption
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_text.decode()

# 2. RSA Encryption, Decryption, and Digital Signatures
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_text.decode()

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception as e:
        return False

# 3. Vigenère Cipher (Classical Cipher)
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    ciphertext = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            ciphertext.append(chr((ord(char) - base + shift) % 26 + base))
            key_index = (key_index + 1) % len(key)
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            base = ord('A') if char is upper() else ord('a')
            plaintext.append(chr((ord(char) - base - shift) % 26 + base))
            key_index = (key_index + 1) % len(key)
        else:
            plaintext.append(char)
    return ''.join(plaintext)

# 4. File Hashing
def hash_file(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def list_files_with_hashes(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = hash_file(filepath)
            print(f"File: {filepath}, SHA-256: {file_hash}")

# 5. EXIF Metadata Extraction (like EXIFTool)
def extract_exif_data(image_path):
    image = Image.open(image_path)
    exif_data = image._getexif()
    if exif_data:
        print(f"EXIF Metadata for {image_path}:")
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)
            print(f"{tag_name}: {value}")
    else:
        print(f"No EXIF data found for {image_path}")

# 6. WHOIS Lookup (for Domain Info)
def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        print(f"WHOIS Lookup for {domain}:")
        print(f"Domain Name: {domain_info.domain_name}")
        print(f"Registrar: {domain_info.registrar}")
        print(f"Creation Date: {domain_info.creation_date}")
        print(f"Expiration Date: {domain_info.expiration_date}")
        print(f"Name Servers: {', '.join(domain_info.name_servers)}")
        print(f"Registrant Country: {domain_info.country}")
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

# 7. File Encryption (Text and Images)
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    iv, encrypted_data = aes_encrypt(file_data.decode('latin-1'), key)
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)
    print(f"File {file_path} encrypted successfully.")

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    decrypted_data = aes_decrypt(encrypted_data, key, iv)
    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(decrypted_data.encode('latin-1'))
    print(f"File {file_path} decrypted successfully.")

# VirusTotal Hash Reputation Search
def virus_total_search(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    
    response = requests.get(url, params=params)
    data = response.json()
    
    if data['response_code'] == 1:
        print(f"\nVirusTotal report for hash {file_hash}:")
        print(f"Detected by {data['positives']} engines out of {data['total']}")
        if 'scans' in data:
            for engine, result in data['scans'].items():
                if result['detected']:
                    print(f"Engine: {engine}, Result: {result['result']}")
        return data.get('positives', 0)
    else:
        print(f"No VirusTotal information found for {file_hash}")
        return 0

# Main menu for choosing operations (CyberChef-like approach)
def main_menu():
    print("=== Cryptography Toolkit ===")
    print("1. AES Encryption/Decryption")
    print("2. RSA Encryption/Decryption")
    print("3. Vigenère Cipher")
    print("4. File Hashing")
    print("5. EXIF Metadata Extraction")
    print("6. WHOIS Lookup")
    print("7. File Encryption/Decryption")
    print("8. VirusTotal Hash Reputation")

    choice = int(input("Select an option: "))
    
    if choice == 1:
        key = os.urandom(32)
        text = input("Enter text to encrypt: ")
        iv, encrypted = aes_encrypt(text, key)
        print(f"Encrypted text: {encrypted}")
        decrypted = aes_decrypt(encrypted, key, iv)
        print(f"Decrypted text: {decrypted}")

    elif choice == 2:
        private_key, public_key = generate_rsa_keys()
        text = input("Enter text to encrypt with RSA: ")
        encrypted = rsa_encrypt(public_key, text)
        print(f"Encrypted: {encrypted}")
        decrypted = rsa_decrypt(private_key, encrypted)
        print(f"Decrypted: {decrypted}")

    elif choice == 3:
        text = input("Enter text for Vigenère Cipher: ")
        key = input("Enter key: ")
        encrypted = vigenere_encrypt(text, key)
        print(f"Encrypted: {encrypted}")
        decrypted = vigenere_decrypt(encrypted, key)
        print(f"Decrypted: {decrypted}")

    elif choice == 4:
        directory = input("Enter the directory to hash files: ")
        list_files_with_hashes(directory)

    elif choice == 5:
        image_path = input("Enter the image path for EXIF data: ")
        extract_exif_data(image_path)

    elif choice == 6:
        domain = input("Enter the domain for WHOIS lookup: ")
        whois_lookup(domain)

    elif choice == 7:
        file_path = input("Enter the file path to encrypt: ")
        key = os.urandom(32)
        encrypt_file(file_path, key)
        decrypt_choice = input("Do you want to decrypt the file? (y/n): ")
        if decrypt_choice.lower() == 'y':
            decrypt_file(file_path + '.enc', key)

    elif choice == 8:
        file_path = input("Enter the file path to check VirusTotal: ")
        file_hash = hash_file(file_path)
        print(f"File: {file_path}, Hash: {file_hash}")
        virus_total_search(file_hash)

if __name__ == "__main__":
    main_menu()
