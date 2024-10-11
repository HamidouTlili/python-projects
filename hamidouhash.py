import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 1. Convert "Hamidou" to Morse Code
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.',
    'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.',
    'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-',
    'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '0': '-----', ' ': '/'
}

def string_to_morse_code(text):
    return ' '.join(MORSE_CODE_DICT[char.upper()] for char in text)

# 2. Custom Hash Function that Combines MD5, SHA-256, and integrates Morse Code
def custom_hash(input_string):
    # Step 1: Hash with MD5
    md5_hash = hashlib.md5(input_string.encode('utf-8')).hexdigest()
    
    # Step 2: Hash with SHA-256
    sha256_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    
    # Step 3: Convert "Hamidou" to Morse Code and hash it with SHA-512
    morse_code = string_to_morse_code("Hamidou")
    morse_hash = hashlib.sha512(morse_code.encode('utf-8')).hexdigest()
    
    # Step 4: Combine all the hashes
    combined_hash = md5_hash + sha256_hash + morse_hash
    
    # Step 5: Final hash using SHA-256 on the combination
    final_hash = hashlib.sha256(combined_hash.encode('utf-8')).hexdigest()
    
    return final_hash

# 3. AES Encryption (only you can decrypt it with a key)
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

# 4. Main function to generate the custom hash and encrypt it
def encrypt_my_files(input_string, key):
    # Step 1: Generate the custom hash
    custom_hashed_value = custom_hash(input_string)
    
    # Step 2: Encrypt the hash using AES (with your custom key)
    iv, encrypted_hash = aes_encrypt(custom_hashed_value, key)
    
    # Step 3: Return the encrypted hash and IV for decryption
    return iv, encrypted_hash

# 5. Decryption function (only for you)
def decrypt_my_files(encrypted_hash, key, iv):
    # Decrypt the encrypted hash
    decrypted_hash = aes_decrypt(encrypted_hash, key, iv)
    return decrypted_hash

# Set your AES encryption key (must be 32 bytes for AES-256)
MY_AES_KEY = hashlib.sha256(b'1fbd8ca2fc988a452b44fed2c165606635b8adf6').digest()

if __name__ == "__main__":
    # The data you want to hash and encrypt
    data = "This is a secret message."

    # Generate custom hash and encrypt it
    iv, encrypted = encrypt_my_files(data, MY_AES_KEY)
    print(f"Encrypted Hash (Hex): {encrypted.hex()}")
    
    # Decrypt the custom encrypted hash (only you can do this)
    decrypted = decrypt_my_files(encrypted, MY_AES_KEY, iv)
    print(f"Decrypted Hash: {decrypted}")

    # Define HASH_TYPE for the second encryption
    HASH_TYPE = "Another secret message."  # You can change this to any string you like

    # Generate custom hash, encrypt it, and get the key
    iv, encrypted = encrypt_my_files(data, MY_AES_KEY)  # Use MY_AES_KEY again or define a new key if needed
    print(f"Encrypted Hash (Hex): {encrypted.hex()}")
    
    # Note: Since you're not returning a key from encrypt_my_files, remove key from return values.
