import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Morse Code Dictionary
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ' ': '/'
}

def string_to_morse_code(text):
    return ''.join(MORSE_CODE_DICT[char.upper()] for char in text)

def custom_hash(input_string):
    # Hash with MD5
    md5_hash = hashlib.md5(input_string.encode('utf-8')).hexdigest()
    
    # Hash with SHA-256
    sha256_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    
    # Convert "Hamidou" to Morse Code and hash it with SHA-512
    morse_code = string_to_morse_code("Hamidou")
    morse_hash = hashlib.sha512(morse_code.encode('utf-8')).hexdigest()
    
    # Combine all hashes
    combined_hash = md5_hash + sha256_hash + morse_hash
    
    # Final hash using SHA-256 on the combination
    final_hash = hashlib.sha256(combined_hash.encode('utf-8')).hexdigest()
    
    return final_hash

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

# Fixed AES encryption key (must be 32 bytes for AES-256)
MY_AES_KEY = hashlib.sha256(b'1fbd8ca2fc988a452b44fed2c165606635b8adf6').digest()

if __name__ == "__main__":
    while True:
        action = input("Would you like to (E)ncrypt or (D)ecrypt? (Q to quit): ").strip().upper()

        if action == "Q":
            break

        if action == "E":
            data_to_encrypt = input("Enter the message to encrypt: ")
            custom_hashed_value = custom_hash(data_to_encrypt)
            print(f"Original Custom Hash: {custom_hashed_value}")  # Print original hash
            iv, encrypted_hash = aes_encrypt(custom_hashed_value, MY_AES_KEY)
            print(f"Encrypted Hash (Hex): {encrypted_hash.hex()}")
            print(f"IV (Hex): {iv.hex()}")

        elif action == "D":
            encrypted_hex = input("Enter the encrypted hash (in hex): ")
            iv_hex = input("Enter the IV (in hex): ")
            try:
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                iv_bytes = bytes.fromhex(iv_hex)
                decrypted_hash = aes_decrypt(encrypted_bytes, MY_AES_KEY, iv_bytes)
                print(f"Decrypted Hash: {decrypted_hash}")
                
                # Optional: Print out what the original hash would be for comparison
                print(f"Expected Original Hash from Input: {custom_hash(data_to_encrypt)}")
                
            except ValueError as e:
                print(f"Error during decryption: {e}")

        else:
            print("Invalid option. Please choose E, D, or Q.")
