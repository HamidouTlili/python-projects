import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Generate a random salt
salt = secrets.token_bytes(16)

# Use PBKDF2 to derive a key from the passphrase and salt
passphrase = "Hamidou"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256-bit key
    salt=salt,
    iterations=100000
)
key = kdf.derive(passphrase.encode())
