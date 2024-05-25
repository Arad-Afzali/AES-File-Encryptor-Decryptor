import secrets
import binascii

def generate_key():
    key = secrets.token_bytes(32)  # Generate a 256-bit key
    hex_key = binascii.hexlify(key).decode()
    del key  # Securely delete the original key bytes
    return hex_key

