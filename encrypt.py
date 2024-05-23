from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import binascii
import secrets

def encrypt_text(key, plaintext):
    key = binascii.unhexlify(key)
    iv = secrets.token_bytes(16)  # AES block size for CBC mode is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return binascii.hexlify(iv + ciphertext).decode()

def encrypt_file(key, filepath):
    key = binascii.unhexlify(key)
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_filepath = filepath + '.enc'
    
    with open(encrypted_filepath, 'wb') as f:
        f.write(iv + ciphertext)
    
    return encrypted_filepath

if __name__ == "__main__":
    import sys
    mode = sys.argv[1]
    key = sys.argv[2]
    data = sys.argv[3]
    
    if mode == "text":
        print(encrypt_text(key, data))
    elif mode == "file":
        print(encrypt_file(key, data))
