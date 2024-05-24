from Crypto.Cipher import AES
import secrets
import binascii
import os

def pad(data):
    padding_length = AES.block_size - len(data) % AES.block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_text(key, plaintext):
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    encrypted = iv + cipher.encrypt(pad(plaintext.encode()))
    return binascii.hexlify(encrypted).decode()

def encrypt_file(key, filepath):
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    encrypted_filepath = filepath + '.enc'

    with open(filepath, 'rb') as f_in, open(encrypted_filepath, 'wb') as f_out:
        f_out.write(iv)
        while chunk := f_in.read(1024 * AES.block_size):  # read in chunks
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk)
            f_out.write(cipher.encrypt(chunk))
    
    return encrypted_filepath
