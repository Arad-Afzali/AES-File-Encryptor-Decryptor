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

def encrypt_file(key, filepath, progress_callback=None):
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    encrypted_filepath = filepath + '.enc'
    filesize = os.path.getsize(filepath)
    total_chunks = (filesize // (1024 * AES.block_size)) + 1

    with open(filepath, 'rb') as f_in, open(encrypted_filepath, 'wb') as f_out:
        f_out.write(iv)
        for i, chunk in enumerate(iter(lambda: f_in.read(1024 * AES.block_size), b'')):
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk)
            f_out.write(cipher.encrypt(chunk))
            if progress_callback:
                progress_callback((i + 1) / total_chunks * 100)
    with open(filepath + "_key.txt", 'w') as key_file:
        key_file.write(key)
    return encrypted_filepath
