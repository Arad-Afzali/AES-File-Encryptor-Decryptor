from Crypto.Cipher import AES
import binascii
import os

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_text(key, ciphertext):
    ciphertext = binascii.unhexlify(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(decrypted).decode()

def decrypt_file(key, filepath):
    decrypted_filepath = filepath.replace('.enc', '')
    
    with open(filepath, 'rb') as f_in, open(decrypted_filepath, 'wb') as f_out:
        iv = f_in.read(AES.block_size)
        cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
        next_chunk = f_in.read(1024 * AES.block_size)
        
        while next_chunk:
            chunk, next_chunk = next_chunk, f_in.read(1024 * AES.block_size)
            if not next_chunk:
                chunk = unpad(cipher.decrypt(chunk))
            else:
                chunk = cipher.decrypt(chunk)
            f_out.write(chunk)
    
    return decrypted_filepath
