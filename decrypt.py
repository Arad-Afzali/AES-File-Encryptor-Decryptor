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
    result = unpad(decrypted).decode()
    
    # Securely clear sensitive data
    del decrypted, ciphertext, key
    
    return result

def decrypt_file(key, filepath, progress_callback=None):
    decrypted_filepath = filepath.replace('.enc', '')
    filesize = os.path.getsize(filepath)
    total_chunks = (filesize // (1024 * AES.block_size)) + 1

    with open(filepath, 'rb') as f_in, open(decrypted_filepath, 'wb') as f_out:
        iv = f_in.read(AES.block_size)
        cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
        for i, next_chunk in enumerate(iter(lambda: f_in.read(1024 * AES.block_size), b'')):
            if not next_chunk:
                chunk = unpad(cipher.decrypt(next_chunk))
            else:
                chunk = cipher.decrypt(next_chunk)
            f_out.write(chunk)
            if progress_callback:
                progress_callback((i + 1) / total_chunks * 100)
    
    # Securely clear sensitive data
    del iv, key, cipher
    
    return decrypted_filepath
