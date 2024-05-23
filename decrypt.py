from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def decrypt_text(key, ciphertext):
    key = binascii.unhexlify(key)
    
    # Ensure the ciphertext has an even length
    if len(ciphertext) % 2 != 0:
        raise ValueError("Ciphertext has an odd length, which is invalid for hex decoding.")
    
    ciphertext = binascii.unhexlify(ciphertext)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def decrypt_file(key, filepath):
    key = binascii.unhexlify(key)
    
    with open(filepath, 'rb') as f:
        ciphertext = f.read()
    
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    decrypted_filepath = filepath.replace('.enc', '')
    with open(decrypted_filepath, 'wb') as f:
        f.write(plaintext)
    
    return decrypted_filepath

if __name__ == "__main__":
    import sys
    mode = sys.argv[1]
    key = sys.argv[2]
    data = sys.argv[3]
    
    if mode == "text":
        print(decrypt_text(key, data))
    elif mode == "file":
        print(decrypt_file(key, data))
