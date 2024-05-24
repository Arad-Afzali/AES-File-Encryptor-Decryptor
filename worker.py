import generatekey
import encrypt
import decrypt

def encrypt_text_process(key, text, result_queue):
    encrypted_text = encrypt.encrypt_text(key, text)
    result_queue.put(encrypted_text)

def encrypt_file_process(key, filepath, progress_queue, result_queue):
    encrypted_file = encrypt.encrypt_file(key, filepath, lambda value: progress_queue.put(value))
    result_queue.put(encrypted_file)

def decrypt_text_process(key, text, result_queue):
    decrypted_text = decrypt.decrypt_text(key, text)
    result_queue.put(decrypted_text)

def decrypt_file_process(key, filepath, progress_queue, result_queue):
    decrypted_file = decrypt.decrypt_file(key, filepath, lambda value: progress_queue.put(value))
    result_queue.put(decrypted_file)
