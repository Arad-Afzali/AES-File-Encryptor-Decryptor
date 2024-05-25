import generatekey
import encrypt
import decrypt

def encrypt_text_process(key, text, progress_queue, result_queue):
    encrypted_text = encrypt.encrypt_text(key, text)
    for i in range(100):  # Simulate progress
        progress_queue.put(i + 1)
    result_queue.put(encrypted_text)
    
    # Securely clear sensitive data
    del key, text

def encrypt_file_process(key, filepath, progress_queue, result_queue):
    encrypted_file = encrypt.encrypt_file(key, filepath, lambda value: progress_queue.put(value))
    result_queue.put(encrypted_file)
    
    # Securely clear sensitive data
    del key, filepath

def decrypt_text_process(key, text, progress_queue, result_queue):
    decrypted_text = decrypt.decrypt_text(key, text)
    for i in range(100):  # Simulate progress
        progress_queue.put(i + 1)
    result_queue.put(decrypted_text)
    
    # Securely clear sensitive data
    del key, text

def decrypt_file_process(key, filepath, progress_queue, result_queue):
    decrypted_file = decrypt.decrypt_file(key, filepath, lambda value: progress_queue.put(value))
    result_queue.put(decrypted_file)
    
    # Securely clear sensitive data
    del key, filepath
