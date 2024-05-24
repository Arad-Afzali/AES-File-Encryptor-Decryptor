import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import generatekey
import encrypt
import decrypt

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        
        self.key = ""
        
        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.root)

        self.tab_encrypt = tk.Frame(self.tab_control)
        self.tab_decrypt = tk.Frame(self.tab_control)

        self.tab_control.add(self.tab_encrypt, text='Encrypt')
        self.tab_control.add(self.tab_decrypt, text='Decrypt')

        self.create_encrypt_tab()
        self.create_decrypt_tab()

        self.tab_control.pack(expand=1, fill='both')

    def create_encrypt_tab(self):
        frame = tk.Frame(self.tab_encrypt)
        frame.pack(padx=10, pady=10)
        
        tk.Label(frame, text="Encryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_encrypt = tk.Entry(frame, width=64)
        self.key_entry_encrypt.grid(row=0, column=1, padx=5, pady=5)
        
        self.generate_key_button_encrypt = tk.Button(frame, text="Generate Key", width=20, command=self.generate_key)
        self.generate_key_button_encrypt.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Text to Encrypt:").grid(row=2, column=0, padx=5, pady=5)
        self.text_entry_encrypt = tk.Entry(frame, width=64)
        self.text_entry_encrypt.grid(row=2, column=1, padx=5, pady=5)
        
        self.file_button_encrypt = tk.Button(frame, text="Choose File", width=20, command=self.choose_file_encrypt)
        self.file_button_encrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.file_label_encrypt = tk.Label(frame, text="", wraplength=400)
        self.file_label_encrypt.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        
        self.encrypt_button = tk.Button(frame, text="Encrypt", width=20, command=self.encrypt_data)
        self.encrypt_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Encrypted Text:").grid(row=6, column=0, padx=5, pady=5)
        self.encrypted_text_output = tk.Text(frame, width=64, height=10)
        self.encrypted_text_output.grid(row=6, column=1, padx=5, pady=5)

    def create_decrypt_tab(self):
        frame = tk.Frame(self.tab_decrypt)
        frame.pack(padx=10, pady=10)
        
        tk.Label(frame, text="Decryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_decrypt = tk.Entry(frame, width=64)
        self.key_entry_decrypt.grid(row=0, column=1, padx=5, pady=5)
        
        self.generate_key_button_decrypt = tk.Button(frame, text="Generate Key", width=20, command=self.generate_key)
        self.generate_key_button_decrypt.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Text to Decrypt:").grid(row=2, column=0, padx=5, pady=5)
        self.text_entry_decrypt = tk.Entry(frame, width=64)
        self.text_entry_decrypt.grid(row=2, column=1, padx=5, pady=5)
        
        self.file_button_decrypt = tk.Button(frame, text="Choose File", width=20, command=self.choose_file_decrypt)
        self.file_button_decrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.file_label_decrypt = tk.Label(frame, text="", wraplength=400)
        self.file_label_decrypt.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        
        self.decrypt_button = tk.Button(frame, text="Decrypt", width=20, command=self.decrypt_data)
        self.decrypt_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Decrypted Text:").grid(row=6, column=0, padx=5, pady=5)
        self.decrypted_text_output = tk.Text(frame, width=64, height=10)
        self.decrypted_text_output.grid(row=6, column=1, padx=5, pady=5)

    def generate_key(self):
        self.key = generatekey.generate_key()
        self.key_entry_encrypt.delete(0, tk.END)
        self.key_entry_encrypt.insert(0, self.key)
        self.key_entry_decrypt.delete(0, tk.END)
        self.key_entry_decrypt.insert(0, self.key)

    def choose_file_encrypt(self):
        self.encrypt_file_path = filedialog.askopenfilename()
        if self.encrypt_file_path:
            self.file_label_encrypt.config(text=self.encrypt_file_path)
    
    def choose_file_decrypt(self):
        self.decrypt_file_path = filedialog.askopenfilename()
        if self.decrypt_file_path:
            self.file_label_decrypt.config(text=self.decrypt_file_path)
    
    def encrypt_data(self):
        key = self.key_entry_encrypt.get()
        text = self.text_entry_encrypt.get()
        
        if key and text:
            encrypted_text = encrypt.encrypt_text(key, text)
            self.encrypted_text_output.delete(1.0, tk.END)
            self.encrypted_text_output.insert(tk.END, encrypted_text)
        elif key and hasattr(self, 'encrypt_file_path'):
            encrypted_file = encrypt.encrypt_file(key, self.encrypt_file_path)
            messagebox.showinfo("Encrypted File", f"File saved as {encrypted_file}")
        else:
            messagebox.showerror("Error", "Please provide text or choose a file and key for encryption.")

    def decrypt_data(self):
        key = self.key_entry_decrypt.get()
        text = self.text_entry_decrypt.get().strip()
        
        if key and text:
            try:
                decrypted_text = decrypt.decrypt_text(key, text)
                self.decrypted_text_output.delete(1.0, tk.END)
                self.decrypted_text_output.insert(tk.END, decrypted_text)
            except Exception as e:
                messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")
        elif key and hasattr(self, 'decrypt_file_path'):
            try:
                decrypted_file = decrypt.decrypt_file(key, self.decrypt_file_path)
                messagebox.showinfo("Decrypted File", f"File saved as {decrypted_file}")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"An error occurred during file decryption: {e}")
        else:
            messagebox.showerror("Error", "Please provide text or choose a file and key for decryption.")

    def encrypt_file(self):
        if hasattr(self, 'enc_file_path'):
            key = self.enc_key_entry.get()
            encrypted_filepath = encrypt.encrypt_file(key, self.enc_file_path)
            self.enc_output_text.delete('1.0', tk.END)
            self.enc_output_text.insert(tk.END, f"Encrypted file saved as: {encrypted_filepath}")
            return encrypted_filepath

    def decrypt_file(self):
        if hasattr(self, 'dec_file_path'):
            password = self.dec_key_entry.get()
            decrypted_filepath = decrypt.decrypt_file(password, self.dec_file_path)
            self.dec_output_text.delete('1.0', tk.END)
            self.dec_output_text.insert(tk.END, f"Decrypted file saved as: {decrypted_filepath}")
            return decrypted_filepath
if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
