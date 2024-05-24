import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import generatekey
import multiprocessing
import worker

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")

        self.key = ""
        self.encrypt_file_path = ""
        self.decrypt_file_path = ""

        self.current_task_type = None

        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.root)

        self.tab_encrypt = tk.Frame(self.tab_control)
        self.tab_decrypt = tk.Frame(self.tab_control)

        self.tab_control.add(self.tab_encrypt, text='Encrypt')
        self.tab_control.add(self.tab_decrypt, text='Decrypt')

        self.tab_control.pack(expand=1, fill='both')

        self.create_encrypt_tab()
        self.create_decrypt_tab()

    def create_encrypt_tab(self):
        self.encrypt_tab_control = ttk.Notebook(self.tab_encrypt)

        self.tab_encrypt_text = tk.Frame(self.encrypt_tab_control)
        self.tab_encrypt_file = tk.Frame(self.encrypt_tab_control)

        self.encrypt_tab_control.add(self.tab_encrypt_text, text='Encrypt Text')
        self.encrypt_tab_control.add(self.tab_encrypt_file, text='Encrypt File')

        self.encrypt_tab_control.pack(expand=1, fill='both')

        self.create_encrypt_text_tab()
        self.create_encrypt_file_tab()

    def create_encrypt_text_tab(self):
        frame = tk.Frame(self.tab_encrypt_text)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Encryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_encrypt = tk.Entry(frame, width=64)
        self.key_entry_encrypt.grid(row=0, column=1, padx=5, pady=5)

        self.generate_key_button_encrypt = tk.Button(frame, text="Generate Key", width=20, command=self.generate_key)
        self.generate_key_button_encrypt.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Text to Encrypt:").grid(row=2, column=0, padx=5, pady=5)
        self.text_entry_encrypt = tk.Entry(frame, width=64)
        self.text_entry_encrypt.grid(row=2, column=1, padx=5, pady=5)

        self.encrypt_button_text = tk.Button(frame, text="Encrypt Text", width=20, command=self.encrypt_data)
        self.encrypt_button_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.progress_bar_encrypt_text = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar_encrypt_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Encrypted Text:").grid(row=5, column=0, padx=5, pady=5)
        self.encrypted_text_output = tk.Text(frame, width=64, height=10)
        self.encrypted_text_output.grid(row=5, column=1, padx=5, pady=5)

    def create_encrypt_file_tab(self):
        frame = tk.Frame(self.tab_encrypt_file)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Encryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_encrypt_file = tk.Entry(frame, width=64)
        self.key_entry_encrypt_file.grid(row=0, column=1, padx=5, pady=5)

        self.generate_key_button_encrypt_file = tk.Button(frame, text="Generate Key", width=20, command=self.generate_key)
        self.generate_key_button_encrypt_file.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.file_button_encrypt = tk.Button(frame, text="Choose File", width=20, command=self.choose_file_encrypt)
        self.file_button_encrypt.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.file_label_encrypt = tk.Label(frame, text="", wraplength=400)
        self.file_label_encrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.encrypt_button_file = tk.Button(frame, text="Encrypt File", width=20, command=self.encrypt_data)
        self.encrypt_button_file.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        self.progress_bar_encrypt_file = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar_encrypt_file.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def create_decrypt_tab(self):
        self.decrypt_tab_control = ttk.Notebook(self.tab_decrypt)

        self.tab_decrypt_text = tk.Frame(self.decrypt_tab_control)
        self.tab_decrypt_file = tk.Frame(self.decrypt_tab_control)

        self.decrypt_tab_control.add(self.tab_decrypt_text, text='Decrypt Text')
        self.decrypt_tab_control.add(self.tab_decrypt_file, text='Decrypt File')

        self.decrypt_tab_control.pack(expand=1, fill='both')

        self.create_decrypt_text_tab()
        self.create_decrypt_file_tab()

    def create_decrypt_text_tab(self):
        frame = tk.Frame(self.tab_decrypt_text)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Decryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_decrypt = tk.Entry(frame, width=64)
        self.key_entry_decrypt.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Text to Decrypt:").grid(row=2, column=0, padx=5, pady=5)
        self.text_entry_decrypt = tk.Entry(frame, width=64)
        self.text_entry_decrypt.grid(row=2, column=1, padx=5, pady=5)

        self.decrypt_button_text = tk.Button(frame, text="Decrypt Text", width=20, command=self.decrypt_data)
        self.decrypt_button_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.progress_bar_decrypt_text = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar_decrypt_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        tk.Label(frame, text="Decrypted Text:").grid(row=5, column=0, padx=5, pady=5)
        self.decrypted_text_output = tk.Text(frame, width=64, height=10)
        self.decrypted_text_output.grid(row=5, column=1, padx=5, pady=5)

    def create_decrypt_file_tab(self):
        frame = tk.Frame(self.tab_decrypt_file)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Decryption Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry_decrypt_file = tk.Entry(frame, width=64)
        self.key_entry_decrypt_file.grid(row=0, column=1, padx=5, pady=5)

        self.file_button_decrypt = tk.Button(frame, text="Choose File", width=20, command=self.choose_file_decrypt)
        self.file_button_decrypt.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.file_label_decrypt = tk.Label(frame, text="", wraplength=400)
        self.file_label_decrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.decrypt_button_file = tk.Button(frame, text="Decrypt File", width=20, command=self.decrypt_data)
        self.decrypt_button_file.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        self.progress_bar_decrypt_file = ttk.Progressbar(frame, orient='horizontal', length=400, mode='determinate')
        self.progress_bar_decrypt_file.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def choose_file_encrypt(self):
        self.encrypt_file_path = filedialog.askopenfilename()
        self.file_label_encrypt.config(text=self.encrypt_file_path)

    def choose_file_decrypt(self):
        self.decrypt_file_path = filedialog.askopenfilename()
        self.file_label_decrypt.config(text=self.decrypt_file_path)

    def generate_key(self):
        key = generatekey.generate_key()
        self.key_entry_encrypt.delete(0, tk.END)
        self.key_entry_encrypt.insert(0, key)
        self.key_entry_decrypt.delete(0, tk.END)
        self.key_entry_decrypt.insert(0, key)
        self.key_entry_encrypt_file.delete(0, tk.END)
        self.key_entry_encrypt_file.insert(0, key)
        self.key_entry_decrypt_file.delete(0, tk.END)
        self.key_entry_decrypt_file.insert(0, key)

    def encrypt_data(self):
        key = self.key_entry_encrypt.get()
        text = self.text_entry_encrypt.get().strip()
        self.progress_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()

        if key and text and not self.encrypt_file_path:
            self.current_task_type = "text"
            self.progress_bar_encrypt_text['value'] = 0
            self.process = multiprocessing.Process(target=worker.encrypt_text_process, args=(key, text, self.progress_queue, self.result_queue))
            self.process.start()
            self.root.after(100, self.check_process_encrypt)
        elif key and self.encrypt_file_path and not text:
            self.current_task_type = "file"
            self.progress_bar_encrypt_file['value'] = 0
            self.process = multiprocessing.Process(target=worker.encrypt_file_process, args=(key, self.encrypt_file_path, self.progress_queue, self.result_queue))
            self.process.start()
            self.root.after(100, self.check_process_encrypt)
        else:
            messagebox.showerror("Error", "Please provide either text or choose a file for encryption, and ensure a key is provided.")
    
    def decrypt_data(self):
        key = self.key_entry_decrypt.get()
        text = self.text_entry_decrypt.get().strip()
        self.progress_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()

        if key and text and not self.decrypt_file_path:
            self.current_task_type = "text"
            self.progress_bar_decrypt_text['value'] = 0
            self.process = multiprocessing.Process(target=worker.decrypt_text_process, args=(key, text, self.progress_queue, self.result_queue))
            self.process.start()
            self.root.after(100, self.check_process_decrypt)
        elif key and self.decrypt_file_path and not text:
            self.current_task_type = "file"
            self.progress_bar_decrypt_file['value'] = 0
            self.process = multiprocessing.Process(target=worker.decrypt_file_process, args=(key, self.decrypt_file_path, self.progress_queue, self.result_queue))
            self.process.start()
            self.root.after(100, self.check_process_decrypt)
        else:
            messagebox.showerror("Error", "Please provide either text or choose a file for decryption, and ensure a key is provided.")

    def check_process_encrypt(self):
        if self.process.is_alive():
            self.root.after(100, self.check_process_encrypt)
            if self.current_task_type == "text":
                self.update_progress(self.progress_bar_encrypt_text, self.progress_queue)
            elif self.current_task_type == "file":
                self.update_progress(self.progress_bar_encrypt_file, self.progress_queue)
        else:
            self.process.join()
            if not self.result_queue.empty():
                result = self.result_queue.get()
                if self.current_task_type == "text" and isinstance(result, str):
                    self.encrypted_text_output.delete(1.0, tk.END)
                    self.encrypted_text_output.insert(tk.END, result)
                elif self.current_task_type == "file" and isinstance(result, dict) and 'file' in result:
                    encrypted_file = result['file']
                    messagebox.showinfo("Encryption Complete", f"File encrypted successfully: {encrypted_file}")
            self.progress_bar_encrypt_text['value'] = 0
            self.progress_bar_encrypt_file['value'] = 0

    def check_process_decrypt(self):
        if self.process.is_alive():
            self.root.after(100, self.check_process_decrypt)
            if self.current_task_type == "text":
                self.update_progress(self.progress_bar_decrypt_text, self.progress_queue)
            elif self.current_task_type == "file":
                self.update_progress(self.progress_bar_decrypt_file, self.progress_queue)
        else:
            self.process.join()
            if not self.result_queue.empty():
                result = self.result_queue.get()
                if self.current_task_type == "text" and isinstance(result, str):
                    self.decrypted_text_output.delete(1.0, tk.END)
                    self.decrypted_text_output.insert(tk.END, result)
                elif self.current_task_type == "file" and isinstance(result, dict) and 'file' in result:
                    decrypted_file = result['file']
                    messagebox.showinfo("Decryption Complete", f"File decrypted successfully: {decrypted_file}")
            self.progress_bar_decrypt_text['value'] = 0
            self.progress_bar_decrypt_file['value'] = 0

    def update_progress(self, progress_bar, progress_queue):
        while not progress_queue.empty():
            value = progress_queue.get()
            progress_bar['value'] = value
            self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
