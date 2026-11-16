import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import aes_crypto


class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES File Encryptor")
        self.root.geometry("640x540")
        self.root.minsize(560, 500)

        # The worker thread puts its progress here and the GUI reads it,
        # because tkinter widgets may only be changed from the main thread.
        self.events = queue.Queue()
        self.busy = False

        self.mode = tk.IntVar(value=aes_crypto.MODE_PASSWORD)
        self.show_secret = tk.BooleanVar(value=False)
        self.file_path = tk.StringVar()
        self.status = tk.StringVar(value="Ready")

        outer = ttk.Frame(root, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, textvariable=self.status, foreground="#888").pack(side="bottom", anchor="w", pady=(8, 0))
        self.create_key_box(outer)
        self.create_tabs(outer)

        self.update_mode()
        self.root.after(100, self.check_events)

    # ---------- widgets ----------

    def create_key_box(self, parent):
        box = ttk.LabelFrame(parent, text="Key", padding=10)
        box.pack(fill="x")

        modes = ttk.Frame(box)
        modes.pack(fill="x")
        ttk.Radiobutton(modes, text="Password", variable=self.mode,
                        value=aes_crypto.MODE_PASSWORD, command=self.update_mode).pack(side="left")
        ttk.Radiobutton(modes, text="256-bit key (hex)", variable=self.mode,
                        value=aes_crypto.MODE_KEY, command=self.update_mode).pack(side="left", padx=12)
        ttk.Checkbutton(modes, text="Show", variable=self.show_secret,
                        command=self.update_mode).pack(side="right")

        row = ttk.Frame(box)
        row.pack(fill="x", pady=(8, 0))
        self.secret_entry = ttk.Entry(row, font=("Menlo", 11))
        self.secret_entry.pack(side="left", fill="x", expand=True)
        self.generate_button = ttk.Button(row, text="Generate", command=self.generate_key)
        self.generate_button.pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Copy", command=lambda: self.copy(self.secret_entry.get())).pack(side="left", padx=(6, 0))

        self.key_hint = ttk.Label(box, foreground="#888")
        self.key_hint.pack(anchor="w", pady=(6, 0))

    def create_tabs(self, parent):
        tabs = ttk.Notebook(parent)
        tabs.pack(fill="both", expand=True, pady=(12, 0))

        # Text tab
        text_tab = ttk.Frame(tabs, padding=10)
        tabs.add(text_tab, text="Text")

        ttk.Label(text_tab, text="Input").pack(anchor="w")
        self.input_text = tk.Text(text_tab, height=6, wrap="word", font=("Menlo", 11),
                                  relief="solid", borderwidth=1)
        self.input_text.pack(fill="both", expand=True, pady=(2, 8))

        buttons = ttk.Frame(text_tab)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Encrypt", command=self.encrypt_text).pack(side="left")
        ttk.Button(buttons, text="Decrypt", command=self.decrypt_text).pack(side="left", padx=6)
        ttk.Button(buttons, text="Copy output",
                   command=lambda: self.copy(self.output_text.get("1.0", "end").strip())).pack(side="right")

        ttk.Label(text_tab, text="Output").pack(anchor="w", pady=(8, 0))
        self.output_text = tk.Text(text_tab, height=6, wrap="char", font=("Menlo", 11),
                                   relief="solid", borderwidth=1, state="disabled")
        self.output_text.pack(fill="both", expand=True, pady=(2, 0))

        # File tab
        file_tab = ttk.Frame(tabs, padding=10)
        tabs.add(file_tab, text="File")

        ttk.Label(file_tab, text="File").pack(anchor="w")
        row = ttk.Frame(file_tab)
        row.pack(fill="x", pady=(2, 10))
        ttk.Entry(row, textvariable=self.file_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse).pack(side="left", padx=(6, 0))

        buttons = ttk.Frame(file_tab)
        buttons.pack(fill="x")
        self.encrypt_file_button = ttk.Button(buttons, text="Encrypt file", command=self.encrypt_file)
        self.encrypt_file_button.pack(side="left")
        self.decrypt_file_button = ttk.Button(buttons, text="Decrypt file", command=self.decrypt_file)
        self.decrypt_file_button.pack(side="left", padx=6)

        self.progress = ttk.Progressbar(file_tab, maximum=100)
        self.progress.pack(fill="x", pady=(14, 4))
        ttk.Label(file_tab, foreground="#888", wraplength=520, justify="left",
                  text="Encrypting writes <file>.enc next to the file. Decrypting never "
                       "overwrites a file: if the name is taken, a number is added.").pack(anchor="w", pady=(8, 0))

    # ---------- key ----------

    def update_mode(self):
        hidden = self.mode.get() == aes_crypto.MODE_PASSWORD and not self.show_secret.get()
        self.secret_entry.config(show="•" if hidden else "")
        if self.mode.get() == aes_crypto.MODE_PASSWORD:
            self.generate_button.state(["disabled"])
            self.key_hint.config(text="The key is made from the password with scrypt and a random salt.")
        else:
            self.generate_button.state(["!disabled"])
            self.key_hint.config(text="Keep the key safe: without it the data cannot be decrypted.")

    def generate_key(self):
        self.secret_entry.delete(0, "end")
        self.secret_entry.insert(0, aes_crypto.generate_key())
        self.status.set("New key generated. Save it somewhere safe.")

    def get_secret(self):
        secret = self.secret_entry.get()
        if not secret:
            messagebox.showwarning("No key", "Enter a password or a key first.")
            return None
        return secret

    def copy(self, text):
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status.set("Copied to the clipboard.")

    # ---------- text ----------

    def set_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.config(state="disabled")

    def encrypt_text(self):
        secret = self.get_secret()
        text = self.input_text.get("1.0", "end-1c")
        if secret is None or not text:
            return
        try:
            self.set_output(aes_crypto.encrypt_text(text, secret, self.mode.get()))
            self.status.set("Text encrypted (AES-256-GCM, base64).")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        secret = self.get_secret()
        data = self.input_text.get("1.0", "end-1c")
        if secret is None or not data.strip():
            return
        try:
            self.set_output(aes_crypto.decrypt_text(data, secret))
            self.status.set("Text decrypted and verified.")
        except (ValueError, aes_crypto.DecryptionError) as e:
            self.set_output("")
            messagebox.showerror("Decryption failed", str(e))

    # ---------- files ----------

    def browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def encrypt_file(self):
        self.start_file_job("encrypt")

    def decrypt_file(self):
        self.start_file_job("decrypt")

    def start_file_job(self, action):
        if self.busy:
            return
        secret = self.get_secret()
        path = self.file_path.get()
        if secret is None:
            return
        if not os.path.isfile(path):
            messagebox.showwarning("No file", "Choose a file first.")
            return

        self.busy = True
        self.encrypt_file_button.state(["disabled"])
        self.decrypt_file_button.state(["disabled"])
        self.progress["value"] = 0
        self.status.set("Encrypting..." if action == "encrypt" else "Decrypting...")
        mode = self.mode.get()
        threading.Thread(target=self.file_job, args=(action, path, secret, mode), daemon=True).start()

    def file_job(self, action, path, secret, mode):
        # Runs in a background thread so the window does not freeze
        def progress(done, total):
            self.events.put(("progress", done * 100 / total if total else 100))

        try:
            if action == "encrypt":
                out = aes_crypto.encrypt_file(path, secret, mode, progress)
            else:
                out = aes_crypto.decrypt_file(path, secret, progress)
            self.events.put(("done", out))
        except (ValueError, aes_crypto.DecryptionError, OSError) as e:
            self.events.put(("error", str(e)))

    def check_events(self):
        while not self.events.empty():
            kind, value = self.events.get()
            if kind == "progress":
                self.progress["value"] = value
            else:
                self.busy = False
                self.encrypt_file_button.state(["!disabled"])
                self.decrypt_file_button.state(["!disabled"])
                if kind == "done":
                    self.progress["value"] = 100
                    self.status.set(f"Saved as {os.path.basename(value)}")
                    messagebox.showinfo("Done", f"Saved as:\n{value}")
                else:
                    self.progress["value"] = 0
                    self.status.set("Failed.")
                    messagebox.showerror("Error", value)
        self.root.after(100, self.check_events)
