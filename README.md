# AES File Encryptor and Decryptor

A desktop app written in Python that encrypts and decrypts files and text with AES, using a simple tkinter interface.

## Features

- Generates a random 256-bit AES key (shown as a hex string).
- Encrypts and decrypts text.
- Encrypts and decrypts files.
- Uses AES in CBC mode with a random IV that is stored at the start of the output.
- Shows a progress bar for each operation.
- Runs the work in a separate process so the window stays responsive.

## Screenshots

![alt text](<ss/Screenshot 1403-03-05 at 03.41.04.png>)
![alt text](<ss/Screenshot 1403-03-05 at 03.41.22.png>)

## Installation

You need Python 3.8 or higher and `pip`.

1. Clone the repository:
    ```bash
    git clone https://github.com/Arad-Afzali/AES-File-Encryptor-Decryptor.git
    cd AES-File-Encryptor-Decryptor
    ```

2. Create and activate a virtual environment (recommended).

    On macOS/Linux:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

    On Windows:
    ```cmd
    python3 -m venv venv
    venv\Scripts\activate
    ```

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

The packages in `requirements.txt` are:

```plaintext
cffi==1.16.0
cryptography==42.0.7
pycparser==2.22
pycryptodome==3.20.0
tk==0.1.0
```

The cryptographic functions use the `pycryptodome` library.

## Usage

Start the app:

```bash
python3 main.py
```

The window has an Encrypt tab and a Decrypt tab. Each one has a text tab and a file tab.

- **Generate Key**: creates a new key and puts it in the key field.
- **Encrypt Text / Encrypt File**: enter a key, then type text or choose a file and click the encrypt button. A file is saved next to the original with `.enc` added to its name.
- **Decrypt Text / Decrypt File**: enter the key, then paste the encrypted text or choose an encrypted file and click the decrypt button. For a file, the `.enc` part is removed from the name to make the output file.

## Project files

- `main.py`: starts the GUI.
- `newgui.py`: the tkinter interface.
- `worker.py`: runs encryption and decryption in the background and reports progress.
- `generatekey.py`: generates the keys.
- `encrypt.py`: encrypts text and files.
- `decrypt.py`: decrypts text and files.

## Key management

When you encrypt a file, the key is saved in a text file next to the original file, named `<original file name>_key.txt`. You need this key to decrypt the file. If the key is lost, the encrypted file cannot be decrypted.

The key for encrypted text is not saved anywhere by the app. You must save it yourself. If it is lost, the encrypted text cannot be decrypted.

- Store the key file in a safe place, not in a public or unprotected folder.
- Make a backup of the key file in case it is deleted or your disk fails.
- Do not share the key with people who should not read the data. Anyone with the key can decrypt the matching file or text.
- If the key file is exposed, the encrypted data is no longer secure.

To send a key to someone safely, you can encrypt it with my RSA project: [RSA Encryption and Decryption](https://github.com/Arad-Afzali/RSA-Encryption-Decryption). It uses a public key to encrypt and a private key to decrypt.

## Limitations and future work

- The key file is saved as plain text. A planned improvement is to protect it with a user-provided password, so the key cannot be used if the file is exposed.
- Keys are not stored by the app for text, as described above.
- If you have trouble running the app, make sure you are allowed to run scripts on your system, or open an issue on GitHub.
