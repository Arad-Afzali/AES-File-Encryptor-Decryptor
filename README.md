# AES Encryption and Decryption Project

This project provides a graphical user interface (GUI) for encrypting and decrypting files using AES (Advanced Encryption Standard) encryption. The application supports key generation, file encryption, and file decryption.


![alt text](<ss/Screenshot 1403-03-05 at 03.41.04.png>)
![alt text](<ss/Screenshot 1403-03-05 at 03.41.22.png>)
## Prerequisites

- Python 3.8 or higher
- `pip` (Python package installer)

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/Arad-Afzali/AES-File-Encryptor-Decryptor.git
    cd AES-File-Encryptor-Decryptor
    ```

2. **Create and activate a virtual environment** (recommended):
    
    **On macOS/Linux:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

    **On Windows:**
    ```cmd
    python3 -m venv venv
    venv\Scripts\activate
    ```

3. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the main script**:
    ```bash
    python3 main.py
    ```

2. **Using the GUI**:
    - **Generate Key**: Use the 'Generate Key' button to create a new encryption key.
    - **Encrypt File and Text**: Select a file or enter text, then click the ‘Encrypt’ button to encrypt it using the generated key.
    - **Decrypt File and Text**: Select an encrypted file or paste encrypted text, then click the ‘Decrypt’ button to decrypt it.


### Main Components

- **Main.py**: Launches the GUI and integrates the functionalities of the other scripts.
- **Worker.py**: Manages background processing tasks to keep the GUI responsive.
- **generatekey.py**: Contains functions for generating secure AES keys.
- **encrypt.py**: Provides functions to encrypt files using AES.
- **decrypt.py**: Provides functions to decrypt AES-encrypted files.
- **newgui.py**: Defines the graphical user interface using `tkinter`.

## Note on Key Management

When you encrypt a file, the encryption key is saved in a text file beside the encrypted file. It is crucial to save this key securely, as it is required for decrypting the file. If the key is lost, the encrypted file cannot be decrypted, and its contents will be irretrievable.

### Warnings

- **Store the Key Securely**: Ensure that the key file is stored in a secure location. Do not leave it in a publicly accessible or unprotected directory.
- **Backup the Key**: Make backups of the key file in case of accidental deletion or hardware failure.
- **Do Not Share the Key**: Do not share the key file with unauthorized individuals. Anyone with access to the key can decrypt the corresponding file.
- **Encryption Safety**: Be aware that if the key file is compromised, the security of the encrypted file is also compromised.
- **Manual Key Management**: The text encryption key is not saved anywhere else by the application. Users must manually save this key and ensure its security. If the key is lost, the encrypted file cannot be decrypted.


## Dependencies

The project requires the following Python packages, listed in `requirements.txt`:

```plaintext
cffi==1.16.0
cryptography==42.0.7
pycparser==2.22
pycryptodome==3.20.0
tk==0.1.0


## Notes

- Ensure you have the necessary permissions to execute scripts on your operating system.
- This project uses the `pycryptodome` library for cryptographic functions.
- If you encounter any issues, please open an issue on GitHub.
- **Manual Key Management**: The text encryption key is not saved anywhere else by the application. Users must manually save this key and ensure its security. If the key is lost, the encrypted file cannot be decrypted.

## Future Work

The following enhancements are planned for future releases:
- **Password Protection for Keys**: Add functionality to encrypt the key file with a user-provided password. This will add an extra layer of security, ensuring that even if the key file is compromised, it cannot be used without the password.