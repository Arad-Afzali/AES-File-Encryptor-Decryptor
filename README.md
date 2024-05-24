# AES Encryption and Decryption Project

This project provides a graphical user interface (GUI) for encrypting and decrypting files using AES (Advanced Encryption Standard) encryption. The application supports key generation, file encryption, and file decryption.

## Prerequisites

- Python 3.8 or higher
- `pip` (Python package installer)

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/Arad-Afzali/AES-enc-dyc.git
    cd yourproject
    ```

2. **Create and activate a virtual environment** (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the main script**:
    ```bash
    python Main.py
    ```

2. **Using the GUI**:
    - **Generate Key**: Use the 'Generate Key' button to create a new encryption key.
    - **Encrypt File**: Select a file and click the 'Encrypt' button to encrypt it using the generated key.
    - **Decrypt File**: Select an encrypted file and click the 'Decrypt' button to decrypt it.


### Main Components

- **Main.py**: Launches the GUI and integrates the functionalities of the other scripts.
- **Worker.py**: Manages background processing tasks to keep the GUI responsive.
- **generatekey.py**: Contains functions for generating secure AES keys.
- **encrypt.py**: Provides functions to encrypt files using AES.
- **decrypt.py**: Provides functions to decrypt AES-encrypted files.
- **newgui.py**: Defines the graphical user interface using `tkinter`.

## Dependencies

The project requires the following Python packages, listed in `requirements.txt`:

```plaintext
cffi==1.16.0
cryptography==42.0.7
pycparser==2.22
pycryptodome==3.20.0


pip install -r requirements.txt

