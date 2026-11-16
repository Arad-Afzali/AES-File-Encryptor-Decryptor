# aes_crypto.py
#
# AES-256-GCM encryption for files and text.
#
# The data is encrypted in chunks of 64 KB, so big files never have to fit in
# memory. Every chunk gets its own nonce and its own GCM tag, so a changed byte
# anywhere is detected. The last chunk is marked as last, so cutting chunks off
# the end of a file is detected too.
#
# File format:
#   header:  b"AESF" | version (1 byte) | mode (1 byte) | salt (16) | nonce prefix (8)
#   chunks:  ciphertext + 16-byte tag, for every 64 KB of plaintext
#
# mode 0 = a raw 256-bit key (64 hex characters)
# mode 1 = a password, turned into a key with scrypt and the salt

import io
import os
import base64
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AESF"
VERSION = 1
MODE_KEY = 0
MODE_PASSWORD = 1
CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16
HEADER_SIZE = 4 + 1 + 1 + 16 + 8


class DecryptionError(Exception):
    pass


def generate_key():
    """A random 256-bit key, as 64 hex characters."""
    return secrets.token_hex(32)


def _make_key(secret, mode, salt):
    if mode == MODE_KEY:
        try:
            key = bytes.fromhex(secret.strip())
        except ValueError:
            raise ValueError("The key must be 64 hex characters.")
        if len(key) != 32:
            raise ValueError("The key must be 64 hex characters (256 bits).")
        return key
    if not secret:
        raise ValueError("The password is empty.")
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(secret.encode("utf-8"))


def _nonce(prefix, counter):
    return prefix + struct.pack(">I", counter)


def _aad(header, is_last):
    # The header and the "last chunk" flag are authenticated with every chunk
    return header + (b"\x01" if is_last else b"\x00")


def encrypt_stream(src, dst, secret, mode, total_size=0, progress=None):
    salt = os.urandom(16)
    prefix = os.urandom(8)
    key = _make_key(secret, mode, salt)
    aes = AESGCM(key)

    header = MAGIC + bytes([VERSION, mode]) + salt + prefix
    dst.write(header)

    counter = 0
    done = 0
    chunk = src.read(CHUNK_SIZE)
    while True:
        next_chunk = src.read(CHUNK_SIZE)
        is_last = len(next_chunk) == 0
        dst.write(aes.encrypt(_nonce(prefix, counter), chunk, _aad(header, is_last)))
        counter += 1
        done += len(chunk)
        if progress:
            progress(done, total_size)
        if is_last:
            break
        chunk = next_chunk


def decrypt_stream(src, dst, secret, total_size=0, progress=None):
    header = src.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[:4] != MAGIC:
        raise DecryptionError("This is not a file made by this tool.")
    if header[4] != VERSION:
        raise DecryptionError("Unknown file version.")
    mode = header[5]
    salt = header[6:22]
    prefix = header[22:30]
    aes = AESGCM(_make_key(secret, mode, salt))

    counter = 0
    done = HEADER_SIZE
    chunk = src.read(CHUNK_SIZE + TAG_SIZE)
    while True:
        next_chunk = src.read(CHUNK_SIZE + TAG_SIZE)
        is_last = len(next_chunk) == 0
        try:
            dst.write(aes.decrypt(_nonce(prefix, counter), chunk, _aad(header, is_last)))
        except InvalidTag:
            raise DecryptionError("Wrong key or password, or the data was changed.")
        counter += 1
        done += len(chunk)
        if progress:
            progress(done, total_size)
        if is_last:
            break
        chunk = next_chunk
    return mode


def encrypt_text(text, secret, mode):
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(text.encode("utf-8")), out, secret, mode)
    return base64.b64encode(out.getvalue()).decode("ascii")


def decrypt_text(data, secret):
    try:
        raw = base64.b64decode(data.strip(), validate=True)
    except ValueError:
        raise DecryptionError("The encrypted text is not valid base64.")
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(raw), out, secret)
    try:
        return out.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("The decrypted data is not text.")


def _free_name(path):
    # Never overwrite a file that is already there
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def encrypt_file(path, secret, mode, progress=None):
    out_path = _free_name(path + ".enc")
    size = os.path.getsize(path)
    try:
        with open(path, "rb") as src, open(out_path, "wb") as dst:
            encrypt_stream(src, dst, secret, mode, size, progress)
    except Exception:
        if os.path.exists(out_path):
            os.remove(out_path)
        raise
    return out_path


def decrypt_file(path, secret, progress=None):
    if path.endswith(".enc"):
        out_path = path[:-4]
    else:
        out_path = path + ".dec"
    out_path = _free_name(out_path)
    size = os.path.getsize(path)
    try:
        with open(path, "rb") as src, open(out_path, "wb") as dst:
            decrypt_stream(src, dst, secret, size, progress)
    except Exception:
        # Don't leave half-decrypted data behind
        if os.path.exists(out_path):
            os.remove(out_path)
        raise
    return out_path
