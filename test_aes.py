# Run with: python3 test_aes.py
import os
import tempfile

import aes_crypto
from aes_crypto import MODE_KEY, MODE_PASSWORD, DecryptionError


def fails(func, *args):
    try:
        func(*args)
    except DecryptionError:
        return True
    return False


key = aes_crypto.generate_key()

# Text, with a key and with a password
for secret, mode in ((key, MODE_KEY), ("correct horse", MODE_PASSWORD)):
    enc = aes_crypto.encrypt_text("hello, ciao, سلام", secret, mode)
    assert aes_crypto.decrypt_text(enc, secret) == "hello, ciao, سلام"
assert fails(aes_crypto.decrypt_text, enc, "wrong password")

# Files of different sizes, including empty and exactly one chunk
with tempfile.TemporaryDirectory() as d:
    for size in (0, 1, aes_crypto.CHUNK_SIZE, 3 * aes_crypto.CHUNK_SIZE + 5):
        path = os.path.join(d, f"f{size}.bin")
        data = os.urandom(size)
        with open(path, "wb") as f:
            f.write(data)
        enc = aes_crypto.encrypt_file(path, key, MODE_KEY)
        out = aes_crypto.decrypt_file(enc, key)
        assert out != path, "the original must not be overwritten"
        with open(out, "rb") as f:
            assert f.read() == data

        raw = open(enc, "rb").read()
        if size:
            # One flipped bit
            bad = bytearray(raw)
            bad[-20] ^= 1
            open(enc, "wb").write(bad)
            assert fails(aes_crypto.decrypt_file, enc, key)
        if size > aes_crypto.CHUNK_SIZE:
            # Last chunk cut off
            open(enc, "wb").write(raw[:aes_crypto.HEADER_SIZE + aes_crypto.CHUNK_SIZE + 16])
            assert fails(aes_crypto.decrypt_file, enc, key)
        open(enc, "wb").write(raw)
        assert fails(aes_crypto.decrypt_file, enc, aes_crypto.generate_key())

print("All tests passed")
