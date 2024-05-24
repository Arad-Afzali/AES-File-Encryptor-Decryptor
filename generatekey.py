import secrets
import binascii

def generate_key():
    key = secrets.token_bytes(32)  # Generate a 256-bit key
    return binascii.hexlify(key).decode()

# if __name__ == "__main__":
#     key = generate_key()
#     print(f"Generated key: {key}")
