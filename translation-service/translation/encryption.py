from cryptography.fernet import Fernet
import os

KEY_PATH = "secret.key"

def load_key():
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        return key
    else:
        with open(KEY_PATH, "rb") as f:
            return f.read()

cipher = Fernet(load_key())
