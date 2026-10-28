import sys
import os
import base64
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 16
ITERATIONS = 480000


def key_from_password(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(path):
    password = getpass.getpass("Create a password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords don't match. Nothing was changed.")
        return
    with open(path, "rb") as f:
        data = f.read()
    salt = os.urandom(SALT_SIZE)
    token = Fernet(key_from_password(password, salt)).encrypt(data)
    with open(path + ".vault", "wb") as f:
        f.write(salt + token)
    os.remove(path)
    print(f"Locked -> {path}.vault  (original deleted)")


def decrypt(path):
    with open(path, "rb") as f:
        blob = f.read()
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    password = getpass.getpass("Enter password: ")
    try:
        data = Fernet(key_from_password(password, salt)).decrypt(token)
    except InvalidToken:
        print("Wrong password or the file was tampered with. Stopping.")
        return
    out = path[:-6] if path.endswith(".vault") else path + ".out"
    with open(out, "wb") as f:
        f.write(data)
    print(f"Unlocked -> {out}")


if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
    print("Usage:")
    print("  python vault.py encrypt <file>")
    print("  python vault.py decrypt <file.vault>")
elif sys.argv[1] == "encrypt":
    encrypt(sys.argv[2])
else:
    decrypt(sys.argv[2])