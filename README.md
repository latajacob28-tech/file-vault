# File Vault

A dark-themed desktop app that encrypts and decrypts your files behind a password,
built in Python. Pick a file, set a password, and it's locked with real
authenticated encryption — the original plaintext is deleted, leaving only the
encrypted `.vault` file.

## Features

- **Real encryption** — AES via Fernet, with PBKDF2 key derivation (480,000 iterations) and a random salt per file
- **Password protected** — wrong password or a tampered file is rejected, not silently mangled
- **Deletes the plaintext** after locking, so no readable copy is left behind
- **Auto re-lock** — after decrypting, optionally re-encrypt the file automatically after a set number of minutes
- **Dark, frameless UI** — drag-anywhere window with a progress animation, built in PySide6

## How it works

A password is turned into an encryption key using PBKDF2-HMAC-SHA256 with a random
16-byte salt, which is stored alongside the ciphertext. The file is then encrypted
with Fernet (authenticated AES), so both confidentiality and integrity are protected.

## Built with

- Python 3
- PySide6 (GUI)
- cryptography (encryption)
- pyqtdarktheme (dark theme)

## Running from source
```pip install -r requirements.txt```
```python vault_gui.py```


A command-line version is also included: `python vault.py encrypt <file>`.

## Warning

If you forget a file's password, that file cannot be recovered. There is no backdoor.
Test with throwaway files first.

## Future improvements

- Secure deletion (overwrite before delete) instead of a plain file removal
- Encrypting whole folders at once

<img width="498" height="460" alt="image" src="https://github.com/user-attachments/assets/ecf7e6b2-3b36-44d8-b560-f0e71acacc89" />
