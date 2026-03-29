# AES Folder Encryption Tools

Two encryption modes are available. Choose based on your needs.

---

## Mode 1: Per-file encryption (existing)

Encrypts each file individually, preserving the folder structure in a new directory.

**Encrypt:**
```bash
python aes_encrypt.py <source_folder> <destination_folder>
# Example:
python aes_encrypt.py source destination
```

**Decrypt:**
```bash
python aes_decrypt.py <encrypted_folder> <output_folder>
# Example:
python aes_decrypt.py destination restored
```

**Result:** `destination/` mirrors the structure of `source/`, with every file encrypted.

---

## Mode 2: Single-file encryption (new)

Compresses the entire folder into a zip archive in memory, then encrypts it into **one `.enc` file**.

**Encrypt:**
```bash
python aes_encrypt_single.py <source_folder> <output.enc>
# Example:
python aes_encrypt_single.py source source.enc
```

**Decrypt:**
```bash
python aes_decrypt_single.py <input.enc> <output_folder>
# Example:
python aes_decrypt_single.py source.enc restored
```

**Result:** One file `source.enc` contains the entire encrypted folder. Decryption restores the original structure under `restored/`.

---

## Comparison

| | Per-file (Mode 1) | Single-file (Mode 2) |
|---|---|---|
| Output | Directory of encrypted files | One `.enc` file |
| Folder structure visible | Yes (filenames/paths exposed) | No (completely hidden) |
| Easy to share/move | No | Yes |
| Supports binary files | No (text only) | Yes |

---

## Notes

- Both modes use **AES (Fernet / AES-128-CBC)** with **PBKDF2-HMAC-SHA256** key derivation (100,000 iterations).
- Keep your password safe — there is no recovery mechanism.
- Requires the `cryptography` package: `pip install cryptography`

zip -r destination /xxx.zip source/xxx
gpg -c destination/xxx.zip

gpg -d xxx.zip.gpg > xxx.zip
unzip mydata.zip