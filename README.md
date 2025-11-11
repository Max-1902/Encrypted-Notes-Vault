# Encrypted Notes Vault

A command-line tool for storing notes with AES-256 encryption. All data stays on your computer no cloud, no tracking, completely private.

## Overview

This project implements local-only encrypted note storage using industry-standard cryptography. Notes are encrypted with unique keys, password-protected with PBKDF2 key derivation, and stored in a SQLite database.

**Built to solve:** Need for simple, trustworthy note storage without relying on cloud services.

**What I learned:**
- Practical implementation of AES-GCM authenticated encryption
- Why password-based key derivation matters (PBKDF2 vs plain hashing)
- Proper handling of sensitive data in memory
- Database design for encrypted storage

## Quick Start

**Prerequisites:**
- Python 3.8 or higher
- pip (Python package installer)

**Installation:**

```
# Clone the repository
git clone https://github.com/Max-1902/Encrypted-Notes-Vault.git
cd Encrypted-Notes-Vault

# Install dependencies
pip install -r requirements.txt

# Run the program
python3 Note_Vault.py
```

**First-time setup:**
1. Create a master password (minimum 6 characters)
2. Password must be strong and memorable there is no recovery option if forgotten
3. Use the command menu to add, read, search, or delete notes

## Usage Examples

**Creating a vault:**
```
$ python3 Note_Vault.py
Create master password: ****
Confirm password: ****
Vault created successfully!
(Note for unexperienced users: In the process of setting up a password, no letters will be displayed)
```

**Adding a note:**
```
Commands:
  [a] Add note
  [l] List all notes
  [r] Read note
  [s] Search notes
  [d] Delete note
  [q] Quit

> a
Note title: Project Ideas
Enter content (press Enter twice when done):
Build encrypted messaging app
Create password manager

Note 'Project Ideas' saved! (ID: 1)
```

**Listing notes:**
```
> l
Your Notes:
 Project Ideas[10]
    Created: 2025-11-09 14:30:22
```

## How It Works

**Security architecture:**

```
User Password
    ↓
PBKDF2-HMAC-SHA256 (100,000 iterations)
    ↓
32-byte Master Key
    ↓
AES-256-GCM + Unique Nonce per Note
    ↓
Encrypted Content → SQLite Database
```

**Key security features:**
- Password never stored (only verification hash using SHA-256)
- Each note encrypted with unique 12-byte nonce
- PBKDF2 with 100,000 iterations prevents brute-force attacks
- AES-GCM provides both encryption and tamper detection
- All data stored locally in notes.db file

**What gets encrypted:**
- Note content (fully encrypted)
- Password verification (hashed, not encrypted)

**What stays in plaintext:**
- Note titles (for search functionality)
- Creation timestamps
- Note IDs

## Installation Guide

**Check Python version:**
```
python3 --version
```
Must be 3.8 or higher.

**Install dependencies:**

On macOS/Linux:
```
pip3 install cryptography
```

On Windows:
```
pip install cryptography
```

If you encounter "externally-managed-environment" error (macOS):
```
pip3 install --break-system-packages cryptography
```

## Troubleshooting

**"ModuleNotFoundError: No module named 'cryptography'"**

Solution:
```
python3 -m pip install cryptography
```

**"Vault already exists"**

The program found an existing notes.db file. Either use the existing vault with your password, or delete notes.db to restart.

**"Wrong password"**

The entered password doesn't match the vault. No recovery is possible, this is intentional for security.

**"zsh: command not found: python3"**

Python isn't installed or isn't in your PATH. Try `python` instead of `python3`, or install Python from python.org.

## Project Structure

```
Encrypted-Notes-Vault/
├── Note_Vault.py          # Main program
├── README.md              # This file
├── requirements.txt       # Dependencies
├── LICENSE                # MIT license
├── .gitignore             # Git exclusions
└── notes.db               # Encrypted notes (created on first run)
```

**Important:** Never commit notes.db to version control.

## Security Considerations

**What this protects against:**
- Physical device theft (notes encrypted at rest)
- File system access by unauthorized users
- Basic malware that reads files but can't decrypt
- Brute-force password attempts (expensive key derivation)

**What this does NOT protect against:**
- Keyloggers or screen capture malware
- Someone watching you enter your password
- Physical memory dumps while vault is unlocked
- Forgetting your password (no recovery mechanism)

**Best practices:**
- Use a strong, unique password
- Back up notes.db file regularly to external storage
- Don't share your password
- Lock the vault (quit program) when not in use
- Store backups securely

## Technical Details

**Cryptographic components:**
- Encryption: AES-256-GCM (NIST approved)
- Key derivation: PBKDF2-HMAC-SHA256 (100,000 iterations)
- Password verification: SHA-256 hash
- Nonce: 12 bytes, cryptographically random per note

**Database:**
- SQLite3 (built into Python)
- Two tables: vault_meta (password data), notes (encrypted content)
- Atomic operations for data integrity

**Performance:**
- Vault unlock: ~50-100ms (key derivation overhead)
- Note encryption/decryption: <1ms per note
- Search: O(n) linear scan of note titles

## Future Enhancements

Planned features for future versions:
- Password change functionality
- Note editing capability
- Export to encrypted archive
- Import from text files
- Categories/tags for organization
- Graphical user interface
- Multi-vault support

## Known Limitations

- Single user per vault
- No concurrent access support
- Titles stored in plaintext (by design for search)
- No automated backup system
- Command-line only (no GUI)
- No mobile support

## Contributing

This is a learning project, but contributions are welcome.

**Report bugs:**
Open an issue with:
1. Steps to reproduce
2. Expected behavior
3. Actual behavior
4. OS and Python version

**Submit changes:**
1. Fork the repository
2. Create feature branch
3. Make your changes
4. Submit pull request with description

## License

MIT License - See LICENSE file for full text.

You are free to use, modify, and distribute this code.

## Disclaimer

Educational project demonstrating encryption concepts. Uses industry-standard cryptography but has not undergone professional security audit. 

## Author

Built by Max-1902 as a learning project to understand practical cryptography implementation.

GitHub: github.com/Max-1902

## Acknowledgments

- Python cryptography library maintainers
- SQLite development team
- NIST cryptographic standards documentation
```
