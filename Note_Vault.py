#!/usr/bin/env python3
"""
Simple Encrypted Notes Vault
A straightforward local-only encrypted notes application
"""

import sqlite3
import os
import hashlib
import secrets
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class NotesVault:
    """Simple encrypted notes storage"""
    
    def __init__(self, db_path="notes.db"):
        self.db_path = db_path
        self.master_key = None  # Will hold decryption key when unlocked
        
    def initialize(self):
        """Set up a new vault with password"""
        if os.path.exists(self.db_path):
            print("Vault already exists!")
            return False
            
        password = getpass("Create master password: ")
        confirm = getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords don't match")
            return False
            
        if len(password) < 6:
            print("Password too short (minimum 6 characters)")
            return False
            
        # Generate random salt for this vault
        salt = secrets.token_bytes(16)
        
        # Derive key from password (100k iterations makes brute-force expensive)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        # Create database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store salt and a test value to verify passwords
        cursor.execute('''
            CREATE TABLE vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute("INSERT INTO vault_meta VALUES ('salt', ?)", (salt,))
        
        # Store hash of password to verify logins
        password_hash = hashlib.sha256((password + salt.hex()).encode()).digest()
        cursor.execute("INSERT INTO vault_meta VALUES ('password_check', ?)", (password_hash,))
        
        conn.commit()
        conn.close()
        
        print("✓ Vault created successfully!")
        return True
        
    def unlock(self):
        """Unlock vault with password"""
        if not os.path.exists(self.db_path):
            print("No vault found. Run initialize first.")
            return False
            
        password = getpass("Enter master password: ")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get salt
        cursor.execute("SELECT value FROM vault_meta WHERE key='salt'")
        result = cursor.fetchone()
        if not result:
            print("Vault corrupted (no salt found)")
            conn.close()
            return False
        salt = result[0]
        
        # Get stored password hash
        cursor.execute("SELECT value FROM vault_meta WHERE key='password_check'")
        result = cursor.fetchone()
        if not result:
            print("Vault corrupted (no password check)")
            conn.close()
            return False
        stored_hash = result[0]
        
        # Check password
        test_hash = hashlib.sha256((password + salt.hex()).encode()).digest()
        
        if test_hash != stored_hash:
            print("✗ Wrong password!")
            conn.close()
            return False
            
        # Derive encryption key
        self.master_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        conn.close()
        print("✓ Vault unlocked!")
        return True
        
    def add_note(self, title, content):
        """Add encrypted note to vault"""
        if not self.master_key:
            print("Vault is locked! Unlock first.")
            return False
            
        if not title or not content:
            print("Title and content cannot be empty")
            return False
            
        # Generate random nonce (number used once)
        nonce = secrets.token_bytes(12)
        
        # Encrypt the content
        aesgcm = AESGCM(self.master_key)
        encrypted = aesgcm.encrypt(nonce, content.encode(), None)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (title, encrypted_content, nonce) VALUES (?, ?, ?)",
            (title, encrypted, nonce)
        )
        conn.commit()
        note_id = cursor.lastrowid
        conn.close()
        
        print(f"✓ Note '{title}' saved! (ID: {note_id})")
        return True
        
    def list_notes(self):
        """Show all note titles"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, created_at FROM notes ORDER BY created_at DESC")
        notes = cursor.fetchall()
        conn.close()
        
        if not notes:
            print("\nNo notes yet.")
            return []
            
        print("\n" + "="*60)
        print("Your Notes:")
        print("="*60)
        for note_id, title, created in notes:
            print(f"[{note_id}] {title}")
            print(f"    Created: {created}")
        print("="*60)
        return notes
        
    def read_note(self, note_id):
        """Decrypt and display a note"""
        if not self.master_key:
            print("Vault is locked! Unlock first.")
            return False
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT title, encrypted_content, nonce, created_at FROM notes WHERE id=?",
            (note_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            print("Note not found.")
            return False
            
        title, encrypted, nonce, created = result
        
        # Decrypt
        aesgcm = AESGCM(self.master_key)
        try:
            decrypted = aesgcm.decrypt(nonce, encrypted, None)
            content = decrypted.decode()
            
            print("\n" + "="*60)
            print(f"Title: {title}")
            print(f"Created: {created}")
            print("="*60)
            print(content)
            print("="*60 + "\n")
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return False
            
        return True
        
    def delete_note(self, note_id):
        """Delete a note"""
        if not self.master_key:
            print("Vault is locked! Unlock first.")
            return False
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if note exists
        cursor.execute("SELECT title FROM notes WHERE id=?", (note_id,))
        result = cursor.fetchone()
        
        if not result:
            print("Note not found.")
            conn.close()
            return False
            
        title = result[0]
        
        # Confirm deletion
        confirm = input(f"Delete '{title}'? (yes/no): ").lower()
        if confirm != 'yes':
            print("Deletion cancelled.")
            conn.close()
            return False
            
        cursor.execute("DELETE FROM notes WHERE id=?", (note_id,))
        conn.commit()
        conn.close()
        
        print(f"✓ Note '{title}' deleted.")
        return True
        
    def search_notes(self, search_term):
        """Search notes by title (titles are not encrypted)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, created_at FROM notes WHERE title LIKE ? ORDER BY created_at DESC",
            (f"%{search_term}%",)
        )
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            print(f"\nNo notes found matching '{search_term}'")
            return []
            
        print(f"\n{'='*60}")
        print(f"Search results for '{search_term}':")
        print("="*60)
        for note_id, title, created in results:
            print(f"[{note_id}] {title}")
            print(f"    Created: {created}")
        print("="*60)
        return results


def main():
    """Simple command-line interface"""
    vault = NotesVault()
    
    print("="*60)
    print(" Encrypted Notes Vault")
    print("="*60 + "\n")
    
    # Initialize or unlock
    if not os.path.exists("notes.db"):
        print("No vault found. Creating new vault...\n")
        if not vault.initialize():
            return
        print("\nNow unlocking your new vault...\n")
        if not vault.unlock():
            return
    else:
        if not vault.unlock():
            return
    
    # Main loop
    while True:
        print("\nCommands:")
        print("  [a] Add note")
        print("  [l] List all notes")
        print("  [r] Read note")
        print("  [s] Search notes")
        print("  [d] Delete note")
        print("  [q] Quit")
        
        choice = input("\n> ").lower().strip()
        
        if choice == 'q':
            print("Goodbye!")
            break
        elif choice == 'a':
            title = input("Note title: ").strip()
            print("Enter content (press Enter twice when done):")
            lines = []
            while True:
                line = input()
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)
            content = "\n".join(lines[:-1])  # Remove last empty line
            vault.add_note(title, content)
        elif choice == 'l':
            vault.list_notes()
        elif choice == 'r':
            vault.list_notes()
            try:
                note_id = int(input("\nNote ID to read: "))
                vault.read_note(note_id)
            except ValueError:
                print("Invalid ID")
        elif choice == 's':
            search_term = input("Search for: ").strip()
            vault.search_notes(search_term)
        elif choice == 'd':
            vault.list_notes()
            try:
                note_id = int(input("\nNote ID to delete: "))
                vault.delete_note(note_id)
            except ValueError:
                print("Invalid ID")
        else:
            print("Unknown command")


if __name__ == "__main__":
    main()
