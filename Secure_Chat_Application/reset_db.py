"""
reset_db.py — Database Reset and Initialization Helper.
Resets the SQLite database tables (users, public_keys, messages) to a clean state.
Useful before performing a fresh live demonstration for evaluations or examiners.
"""

import os
import sys
import sqlite3

# Ensure we can import config
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config import config

def reset_database():
    db_path = config.DATABASE
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"Connecting to database at: {db_path}")
    cursor.execute("DROP TABLE IF EXISTS messages;")
    cursor.execute("DROP TABLE IF EXISTS public_keys;")
    cursor.execute("DROP TABLE IF EXISTS users;")
    
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT    NOT NULL,
            public_key    TEXT,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            last_login    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS public_keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            public_key    TEXT    NOT NULL,
            algorithm     TEXT    NOT NULL DEFAULT 'X25519',
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_public_keys_user ON public_keys(user_id);

        CREATE TABLE IF NOT EXISTS messages (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id          INTEGER NOT NULL,
            recipient_id       INTEGER NOT NULL,
            ciphertext         TEXT    NOT NULL DEFAULT '',
            nonce              TEXT    NOT NULL DEFAULT '',
            tag                TEXT    NOT NULL DEFAULT '',
            encrypted_package  TEXT    NOT NULL,
            created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            delivered          INTEGER NOT NULL DEFAULT 0,
            is_deleted         INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id);
        CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
    """)
    conn.commit()
    conn.close()
    print("[OK] Database reset successfully! Schema ready for college project demonstration.")

if __name__ == "__main__":
    reset_database()

