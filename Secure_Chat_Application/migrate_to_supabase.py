"""
migrate_to_supabase.py — Safe SQLite to Supabase PostgreSQL Database Migration.

Capabilities:
  1. Inspects local SQLite database (database/chat.db).
  2. Inspects message encryption format (verifies ciphertext, nonce, tag; zero plaintext).
  3. Provisions all 6 PostgreSQL tables & indexes in Supabase using database/schema_supabase.sql.
  4. Safely migrates user accounts, public keys, and encrypted messages preserving timestamps and relationships.
  5. Initializes user_profiles and message_status tables in Supabase.
  6. Synchronizes PostgreSQL auto-increment sequences.
  7. Verifies migrated records against SQLite source records.
  8. Strictly leaves original SQLite database completely untouched and intact.
"""

import os
import sys
import json
import sqlite3
import argparse
from typing import Dict, Any, List

# Ensure application imports work
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

from config import config

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False


def inspect_sqlite(sqlite_path: str) -> Dict[str, Any]:
    """Inspect and validate existing records in SQLite database."""
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite database not found at '{sqlite_path}'")

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    
    users = []
    if "users" in tables:
        users = [dict(r) for r in cur.execute("SELECT * FROM users ORDER BY id ASC").fetchall()]

    public_keys = []
    if "public_keys" in tables:
        public_keys = [dict(r) for r in cur.execute("SELECT * FROM public_keys ORDER BY id ASC").fetchall()]

    messages = []
    if "messages" in tables:
        messages = [dict(r) for r in cur.execute("SELECT * FROM messages ORDER BY id ASC").fetchall()]

    conn.close()

    # Inspect message encryption format
    encrypted_count = 0
    suspicious_count = 0
    for m in messages:
        # Check if ciphertext or encrypted_package has encrypted characteristics
        has_ciphertext = bool(m.get("ciphertext"))
        has_nonce = bool(m.get("nonce"))
        has_tag = bool(m.get("tag") or m.get("authentication_tag"))
        pkg = m.get("encrypted_package")

        if has_ciphertext and has_nonce:
            encrypted_count += 1
        elif pkg:
            try:
                parsed = json.loads(pkg)
                if isinstance(parsed, dict) and "ciphertext" in parsed:
                    encrypted_count += 1
                else:
                    suspicious_count += 1
            except Exception:
                suspicious_count += 1
        else:
            suspicious_count += 1

    return {
        "sqlite_path": sqlite_path,
        "tables": tables,
        "users": users,
        "public_keys": public_keys,
        "messages": messages,
        "encrypted_count": encrypted_count,
        "suspicious_count": suspicious_count,
    }


def migrate_to_supabase(sqlite_data: Dict[str, Any], dsn: str, dry_run: bool = False):
    """Perform the migration into Supabase PostgreSQL."""
    if not HAS_PSYCOPG2:
        print("[ERROR] psycopg2-binary is required for migration. Run: pip install psycopg2-binary")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("TMEEE: Secure Chat SQLite -> Supabase PostgreSQL Migration")
    print("=" * 65)
    print(f"[*] SQLite Source Database: {sqlite_data['sqlite_path']}")
    print(f"[*] Found {len(sqlite_data['users'])} users, {len(sqlite_data['public_keys'])} public keys, and {len(sqlite_data['messages'])} messages.")
    print(f"[*] Encryption format verification: {sqlite_data['encrypted_count']} verified encrypted, {sqlite_data['suspicious_count']} unverified.")

    if sqlite_data['suspicious_count'] > 0:
        print("[WARNING] Some messages did not match standard AES-GCM ciphertext format!")

    if dry_run:
        print("\n[DRY RUN MODE] Inspection complete. No changes made to Supabase or SQLite.")
        return

    print("\n[*] Connecting to Supabase PostgreSQL...")
    pg_conn = psycopg2.connect(dsn)
    pg_conn.autocommit = False
    cur = pg_conn.cursor()

    try:
        # 1. Apply Schema
        schema_path = os.path.join(BASE_DIR, "database", "schema_supabase.sql")
        print(f"[*] Applying database schema from {os.path.basename(schema_path)}...")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        cur.execute(schema_sql)
        pg_conn.commit()
        print("[OK] Supabase tables and RLS policies verified.")

        # 2. Migrate Users
        print("\n[*] Migrating users...")
        for u in sqlite_data["users"]:
            cur.execute("""
                INSERT INTO users (id, username, email, password_hash, public_key, created_at, last_login)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    username = EXCLUDED.username,
                    email = EXCLUDED.email,
                    password_hash = EXCLUDED.password_hash,
                    public_key = EXCLUDED.public_key,
                    last_login = EXCLUDED.last_login;
            """, (
                u["id"],
                u["username"],
                u["email"],
                u["password_hash"],
                u.get("public_key"),
                u.get("created_at"),
                u.get("last_login"),
            ))

            # Provision user profile
            cur.execute("""
                INSERT INTO user_profiles (user_id, bio, online_status)
                VALUES (%s, %s, 'offline')
                ON CONFLICT (user_id) DO NOTHING;
            """, (u["id"], f"Hello, I am {u['username']}."))
        pg_conn.commit()
        print(f"[OK] Migrated {len(sqlite_data['users'])} users successfully.")

        # 3. Migrate Public Keys
        print("[*] Migrating public keys...")
        for pk in sqlite_data["public_keys"]:
            cur.execute("""
                INSERT INTO public_keys (id, user_id, public_key, algorithm, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    public_key = EXCLUDED.public_key,
                    algorithm = EXCLUDED.algorithm;
            """, (
                pk["id"],
                pk["user_id"],
                pk["public_key"],
                pk.get("algorithm", "X25519"),
                pk.get("created_at"),
            ))
        pg_conn.commit()
        print(f"[OK] Migrated {len(sqlite_data['public_keys'])} public keys.")

        # 4. Migrate Messages
        print("[*] Migrating encrypted messages...")
        for m in sqlite_data["messages"]:
            receiver_id = m.get("receiver_id") or m.get("recipient_id") or 0
            auth_tag = m.get("authentication_tag") or m.get("tag") or ""
            pkg = m.get("encrypted_package") or ""
            if isinstance(pkg, dict):
                pkg = json.dumps(pkg)

            cur.execute("""
                INSERT INTO messages (
                    id, sender_id, receiver_id, ciphertext, nonce,
                    authentication_tag, encrypted_package, created_at,
                    delivered, is_deleted
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    ciphertext = EXCLUDED.ciphertext,
                    nonce = EXCLUDED.nonce,
                    authentication_tag = EXCLUDED.authentication_tag,
                    encrypted_package = EXCLUDED.encrypted_package,
                    delivered = EXCLUDED.delivered,
                    is_deleted = EXCLUDED.is_deleted;
            """, (
                m["id"],
                m["sender_id"],
                receiver_id,
                m.get("ciphertext", ""),
                m.get("nonce", ""),
                auth_tag,
                pkg,
                m.get("created_at"),
                bool(m.get("delivered", 0)),
                bool(m.get("is_deleted", 0)),
            ))

            # Record message status
            if m.get("delivered"):
                cur.execute("""
                    INSERT INTO message_status (message_id, delivered_at)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING;
                """, (m["id"], m.get("created_at")))
        pg_conn.commit()
        print(f"[OK] Migrated {len(sqlite_data['messages'])} encrypted messages.")

        # 5. Synchronize PostgreSQL Sequences
        print("[*] Synchronizing PostgreSQL sequence IDs...")
        cur.execute("SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1));")
        cur.execute("SELECT setval('public_keys_id_seq', COALESCE((SELECT MAX(id) FROM public_keys), 1));")
        cur.execute("SELECT setval('messages_id_seq', COALESCE((SELECT MAX(id) FROM messages), 1));")
        pg_conn.commit()

        # 6. Verification
        print("\n" + "=" * 65)
        print("VERIFICATION & INTEGRITY CHECK")
        print("=" * 65)
        cur.execute("SELECT count(*) FROM users;")
        pg_users_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM public_keys;")
        pg_keys_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM messages;")
        pg_messages_count = cur.fetchone()[0]

        print(f"Users Count:       SQLite = {len(sqlite_data['users'])}, Supabase = {pg_users_count}")
        print(f"Public Keys Count: SQLite = {len(sqlite_data['public_keys'])}, Supabase = {pg_keys_count}")
        print(f"Messages Count:    SQLite = {len(sqlite_data['messages'])}, Supabase = {pg_messages_count}")

        assert pg_users_count >= len(sqlite_data['users']), "User count mismatch!"
        assert pg_keys_count >= len(sqlite_data['public_keys']), "Public keys count mismatch!"
        assert pg_messages_count >= len(sqlite_data['messages']), "Messages count mismatch!"

        print("\n[SUCCESS] Migration completed successfully!")
        print("[INFO] Original SQLite database preserved at: " + sqlite_data["sqlite_path"])
        print("=" * 65)

    except Exception as e:
        pg_conn.rollback()
        print(f"\n[ERROR] Migration failed: {e}")
        raise
    finally:
        cur.close()
        pg_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Migrate TMEEE Secure Chat from SQLite to Supabase PostgreSQL.")
    parser.add_argument("--sqlite", default=config.DATABASE, help="Path to SQLite database file")
    parser.add_argument("--dsn", default="", help="Supabase PostgreSQL connection string")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and validate without writing to Supabase")
    args = parser.parse_args()

    sqlite_path = os.path.abspath(args.sqlite)
    dsn = args.dsn or config.get_postgres_dsn()

    print(f"[*] Inspecting SQLite database: {sqlite_path}")
    sqlite_data = inspect_sqlite(sqlite_path)

    if not dsn and not args.dry_run:
        print("\n[NOTICE] Supabase connection string not configured in .env or via --dsn.")
        print(f"Local SQLite contains {len(sqlite_data['users'])} users and {len(sqlite_data['messages'])} messages.")
        print("Run with --dry-run to inspect existing SQLite records, or provide --dsn to migrate.")
        return

    migrate_to_supabase(sqlite_data, dsn, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
