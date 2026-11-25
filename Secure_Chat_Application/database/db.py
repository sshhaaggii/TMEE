"""
database/db.py — Unified Database Interface for TMEEE Secure Chat Application.
Supports Supabase PostgreSQL (via psycopg2) with automated schema provisioning,
thread-safe connection pooling, parameterized queries, and graceful SQLite fallback.
"""

import os
import re
import json
import logging
import sqlite3
from typing import Any, Optional, Union, List, Dict
from datetime import datetime, timezone, timedelta

from flask import g

from config import config

# Optional PostgreSQL driver imports
try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

logger = logging.getLogger("securechat.database")

# Global connection pool for Supabase PostgreSQL
_pg_pool: Optional["psycopg2.pool.ThreadedConnectionPool"] = None
_db_engine_in_use: Optional[str] = None


class UnifiedCursor:
    """
    Cursor wrapper providing identical dict-like row access,
    rowcount, and lastrowid across both PostgreSQL and SQLite.
    """
    def __init__(self, raw_cursor, is_postgres: bool = False, lastrowid: Optional[int] = None):
        self.cursor = raw_cursor
        self.is_postgres = is_postgres
        self._lastrowid = lastrowid

    def _normalize_row(self, row):
        if row is None:
            return None
        d = dict(row)
        if "receiver_id" in d and "recipient_id" not in d:
            d["recipient_id"] = d["receiver_id"]
        elif "recipient_id" in d and "receiver_id" not in d:
            d["receiver_id"] = d["recipient_id"]
        if "authentication_tag" in d and "tag" not in d:
            d["tag"] = d["authentication_tag"]
        elif "tag" in d and "authentication_tag" not in d:
            d["authentication_tag"] = d["tag"]
        return d

    def fetchone(self) -> Optional[Dict[str, Any]]:
        row = self.cursor.fetchone()
        if row is None:
            return None
        return self._normalize_row(row)

    def fetchall(self) -> List[Any]:
        rows = self.cursor.fetchall()
        if not rows:
            return []
        return [self._normalize_row(r) for r in rows]

    @property
    def rowcount(self) -> int:
        return self.cursor.rowcount

    @property
    def lastrowid(self) -> Optional[int]:
        if self.is_postgres:
            return self._lastrowid
        return getattr(self.cursor, "lastrowid", None)

    def __iter__(self):
        for r in self.cursor:
            yield self._normalize_row(r)


class UnifiedConnection:
    """
    Connection wrapper that provides a uniform interface whether
    talking to Supabase PostgreSQL or local SQLite.
    Automatically translates query placeholders (? -> %s for Postgres)
    and handles RETURNING id for lastrowid compatibility.
    """
    def __init__(self, raw_conn, is_postgres: bool = False):
        self.conn = raw_conn
        self.is_postgres = is_postgres

    def execute(self, sql: str, params: Union[tuple, list] = ()) -> UnifiedCursor:
        query = sql.strip()
        last_id = None

        if self.is_postgres:
            # Normalize SQLite-isms to PostgreSQL syntax
            # 1. Translate COLLATE NOCASE
            # Replace: WHERE col = ? COLLATE NOCASE -> WHERE LOWER(col) = LOWER(?)
            query = re.sub(
                r'(\w+)\s*=\s*\?\s*COLLATE\s+NOCASE',
                r'LOWER(\1) = LOWER(?)',
                query,
                flags=re.IGNORECASE
            )
            # Remove any trailing COLLATE NOCASE in other contexts
            query = re.sub(r'COLLATE\s+NOCASE', '', query, flags=re.IGNORECASE)

            # 2. Translate datetime('now') -> NOW()
            query = re.sub(r"datetime\('now'\)", "NOW()", query, flags=re.IGNORECASE)

            # 3. Translate ? -> %s
            query = query.replace("?", "%s")

            # 4. Translate recipient_id -> receiver_id and tag -> authentication_tag
            if is_insert or query.upper().startswith("UPDATE"):
                query = re.sub(r'\brecipient_id\b', 'receiver_id', query)
                query = re.sub(r'\btag\b', 'authentication_tag', query)

            # 5. Handle auto-generated primary key for INSERT
            if is_insert and "RETURNING" not in query.upper():
                query = query.rstrip("; ") + " RETURNING id;"

            cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(query, params)

            if is_insert:
                try:
                    res = cursor.fetchone()
                    if res and "id" in res:
                        last_id = res["id"]
                except Exception:
                    pass

            return UnifiedCursor(cursor, is_postgres=True, lastrowid=last_id)
        else:
            # SQLite path
            # If inserting into messages, ensure both receiver_id and recipient_id are populated
            if "INSERT INTO MESSAGES" in query.upper():
                if "receiver_id" in query and "recipient_id" not in query:
                    query = re.sub(r'\breceiver_id\b', 'receiver_id, recipient_id', query)
                    # Find parameter index for receiver_id to duplicate in params
                    # Parse column list
                    cols_match = re.search(r'\((.*?)\)\s*VALUES\s*\((.*?)\)', query, re.DOTALL | re.IGNORECASE)
                    if cols_match:
                        # adjust placeholders
                        cols = [c.strip() for c in cols_match.group(1).split(',')]
                        placeholders = [p.strip() for p in cols_match.group(2).split(',')]
                        rec_idx = cols.index('receiver_id')
                        # Insert a duplicate placeholder
                        placeholders.insert(rec_idx + 1, '?')
                        query = query[:cols_match.start(2)] + ', '.join(placeholders) + query[cols_match.end(2):]
                        params_list = list(params)
                        params_list.insert(rec_idx, params_list[rec_idx])
                        params = tuple(params_list)

            cursor = self.conn.cursor()
            cursor.execute(query, params)
            return UnifiedCursor(cursor, is_postgres=False, lastrowid=cursor.lastrowid)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        if not self.is_postgres:
            self.conn.close()


def _get_pg_pool() -> Optional["psycopg2.pool.ThreadedConnectionPool"]:
    """Initialize or reuse the ThreadedConnectionPool for Supabase."""
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool

    if not HAS_PSYCOPG2:
        logger.warning("psycopg2 is not installed; Supabase PostgreSQL connection unavailable.")
        return None

    dsn = config.get_postgres_dsn()
    if not dsn:
        return None

    try:
        # Establish ThreadedConnectionPool (min 1, max 10 connections)
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=dsn,
            connect_timeout=10,
        )
        logger.info("Connected to Supabase PostgreSQL connection pool successfully.")
        return _pg_pool
    except Exception as e:
        logger.warning("Failed to connect to Supabase PostgreSQL pool (%s). Falling back.", e)
        return None


def get_active_engine() -> str:
    """Return currently active database engine: 'supabase' or 'sqlite'."""
    global _db_engine_in_use
    if _db_engine_in_use:
        return _db_engine_in_use

    if config.is_supabase_configured() and HAS_PSYCOPG2:
        pool = _get_pg_pool()
        if pool is not None:
            _db_engine_in_use = "supabase"
            return "supabase"

    _db_engine_in_use = "sqlite"
    return "sqlite"


def get_db() -> UnifiedConnection:
    """
    Open or reuse the database connection for the current Flask request context.
    Returns a UnifiedConnection wrapping either Supabase PostgreSQL or SQLite.
    """
    if "unified_db" in g:
        return g.unified_db

    engine = get_active_engine()

    if engine == "supabase":
        pool = _get_pg_pool()
        if pool:
            try:
                pg_conn = pool.getconn()
                # Ensure connection is responsive
                pg_conn.autocommit = False
                g.pg_conn = pg_conn
                g.unified_db = UnifiedConnection(pg_conn, is_postgres=True)
                return g.unified_db
            except Exception as e:
                logger.error("Error leasing connection from Supabase pool: %s", e)

    # SQLite fallback
    os.makedirs(os.path.dirname(config.DATABASE), exist_ok=True)
    sqlite_conn = sqlite3.connect(
        config.DATABASE,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_conn.execute("PRAGMA journal_mode=WAL;")
    sqlite_conn.execute("PRAGMA foreign_keys=ON;")
    g.sqlite_conn = sqlite_conn
    g.unified_db = UnifiedConnection(sqlite_conn, is_postgres=False)
    return g.unified_db


def close_db(exc=None) -> None:
    """Teardown handler to return or close the DB connection at end of request."""
    # Handle PostgreSQL
    pg_conn = g.pop("pg_conn", None)
    if pg_conn is not None and _pg_pool is not None:
        try:
            if exc:
                pg_conn.rollback()
            else:
                pg_conn.commit()
            _pg_pool.putconn(pg_conn)
        except Exception as e:
            logger.warning("Error returning connection to Supabase pool: %s", e)

    # Handle SQLite
    sqlite_conn = g.pop("sqlite_conn", None)
    if sqlite_conn is not None:
        try:
            if exc:
                sqlite_conn.rollback()
            sqlite_conn.close()
        except Exception:
            pass

    g.pop("unified_db", None)


def init_db() -> None:
    """
    Provision all 6 required tables in the active database engine:
      1. users
      2. public_keys
      3. messages
      4. user_profiles
      5. user_sessions
      6. message_status
    """
    db = get_db()
    is_pg = db.is_postgres

    if is_pg:
        schema_path = os.path.join(config.BASE_DIR, "database", "schema_supabase.sql")
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            with db.conn.cursor() as cur:
                cur.execute(schema_sql)
            db.commit()
            logger.info("Supabase PostgreSQL tables successfully initialized.")
            return

    # SQLite schema provisioning
    raw_conn = db.conn

    # 1. Pre-migration check for existing messages table in SQLite
    has_messages = raw_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'").fetchone()
    if has_messages:
        cols = [r[1] for r in raw_conn.execute("PRAGMA table_info(messages)").fetchall()]
        if "receiver_id" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN receiver_id INTEGER DEFAULT 0;")
            if "recipient_id" in cols:
                raw_conn.execute("UPDATE messages SET receiver_id = recipient_id WHERE receiver_id = 0 OR receiver_id IS NULL;")
        if "recipient_id" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN recipient_id INTEGER DEFAULT 0;")
            if "receiver_id" in cols:
                raw_conn.execute("UPDATE messages SET recipient_id = receiver_id WHERE recipient_id = 0 OR recipient_id IS NULL;")
        if "authentication_tag" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN authentication_tag TEXT DEFAULT '';")
            if "tag" in cols:
                raw_conn.execute("UPDATE messages SET authentication_tag = tag WHERE authentication_tag = '' OR authentication_tag IS NULL;")
        if "tag" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN tag TEXT DEFAULT '';")
            if "authentication_tag" in cols:
                raw_conn.execute("UPDATE messages SET tag = authentication_tag WHERE tag = '' OR tag IS NULL;")
        if "is_edited" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN is_edited INTEGER DEFAULT 0;")
        if "edited_at" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN edited_at TEXT DEFAULT '';")
        if "reply_to_id" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER DEFAULT NULL;")
        if "is_pinned" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN is_pinned INTEGER DEFAULT 0;")
        if "message_type" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text';")
        if "media_meta" not in cols:
            raw_conn.execute("ALTER TABLE messages ADD COLUMN media_meta TEXT DEFAULT '';")
        raw_conn.commit()

    raw_conn.executescript("""
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
            receiver_id        INTEGER NOT NULL DEFAULT 0,
            recipient_id       INTEGER NOT NULL DEFAULT 0,
            ciphertext         TEXT    NOT NULL DEFAULT '',
            nonce              TEXT    NOT NULL DEFAULT '',
            authentication_tag TEXT    NOT NULL DEFAULT '',
            tag                TEXT    NOT NULL DEFAULT '',
            encrypted_package  TEXT    NOT NULL DEFAULT '',
            created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            delivered          INTEGER NOT NULL DEFAULT 0,
            is_deleted         INTEGER NOT NULL DEFAULT 0,
            is_edited          INTEGER NOT NULL DEFAULT 0,
            edited_at          TEXT    DEFAULT '',
            reply_to_id        INTEGER DEFAULT NULL,
            is_pinned          INTEGER NOT NULL DEFAULT 0,
            message_type       TEXT    NOT NULL DEFAULT 'text',
            media_meta         TEXT    NOT NULL DEFAULT '',
            expires_at         TEXT    DEFAULT NULL,
            expiration_seconds INTEGER NOT NULL DEFAULT 0,
            is_view_once       INTEGER NOT NULL DEFAULT 0,
            is_vanish          INTEGER NOT NULL DEFAULT 0,
            viewed_at          TEXT    DEFAULT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id);
        CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_pinned ON messages(is_pinned);

        CREATE TABLE IF NOT EXISTS message_reactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            emoji      TEXT    NOT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(message_id, user_id, emoji),
            FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_reactions_msg ON message_reactions(message_id);

        CREATE TABLE IF NOT EXISTS user_profiles (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER NOT NULL UNIQUE,
            profile_picture_url TEXT,
            bio                 TEXT,
            online_status       TEXT NOT NULL DEFAULT 'offline',
            updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_sessions (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER NOT NULL,
            session_id         TEXT,
            session_created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_active_at     TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS message_status (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id   INTEGER NOT NULL,
            delivered_at TEXT,
            read_at      TEXT,
            FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS call_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id        INTEGER NOT NULL,
            callee_id        INTEGER NOT NULL,
            call_type        TEXT NOT NULL DEFAULT 'voice',
            status           TEXT NOT NULL DEFAULT 'completed',
            duration_seconds INTEGER DEFAULT 0,
            started_at       TEXT NOT NULL,
            ended_at         TEXT,
            FOREIGN KEY(caller_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(callee_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_call_caller ON call_history(caller_id);
        CREATE INDEX IF NOT EXISTS idx_call_callee ON call_history(callee_id);

        CREATE TABLE IF NOT EXISTS scheduled_messages (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id          INTEGER NOT NULL,
            receiver_id        INTEGER NOT NULL,
            ciphertext         TEXT    NOT NULL DEFAULT '',
            nonce              TEXT    NOT NULL DEFAULT '',
            authentication_tag TEXT    NOT NULL DEFAULT '',
            tag                TEXT    NOT NULL DEFAULT '',
            encrypted_package  TEXT    NOT NULL DEFAULT '',
            message_type       TEXT    NOT NULL DEFAULT 'text',
            media_meta         TEXT    NOT NULL DEFAULT '',
            scheduled_for      TEXT    NOT NULL,
            status             TEXT    NOT NULL DEFAULT 'pending',
            created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            sent_at            TEXT    DEFAULT NULL,
            actual_message_id  INTEGER DEFAULT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sched_status_time ON scheduled_messages(status, scheduled_for);
        CREATE INDEX IF NOT EXISTS idx_sched_sender ON scheduled_messages(sender_id);
        CREATE INDEX IF NOT EXISTS idx_sched_receiver ON scheduled_messages(receiver_id);

        CREATE TABLE IF NOT EXISTS groups (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            avatar_url    TEXT NOT NULL DEFAULT '',
            creator_id    INTEGER NOT NULL,
            current_epoch INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_groups_creator ON groups(creator_id);

        CREATE TABLE IF NOT EXISTS group_members (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            role       TEXT NOT NULL DEFAULT 'member',
            joined_at  TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(group_id, user_id),
            FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);
        CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

        CREATE TABLE IF NOT EXISTS group_epoch_keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id      INTEGER NOT NULL,
            epoch         INTEGER NOT NULL,
            user_id       INTEGER NOT NULL,
            creator_id    INTEGER NOT NULL,
            encrypted_key TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(group_id, epoch, user_id),
            FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_group_epoch_keys_lookup ON group_epoch_keys(group_id, epoch, user_id);

        CREATE TABLE IF NOT EXISTS group_messages (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id           INTEGER NOT NULL,
            sender_id          INTEGER NOT NULL,
            epoch              INTEGER NOT NULL DEFAULT 1,
            ciphertext         TEXT NOT NULL DEFAULT '',
            nonce              TEXT NOT NULL DEFAULT '',
            authentication_tag TEXT NOT NULL DEFAULT '',
            tag                TEXT NOT NULL DEFAULT '',
            encrypted_package  TEXT NOT NULL DEFAULT '',
            message_type       TEXT NOT NULL DEFAULT 'text',
            media_meta         TEXT NOT NULL DEFAULT '',
            reply_to_id        INTEGER DEFAULT NULL,
            is_pinned          INTEGER NOT NULL DEFAULT 0,
            is_deleted         INTEGER NOT NULL DEFAULT 0,
            created_at         TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, created_at ASC);

        CREATE TABLE IF NOT EXISTS group_message_reactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            emoji      TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(message_id, user_id, emoji),
            FOREIGN KEY(message_id) REFERENCES group_messages(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_group_reactions_msg ON group_message_reactions(message_id);
    """)

    # Schema migration: ensure public_key column exists in users
    user_cols = [row[1] for row in raw_conn.execute("PRAGMA table_info(users)").fetchall()]
    if "public_key" not in user_cols:
        raw_conn.execute("ALTER TABLE users ADD COLUMN public_key TEXT;")

    # Schema migration: ensure disappearing and vanish columns exist in messages
    msg_cols = [row[1] for row in raw_conn.execute("PRAGMA table_info(messages)").fetchall()]
    if "expires_at" not in msg_cols:
        raw_conn.execute("ALTER TABLE messages ADD COLUMN expires_at TEXT DEFAULT NULL;")
    if "expiration_seconds" not in msg_cols:
        raw_conn.execute("ALTER TABLE messages ADD COLUMN expiration_seconds INTEGER NOT NULL DEFAULT 0;")
    if "is_view_once" not in msg_cols:
        raw_conn.execute("ALTER TABLE messages ADD COLUMN is_view_once INTEGER NOT NULL DEFAULT 0;")
    if "is_vanish" not in msg_cols:
        raw_conn.execute("ALTER TABLE messages ADD COLUMN is_vanish INTEGER NOT NULL DEFAULT 0;")
    if "viewed_at" not in msg_cols:
        raw_conn.execute("ALTER TABLE messages ADD COLUMN viewed_at TEXT DEFAULT NULL;")

    raw_conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);")

    # Schema migration: ensure disappearing columns exist in group_messages
    grp_msg_cols = [row[1] for row in raw_conn.execute("PRAGMA table_info(group_messages)").fetchall()]
    if "expires_at" not in grp_msg_cols:
        raw_conn.execute("ALTER TABLE group_messages ADD COLUMN expires_at TEXT DEFAULT NULL;")
    if "expiration_seconds" not in grp_msg_cols:
        raw_conn.execute("ALTER TABLE group_messages ADD COLUMN expiration_seconds INTEGER NOT NULL DEFAULT 0;")
    if "is_view_once" not in grp_msg_cols:
        raw_conn.execute("ALTER TABLE group_messages ADD COLUMN is_view_once INTEGER NOT NULL DEFAULT 0;")
    if "is_vanish" not in grp_msg_cols:
        raw_conn.execute("ALTER TABLE group_messages ADD COLUMN is_vanish INTEGER NOT NULL DEFAULT 0;")
    if "viewed_at" not in grp_msg_cols:
        raw_conn.execute("ALTER TABLE group_messages ADD COLUMN viewed_at TEXT DEFAULT NULL;")

    raw_conn.execute("CREATE INDEX IF NOT EXISTS idx_group_messages_expires_at ON group_messages(expires_at);")

    # Schema migration: ensure disappearing_timer exists in groups
    grp_cols = [row[1] for row in raw_conn.execute("PRAGMA table_info(groups)").fetchall()]
    if "disappearing_timer" not in grp_cols:
        raw_conn.execute("ALTER TABLE groups ADD COLUMN disappearing_timer INTEGER NOT NULL DEFAULT 0;")

    # Schema migration: ensure conversation_settings table exists
    raw_conn.execute("""
        CREATE TABLE IF NOT EXISTS conversation_settings (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id            INTEGER NOT NULL,
            user2_id            INTEGER NOT NULL,
            disappearing_timer  INTEGER NOT NULL DEFAULT 0,
            vanish_mode         INTEGER NOT NULL DEFAULT 0,
            updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user1_id, user2_id)
        );
    """)
    raw_conn.execute("CREATE INDEX IF NOT EXISTS idx_conv_settings_users ON conversation_settings(user1_id, user2_id);")

    raw_conn.commit()
    logger.info("SQLite tables successfully initialized.")


# ── Profile & Session Helper Operations ─────────────────────────────

def record_user_session(user_id: int, session_id: Optional[str] = None) -> None:
    """Insert or update user active session timestamp."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO user_sessions (user_id, session_id, session_created_at, last_active_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, session_id or "", now, now),
        )
        db.commit()
    except Exception as e:
        logger.debug("Session record skipped: %s", e)


def update_user_profile_status(user_id: int, status: str = "online", bio: Optional[str] = None) -> None:
    """Insert or update profile presence and metadata."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO user_profiles (user_id, profile_picture_url, bio, online_status, updated_at)
            VALUES (?, '', ?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE SET online_status = EXCLUDED.online_status, updated_at = EXCLUDED.updated_at
            """ if db.is_postgres else """
            INSERT INTO user_profiles (user_id, profile_picture_url, bio, online_status, updated_at)
            VALUES (?, '', ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET online_status = excluded.online_status, updated_at = excluded.updated_at
            """,
            (user_id, bio or "", status, now),
        )
        db.commit()
    except Exception as e:
        logger.debug("Profile status update skipped: %s", e)


def record_message_status(message_id: int, delivered: bool = True, read: bool = False) -> None:
    """Record delivery and read receipts in message_status table."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        delivered_at = now if delivered else None
        read_at = now if read else None

        db.execute(
            """
            INSERT INTO message_status (message_id, delivered_at, read_at)
            VALUES (?, ?, ?)
            """,
            (message_id, delivered_at, read_at),
        )
        db.commit()
    except Exception as e:
        logger.debug("Message status recording skipped: %s", e)


def update_message_read_status(message_id: int) -> None:
    """Update read timestamp in message_status."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute("UPDATE message_status SET read_at = ? WHERE message_id = ?", (now, message_id))
        if cur.rowcount <= 0:
            db.execute("INSERT INTO message_status (message_id, delivered_at, read_at) VALUES (?, ?, ?)", (message_id, now, now))
        db.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,))
        db.commit()
    except Exception as e:
        logger.debug("Read status update skipped: %s", e)


def add_or_toggle_reaction(message_id: int, user_id: int, emoji: str) -> Dict[str, Any]:
    """Toggle an emoji reaction for a message. Returns current reactions list for the message."""
    db = get_db()
    existing = db.execute(
        "SELECT id FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
        (message_id, user_id, emoji)
    ).fetchone()
    if existing:
        db.execute("DELETE FROM message_reactions WHERE id = ?", (existing["id"],))
        action = "removed"
    else:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)",
            (message_id, user_id, emoji, now)
        )
        action = "added"
    db.commit()
    reactions = get_message_reactions(message_id)
    return {"action": action, "reactions": reactions}


def get_message_reactions(message_id: int) -> List[Dict[str, Any]]:
    """Retrieve grouped emoji reactions for a message."""
    try:
        db = get_db()
        rows = db.execute(
            """
            SELECT mr.emoji, COUNT(mr.id) as count, GROUP_CONCAT(u.username) as usernames
            FROM message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ?
            GROUP BY mr.emoji
            """ if not db.is_postgres else """
            SELECT mr.emoji, COUNT(mr.id) as count, STRING_AGG(u.username, ',') as usernames
            FROM message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ?
            GROUP BY mr.emoji
            """,
            (message_id,)
        ).fetchall()
        result = []
        for r in rows:
            users_list = (r["usernames"] or "").split(",") if r.get("usernames") else []
            result.append({
                "emoji": r["emoji"],
                "count": r["count"],
                "users": users_list
            })
        return result
    except Exception as e:
        logger.debug("Reactions fetch error: %s", e)
        return []


def get_reactions_for_messages(message_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
    """Batch fetch reactions for a list of message IDs."""
    if not message_ids:
        return {}
    try:
        db = get_db()
        placeholders = ",".join(["?"] * len(message_ids))
        query = f"""
            SELECT mr.message_id, mr.emoji, COUNT(mr.id) as count,
                   {'GROUP_CONCAT(u.username)' if not db.is_postgres else 'STRING_AGG(u.username, \',\')'} as usernames
            FROM message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id IN ({placeholders})
            GROUP BY mr.message_id, mr.emoji
        """
        rows = db.execute(query, tuple(message_ids)).fetchall()
        result = {mid: [] for mid in message_ids}
        for r in rows:
            mid = r["message_id"]
            users_list = (r["usernames"] or "").split(",") if r.get("usernames") else []
            if mid in result:
                result[mid].append({
                    "emoji": r["emoji"],
                    "count": r["count"],
                    "users": users_list
                })
        return result
    except Exception as e:
        logger.debug("Batch reactions fetch error: %s", e)
        return {}


# ── Call History Helper Operations ──────────────────────────────────

def record_call_start(caller_id: int, callee_id: int, call_type: str = "voice") -> Optional[int]:
    """Record initiation of a WebRTC voice or video call."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            """
            INSERT INTO call_history (caller_id, callee_id, call_type, status, started_at)
            VALUES (?, ?, ?, 'calling', ?)
            """,
            (caller_id, callee_id, call_type, now)
        )
        db.commit()
        return cur.lastrowid
    except Exception as e:
        logger.error("Error recording call start: %s", e)
        return None


def record_call_end(call_id: int, status: str = "completed", duration_seconds: int = 0) -> Optional[Dict[str, Any]]:
    """Update call record upon completion, rejection, or missed call."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            UPDATE call_history
            SET status = ?, duration_seconds = ?, ended_at = ?
            WHERE id = ?
            """,
            (status, max(0, int(duration_seconds)), now, call_id)
        )
        db.commit()
        row = db.execute("SELECT * FROM call_history WHERE id = ?", (call_id,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error("Error updating call end: %s", e)
        return None


def get_call_history_for_user(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent call history for a user across all contacts."""
    try:
        db = get_db()
        query = """
            SELECT ch.id, ch.caller_id, ch.callee_id, ch.call_type, ch.status,
                   ch.duration_seconds, ch.started_at, ch.ended_at,
                   u_caller.username as caller_username,
                   u_callee.username as callee_username
            FROM call_history ch
            JOIN users u_caller ON ch.caller_id = u_caller.id
            JOIN users u_callee ON ch.callee_id = u_callee.id
            WHERE ch.caller_id = ? OR ch.callee_id = ?
            ORDER BY ch.id DESC
            LIMIT ?
        """
        rows = db.execute(query, (user_id, user_id, limit)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching call history for user: %s", e)
        return []


def get_call_history_between_users(user1_id: int, user2_id: int, limit: int = 30) -> List[Dict[str, Any]]:
    """Get call history between two specific users."""
    try:
        db = get_db()
        query = """
            SELECT ch.id, ch.caller_id, ch.callee_id, ch.call_type, ch.status,
                   ch.duration_seconds, ch.started_at, ch.ended_at,
                   u_caller.username as caller_username,
                   u_callee.username as callee_username
            FROM call_history ch
            JOIN users u_caller ON ch.caller_id = u_caller.id
            JOIN users u_callee ON ch.callee_id = u_callee.id
            WHERE (ch.caller_id = ? AND ch.callee_id = ?)
               OR (ch.caller_id = ? AND ch.callee_id = ?)
            ORDER BY ch.id DESC
            LIMIT ?
        """
        rows = db.execute(query, (user1_id, user2_id, user2_id, user1_id, limit)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching calls between users: %s", e)
        return []


# ── Scheduled Messaging Helper Operations ────────────────────────────

def create_scheduled_message(
    sender_id: int,
    receiver_id: int,
    ciphertext: str,
    nonce: str,
    tag: str,
    encrypted_package: str,
    scheduled_for: str,
    message_type: str = "text",
    media_meta: str = ""
) -> Optional[int]:
    """Store an encrypted scheduled message with zero plaintext. Returns scheduled message ID."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cursor = db.execute(
            """
            INSERT INTO scheduled_messages (
                sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                tag, encrypted_package, message_type, media_meta, scheduled_for,
                status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                sender_id, receiver_id, ciphertext, nonce, tag,
                tag, encrypted_package, message_type, media_meta,
                scheduled_for, now, now
            ),
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        logger.error("Error creating scheduled message: %s", e)
        return None


def get_scheduled_messages_for_user(user_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve scheduled messages created by a user with recipient details."""
    try:
        db = get_db()
        if status:
            query = """
                SELECT sm.*,
                       u_rec.username as recipient_username,
                       u_send.username as sender_username
                FROM scheduled_messages sm
                JOIN users u_rec ON sm.receiver_id = u_rec.id
                JOIN users u_send ON sm.sender_id = u_send.id
                WHERE sm.sender_id = ? AND sm.status = ?
                ORDER BY sm.scheduled_for ASC
            """
            rows = db.execute(query, (user_id, status)).fetchall()
        else:
            query = """
                SELECT sm.*,
                       u_rec.username as recipient_username,
                       u_send.username as sender_username
                FROM scheduled_messages sm
                JOIN users u_rec ON sm.receiver_id = u_rec.id
                JOIN users u_send ON sm.sender_id = u_send.id
                WHERE sm.sender_id = ?
                ORDER BY sm.scheduled_for ASC
            """
            rows = db.execute(query, (user_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching scheduled messages for user %s: %s", user_id, e)
        return []


def get_scheduled_messages_between(sender_id: int, receiver_id: int, status: str = "pending") -> List[Dict[str, Any]]:
    """Retrieve pending scheduled messages sent by sender to specific recipient."""
    try:
        db = get_db()
        query = """
            SELECT sm.*,
                   u_rec.username as recipient_username,
                   u_send.username as sender_username
            FROM scheduled_messages sm
            JOIN users u_rec ON sm.receiver_id = u_rec.id
            JOIN users u_send ON sm.sender_id = u_send.id
            WHERE sm.sender_id = ? AND sm.receiver_id = ? AND sm.status = ?
            ORDER BY sm.scheduled_for ASC
        """
        rows = db.execute(query, (sender_id, receiver_id, status)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching scheduled messages between %s and %s: %s", sender_id, receiver_id, e)
        return []


def get_scheduled_message_by_id(msg_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Fetch a single scheduled message by ID, verifying sender ownership if user_id is provided."""
    try:
        db = get_db()
        if user_id is not None:
            query = """
                SELECT sm.*,
                       u_rec.username as recipient_username,
                       u_send.username as sender_username
                FROM scheduled_messages sm
                JOIN users u_rec ON sm.receiver_id = u_rec.id
                JOIN users u_send ON sm.sender_id = u_send.id
                WHERE sm.id = ? AND sm.sender_id = ?
            """
            row = db.execute(query, (msg_id, user_id)).fetchone()
        else:
            query = """
                SELECT sm.*,
                       u_rec.username as recipient_username,
                       u_send.username as sender_username
                FROM scheduled_messages sm
                JOIN users u_rec ON sm.receiver_id = u_rec.id
                JOIN users u_send ON sm.sender_id = u_send.id
                WHERE sm.id = ?
            """
            row = db.execute(query, (msg_id,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error("Error fetching scheduled message %s: %s", msg_id, e)
        return None


def update_scheduled_message(
    msg_id: int,
    user_id: int,
    ciphertext: Optional[str] = None,
    nonce: Optional[str] = None,
    tag: Optional[str] = None,
    encrypted_package: Optional[str] = None,
    scheduled_for: Optional[str] = None
) -> bool:
    """Update scheduled message payload or scheduled time (only if pending)."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        current = get_scheduled_message_by_id(msg_id, user_id)
        if not current or current.get("status") != "pending":
            return False

        new_ciphertext = ciphertext if ciphertext is not None else current["ciphertext"]
        new_nonce = nonce if nonce is not None else current["nonce"]
        new_tag = tag if tag is not None else current.get("tag") or current.get("authentication_tag", "")
        new_pkg = encrypted_package if encrypted_package is not None else current["encrypted_package"]
        new_time = scheduled_for if scheduled_for is not None else current["scheduled_for"]

        cur = db.execute(
            """
            UPDATE scheduled_messages
            SET ciphertext = ?,
                nonce = ?,
                authentication_tag = ?,
                tag = ?,
                encrypted_package = ?,
                scheduled_for = ?,
                updated_at = ?
            WHERE id = ? AND sender_id = ? AND status = 'pending'
            """,
            (new_ciphertext, new_nonce, new_tag, new_tag, new_pkg, new_time, now, msg_id, user_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error updating scheduled message %s: %s", msg_id, e)
        return False


def cancel_scheduled_message(msg_id: int, user_id: int) -> bool:
    """Cancel a pending scheduled message."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            """
            UPDATE scheduled_messages
            SET status = 'cancelled',
                updated_at = ?
            WHERE id = ? AND sender_id = ? AND status = 'pending'
            """,
            (now, msg_id, user_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error cancelling scheduled message %s: %s", msg_id, e)
        return False


def get_due_scheduled_messages() -> List[Dict[str, Any]]:
    """Retrieve all pending scheduled messages whose delivery time has arrived (in UTC)."""
    try:
        db = get_db()
        query = """
            SELECT sm.*,
                   u_rec.username as recipient_username,
                   u_send.username as sender_username
            FROM scheduled_messages sm
            JOIN users u_rec ON sm.receiver_id = u_rec.id
            JOIN users u_send ON sm.sender_id = u_send.id
            WHERE sm.status = 'pending'
            ORDER BY sm.scheduled_for ASC
        """
        rows = db.execute(query).fetchall()
        now_utc = datetime.now(timezone.utc)
        due = []
        for r in rows:
            sched_str = r["scheduled_for"]
            try:
                # Normalize ISO string to UTC
                sched_dt = datetime.fromisoformat(sched_str.replace("Z", "+00:00"))
                if sched_dt.tzinfo is None:
                    sched_dt = sched_dt.replace(tzinfo=timezone.utc)
                if sched_dt <= now_utc:
                    due.append(dict(r))
            except Exception as parse_err:
                logger.warning("Could not parse scheduled_for '%s' for msg %s: %s", sched_str, r.get("id"), parse_err)
                # Fallback to string comparison if parsing fails
                if sched_str <= now_utc.isoformat():
                    due.append(dict(r))
        return due
    except Exception as e:
        logger.error("Error fetching due scheduled messages: %s", e)
        return []


def mark_scheduled_message_sent(msg_id: int, actual_message_id: Optional[int] = None) -> bool:
    """Mark a scheduled message as sent upon delivery."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            """
            UPDATE scheduled_messages
            SET status = 'sent',
                sent_at = ?,
                actual_message_id = ?,
                updated_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (now, actual_message_id, now, msg_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error marking scheduled message %s as sent: %s", msg_id, e)
        return False


# ── Group Conversation Helper Operations ─────────────────────────────

def create_group(name: str, creator_id: int, description: str = "", avatar_url: str = "") -> Optional[int]:
    """Create a new group and add creator as the initial admin."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            """
            INSERT INTO groups (name, description, avatar_url, creator_id, current_epoch, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (name.strip(), description.strip(), avatar_url.strip(), creator_id, now, now),
        )
        db.commit()
        group_id = cur.lastrowid
        if group_id:
            db.execute(
                """
                INSERT INTO group_members (group_id, user_id, role, joined_at)
                VALUES (?, ?, 'admin', ?)
                """,
                (group_id, creator_id, now),
            )
            db.commit()
        return group_id
    except Exception as e:
        logger.error("Error creating group: %s", e)
        return None


def get_group_by_id(group_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve group details by ID."""
    try:
        db = get_db()
        row = db.execute(
            """
            SELECT g.*, u.username as creator_username,
                   (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
            FROM groups g
            JOIN users u ON g.creator_id = u.id
            WHERE g.id = ?
            """,
            (group_id,),
        ).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error("Error fetching group %s: %s", group_id, e)
        return None


def get_user_groups(user_id: int) -> List[Dict[str, Any]]:
    """Retrieve all groups that a user belongs to."""
    try:
        db = get_db()
        query = """
            SELECT g.*, gm.role as my_role, gm.joined_at,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count,
                   (SELECT gm_last.created_at FROM group_messages gm_last WHERE gm_last.group_id = g.id ORDER BY gm_last.id DESC LIMIT 1) as last_message_time
            FROM group_members gm
            JOIN groups g ON gm.group_id = g.id
            WHERE gm.user_id = ?
            ORDER BY COALESCE(last_message_time, g.updated_at) DESC
        """
        rows = db.execute(query, (user_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching groups for user %s: %s", user_id, e)
        return []


def get_group_members(group_id: int) -> List[Dict[str, Any]]:
    """Retrieve all members of a group with their profiles and public keys."""
    try:
        db = get_db()
        query = """
            SELECT gm.id as membership_id, gm.group_id, gm.user_id, gm.role, gm.joined_at,
                   u.username, u.email, u.public_key,
                   COALESCE(up.online_status, 'offline') as online_status,
                   COALESCE(up.bio, '') as bio,
                   COALESCE(up.profile_picture_url, '') as profile_picture_url
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            LEFT JOIN user_profiles up ON u.id = up.user_id
            WHERE gm.group_id = ?
            ORDER BY CASE WHEN gm.role = 'admin' THEN 0 ELSE 1 END, u.username ASC
        """
        rows = db.execute(query, (group_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error("Error fetching members for group %s: %s", group_id, e)
        return []


def is_group_member(group_id: int, user_id: int) -> bool:
    """Check if user is a member of the group."""
    try:
        db = get_db()
        row = db.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
        return bool(row)
    except Exception as e:
        logger.error("Error checking group membership: %s", e)
        return False


def get_group_member_role(group_id: int, user_id: int) -> Optional[str]:
    """Return 'admin' or 'member', or None if not a member."""
    try:
        db = get_db()
        row = db.execute(
            "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
        return row["role"] if row else None
    except Exception as e:
        logger.error("Error fetching group role: %s", e)
        return None


def add_group_member(group_id: int, user_id: int, role: str = "member") -> bool:
    """Add a new member to the group."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_at)
            VALUES (?, ?, ?, ?)
            """ if not db.is_postgres else """
            INSERT INTO group_members (group_id, user_id, role, joined_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (group_id, user_id) DO NOTHING
            """,
            (group_id, user_id, role, now),
        )
        db.execute("UPDATE groups SET updated_at = ? WHERE id = ?", (now, group_id))
        db.commit()
        return True
    except Exception as e:
        logger.error("Error adding group member: %s", e)
        return False


def remove_group_member(group_id: int, user_id: int) -> bool:
    """Remove a member from the group."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        )
        db.execute("UPDATE groups SET updated_at = ? WHERE id = ?", (now, group_id))
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error removing group member: %s", e)
        return False


def update_group_info(group_id: int, name: Optional[str] = None, description: Optional[str] = None, avatar_url: Optional[str] = None) -> bool:
    """Update group metadata."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        current = get_group_by_id(group_id)
        if not current:
            return False
        new_name = name.strip() if name is not None else current["name"]
        new_desc = description.strip() if description is not None else current["description"]
        new_avatar = avatar_url.strip() if avatar_url is not None else current["avatar_url"]

        cur = db.execute(
            """
            UPDATE groups
            SET name = ?, description = ?, avatar_url = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_name, new_desc, new_avatar, now, group_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error updating group info: %s", e)
        return False


def update_group_member_role(group_id: int, user_id: int, role: str) -> bool:
    """Promote or demote group member role."""
    try:
        db = get_db()
        cur = db.execute(
            "UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?",
            (role, group_id, user_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error updating group member role: %s", e)
        return False


def update_group_epoch(group_id: int, new_epoch: int) -> bool:
    """Increment group current_epoch for key rotation."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "UPDATE groups SET current_epoch = ?, updated_at = ? WHERE id = ?",
            (new_epoch, now, group_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error updating group epoch: %s", e)
        return False


def store_group_epoch_keys(group_id: int, epoch: int, creator_id: int, member_keys: List[Dict[str, Any]]) -> bool:
    """
    Store wrapped Group Encryption Keys (GEK) encrypted pairwise for each member.
    ZERO plaintext group key is ever stored.
    member_keys format: [{'user_id': int, 'encrypted_key': str}, ...]
    """
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        for mk in member_keys:
            target_user_id = mk["user_id"]
            enc_key = mk["encrypted_key"]
            if not isinstance(enc_key, str):
                enc_key = json.dumps(enc_key)

            db.execute(
                """
                INSERT OR REPLACE INTO group_epoch_keys (group_id, epoch, user_id, creator_id, encrypted_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """ if not db.is_postgres else """
                INSERT INTO group_epoch_keys (group_id, epoch, user_id, creator_id, encrypted_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (group_id, epoch, user_id) DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key, created_at = EXCLUDED.created_at
                """,
                (group_id, epoch, target_user_id, creator_id, enc_key, now),
            )
        update_group_epoch(group_id, epoch)
        db.commit()
        return True
    except Exception as e:
        logger.error("Error storing group epoch keys: %s", e)
        return False


def get_group_epoch_key_for_user(group_id: int, epoch: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve wrapped group key package for user in specified epoch."""
    try:
        db = get_db()
        row = db.execute(
            """
            SELECT k.*, u.username as creator_username
            FROM group_epoch_keys k
            LEFT JOIN users u ON k.creator_id = u.id
            WHERE k.group_id = ? AND k.epoch = ? AND k.user_id = ?
            """,
            (group_id, epoch, user_id),
        ).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error("Error fetching group epoch key: %s", e)
        return None


def create_group_message(
    group_id: int,
    sender_id: int,
    epoch: int,
    ciphertext: str,
    nonce: str,
    tag: str,
    encrypted_package: str,
    message_type: str = "text",
    media_meta: str = "",
    reply_to_id: Optional[int] = None,
    expires_at: Optional[str] = None,
    expiration_seconds: int = 0,
    is_view_once: int = 0,
    is_vanish: int = 0
) -> Optional[int]:
    """Store encrypted group message payload with zero plaintext."""
    try:
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            """
            INSERT INTO group_messages (
                group_id, sender_id, epoch, ciphertext, nonce, authentication_tag,
                tag, encrypted_package, message_type, media_meta, reply_to_id,
                is_pinned, is_deleted, created_at, expires_at, expiration_seconds,
                is_view_once, is_vanish
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?)
            """,
            (
                group_id, sender_id, epoch, ciphertext, nonce, tag,
                tag, encrypted_package, message_type, media_meta, reply_to_id, now,
                expires_at, expiration_seconds, is_view_once, is_vanish
            ),
        )
        db.execute("UPDATE groups SET updated_at = ? WHERE id = ?", (now, group_id))
        db.commit()
        return cur.lastrowid
    except Exception as e:
        logger.error("Error creating group message: %s", e)
        return None


def get_group_messages(group_id: int, limit: int = 60) -> List[Dict[str, Any]]:
    """Retrieve recent encrypted group messages (excluding expired)."""
    try:
        db = get_db()
        now_iso = datetime.now(timezone.utc).isoformat()
        query = """
            SELECT gm.*, u.username as sender_username,
                   COALESCE(up.profile_picture_url, '') as sender_avatar,
                   COALESCE(up.online_status, 'offline') as sender_status
            FROM group_messages gm
            JOIN users u ON gm.sender_id = u.id
            LEFT JOIN user_profiles up ON u.id = up.user_id
            WHERE gm.group_id = ? AND gm.is_deleted = 0
              AND (gm.expires_at IS NULL OR gm.expires_at > ?)
            ORDER BY gm.id ASC
            LIMIT ?
        """
        rows = db.execute(query, (group_id, now_iso, limit)).fetchall()
        msgs = []
        for r in rows:
            m = dict(r)
            m["reactions"] = get_group_message_reactions(m["id"])
            msgs.append(m)
        return msgs
    except Exception as e:
        logger.error("Error fetching group messages: %s", e)
        return []


def add_or_toggle_group_reaction(message_id: int, user_id: int, emoji: str) -> Dict[str, Any]:
    """Toggle reaction on a group message."""
    db = get_db()
    existing = db.execute(
        "SELECT id FROM group_message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
        (message_id, user_id, emoji),
    ).fetchone()
    if existing:
        db.execute("DELETE FROM group_message_reactions WHERE id = ?", (existing["id"],))
        action = "removed"
    else:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO group_message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)",
            (message_id, user_id, emoji, now),
        )
        action = "added"
    db.commit()
    reactions = get_group_message_reactions(message_id, user_id)
    count = sum(r["count"] for r in reactions if r["emoji"] == emoji)
    return {"action": action, "added": (action == "added"), "count": count, "reactions": reactions}


def get_group_message_reactions(message_id: int, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieve aggregated reactions for a group message."""
    try:
        db = get_db()
        my_username = None
        if user_id:
            my_user_row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            if my_user_row:
                my_username = my_user_row["username"]

        query = """
            SELECT mr.emoji, COUNT(mr.id) as count,
                   GROUP_CONCAT(u.username) as usernames
            FROM group_message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ?
            GROUP BY mr.emoji
        """ if not db.is_postgres else """
            SELECT mr.emoji, COUNT(mr.id) as count,
                   STRING_AGG(u.username, ',') as usernames
            FROM group_message_reactions mr
            JOIN users u ON mr.user_id = u.id
            WHERE mr.message_id = ?
            GROUP BY mr.emoji
        """
        rows = db.execute(query, (message_id,)).fetchall()
        result = []
        for r in rows:
            users_list = [u.strip() for u in (r["usernames"] or "").split(",") if u.strip()] if r.get("usernames") else []
            reacted_by_me = (my_username in users_list) if my_username else False
            result.append({
                "emoji": r["emoji"],
                "count": r["count"],
                "users": users_list,
                "reacted_by_me": reacted_by_me,
            })
        return result
    except Exception as e:
        logger.error("Error fetching group message reactions: %s", e)
        return []


def delete_group_message(message_id: int, user_id: int) -> bool:
    """Soft-delete a group message if the user is the sender or a group admin."""
    try:
        db = get_db()
        msg = db.execute("SELECT * FROM group_messages WHERE id = ?", (message_id,)).fetchone()
        if not msg:
            return False

        group_id = msg["group_id"]
        sender_id = msg["sender_id"]
        role = get_group_member_role(group_id, user_id)

        # Allowed if user is sender or admin
        if user_id != sender_id and role != "admin":
            return False

        cur = db.execute("UPDATE group_messages SET is_deleted = 1 WHERE id = ?", (message_id,))
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error deleting group message: %s", e)
        return False


# ─── DISAPPEARING MESSAGES & VANISH MODE HELPERS ─────────────────────────

def get_conversation_settings(user1_id: int, user2_id: int) -> Dict[str, Any]:
    """Retrieve shared conversation settings (disappearing timer, vanish mode) for a user pair."""
    try:
        db = get_db()
        u1, u2 = (user1_id, user2_id) if user1_id < user2_id else (user2_id, user1_id)
        row = db.execute(
            "SELECT * FROM conversation_settings WHERE user1_id = ? AND user2_id = ?",
            (u1, u2),
        ).fetchone()
        if row:
            return {
                "user1_id": u1,
                "user2_id": u2,
                "disappearing_timer": int(row["disappearing_timer"] or 0),
                "vanish_mode": bool(row["vanish_mode"]),
                "updated_at": row.get("updated_at") or "",
            }
        return {
            "user1_id": u1,
            "user2_id": u2,
            "disappearing_timer": 0,
            "vanish_mode": False,
            "updated_at": "",
        }
    except Exception as e:
        logger.error("Error retrieving conversation settings: %s", e)
        return {"user1_id": min(user1_id, user2_id), "user2_id": max(user1_id, user2_id), "disappearing_timer": 0, "vanish_mode": False, "updated_at": ""}


def set_conversation_settings(
    user1_id: int,
    user2_id: int,
    disappearing_timer: Optional[int] = None,
    vanish_mode: Optional[bool] = None,
) -> Dict[str, Any]:
    """Create or update conversation settings for a 1-on-1 user pair."""
    try:
        db = get_db()
        u1, u2 = (user1_id, user2_id) if user1_id < user2_id else (user2_id, user1_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        existing = db.execute(
            "SELECT * FROM conversation_settings WHERE user1_id = ? AND user2_id = ?",
            (u1, u2),
        ).fetchone()

        if existing:
            new_timer = int(disappearing_timer) if disappearing_timer is not None else int(existing["disappearing_timer"] or 0)
            new_vanish = int(bool(vanish_mode)) if vanish_mode is not None else int(bool(existing["vanish_mode"]))
            db.execute(
                """
                UPDATE conversation_settings
                SET disappearing_timer = ?, vanish_mode = ?, updated_at = ?
                WHERE user1_id = ? AND user2_id = ?
                """,
                (new_timer, new_vanish, now_iso, u1, u2),
            )
        else:
            new_timer = int(disappearing_timer) if disappearing_timer is not None else 0
            new_vanish = int(bool(vanish_mode)) if vanish_mode is not None else 0
            db.execute(
                """
                INSERT INTO conversation_settings (user1_id, user2_id, disappearing_timer, vanish_mode, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (u1, u2, new_timer, new_vanish, now_iso),
            )
        db.commit()
        return {
            "user1_id": u1,
            "user2_id": u2,
            "disappearing_timer": new_timer,
            "vanish_mode": bool(new_vanish),
            "updated_at": now_iso,
        }
    except Exception as e:
        logger.error("Error updating conversation settings: %s", e)
        return {"error": str(e)}


def get_group_disappearing_timer(group_id: int) -> int:
    """Get group disappearing timer in seconds (0 = off)."""
    try:
        db = get_db()
        row = db.execute("SELECT disappearing_timer FROM groups WHERE id = ?", (group_id,)).fetchone()
        return int(row["disappearing_timer"]) if row and row.get("disappearing_timer") else 0
    except Exception as e:
        logger.error("Error getting group disappearing timer: %s", e)
        return 0


def set_group_disappearing_timer(group_id: int, timer: int) -> bool:
    """Set group disappearing timer in seconds."""
    try:
        db = get_db()
        now_iso = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "UPDATE groups SET disappearing_timer = ?, updated_at = ? WHERE id = ?",
            (int(timer), now_iso, group_id),
        )
        db.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error setting group disappearing timer: %s", e)
        return False


def _cleanup_media_file(media_meta_raw: Any):
    """Safely delete encrypted media file on disk when a message expires or is purged."""
    try:
        if not media_meta_raw:
            return
        meta = media_meta_raw
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                return
        if not isinstance(meta, dict):
            return

        # Check common file path keys
        for key in ("file_path", "disk_path", "filepath", "path"):
            path = meta.get(key)
            if path and isinstance(path, str) and os.path.exists(path):
                try:
                    os.remove(path)
                    logger.info("Deleted expired encrypted file: %s", path)
                except Exception as ex:
                    logger.warning("Could not delete expired media file %s: %s", path, ex)
    except Exception as e:
        logger.error("Error cleaning up media file: %s", e)


def mark_message_viewed(message_id: int, is_group: bool = False, viewer_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Mark an ephemeral message (such as view-once or vanish-mode) as viewed.
    Starts the short countdown (10s) to permanent purge if view-once, or records viewed_at.
    """
    try:
        db = get_db()
        table = "group_messages" if is_group else "messages"
        msg = db.execute(f"SELECT * FROM {table} WHERE id = ?", (message_id,)).fetchone()
        if not msg:
            return {"ok": False, "error": "Message not found"}

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # If already has viewed_at, keep existing expires_at
        if msg.get("viewed_at"):
            return {
                "ok": True,
                "id": message_id,
                "viewed_at": msg["viewed_at"],
                "expires_at": msg.get("expires_at"),
                "is_view_once": bool(msg.get("is_view_once")),
            }

        updates = ["viewed_at = ?"]
        params = [now_iso]

        # For view-once messages, set expiration to 10 seconds after viewing
        expires_at = msg.get("expires_at")
        if msg.get("is_view_once"):
            exp_time = now + timedelta(seconds=10)
            expires_at = exp_time.isoformat()
            updates.append("expires_at = ?")
            updates.append("expiration_seconds = ?")
            params.extend([expires_at, 10])

        params.append(message_id)
        db.execute(f"UPDATE {table} SET {', '.join(updates)} WHERE id = ?", tuple(params))
        db.commit()

        return {
            "ok": True,
            "id": message_id,
            "viewed_at": now_iso,
            "expires_at": expires_at,
            "is_view_once": bool(msg.get("is_view_once")),
        }
    except Exception as e:
        logger.error("Error marking message viewed: %s", e)
        return {"ok": False, "error": str(e)}


def purge_expired_messages() -> Dict[str, Any]:
    """
    Purge all expired messages and group messages from the database and disk storage.
    Enforces server-side zero-retention for expired content.
    Returns lists of expired 1-on-1 and group messages for real-time notification emission.
    """
    expired_direct = []
    expired_groups = []
    try:
        db = get_db()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Fetch expired 1-on-1 messages
        direct_rows = db.execute(
            """
            SELECT m.id, m.sender_id, m.receiver_id, m.media_meta,
                   u_s.username as sender_username, u_r.username as receiver_username
            FROM messages m
            JOIN users u_s ON m.sender_id = u_s.id
            JOIN users u_r ON m.receiver_id = u_r.id
            WHERE m.expires_at IS NOT NULL AND m.expires_at <= ?
            """,
            (now_iso,),
        ).fetchall()

        for r in direct_rows:
            expired_direct.append({
                "id": r["id"],
                "sender_id": r["sender_id"],
                "receiver_id": r["receiver_id"],
                "sender_username": r["sender_username"],
                "receiver_username": r["receiver_username"],
            })
            _cleanup_media_file(r.get("media_meta"))

        # 2. Fetch expired group messages
        group_rows = db.execute(
            """
            SELECT gm.id, gm.group_id, gm.sender_id, gm.media_meta
            FROM group_messages gm
            WHERE gm.expires_at IS NOT NULL AND gm.expires_at <= ?
            """,
            (now_iso,),
        ).fetchall()

        for r in group_rows:
            expired_groups.append({
                "id": r["id"],
                "group_id": r["group_id"],
                "sender_id": r["sender_id"],
            })
            _cleanup_media_file(r.get("media_meta"))

        # 3. Hard delete expired 1-on-1 messages and dependent records
        if direct_rows:
            direct_ids = [r["id"] for r in direct_rows]
            placeholders = ",".join("?" * len(direct_ids))
            db.execute(f"DELETE FROM message_reactions WHERE message_id IN ({placeholders})", direct_ids)
            db.execute(f"DELETE FROM message_status WHERE message_id IN ({placeholders})", direct_ids)
            db.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", direct_ids)

        # 4. Hard delete expired group messages and dependent records
        if group_rows:
            group_msg_ids = [r["id"] for r in group_rows]
            placeholders = ",".join("?" * len(group_msg_ids))
            db.execute(f"DELETE FROM group_message_reactions WHERE message_id IN ({placeholders})", group_msg_ids)
            db.execute(f"DELETE FROM group_messages WHERE id IN ({placeholders})", group_msg_ids)

        db.commit()
    except Exception as e:
        logger.error("Error purging expired messages: %s", e)

    return {
        "expired_direct": expired_direct,
        "expired_groups": expired_groups,
    }




