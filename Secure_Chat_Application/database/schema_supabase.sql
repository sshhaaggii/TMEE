-- =====================================================================
-- TMEEE Secure Chat Application: Supabase PostgreSQL Database Schema
-- Module: End-to-End Encrypted Messaging Database Structure
-- =====================================================================

-- ── 1. USERS TABLE ───────────────────────────────────────────────────
-- Stores user authentication credentials, identity, and active public key.
-- Password hash: pbkdf2:sha256 (600,000+ iterations, salt + digest).
-- Zero plaintext passwords; zero private encryption keys stored.
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    public_key    TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(LOWER(email));

-- ── 2. PUBLIC KEYS TABLE ─────────────────────────────────────────────
-- Stores active and historical X25519 public keys per user.
-- Used by clients to establish Diffie-Hellman key exchange (RFC 7748).
-- Private keys reside exclusively on users' local client devices.
CREATE TABLE IF NOT EXISTS public_keys (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT        NOT NULL,
    algorithm  VARCHAR(50) NOT NULL DEFAULT 'X25519',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_public_keys_user ON public_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_public_keys_created ON public_keys(created_at DESC);

-- ── 3. MESSAGES TABLE ────────────────────────────────────────────────
-- Stores End-to-End Encrypted message payloads.
-- Contains ONLY ciphertext, unique 12-byte nonce, authentication tag,
-- and encrypted package. ZERO PLAINTEXT is ever received or stored.
CREATE TABLE IF NOT EXISTS messages (
    id                 SERIAL PRIMARY KEY,
    sender_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext         TEXT    NOT NULL DEFAULT '',
    nonce              TEXT    NOT NULL DEFAULT '',
    authentication_tag TEXT    NOT NULL DEFAULT '',
    encrypted_package  TEXT    NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered          BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    is_edited          BOOLEAN NOT NULL DEFAULT FALSE,
    edited_at          TIMESTAMPTZ,
    reply_to_id        INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    is_pinned          BOOLEAN NOT NULL DEFAULT FALSE,
    message_type       VARCHAR(50) NOT NULL DEFAULT 'text',
    media_meta         TEXT NOT NULL DEFAULT ''
);

-- Backward compatibility aliases for queries referencing recipient_id and tag
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='recipient_id') THEN
        ALTER TABLE messages ADD COLUMN recipient_id INTEGER GENERATED ALWAYS AS (receiver_id) STORED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='tag') THEN
        ALTER TABLE messages ADD COLUMN tag TEXT GENERATED ALWAYS AS (authentication_tag) STORED;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='is_edited') THEN
        ALTER TABLE messages ADD COLUMN is_edited BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='edited_at') THEN
        ALTER TABLE messages ADD COLUMN edited_at TIMESTAMPTZ;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='reply_to_id') THEN
        ALTER TABLE messages ADD COLUMN reply_to_id INTEGER REFERENCES messages(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='is_pinned') THEN
        ALTER TABLE messages ADD COLUMN is_pinned BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='message_type') THEN
        ALTER TABLE messages ADD COLUMN message_type VARCHAR(50) NOT NULL DEFAULT 'text';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='media_meta') THEN
        ALTER TABLE messages ADD COLUMN media_meta TEXT NOT NULL DEFAULT '';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at ASC);
CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages(is_deleted);
CREATE INDEX IF NOT EXISTS idx_messages_pinned ON messages(is_pinned);

-- ── 3.1 MESSAGE REACTIONS TABLE ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS message_reactions (
    id         SERIAL PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_reactions_msg ON message_reactions(message_id);

-- ── 4. USER PROFILES TABLE ───────────────────────────────────────────
-- User biographical information, profile image, and online status.
CREATE TABLE IF NOT EXISTS user_profiles (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    profile_picture_url TEXT,
    bio                 TEXT,
    online_status       VARCHAR(50) NOT NULL DEFAULT 'offline',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_user ON user_profiles(user_id);

-- ── 5. USER SESSIONS TABLE ───────────────────────────────────────────
-- Tracks active user sessions and heartbeat timestamps for presence.
CREATE TABLE IF NOT EXISTS user_sessions (
    id                 SERIAL PRIMARY KEY,
    user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id         VARCHAR(255),
    session_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(last_active_at DESC);

-- ── 6. MESSAGE STATUS TABLE ──────────────────────────────────────────
-- Detailed delivery and read receipts for real-time messaging.
CREATE TABLE IF NOT EXISTS message_status (
    id           SERIAL PRIMARY KEY,
    message_id   INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    delivered_at TIMESTAMPTZ,
    read_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_message_status_msg ON message_status(message_id);

-- ── 7. SCHEDULED MESSAGES TABLE ──────────────────────────────────────
-- Stores encrypted messages scheduled for future delivery.
-- Zero plaintext: stores only ciphertext, nonce, tag, encrypted_package.
CREATE TABLE IF NOT EXISTS scheduled_messages (
    id                 SERIAL PRIMARY KEY,
    sender_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext         TEXT    NOT NULL DEFAULT '',
    nonce              TEXT    NOT NULL DEFAULT '',
    authentication_tag TEXT    NOT NULL DEFAULT '',
    tag                TEXT    NOT NULL DEFAULT '',
    encrypted_package  TEXT    NOT NULL DEFAULT '',
    message_type       VARCHAR(50) NOT NULL DEFAULT 'text',
    media_meta         TEXT    NOT NULL DEFAULT '',
    scheduled_for      TIMESTAMPTZ NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at            TIMESTAMPTZ,
    actual_message_id  INTEGER REFERENCES messages(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sched_status_time ON scheduled_messages(status, scheduled_for);
CREATE INDEX IF NOT EXISTS idx_sched_sender ON scheduled_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_sched_receiver ON scheduled_messages(receiver_id);

-- ═════════════════════════════════════════════════════════════════════
-- ROW LEVEL SECURITY (RLS) POLICIES FOR SUPABASE
-- ═════════════════════════════════════════════════════════════════════
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_messages ENABLE ROW LEVEL SECURITY;

-- Allow backend service-role / authenticated pooler unrestricted access
CREATE POLICY IF NOT EXISTS backend_all_users ON users FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_public_keys ON public_keys FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_messages ON messages FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_user_profiles ON user_profiles FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_user_sessions ON user_sessions FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_message_status ON message_status FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_scheduled_messages ON scheduled_messages FOR ALL USING (true);

-- ── 8. GROUPS TABLE ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS groups (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(100) NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    avatar_url    TEXT NOT NULL DEFAULT '',
    creator_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_epoch INTEGER NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_groups_creator ON groups(creator_id);

-- ── 9. GROUP MEMBERS TABLE ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_members (
    id         SERIAL PRIMARY KEY,
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(20) NOT NULL DEFAULT 'member', -- 'admin' or 'member'
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

-- ── 10. GROUP EPOCH KEYS TABLE ───────────────────────────────────────
-- Stores wrapped Group Encryption Keys (GEK).
-- Encrypted pairwise per member using recipient's X25519 public key.
-- ZERO PLAINTEXT GROUP KEY IS EVER STORED.
CREATE TABLE IF NOT EXISTS group_epoch_keys (
    id            SERIAL PRIMARY KEY,
    group_id      INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch         INTEGER NOT NULL,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    creator_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, epoch, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_epoch_keys_lookup ON group_epoch_keys(group_id, epoch, user_id);

-- ── 11. GROUP MESSAGES TABLE ─────────────────────────────────────────
-- Stores encrypted group messages.
-- Contains ONLY ciphertext, nonce, and tag encrypted with GEK_epoch.
-- ZERO PLAINTEXT IS RECEIVED OR STORED.
CREATE TABLE IF NOT EXISTS group_messages (
    id                 SERIAL PRIMARY KEY,
    group_id           INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    sender_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch              INTEGER NOT NULL DEFAULT 1,
    ciphertext         TEXT NOT NULL DEFAULT '',
    nonce              TEXT NOT NULL DEFAULT '',
    authentication_tag TEXT NOT NULL DEFAULT '',
    tag                TEXT NOT NULL DEFAULT '',
    encrypted_package  TEXT NOT NULL DEFAULT '',
    message_type       VARCHAR(50) NOT NULL DEFAULT 'text',
    media_meta         TEXT NOT NULL DEFAULT '',
    reply_to_id        INTEGER REFERENCES group_messages(id) ON DELETE SET NULL,
    is_pinned          BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, created_at ASC);

-- ── 12. GROUP MESSAGE REACTIONS TABLE ─────────────────────────────────
CREATE TABLE IF NOT EXISTS group_message_reactions (
    id         SERIAL PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES group_messages(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_group_reactions_msg ON group_message_reactions(message_id);

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_epoch_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_message_reactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY IF NOT EXISTS backend_all_groups ON groups FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_group_members ON group_members FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_group_epoch_keys ON group_epoch_keys FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_group_messages ON group_messages FOR ALL USING (true);
CREATE POLICY IF NOT EXISTS backend_all_group_message_reactions ON group_message_reactions FOR ALL USING (true);

-- ── 13. CONVERSATION SETTINGS TABLE ──────────────────────────────────
-- Shared per-chat settings: disappearing messages timer and vanish mode.
CREATE TABLE IF NOT EXISTS conversation_settings (
    id                 SERIAL PRIMARY KEY,
    user1_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user2_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    disappearing_timer INTEGER NOT NULL DEFAULT 0,
    vanish_mode        BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user1_id, user2_id)
);

CREATE INDEX IF NOT EXISTS idx_conv_settings_users ON conversation_settings(user1_id, user2_id);

ALTER TABLE conversation_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS backend_all_conv_settings ON conversation_settings FOR ALL USING (true);

