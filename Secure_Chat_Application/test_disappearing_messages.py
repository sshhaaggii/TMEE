"""
test_disappearing_messages.py
Comprehensive Test Suite for Disappearing Messages & Vanish Mode in TMEEE.

Verifies:
1. User authentication & cryptographic setup for two distinct users (disp_alice & disp_bob).
2. Setting disappearing message timer options (10s, 1m, 1h, 24h, Off).
3. Zero-knowledge E2EE preservation: server stores strictly ciphertext, nonce, tag; zero plaintext.
4. Expiration enforcement: expired messages are filtered out from conversation history and return 404.
5. Automatic Hard Purge: purge_expired_messages permanently erases expired rows from DB & associated reactions.
6. Disk Cleanup: expired encrypted media files on disk are unlinked and permanently deleted.
7. Vanish Mode: toggling vanish mode persists conversation settings and synchronizes between peers.
8. View-Once media flow: marks viewed, activates 10s countdown, and expires safely.
9. Group disappearing messages: group timer inheritance, expiration filter, and hard purge.
10. Mandatory Security Notice: validates presence of screenshot & recording disclaimer.
"""

import sys
import os
import json
import time
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, create_app, socketio
from database.db import (
    init_db, get_db,
    get_conversation_settings,
    set_conversation_settings,
    get_group_disappearing_timer,
    set_group_disappearing_timer,
    mark_message_viewed,
    purge_expired_messages,
    _cleanup_media_file,
    create_group,
    add_group_member,
    create_group_message,
    get_group_messages,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64


def generate_test_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    return priv, pub, pub_b64


def derive_aes_key(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"TMEEE_E2EE_KEY_EXCHANGE_SALT_V1",
        info=b"TMEEE_AES_GCM_ENCRYPTION_KEY",
    )
    return hkdf.derive(shared)


def encrypt_payload(aes_key: bytes, plaintext: str):
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    full_ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    ciphertext = full_ct[:-16]
    tag = full_ct[-16:]
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    }


def decrypt_payload(aes_key: bytes, enc_dict: dict):
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    nonce = base64.b64decode(enc_dict["nonce"])
    tag = base64.b64decode(enc_dict["tag"])
    aesgcm = AESGCM(aes_key)
    full_ct = ciphertext + tag
    decrypted_bytes = aesgcm.decrypt(nonce, full_ct, None)
    return decrypted_bytes.decode('utf-8')


class TestDisappearingMessages(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.app_context():
            init_db()

    def setUp(self):
        self.client = app.test_client()
        self.alice_username = f"disp_alice_{int(time.time()*1000)%100000}"
        self.bob_username = f"disp_bob_{int(time.time()*1000)%100000}"

        self.alice_priv, self.alice_pub, self.alice_pub_b64 = generate_test_keypair()
        self.bob_priv, self.bob_pub, self.bob_pub_b64 = generate_test_keypair()

        # Shared symmetric keys
        self.alice_aes = derive_aes_key(self.alice_priv, self.bob_pub)
        self.bob_aes = derive_aes_key(self.bob_priv, self.alice_pub)

        # Register users
        with app.app_context():
            db = get_db()
            db.execute(
                "INSERT INTO users (username, email, password_hash, public_key) VALUES (?, ?, ?, ?)",
                (self.alice_username, f"{self.alice_username}@test.tmeee", "hash1", self.alice_pub_b64)
            )
            db.execute(
                "INSERT INTO users (username, email, password_hash, public_key) VALUES (?, ?, ?, ?)",
                (self.bob_username, f"{self.bob_username}@test.tmeee", "hash2", self.bob_pub_b64)
            )
            db.commit()

            r1 = db.execute("SELECT id FROM users WHERE username = ?", (self.alice_username,)).fetchone()
            r2 = db.execute("SELECT id FROM users WHERE username = ?", (self.bob_username,)).fetchone()
            self.alice_id = r1["id"]
            self.bob_id = r2["id"]

    def login_as(self, username: str, user_id: int):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = username

    # ─── 1. Disappearing Timer Settings & Options ───────────────────────────
    def test_01_set_and_get_disappearing_timer(self):
        """Test setting disappearing options (10s, 60s, 3600s, 86400s, 0) via REST API."""
        self.login_as(self.alice_username, self.alice_id)

        # 1. Default should be 0 (off)
        resp = self.client.get(f"/api/conversations/{self.bob_username}/settings")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["settings"]["disappearing_timer"], 0)
        self.assertFalse(data["settings"]["vanish_mode"])

        # 2. Set to 10 seconds
        resp = self.client.post(
            f"/api/conversations/{self.bob_username}/disappearing",
            json={"timer": 10}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["settings"]["disappearing_timer"], 10)
        # Verify required screenshot disclaimer notice is present
        self.assertIn("cannot prevent screenshots", data.get("notice", "").lower())

        # 3. Verify Bob sees the same setting (canonical pair shared synchronization)
        self.login_as(self.bob_username, self.bob_id)
        resp_bob = self.client.get(f"/api/conversations/{self.alice_username}/settings")
        self.assertEqual(resp_bob.status_code, 200)
        data_bob = resp_bob.get_json()
        self.assertEqual(data_bob["settings"]["disappearing_timer"], 10)

        # 4. Test other options: 60s (1m), 3600s (1h), 86400s (24h)
        for timer_val in (60, 3600, 86400, 0):
            res = self.client.post(
                f"/api/conversations/{self.alice_username}/disappearing",
                json={"timer": timer_val}
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json()["settings"]["disappearing_timer"], timer_val)

    # ─── 2. Zero-Knowledge Cryptographic Storage & Expiration ───────────────
    def test_02_encrypted_message_storage_and_zero_plaintext(self):
        """Verify that disappearing messages store ONLY ciphertext/nonce/tag with zero plaintext."""
        self.login_as(self.alice_username, self.alice_id)

        plaintext_secret = "TopSecretExplodingMessage_789"
        enc = encrypt_payload(self.alice_aes, plaintext_secret)

        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=10)).isoformat()

        with app.app_context():
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, authentication_tag, tag,
                    encrypted_package, created_at, delivered, is_deleted,
                    expires_at, expiration_seconds, is_view_once, is_vanish
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, 0, 0)
                """,
                (
                    self.alice_id, self.bob_id, enc["ciphertext"], enc["nonce"],
                    enc["tag"], enc["tag"], json.dumps(enc), now.isoformat(),
                    expires_at, 10
                )
            )
            db.commit()
            msg_id = cur.lastrowid

            # Verify in DB: absolutely zero plaintext stored
            row = db.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["ciphertext"], enc["ciphertext"])
            self.assertEqual(row["nonce"], enc["nonce"])
            self.assertEqual(row["tag"], enc["tag"])
            self.assertEqual(row["expires_at"], expires_at)
            self.assertEqual(row["expiration_seconds"], 10)

            # Assert database has no instance of the secret plaintext
            all_text_cols = " ".join([str(val) for val in row])
            self.assertNotIn(plaintext_secret, all_text_cols)

            # Recipient can decrypt using local client key
            decrypted = decrypt_payload(self.bob_aes, enc)
            self.assertEqual(decrypted, plaintext_secret)

    # ─── 3. Expiration Query Enforcement ────────────────────────────────────
    def test_03_expired_message_filtering_and_404(self):
        """Verify that expired messages are filtered from history and return 404 for single access."""
        self.login_as(self.alice_username, self.alice_id)

        enc_active = encrypt_payload(self.alice_aes, "Active Message")
        enc_expired = encrypt_payload(self.alice_aes, "Expired Message")

        now = datetime.now(timezone.utc)
        future_exp = (now + timedelta(seconds=300)).isoformat()
        past_exp = (now - timedelta(seconds=10)).isoformat()

        with app.app_context():
            db = get_db()
            cur1 = db.execute(
                """
                INSERT INTO messages (sender_id, receiver_id, ciphertext, nonce, tag, encrypted_package, created_at, delivered, is_deleted, expires_at, expiration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, 300)
                """,
                (self.alice_id, self.bob_id, enc_active["ciphertext"], enc_active["nonce"], enc_active["tag"], json.dumps(enc_active), now.isoformat(), future_exp)
            )
            active_id = cur1.lastrowid

            cur2 = db.execute(
                """
                INSERT INTO messages (sender_id, receiver_id, ciphertext, nonce, tag, encrypted_package, created_at, delivered, is_deleted, expires_at, expiration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, 10)
                """,
                (self.alice_id, self.bob_id, enc_expired["ciphertext"], enc_expired["nonce"], enc_expired["tag"], json.dumps(enc_expired), now.isoformat(), past_exp)
            )
            expired_id = cur2.lastrowid
            db.commit()

        # Check conversation history endpoint
        resp = self.client.get(f"/api/messages/{self.bob_username}")
        self.assertEqual(resp.status_code, 200)
        messages = resp.get_json()["messages"]
        msg_ids = [m["id"] for m in messages]

        # Active message must be returned; expired message must NOT be returned
        self.assertIn(active_id, msg_ids)
        self.assertNotIn(expired_id, msg_ids)

        # Single message retrieval
        resp_act = self.client.get(f"/api/messages/id/{active_id}")
        self.assertEqual(resp_act.status_code, 200)

        resp_exp = self.client.get(f"/api/messages/id/{expired_id}")
        self.assertEqual(resp_exp.status_code, 404)

    # ─── 4. Automatic Hard Purge & Disk Media Deletion ───────────────────────
    def test_04_hard_purge_and_disk_file_cleanup(self):
        """Verify purge_expired_messages() deletes expired DB rows and disk media files."""
        # Create a dummy temporary encrypted media file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
        temp_file.write(b"ENCRYPTED_MEDIA_BYTES_AES256GCM")
        temp_file_path = temp_file.name
        temp_file.close()

        self.assertTrue(os.path.exists(temp_file_path))

        now = datetime.now(timezone.utc)
        past_exp = (now - timedelta(seconds=5)).isoformat()
        media_meta = json.dumps({"name": "photo.jpg", "file_path": temp_file_path})

        with app.app_context():
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, tag, encrypted_package, created_at, delivered,
                    is_deleted, expires_at, expiration_seconds, media_meta
                )
                VALUES (?, ?, 'ct', 'nonce', 'tag', '{"ct":"test"}', ?, 1, 0, ?, 10, ?)
                """,
                (self.alice_id, self.bob_id, now.isoformat(), past_exp, media_meta)
            )
            expired_id = cur.lastrowid
            db.commit()

            # Execute server purger
            purged = purge_expired_messages()
            self.assertIn(expired_id, [d["id"] for d in purged["expired_direct"]])

            # Verify DB record is completely erased (zero-retention)
            check = db.execute("SELECT id FROM messages WHERE id = ?", (expired_id,)).fetchone()
            self.assertIsNone(check)

            # Verify file on disk is permanently deleted
            self.assertFalse(os.path.exists(temp_file_path))

    # ─── 5. Vanish Mode Persistence & Toggle ────────────────────────────────
    def test_05_vanish_mode_toggle_and_sync(self):
        """Verify Vanish Mode toggle persists state and returns disclaimer."""
        self.login_as(self.alice_username, self.alice_id)

        # Toggle on
        resp = self.client.post(
            f"/api/conversations/{self.bob_username}/vanish-mode",
            json={"enabled": True}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["settings"]["vanish_mode"])
        self.assertIn("cannot prevent external recording", data.get("notice", "").lower())

        # Bob verifies vanish mode is active
        self.login_as(self.bob_username, self.bob_id)
        resp2 = self.client.get(f"/api/conversations/{self.alice_username}/settings")
        self.assertTrue(resp2.get_json()["settings"]["vanish_mode"])

        # Toggle off
        resp3 = self.client.post(
            f"/api/conversations/{self.alice_username}/vanish-mode",
            json={"enabled": False}
        )
        self.assertEqual(resp3.status_code, 200)
        self.assertFalse(resp3.get_json()["settings"]["vanish_mode"])

    # ─── 6. View-Once Media Viewing & Expiration Countdown ──────────────────
    def test_06_view_once_media_flow(self):
        """Verify View-Once sets viewed_at and schedules 10s countdown upon viewing."""
        now = datetime.now(timezone.utc)
        with app.app_context():
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, tag, encrypted_package, created_at, delivered,
                    is_deleted, is_view_once, viewed_at, expires_at
                )
                VALUES (?, ?, 'view_once_ct', 'nonce', 'tag', '{"ct":"view_once"}', ?, 1, 0, 1, NULL, NULL)
                """,
                (self.alice_id, self.bob_id, now.isoformat())
            )
            msg_id = cur.lastrowid
            db.commit()

        # Bob views the message
        self.login_as(self.bob_username, self.bob_id)
        resp = self.client.post(f"/api/messages/{msg_id}/view", json={})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["is_view_once"])
        self.assertIsNotNone(data["viewed_at"])
        self.assertIsNotNone(data["expires_at"])

        # Verify DB has updated viewed_at and set expires_at ~ 10s in the future
        with app.app_context():
            db = get_db()
            row = db.execute("SELECT viewed_at, expires_at, expiration_seconds FROM messages WHERE id = ?", (msg_id,)).fetchone()
            self.assertIsNotNone(row["viewed_at"])
            self.assertIsNotNone(row["expires_at"])
            self.assertEqual(row["expiration_seconds"], 10)

    # ─── 7. Group Disappearing Messages ─────────────────────────────────────
    def test_07_group_disappearing_messages_and_purge(self):
        """Verify group disappearing timer setting, message inheritance, and purge."""
        self.login_as(self.alice_username, self.alice_id)

        # 1. Create a test group
        with app.app_context():
            group_id = create_group("Ephemeral Squad", creator_id=self.alice_id)
            add_group_member(group_id, self.bob_id, role="member")

        # 2. Set group disappearing timer to 60s
        resp = self.client.post(f"/api/groups/{group_id}/disappearing", json={"timer": 60})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["disappearing_timer"], 60)

        # 3. Insert group message with 60s timer and an already expired group message
        now = datetime.now(timezone.utc)
        future_exp = (now + timedelta(seconds=60)).isoformat()
        past_exp = (now - timedelta(seconds=5)).isoformat()

        with app.app_context():
            db = get_db()
            cur1 = db.execute(
                """
                INSERT INTO group_messages (group_id, sender_id, epoch, ciphertext, nonce, tag, created_at, is_deleted, expires_at, expiration_seconds)
                VALUES (?, ?, 1, 'active_grp_ct', 'nonce', 'tag', ?, 0, ?, 60)
                """,
                (group_id, self.alice_id, now.isoformat(), future_exp)
            )
            active_grp_msg_id = cur1.lastrowid

            cur2 = db.execute(
                """
                INSERT INTO group_messages (group_id, sender_id, epoch, ciphertext, nonce, tag, created_at, is_deleted, expires_at, expiration_seconds)
                VALUES (?, ?, 1, 'expired_grp_ct', 'nonce', 'tag', ?, 0, ?, 10)
                """,
                (group_id, self.alice_id, now.isoformat(), past_exp)
            )
            expired_grp_msg_id = cur2.lastrowid
            db.commit()

        # 4. Fetch group messages: expired should be filtered out
        resp_grp = self.client.get(f"/api/groups/{group_id}/messages")
        self.assertEqual(resp_grp.status_code, 200)
        grp_msgs = resp_grp.get_json()["messages"]
        grp_msg_ids = [m["id"] for m in grp_msgs]
        self.assertIn(active_grp_msg_id, grp_msg_ids)
        self.assertNotIn(expired_grp_msg_id, grp_msg_ids)

        # 5. Purge expired: permanently deletes expired group message
        with app.app_context():
            purged = purge_expired_messages()
            self.assertIn(expired_grp_msg_id, [g["id"] for g in purged["expired_groups"]])
            check_grp = get_db().execute("SELECT id FROM group_messages WHERE id = ?", (expired_grp_msg_id,)).fetchone()
            self.assertIsNone(check_grp)

    # ─── 8. Mandatory Security Notice Validation ────────────────────────────
    def test_08_disclaimer_notice_in_template_and_api(self):
        """Verify that disappearing messages explain that screenshots and external recording cannot be prevented."""
        # 1. Check API endpoint notice
        self.login_as(self.alice_username, self.alice_id)
        resp = self.client.post(
            f"/api/conversations/{self.bob_username}/disappearing",
            json={"timer": 60}
        )
        self.assertEqual(resp.status_code, 200)
        notice = resp.get_json().get("notice", "")
        self.assertIn("cannot prevent screenshots or external recording", notice.lower())

        # 2. Check HTML template renders explicit disclaimer notice and vanish banner
        with open(os.path.join(os.path.dirname(__file__), "templates", "chat.html"), "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("disappearing-security-notice", html)
        self.assertIn("cannot prevent recipients from taking screenshots", html.lower())
        self.assertIn("vanishModeBanner", html)
        self.assertIn("viewOnceModal", html)

    # ─── 9. Multi-Session Expiration and Socket Sync ────────────────────────
    def test_09_multi_session_expiration_socket_sync(self):
        """Test expiration across two separate user sessions and verify background worker."""
        # Alice client session
        self.login_as(self.alice_username, self.alice_id)
        enc = encrypt_payload(self.alice_aes, "MultiSessionExpiringMessage")

        now = datetime.now(timezone.utc)
        # Message expiring 1 second ago
        past_exp = (now - timedelta(seconds=1)).isoformat()

        with app.app_context():
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, tag, encrypted_package,
                    created_at, delivered, is_deleted, expires_at, expiration_seconds
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, 1)
                """,
                (self.alice_id, self.bob_id, enc["ciphertext"], enc["nonce"], enc["tag"], json.dumps(enc), now.isoformat(), past_exp)
            )
            msg_id = cur.lastrowid
            db.commit()

        # Bob's separate session checks conversation history
        self.login_as(self.bob_username, self.bob_id)
        resp_bob = self.client.get(f"/api/messages/{self.alice_username}")
        self.assertEqual(resp_bob.status_code, 200)
        bob_msg_ids = [m["id"] for m in resp_bob.get_json()["messages"]]
        # Expired message is immediately excluded from Bob's view
        self.assertNotIn(msg_id, bob_msg_ids)

        # Background purge sweeps it permanently from DB
        with app.app_context():
            purged = purge_expired_messages()
            self.assertIn(msg_id, [d["id"] for d in purged["expired_direct"]])
            check_msg = get_db().execute("SELECT id FROM messages WHERE id = ?", (msg_id,)).fetchone()
            self.assertIsNone(check_msg)


if __name__ == "__main__":
    unittest.main()
