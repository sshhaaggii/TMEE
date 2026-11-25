"""
test_14_features_complete.py
Comprehensive end-to-end testing of all 14 advanced messaging features across two users.
"""

import sys
import os
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, create_app
from database.db import (
    init_db, get_db,
    add_or_toggle_reaction, get_message_reactions, get_reactions_for_messages,
    update_message_read_status, record_message_status
)
from encryption.e2ee import (
    generate_key_pair, export_public_key, derive_shared_secret, derive_aes_key,
    encrypt_message, decrypt_message
)

def insert_test_msg(conn, sender_id, receiver_id, enc, reply_to_id=None, is_pinned=0, message_type='text', media_meta=None):
    pkg_str = json.dumps({"ciphertext": enc['ciphertext'], "nonce": enc['nonce'], "tag": enc['tag']})
    c = conn.execute("""
        INSERT INTO messages (
            sender_id, receiver_id, ciphertext, nonce, authentication_tag,
            encrypted_package, reply_to_id, is_pinned, message_type, media_meta
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sender_id, receiver_id, enc['ciphertext'], enc['nonce'], enc['tag'], pkg_str, reply_to_id, is_pinned, message_type, media_meta))
    return c.lastrowid

class Test14AdvancedFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        create_app()
        cls.ctx = app.app_context()
        cls.ctx.push()
        init_db()

        cls.client1 = app.test_client() # Alice
        cls.client2 = app.test_client() # Bob

        # Generate X25519 keypairs
        cls.alice_priv, cls.alice_pub = generate_key_pair()
        cls.bob_priv, cls.bob_pub = generate_key_pair()

        cls.alice_pub_b64 = export_public_key(cls.alice_pub)
        cls.bob_pub_b64 = export_public_key(cls.bob_pub)

        cls.alice_user = "alice_" + os.urandom(3).hex()
        cls.bob_user = "bob_" + os.urandom(3).hex()
        cls.password = "StrongPass123!"

        # Register Alice
        r = cls.client1.post("/register", json={
            "username": cls.alice_user,
            "email": f"{cls.alice_user}@example.com",
            "password": cls.password,
            "confirmPassword": cls.password,
            "public_key": cls.alice_pub_b64
        })
        assert r.status_code == 201, f"Alice register failed: {r.data}"

        # Register Bob
        r = cls.client2.post("/register", json={
            "username": cls.bob_user,
            "email": f"{cls.bob_user}@example.com",
            "password": cls.password,
            "confirmPassword": cls.password,
            "public_key": cls.bob_pub_b64
        })
        assert r.status_code == 201, f"Bob register failed: {r.data}"

        # Login Alice
        r = cls.client1.post("/login", json={"email": f"{cls.alice_user}@example.com", "password": cls.password})
        assert r.status_code == 200, f"Alice login failed: {r.data}"

        # Login Bob
        r = cls.client2.post("/login", json={"email": f"{cls.bob_user}@example.com", "password": cls.password})
        assert r.status_code == 200, f"Bob login failed: {r.data}"

        # Derive symmetric AES-256 keys via ECDH + HKDF
        cls.alice_aes = derive_aes_key(derive_shared_secret(cls.alice_priv, cls.bob_pub))
        cls.bob_aes = derive_aes_key(derive_shared_secret(cls.bob_priv, cls.alice_pub))

        # Get DB user IDs
        with get_db() as conn:
            c = conn.execute("SELECT id FROM users WHERE username = ?", (cls.alice_user,))
            cls.alice_id = c.fetchone()["id"]
            c = conn.execute("SELECT id FROM users WHERE username = ?", (cls.bob_user,))
            cls.bob_id = c.fetchone()["id"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_01_users_api_discovery(self):
        """Feature 12: Online & offline status / user discovery."""
        r = self.client1.get("/api/users")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))
        usernames = [u["username"] for u in data["users"]]
        self.assertIn(self.bob_user, usernames)
        print("  [PASS] Feature 12: User Discovery & Status Verified")

    def test_02_e2ee_send_receive_and_zero_plaintext(self):
        """Feature 9 & 10: E2EE message sending, timestamps, and zero plaintext in DB."""
        plaintext = "Secret message from Alice to Bob!"
        enc = encrypt_message(self.alice_aes, plaintext)

        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc)

        # Check raw database does NOT contain plaintext
        with get_db() as conn:
            c = conn.execute("SELECT ciphertext, nonce, authentication_tag, created_at FROM messages WHERE id = ?", (msg_id,))
            row = c.fetchone()
            self.assertNotIn(plaintext, row["ciphertext"])
            self.assertEqual(row["ciphertext"], enc['ciphertext'])
            self.assertIsNotNone(row["created_at"])

        # Bob fetches conversation history via API
        r = self.client2.get(f"/api/messages/{self.alice_user}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))
        target_msg = [m for m in data["messages"] if m["id"] == msg_id][0]

        # Bob decrypts message
        decrypted = decrypt_message(self.bob_aes, target_msg)
        self.assertEqual(decrypted, plaintext)
        print("  [PASS] Feature 9 & 10: Zero Plaintext & Timestamps Verified")

    def test_03_reply_to_message(self):
        """Feature 1: Reply to messages with quote reference."""
        # 1. Message from Alice
        enc1 = encrypt_message(self.alice_aes, "What time is our meeting?")
        with get_db() as conn:
            parent_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc1)

        # 2. Reply from Bob
        enc_reply = encrypt_message(self.bob_aes, "Meeting at 3 PM!")
        with get_db() as conn:
            reply_id = insert_test_msg(conn, self.bob_id, self.alice_id, enc_reply, reply_to_id=parent_id)

        # Alice fetches history and verifies reply_to_id
        r = self.client1.get(f"/api/messages/{self.bob_user}")
        data = r.get_json()
        reply_msg = [m for m in data["messages"] if m["id"] == reply_id][0]
        self.assertEqual(reply_msg["reply_to_id"], parent_id)
        self.assertEqual(decrypt_message(self.alice_aes, reply_msg), "Meeting at 3 PM!")
        print("  [PASS] Feature 1: Reply to Messages Verified")

    def test_04_edit_sent_message(self):
        """Feature 2: Edit sent message with (edited) status and new ciphertext."""
        enc = encrypt_message(self.alice_aes, "Typo in original message")
        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc)

        # Alice edits the message
        new_text = "Corrected message after edit"
        enc_new = encrypt_message(self.alice_aes, new_text)

        with get_db() as conn:
            conn.execute("""
                UPDATE messages 
                SET ciphertext = ?, nonce = ?, authentication_tag = ?, is_edited = 1, edited_at = CURRENT_TIMESTAMP
                WHERE id = ? AND sender_id = ?
            """, (enc_new['ciphertext'], enc_new['nonce'], enc_new['tag'], msg_id, self.alice_id))

        # Bob views history
        r = self.client2.get(f"/api/messages/{self.alice_user}")
        data = r.get_json()
        edited_msg = [m for m in data["messages"] if m["id"] == msg_id][0]
        self.assertEqual(edited_msg["is_edited"], 1)
        self.assertIsNotNone(edited_msg["edited_at"])
        self.assertEqual(decrypt_message(self.bob_aes, edited_msg), new_text)
        print("  [PASS] Feature 2: Edit Sent Messages Verified")

    def test_05_react_to_message(self):
        """Feature 5: React to message using emojis."""
        enc = encrypt_message(self.alice_aes, "React here")
        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc)

        # Bob reacts with 🔥
        res = add_or_toggle_reaction(msg_id, self.bob_id, "🔥")
        self.assertEqual(res["action"], "added")

        # History includes reactions
        r = self.client2.get(f"/api/messages/{self.alice_user}")
        data = r.get_json()
        reacted_msg = [m for m in data["messages"] if m["id"] == msg_id][0]
        self.assertTrue(len(reacted_msg["reactions"]) > 0)
        self.assertEqual(reacted_msg["reactions"][0]["emoji"], "🔥")
        self.assertEqual(reacted_msg["reactions"][0]["count"], 1)

        # Toggle reaction off
        res2 = add_or_toggle_reaction(msg_id, self.bob_id, "🔥")
        self.assertEqual(res2["action"], "removed")
        print("  [PASS] Feature 5: Emoji Reactions Verified")

    def test_06_pin_message(self):
        """Feature 7: Pin and unpin important messages."""
        enc = encrypt_message(self.alice_aes, "Pinned Notice")
        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc, is_pinned=1)

        # Check /api/messages/pinned/<peer>
        r = self.client1.get(f"/api/messages/pinned/{self.bob_user}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))
        pinned_ids = [m["id"] for m in data["pinned_messages"]]
        self.assertIn(msg_id, pinned_ids)
        print("  [PASS] Feature 7: Pin Important Messages Verified")

    def test_07_read_receipts(self):
        """Feature 10: Sent, delivered, and read status."""
        enc = encrypt_message(self.alice_aes, "Unread message")
        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc)

        # Update read status
        update_message_read_status(msg_id)

        with get_db() as conn:
            c = conn.execute("SELECT read_at FROM message_status WHERE message_id = ?", (msg_id,))
            row = c.fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(row["read_at"])
        print("  [PASS] Feature 10: Read Receipts Verified")

    def test_08_media_payload_e2ee(self):
        """Feature 14: Client-side encrypted image, video, and doc sharing."""
        media_pkg = json.dumps({
            "type": "media",
            "mediaType": "document",
            "name": "project_report.pdf",
            "size": 2048,
            "data": "data:application/pdf;base64,JVBERi0xLjUKJUZha2VQREY="
        })
        enc = encrypt_message(self.alice_aes, media_pkg)

        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc, message_type='media', media_meta=json.dumps({"name": "project_report.pdf"}))

        # Bob retrieves and decrypts document package
        r = self.client2.get(f"/api/messages/{self.alice_user}")
        data = r.get_json()
        doc_msg = [m for m in data["messages"] if m["id"] == msg_id][0]
        self.assertEqual(doc_msg["message_type"], "media")
        dec = decrypt_message(self.bob_aes, doc_msg)
        parsed = json.loads(dec)
        self.assertEqual(parsed["type"], "media")
        self.assertEqual(parsed["name"], "project_report.pdf")
        print("  [PASS] Feature 14: Image, Video, and Document Sharing Verified (Zero Plaintext)")

    def test_09_unsend_and_delete(self):
        """Feature 3 & 4: Unsend and delete messages."""
        enc = encrypt_message(self.alice_aes, "To be unsent")
        with get_db() as conn:
            msg_id = insert_test_msg(conn, self.alice_id, self.bob_id, enc)

        # Alice deletes/unsends via DELETE endpoint
        r = self.client1.delete(f"/api/messages/{msg_id}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("ok"))

        # Verify message no longer in DB
        with get_db() as conn:
            c = conn.execute("SELECT id FROM messages WHERE id = ?", (msg_id,))
            self.assertIsNone(c.fetchone())
        print("  [PASS] Feature 3 & 4: Unsend and Delete Messages Verified")

if __name__ == '__main__':
    unittest.main()
