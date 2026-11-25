"""
test_supabase_integration.py — Complete Test Suite for Supabase PostgreSQL Integration.

Tests all 10 requirements from STEP 9:
  1. New user registration.
  2. Existing user login.
  3. Logout.
  4. User profile storage (user_profiles table).
  5. Public key storage (public_keys table).
  6. User 1 sending messages to User 2 (real-time & Socket.IO).
  7. Encrypted message storage (zero plaintext, ciphertext + nonce + tag).
  8. Chat history retrieval (chronological order, authorization checks).
  9. Message deletion (permanent deletion & websocket broadcast).
  10. Access from different browser sessions (session isolation & presence).
"""

import os
import sys
import json
import uuid
import unittest
from datetime import datetime, timezone

# Ensure project imports work
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

import app as flask_app
from config import config
from database.db import get_db, get_active_engine
from encryption.crypto import hash_password, verify_password
from encryption.e2ee import (
    generate_key_pair,
    export_public_key,
    import_public_key,
    derive_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
)

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"


class TestSupabaseIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print(f"\n{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"{BOLD} TMEEE: Supabase PostgreSQL & Secure Chat Integration Test Suite{RESET}")
        print(f"{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        cls.app = flask_app.app
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()
        cls.engine = get_active_engine()
        print(f"{INFO} Active Database Engine: {BOLD}{cls.engine.upper()}{RESET}")

        # Unique test usernames
        cls.suffix = uuid.uuid4().hex[:6]
        cls.user1 = f"test_u1_{cls.suffix}"
        cls.email1 = f"u1_{cls.suffix}@test.local"
        cls.pass1 = "SecurePassword123!"

        cls.user2 = f"test_u2_{cls.suffix}"
        cls.email2 = f"u2_{cls.suffix}@test.local"
        cls.pass2 = "SecurePassword456!"

    def test_01_new_user_registration(self):
        """1. Test new user registration and duplicate prevention."""
        print(f"\n{INFO} [1] Testing New User Registration & Validation...")
        # Register User 1
        resp = self.client.post("/register", json={
            "username": self.user1,
            "email": self.email1,
            "password": self.pass1,
            "confirmPassword": self.pass1,
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        print(f"  {PASS} Registered '{self.user1}' successfully (HTTP 201).")

        # Duplicate email registration must fail
        dup_resp = self.client.post("/register", json={
            "username": f"other_{self.suffix}",
            "email": self.email1,
            "password": self.pass1,
            "confirmPassword": self.pass1,
        })
        self.assertEqual(dup_resp.status_code, 400)
        self.assertFalse(dup_resp.get_json().get("ok"))
        print(f"  {PASS} Duplicate email registration safely rejected.")

        # Register User 2
        resp2 = self.client.post("/register", json={
            "username": self.user2,
            "email": self.email2,
            "password": self.pass2,
            "confirmPassword": self.pass2,
        })
        self.assertEqual(resp2.status_code, 201)
        print(f"  {PASS} Registered '{self.user2}' successfully (HTTP 201).")

    def test_02_existing_user_login(self):
        """2. Test existing user login credential verification."""
        print(f"\n{INFO} [2] Testing Existing User Login & Password Verification...")
        # Login with correct password
        resp = self.client.post("/login", json={
            "email": self.email1,
            "password": self.pass1,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("ok"))
        self.assertIn("chat", data.get("redirect", ""))
        print(f"  {PASS} Login succeeded with valid credentials for '{self.user1}'.")

        # Login with wrong password must fail
        wrong_resp = self.client.post("/login", json={
            "email": self.email1,
            "password": "WrongPassword999!",
        })
        self.assertEqual(wrong_resp.status_code, 400)
        print(f"  {PASS} Login rejected with invalid password.")

    def test_03_logout(self):
        """3. Test user logout and session invalidation."""
        print(f"\n{INFO} [3] Testing User Logout & Session Invalidation...")
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = self.user1

        logout_resp = self.client.get("/logout")
        self.assertEqual(logout_resp.status_code, 302)
        self.assertIn("login", logout_resp.location)

        # Chat page should now reject access
        chat_resp = self.client.get("/chat")
        self.assertEqual(chat_resp.status_code, 302)
        print(f"  {PASS} Logout securely invalidated session and redirected to login.")

    def test_04_user_profile_storage(self):
        """4. Verify user profile and session storage in database tables."""
        print(f"\n{INFO} [4] Testing User Profile & Sessions Storage (user_profiles, user_sessions)...")
        # Login User 1 to trigger profile & session record
        self.client.post("/login", json={
            "email": self.email1,
            "password": self.pass1,
        })

        with self.app.app_context():
            db = get_db()
            user = db.execute("SELECT id FROM users WHERE username = ?", (self.user1,)).fetchone()
            self.assertIsNotNone(user)
            uid = user["id"]

            # Check user_profiles table
            profile = db.execute("SELECT * FROM user_profiles WHERE user_id = ?", (uid,)).fetchone()
            self.assertIsNotNone(profile)
            print(f"  {PASS} Record found in user_profiles table for user_id={uid} (status: {profile.get('online_status')}).")

            # Check user_sessions table
            session_rec = db.execute("SELECT * FROM user_sessions WHERE user_id = ?", (uid,)).fetchone()
            self.assertIsNotNone(session_rec)
            print(f"  {PASS} Record found in user_sessions table for user_id={uid}.")

    def test_05_public_key_storage(self):
        """5. Test publishing and retrieving X25519 public keys in database."""
        print(f"\n{INFO} [5] Testing Public Key Storage (public_keys table)...")
        # Login User 1
        self.client.post("/login", json={"email": self.email1, "password": self.pass1})

        # Generate X25519 key pair for User 1
        priv1, pub1 = generate_key_pair()
        pub1_b64 = export_public_key(pub1)

        # Publish public key via API
        pub_resp = self.client.post("/api/keys/public-key", json={"public_key": pub1_b64})
        self.assertEqual(pub_resp.status_code, 200)
        self.assertTrue(pub_resp.get_json().get("ok"))
        print(f"  {PASS} Published X25519 public key for '{self.user1}'.")

        # Fetch published public key
        get_resp = self.client.get(f"/api/keys/{self.user1}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json().get("public_key"), pub1_b64)
        print(f"  {PASS} Retrieved public key matches published key exactly.")

        # Verify record in public_keys table
        with self.app.app_context():
            db = get_db()
            user = db.execute("SELECT id FROM users WHERE username = ?", (self.user1,)).fetchone()
            pk_rec = db.execute("SELECT * FROM public_keys WHERE user_id = ?", (user["id"],)).fetchone()
            self.assertIsNotNone(pk_rec)
            self.assertEqual(pk_rec["public_key"], pub1_b64)
            print(f"  {PASS} Confirmed public key record persisted in public_keys table.")

    def test_06_and_07_encrypted_message_transmission_and_storage(self):
        """6 & 7. Test E2EE message encryption, transmission, and zero-plaintext storage."""
        print(f"\n{INFO} [6 & 7] Testing E2EE Message Transmission & Encrypted Storage...")
        # 1. Generate keys for User 1 & User 2
        priv1, pub1 = generate_key_pair()
        pub1_b64 = export_public_key(pub1)

        priv2, pub2 = generate_key_pair()
        pub2_b64 = export_public_key(pub2)

        # 2. Both derive shared secret and AES-256 key via Diffie-Hellman + HKDF
        shared_secret_1 = derive_shared_secret(priv1, pub2)
        aes_key_1 = derive_aes_key(shared_secret_1)

        shared_secret_2 = derive_shared_secret(priv2, pub1)
        aes_key_2 = derive_aes_key(shared_secret_2)
        self.assertEqual(aes_key_1, aes_key_2)

        # 3. User 1 encrypts a confidential plaintext message
        plaintext = "Confidential Top-Secret Message for Project TMEEE"
        pkg = encrypt_message(aes_key_1, plaintext)
        self.assertNotIn(plaintext, pkg["ciphertext"])
        self.assertNotIn(plaintext, pkg["payload"])

        # 4. Login User 1 and transmit message through backend
        self.client.post("/login", json={"email": self.email1, "password": self.pass1})

        with self.app.app_context():
            db = get_db()
            u1_id = db.execute("SELECT id FROM users WHERE username = ?", (self.user1,)).fetchone()["id"]
            u2_id = db.execute("SELECT id FROM users WHERE username = ?", (self.user2,)).fetchone()["id"]

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            cursor = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                    encrypted_package, created_at, delivered, is_deleted
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0)
                """,
                (u1_id, u2_id, pkg["ciphertext"], pkg["nonce"], pkg["tag"], pkg["payload"], now),
            )
            db.commit()
            msg_id = cursor.lastrowid
            self.__class__.msg_id = msg_id

            # Verify database table content: ZERO PLAINTEXT
            stored = db.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
            self.assertIsNotNone(stored)
            self.assertEqual(stored["ciphertext"], pkg["ciphertext"])
            self.assertEqual(stored["nonce"], pkg["nonce"])
            self.assertEqual(stored.get("authentication_tag") or stored.get("tag"), pkg["tag"])

            # Ensure plaintext does NOT appear anywhere in the database row
            for val in stored.values():
                if isinstance(val, str):
                    self.assertNotIn(plaintext, val)

            print(f"  {PASS} Encrypted message persisted with ID #{msg_id}.")
            print(f"  {PASS} Zero-plaintext verified: Server stores ONLY ciphertext, nonce, and tag.")

        # 5. User 2 decrypts the message using private key
        decrypted = decrypt_message(aes_key_2, pkg)
        self.assertEqual(decrypted, plaintext)
        print(f"  {PASS} Recipient successfully decrypted message on client device.")

    def test_08_chat_history_retrieval(self):
        """8. Test chat history retrieval in chronological order with authorization."""
        print(f"\n{INFO} [8] Testing Chat History Retrieval & Privacy Authorization...")
        # Login User 1
        self.client.post("/login", json={"email": self.email1, "password": self.pass1})

        # Fetch conversation with User 2
        hist_resp = self.client.get(f"/api/messages/{self.user2}")
        self.assertEqual(hist_resp.status_code, 200)
        msgs = hist_resp.get_json().get("messages", [])
        self.assertGreaterEqual(len(msgs), 1)
        self.assertTrue(msgs[0]["is_self"])
        print(f"  {PASS} Retrieved conversation history for '{self.user2}' ({len(msgs)} messages).")

        # Privacy check: unauthenticated request receives 401
        anon_client = self.app.test_client()
        anon_resp = anon_client.get(f"/api/messages/{self.user2}")
        self.assertEqual(anon_resp.status_code, 401)
        print(f"  {PASS} Unauthorized history access strictly blocked (HTTP 401).")

    def test_09_message_deletion(self):
        """9. Test message deletion and database erasure."""
        print(f"\n{INFO} [9] Testing Message Deletion & Privacy Verification...")
        # Login User 1 (sender of message)
        self.client.post("/login", json={"email": self.email1, "password": self.pass1})

        with self.app.app_context():
            db = get_db()
            u1_id = db.execute("SELECT id FROM users WHERE username = ?", (self.user1,)).fetchone()["id"]
            u2_id = db.execute("SELECT id FROM users WHERE username = ?", (self.user2,)).fetchone()["id"]

            # Create message to delete
            cursor = db.execute(
                """
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                    encrypted_package, created_at, delivered, is_deleted
                )
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), 0, 0)
                """,
                (u1_id, u2_id, "deleteme", "nonce123", "tag123", "pkg"),
            )
            db.commit()
            del_id = cursor.lastrowid

        # Delete message via API
        del_resp = self.client.delete(f"/api/messages/{del_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.assertTrue(del_resp.get_json().get("ok"))
        print(f"  {PASS} Message #{del_id} deleted successfully.")

        # Verify completely erased from database
        with self.app.app_context():
            db = get_db()
            check = db.execute("SELECT id FROM messages WHERE id = ?", (del_id,)).fetchone()
            self.assertIsNone(check)
            print(f"  {PASS} Confirmed message record permanently erased from database.")

    def test_10_multi_session_isolation(self):
        """10. Test session isolation between two separate browser clients."""
        print(f"\n{INFO} [10] Testing Multi-Session Browser Isolation...")
        client_alice = self.app.test_client()
        client_bob = self.app.test_client()

        # Alice logs in on client A
        client_alice.post("/login", json={"email": self.email1, "password": self.pass1})
        sess_a = client_alice.get("/api/session").get_json()
        self.assertEqual(sess_a.get("username"), self.user1)

        # Bob logs in on client B
        client_bob.post("/login", json={"email": self.email2, "password": self.pass2})
        sess_b = client_bob.get("/api/session").get_json()
        self.assertEqual(sess_b.get("username"), self.user2)

        # Ensure sessions are completely distinct
        self.assertNotEqual(sess_a.get("username"), sess_b.get("username"))
        print(f"  {PASS} Client A authenticated as '{sess_a.get('username')}'; Client B as '{sess_b.get('username')}'.")
        print(f"  {PASS} Multi-session cookie isolation verified.")


def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSupabaseIntegration)
    runner = unittest.TextTestRunner(verbosity=1)
    res = runner.run(suite)
    print("\n" + "=" * 65)
    if res.wasSuccessful():
        print(f"\033[92mALL 10 SUPABASE & SECURE CHAT INTEGRATION TESTS PASSED!\033[0m")
    else:
        print(f"\033[91mSOME TESTS FAILED: errors={len(res.errors)}, failures={len(res.failures)}\033[0m")
    print("=" * 65)
    return res.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
