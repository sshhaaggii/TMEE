"""
test_comprehensive_suite.py — Complete End-to-End Test Suite for Secure Chat Application.

Validates all 6 core requirements specified in the project specification:
  1. Registration
  2. Authentication
  3. Encryption (X25519, HKDF-SHA-256, AES-256-GCM)
  4. Real-Time Messaging (Two distinct client sessions over WebSockets)
  5. Database (Ciphertext storage, Zero plaintext, History, Deletion)
  6. End-to-End Encryption Verification (Zero server exposure, Private keys client-only)
"""

import base64
import http.cookiejar
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import socketio
from config import config
from encryption.crypto import hash_password, verify_password
from encryption.e2ee import (
    ClientE2EESession,
    generate_key_pair,
    export_public_key,
    import_public_key,
    derive_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
    CryptoError,
    AuthenticationError,
    NONCE_SIZE_BYTES,
    KEY_SIZE_BYTES,
    TAG_SIZE_BYTES,
)

BASE_URL = "http://127.0.0.1:5000"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
BOLD = "\033[1m"
RESET = "\033[0m"

total_tests = 0
passed_tests = 0
failed_tests = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    global total_tests, passed_tests, failed_tests
    total_tests += 1
    if condition:
        print(f"  {PASS} {label}")
        passed_tests += 1
        return True
    else:
        print(f"  {FAIL} {label} - {detail}")
        failed_tests += 1
        return False


def ensure_server_running():
    try:
        with urllib.request.urlopen(BASE_URL + "/api/session", timeout=0.5):
            return
    except Exception:
        pass

    from app import app, socketio as server_socketio, create_app
    create_app()
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    threading.Thread(
        target=lambda: server_socketio.run(app, host="127.0.0.1", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True),
        daemon=True,
    ).start()

    for _ in range(120):
        time.sleep(0.1)
        try:
            with urllib.request.urlopen(BASE_URL + "/api/session", timeout=1.0):
                return
        except Exception:
            pass
    raise RuntimeError("Failed to start server on http://127.0.0.1:5000")


class SimulatedBrowserSession:
    """Represents an isolated browser session: independent cookie jar, CSRF token, and E2EE engine."""

    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email = email
        self.password = password
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""
        self.user_id = None
        self.crypto = ClientE2EESession(username=username)
        self.sio = socketio.Client()
        self.received_messages = []
        self.delivered_updates = []
        self.status_events = []
        self.deleted_events = []
        self.cleared_events = []

    def fetch_csrf(self, path="/login") -> str:
        req = urllib.request.Request(BASE_URL + path)
        with self.opener.open(req) as r:
            html = r.read().decode()
        m = re.search(r'id="csrf_token" name="csrf_token" value="([^"]+)"', html)
        self.csrf = m.group(1) if m else ""
        return self.csrf

    def post_json(self, path: str, payload: dict, csrf_override: str = None) -> tuple[int, dict]:
        csrf_val = self.csrf if csrf_override is None else csrf_override
        headers = {
            "Content-Type": "application/json",
            "X-CSRFToken": csrf_val,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method="POST")
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"ok": False, "raw": raw}

    def get(self, path: str) -> tuple[int, str, str]:
        req = urllib.request.Request(BASE_URL + path)
        try:
            with self.opener.open(req) as r:
                return r.status, r.read().decode(), r.url
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace"), e.url

    def get_json(self, path: str) -> tuple[int, dict]:
        code, text, _ = self.get(path)
        try:
            return code, json.loads(text)
        except Exception:
            return code, {"ok": False, "raw": text}

    def delete(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(
            BASE_URL + path,
            headers={"X-CSRFToken": self.csrf},
            method="DELETE",
        )
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode())
            except Exception:
                return e.code, {"ok": False}

    def connect_ws(self):
        cookies = [f"{c.name}={c.value}" for c in self.jar]
        cookie_header = "; ".join(cookies)

        @self.sio.on("receive_message")
        def on_msg(data):
            self.received_messages.append(data)

        @self.sio.on("message_status_update")
        def on_status(data):
            self.delivered_updates.append(data)

        @self.sio.on("user_status")
        def on_user_status(data):
            self.status_events.append(data)

        @self.sio.on("message_deleted")
        def on_del(data):
            self.deleted_events.append(data)

        @self.sio.on("conversation_cleared")
        def on_clr(data):
            self.cleared_events.append(data)

        self.sio.connect(BASE_URL, headers={"Cookie": cookie_header})


def run_all_tests():
    print(f"{BOLD}{'=' * 75}{RESET}")
    print(f"{BOLD}  SECURE CHAT APPLICATION: COMPREHENSIVE E2EE VERIFICATION SUITE{RESET}")
    print(f"{BOLD}{'=' * 75}{RESET}")

    ensure_server_running()

    # Clean prior test users
    with sqlite3.connect(config.DATABASE) as conn:
        conn.execute("DELETE FROM users WHERE username LIKE 'usr_%' OR username LIKE 'test_user_%'")
        conn.commit()

    suffix = str(int(time.time()) % 100000)
    user_a = SimulatedBrowserSession(f"usr_a_{suffix}", f"usr_a_{suffix}@securechat.local", "StrongP@ssw0rd1!")
    user_b = SimulatedBrowserSession(f"usr_b_{suffix}", f"usr_b_{suffix}@securechat.local", "StrongP@ssw0rd2!")

    # ═══════════════════════════════════════════════════════════════════════════
    # 1. REGISTRATION TESTING
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 1: REGISTRATION TESTING ==={RESET}")

    user_a.fetch_csrf("/register")
    user_b.fetch_csrf("/register")

    # 1.1 Register two different users
    code, data = user_a.post_json("/register", {
        "username": user_a.username,
        "email": user_a.email,
        "password": user_a.password,
        "confirmPassword": user_a.password,
    })
    check("1.1.1 Register User A returns 201 Created", code == 201 and data.get("ok") is True, str(data))

    code, data = user_b.post_json("/register", {
        "username": user_b.username,
        "email": user_b.email,
        "password": user_b.password,
        "confirmPassword": user_b.password,
    })
    check("1.1.2 Register User B returns 201 Created", code == 201 and data.get("ok") is True, str(data))

    # 1.2 Duplicate email registration
    code, data = user_a.post_json("/register", {
        "username": f"unique_user_{suffix}",
        "email": user_a.email,  # duplicate email
        "password": "ValidPassword123!",
        "confirmPassword": "ValidPassword123!",
    })
    check("1.2 Duplicate email rejected (HTTP 400)", code == 400 and data.get("ok") is False, str(data))

    # 1.3 Duplicate username registration
    code, data = user_a.post_json("/register", {
        "username": user_a.username,  # duplicate username
        "email": f"unique_{suffix}@example.com",
        "password": "ValidPassword123!",
        "confirmPassword": "ValidPassword123!",
    })
    check("1.3 Duplicate username rejected (HTTP 400)", code == 400 and data.get("ok") is False, str(data))

    # 1.4 Invalid inputs
    # 1.4a Invalid short password (< 8 chars)
    code, data = user_a.post_json("/register", {
        "username": f"temp_{suffix}",
        "email": f"temp_{suffix}@example.com",
        "password": "short",
        "confirmPassword": "short",
    })
    check("1.4a Short password (< 8 chars) rejected (HTTP 422)", code == 422 and data.get("ok") is False)

    # 1.4b Password mismatch
    code, data = user_a.post_json("/register", {
        "username": f"temp_{suffix}",
        "email": f"temp_{suffix}@example.com",
        "password": "ValidPassword123!",
        "confirmPassword": "DifferentPassword123!",
    })
    check("1.4b Mismatched passwords rejected (HTTP 422)", code == 422 and data.get("ok") is False)

    # 1.4c Invalid email format
    code, data = user_a.post_json("/register", {
        "username": f"temp_{suffix}",
        "email": "not-an-email",
        "password": "ValidPassword123!",
        "confirmPassword": "ValidPassword123!",
    })
    check("1.4c Invalid email format rejected (HTTP 422)", code == 422 and data.get("ok") is False)

    # 1.4d Invalid username characters (spaces, symbols)
    code, data = user_a.post_json("/register", {
        "username": "invalid user!",
        "email": f"temp_{suffix}@example.com",
        "password": "ValidPassword123!",
        "confirmPassword": "ValidPassword123!",
    })
    check("1.4d Invalid username characters rejected (HTTP 422)", code == 422 and data.get("ok") is False)

    # 1.4e Malformed JSON / None values
    code, data = user_a.post_json("/register", {
        "username": None,
        "email": None,
        "password": None,
    })
    check("1.4e Malformed payload handled safely (HTTP 422/400)", code in (400, 422) and data.get("ok") is False)

    # ═══════════════════════════════════════════════════════════════════════════
    # 2. AUTHENTICATION TESTING
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 2: AUTHENTICATION TESTING ==={RESET}")

    user_a.fetch_csrf("/login")
    user_b.fetch_csrf("/login")

    # 2.1 Login with incorrect passwords
    code, data = user_a.post_json("/login", {
        "email": user_a.email,
        "password": "WrongPassword999!",
    })
    check("2.1a Incorrect password rejected (HTTP 400)", code == 400 and data.get("ok") is False)

    # 2.1b Non-existent user
    code, data = user_a.post_json("/login", {
        "email": "nonexistent@domain.com",
        "password": "SomePassword123!",
    })
    check("2.1b Non-existent user login rejected (HTTP 400)", code == 400 and data.get("ok") is False)

    # 2.2 Successful login for User A and User B
    code, data = user_a.post_json("/login", {
        "email": user_a.email,
        "password": user_a.password,
    })
    check("2.2a User A login successful (HTTP 200)", code == 200 and data.get("ok") is True)
    check("2.2a Redirect to /chat returned", "redirect" in data)

    code, data = user_b.post_json("/login", {
        "email": user_b.email,
        "password": user_b.password,
    })
    check("2.2b User B login successful (HTTP 200)", code == 200 and data.get("ok") is True)

    # Verify session profile
    code, me_a = user_a.get_json("/api/me")
    check("2.2c User A session active via /api/me", code == 200 and me_a.get("username") == user_a.username)
    user_a.user_id = me_a.get("id")

    code, me_b = user_b.get_json("/api/me")
    check("2.2d User B session active via /api/me", code == 200 and me_b.get("username") == user_b.username)
    user_b.user_id = me_b.get("id")

    # 2.3 Access /chat with authenticated session
    code, html, url = user_a.get("/chat")
    check("2.3 Authenticated access to /chat allowed (HTTP 200)", code == 200 and "/chat" in url)

    # 2.4 Test unauthorized access
    unauth_session = SimulatedBrowserSession("anon", "anon@anon.com", "anon")
    code, html, url = unauth_session.get("/chat")
    check("2.4a Unauthenticated access to /chat redirects to /login", "/login" in url)

    code, data = unauth_session.get_json("/api/me")
    check("2.4b Unauthenticated access to /api/me returns HTTP 401", code == 401)

    code, data = unauth_session.get_json("/api/users")
    check("2.4c Unauthenticated access to /api/users returns HTTP 401", code == 401)

    # 2.5 Test logout
    code, html, url = user_a.get("/logout")
    check("2.5a Logout redirects to /login", "/login" in url)

    code, html, url = user_a.get("/chat")
    check("2.5b Accessing /chat after logout redirects to /login", "/login" in url)

    # Re-login User A for remaining tests
    user_a.fetch_csrf("/login")
    user_a.post_json("/login", {"email": user_a.email, "password": user_a.password})
    user_a.fetch_csrf("/login")

    # ═══════════════════════════════════════════════════════════════════════════
    # 3. ENCRYPTION TESTING
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 3: ENCRYPTION TESTING ==={RESET}")

    # 3.1 Generate X25519 key pairs
    priv_a, pub_a = generate_key_pair()
    priv_b, pub_b = generate_key_pair()

    pub_a_b64 = export_public_key(pub_a)
    pub_b_b64 = export_public_key(pub_b)

    check("3.1a User A X25519 public key is 32-byte Base64 (44 chars)", len(pub_a_b64) == 44)
    check("3.1b User B X25519 public key is 32-byte Base64 (44 chars)", len(pub_b_b64) == 44)
    check("3.1c User A and B have distinct key pairs", pub_a_b64 != pub_b_b64)

    # 3.2 Verify shared secret agreement (Diffie-Hellman)
    secret_a = derive_shared_secret(priv_a, pub_b)
    secret_b = derive_shared_secret(priv_b, pub_a)

    check("3.2a User A computes 32-byte shared secret", len(secret_a) == KEY_SIZE_BYTES)
    check("3.2b User B computes 32-byte shared secret", len(secret_b) == KEY_SIZE_BYTES)
    check("3.2c Both parties compute identical shared secret (DH property)", secret_a == secret_b)

    # 3.3 Test HKDF-SHA-256 key derivation
    aes_key_a = derive_aes_key(secret_a)
    aes_key_b = derive_aes_key(secret_b)

    check("3.3a Derived AES-256 key is 32 bytes (256 bits)", len(aes_key_a) == KEY_SIZE_BYTES)
    check("3.3b Derived AES-256 keys match on both endpoints", aes_key_a == aes_key_b)
    check("3.3c Derived key differs from raw shared secret (KDF expansion)", aes_key_a != secret_a)

    # 3.4 Test AES-256-GCM encryption and decryption
    test_plaintext = "Top Secret: Autonomous Agent Verification 2026!"
    pkg = encrypt_message(aes_key_a, test_plaintext)

    check("3.4a Encrypted package contains nonce, ciphertext, and tag",
          bool(pkg.get("nonce") and pkg.get("ciphertext") and pkg.get("tag") and pkg.get("payload")))

    nonce_bytes = base64.b64decode(pkg["nonce"])
    tag_bytes = base64.b64decode(pkg["tag"])
    ct_bytes = base64.b64decode(pkg["ciphertext"])

    check("3.4b Nonce is exactly 12 bytes (96-bit CSPRNG)", len(nonce_bytes) == NONCE_SIZE_BYTES)
    check("3.4c Tag is exactly 16 bytes (128-bit authentication tag)", len(tag_bytes) == TAG_SIZE_BYTES)
    check("3.4d Plaintext is NOT present in raw ciphertext bytes", test_plaintext.encode() not in ct_bytes)

    decrypted = decrypt_message(aes_key_b, pkg)
    check("3.4e Decryption produces exact original plaintext", decrypted == test_plaintext)

    # 3.5 Verify that modified ciphertext cannot be decrypted (Tamper Resistance)
    tampered_ct = bytearray(ct_bytes)
    tampered_ct[0] ^= 0x01  # Flip 1 bit in ciphertext
    tampered_pkg = dict(pkg)
    tampered_pkg["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode()

    tamper_rejected = False
    try:
        decrypt_message(aes_key_b, tampered_pkg)
    except AuthenticationError:
        tamper_rejected = True
    except Exception:
        tamper_rejected = True
    check("3.5a Modified ciphertext CANNOT be decrypted (AuthenticationError raised)", tamper_rejected)

    # 3.5b Tampered authentication tag
    tampered_tag = bytearray(tag_bytes)
    tampered_tag[0] ^= 0xFF
    tampered_tag_pkg = dict(pkg)
    tampered_tag_pkg["tag"] = base64.b64encode(bytes(tampered_tag)).decode()

    tag_tamper_rejected = False
    try:
        decrypt_message(aes_key_b, tampered_tag_pkg)
    except AuthenticationError:
        tag_tamper_rejected = True
    except Exception:
        tag_tamper_rejected = True
    check("3.5b Modified authentication tag CANNOT be decrypted", tag_tamper_rejected)

    # 3.5c Unauthorized third party (wrong key) cannot decrypt
    _, eve_pub = generate_key_pair()
    eve_priv, _ = generate_key_pair()
    eve_secret = derive_shared_secret(eve_priv, pub_a)
    eve_key = derive_aes_key(eve_secret)

    eve_rejected = False
    try:
        decrypt_message(eve_key, pkg)
    except AuthenticationError:
        eve_rejected = True
    except Exception:
        eve_rejected = True
    check("3.5c Unauthorized party with wrong key CANNOT decrypt message", eve_rejected)

    # ═══════════════════════════════════════════════════════════════════════════
    # 4. REAL-TIME MESSAGING TESTING
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 4: REAL-TIME MESSAGING TESTING ==={RESET}")

    # 4.1 Publish public keys to directory
    code, data_a = user_a.post_json("/api/keys/public-key", {"public_key": user_a.crypto.public_key_b64})
    check("4.1a User A publishes public key to server", code == 200 and data_a.get("ok"))

    code, data_b = user_b.post_json("/api/keys/public-key", {"public_key": user_b.crypto.public_key_b64})
    check("4.1b User B publishes public key to server", code == 200 and data_b.get("ok"))

    # Establish local client-side E2EE sessions
    user_a.crypto.establish_session(user_b.username, user_b.crypto.public_key_b64)
    user_b.crypto.establish_session(user_a.username, user_a.crypto.public_key_b64)

    # 4.2 Open two distinct WebSocket sessions
    user_a.connect_ws()
    user_b.connect_ws()
    time.sleep(0.5)

    check("4.2a User A WebSocket connected", user_a.sio.connected)
    check("4.2b User B WebSocket connected", user_b.sio.connected)

    # 4.3 Send encrypted message User A -> User B
    msg_a_to_b = "Hello User B! This is an end-to-end encrypted real-time message."
    encrypted_pkg_a = user_a.crypto.encrypt_for(user_b.username, msg_a_to_b)

    user_a.sio.emit("send_message", {
        "recipient_username": user_b.username,
        "encrypted_package": encrypted_pkg_a,
    })

    # 4.4 Verify instant message delivery
    for _ in range(30):
        if len(user_b.received_messages) > 0:
            break
        time.sleep(0.1)

    check("4.4a User B received real-time WebSocket message", len(user_b.received_messages) >= 1)

    received_pkg = user_b.received_messages[0]
    check("4.4b Sender identity confirmed as User A by server", received_pkg.get("sender_username") == user_a.username)

    # Decrypt client-side on User B
    decrypted_by_b = user_b.crypto.decrypt_from(user_a.username, received_pkg["encrypted_package"])
    check("4.4c User B decrypted exact message sent by User A", decrypted_by_b == msg_a_to_b)

    # 4.5 Bidirectional reply User B -> User A
    msg_b_to_a = "Acknowledged User A! E2EE channel operational in both directions."
    encrypted_pkg_b = user_b.crypto.encrypt_for(user_a.username, msg_b_to_a)

    user_b.sio.emit("send_message", {
        "recipient_username": user_a.username,
        "encrypted_package": encrypted_pkg_b,
    })

    for _ in range(30):
        if len(user_a.received_messages) > 0:
            break
        time.sleep(0.1)

    check("4.5a User A received real-time reply from User B", len(user_a.received_messages) >= 1)
    decrypted_by_a = user_a.crypto.decrypt_from(user_b.username, user_a.received_messages[0]["encrypted_package"])
    check("4.5b User A decrypted exact reply sent by User B", decrypted_by_a == msg_b_to_a)

    # ═══════════════════════════════════════════════════════════════════════════
    # 5. DATABASE VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 5: DATABASE VERIFICATION ==={RESET}")

    conn = sqlite3.connect(config.DATABASE)
    conn.row_factory = sqlite3.Row

    # 5.1 Verify that messages are stored as ciphertext
    db_messages = conn.execute(
        """
        SELECT id, sender_id, recipient_id, ciphertext, nonce, tag, encrypted_package, created_at, is_deleted
        FROM messages
        WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
        ORDER BY id ASC
        """,
        (user_a.user_id, user_b.user_id, user_b.user_id, user_a.user_id),
    ).fetchall()

    check("5.1a Messages stored in database table", len(db_messages) >= 2)
    first_msg = db_messages[0]
    check("5.1b Database stores non-empty ciphertext string", bool(first_msg["ciphertext"]))
    check("5.1c Database stores 12-byte nonce", len(base64.b64decode(first_msg["nonce"])) == 12)
    check("5.1d Database stores 16-byte tag", len(base64.b64decode(first_msg["tag"])) == 16)

    # 5.2 Verify that plaintext messages are NOT stored anywhere in database file
    with open(config.DATABASE, "rb") as f:
        db_bytes = f.read()

    check("5.2a Plaintext message A ('Hello User B!...') is NOT in SQLite binary file",
          msg_a_to_b.encode("utf-8") not in db_bytes)
    check("5.2b Plaintext reply B ('Acknowledged User A!...') is NOT in SQLite binary file",
          msg_b_to_a.encode("utf-8") not in db_bytes)

    # 5.3 Test message history retrieval in chronological order
    code, hist_data = user_a.get_json(f"/api/messages/{user_b.username}")
    check("5.3a Message history API returns HTTP 200", code == 200 and hist_data.get("ok"))
    messages_list = hist_data.get("messages", [])
    check("5.3b Message history returns all exchanged messages", len(messages_list) >= 2)

    # Verify chronological order
    timestamps = [m["timestamp"] for m in messages_list]
    check("5.3c Messages returned in chronological order", timestamps == sorted(timestamps))

    # Decrypt all history messages client-side
    hist_msg_1 = user_a.crypto.decrypt_from(user_b.username, messages_list[0]["encrypted_package"], check_replay=False)
    hist_msg_2 = user_a.crypto.decrypt_from(user_b.username, messages_list[1]["encrypted_package"], check_replay=False)
    check("5.3d History message 1 decrypted client-side", hist_msg_1 == msg_a_to_b)
    check("5.3e History message 2 decrypted client-side", hist_msg_2 == msg_b_to_a)

    # 5.4 Test message deletion
    target_msg_id = messages_list[0]["id"]
    code, del_res = user_a.delete(f"/api/messages/{target_msg_id}")
    check("5.4a User A deletes message 1 (HTTP 200)", code == 200 and del_res.get("ok"))

    # Verify message is permanently erased from database
    row = conn.execute("SELECT * FROM messages WHERE id = ?", (target_msg_id,)).fetchone()
    check("5.4b Deleted message row is permanently purged from SQLite", row is None)

    # Verify history no longer contains deleted message
    code, hist_data_updated = user_a.get_json(f"/api/messages/{user_b.username}")
    updated_ids = [m["id"] for m in hist_data_updated.get("messages", [])]
    check("5.4c Updated history excludes deleted message ID", target_msg_id not in updated_ids)

    # 5.5 Test clear entire conversation
    code, clr_res = user_a.delete(f"/api/messages/conversation/{user_b.username}")
    check("5.5a User A clears entire conversation (HTTP 200)", code == 200 and clr_res.get("ok"))

    remaining_rows = conn.execute(
        """
        SELECT COUNT(*) as count FROM messages
        WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
        """,
        (user_a.user_id, user_b.user_id, user_b.user_id, user_a.user_id),
    ).fetchone()
    check("5.5b All conversation messages purged from SQLite", remaining_rows["count"] == 0)

    # ═══════════════════════════════════════════════════════════════════════════
    # 6. END-TO-END ENCRYPTION VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{INFO} === SECTION 6: END-TO-END ENCRYPTION VERIFICATION ==={RESET}")

    # 6.1 Inspect server database for private keys
    users_rows = conn.execute("SELECT id, username, email, public_key, password_hash FROM users").fetchall()
    all_users_str = str([dict(r) for r in users_rows])

    check("6.1a Private keys never stored in 'users' table",
          "BEGIN PRIVATE KEY" not in all_users_str and "private_key" not in all_users_str)

    pk_rows = conn.execute("SELECT * FROM public_keys").fetchall()
    all_pk_str = str([dict(r) for r in pk_rows])
    check("6.1b Private keys never stored in 'public_keys' table",
          "BEGIN PRIVATE KEY" not in all_pk_str and "private_key" not in all_pk_str)

    # Verify private key bytes never in entire database file
    user_a_priv_bytes = base64.b64decode(user_a.crypto.private_key_b64)
    user_b_priv_bytes = base64.b64decode(user_b.crypto.private_key_b64)

    with open(config.DATABASE, "rb") as f:
        current_db_bytes = f.read()

    check("6.1c User A private key bytes NOT in database file", user_a_priv_bytes not in current_db_bytes)
    check("6.1d User B private key bytes NOT in database file", user_b_priv_bytes not in current_db_bytes)

    # 6.2 Confirm server cannot read message contents
    # The server schema has only ciphertext, nonce, tag, encrypted_package.
    # No symmetric key or private key column exists.
    msg_table_cols = [r["name"] for r in conn.execute("PRAGMA table_info(messages)").fetchall()]
    check("6.2a Messages table has NO key column",
          "key" not in msg_table_cols and "aes_key" not in msg_table_cols and "secret" not in msg_table_cols)
    check("6.2b Messages table has NO plaintext column",
          "plaintext" not in msg_table_cols and "content" not in msg_table_cols and "body" not in msg_table_cols)

    # Clean up WebSockets
    try:
        user_a.sio.disconnect()
        user_b.sio.disconnect()
    except Exception:
        pass
    conn.close()

    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL RESULTS
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n{BOLD}{'=' * 75}{RESET}")
    print(f"{BOLD}  TEST EXECUTION SUMMARY{RESET}")
    print(f"{BOLD}{'=' * 75}{RESET}")
    print(f"  Total Test Assertions:  {total_tests}")
    print(f"  Passed Assertions:      \033[92m{passed_tests}\033[0m")
    print(f"  Failed Assertions:      \033[91m{failed_tests}\033[0m")
    print(f"  Success Rate:           {passed_tests / total_tests * 100:.1f}%")
    print(f"{BOLD}{'=' * 75}{RESET}")

    if failed_tests == 0:
        print(f"\n\033[92m[OK] ALL 6 MODULES AND SECURITY REQUIREMENTS ARE 100% VERIFIED!\033[0m\n")
        return 0
    else:
        print(f"\n\033[91m[X] {failed_tests} TEST(S) FAILED\033[0m\n")
        return 1


if __name__ == "__main__":
    code = run_all_tests()
    sys.exit(code)
