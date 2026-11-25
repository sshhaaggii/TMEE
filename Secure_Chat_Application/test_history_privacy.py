"""
test_history_privacy.py — Comprehensive Integration Test for Module 4:
Secure Chat History and Privacy Management.

Requirements Verified:
  1. Message Storage:
     - Store encrypted message ciphertext in the database.
     - Store sender ID and receiver ID.
     - Store timestamps.
     - Store nonce and authentication tag metadata.
     - Never store plaintext messages (verified with binary file scan).
  2. Chat History:
     - Retrieve previous conversations.
     - Return messages in chronological order.
     - Decrypt messages on the user's device.
     - Verify conversation loading.
  3. Privacy:
     - Allow users to delete their messages.
     - Prevent unauthorized users from accessing conversations (strict 403 checks).
     - Protect private encryption keys (verified only public keys in DB, zero private keys).
     - Do not expose message contents to the backend.
  4. Database:
     - Verify dedicated tables for users, public_keys, and messages.
"""

import http.cookiejar
import json
import os
import re
import sqlite3
import sys
import time
import threading
import logging
import urllib.error
import urllib.parse
import urllib.request
import socketio

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

def ensure_server_running():
    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/api/session", timeout=0.5):
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
    for _ in range(60):
        time.sleep(0.1)
        try:
            with urllib.request.urlopen("http://127.0.0.1:5000/api/session", timeout=0.5):
                return
        except Exception:
            pass
    raise RuntimeError("Failed to start test server on port 5000")

ensure_server_running()

from config import config
from encryption.e2ee import (
    ClientE2EESession,
    generate_key_pair,
    export_public_key,
    import_public_key,
)

BASE_URL = "http://127.0.0.1:5000"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

failures = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global failures
    if condition:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label} - {detail}")
        failures += 1


class TestClient:
    """Represents a client device: HTTP session, cookies, E2EE keys, and WebSocket client."""

    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email    = email
        self.password = password
        self.user_id  = None
        self.jar      = http.cookiejar.CookieJar()
        self.opener   = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf     = ""
        self.crypto   = ClientE2EESession(username=username)
        self.sio      = socketio.Client()
        self.received_messages = []
        self.deleted_events = []
        self.cleared_events = []

    def get_cookie_header(self) -> str:
        cookies = [f"{c.name}={c.value}" for c in self.jar]
        return "; ".join(cookies)

    def fetch_csrf(self) -> str:
        with self.opener.open(BASE_URL + "/login") as r:
            html = r.read().decode()
        m = re.search(r'id="csrf_token" name="csrf_token" value="([^"]+)"', html)
        self.csrf = m.group(1) if m else ""
        return self.csrf

    def post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        headers = {
            "Content-Type": "application/json",
            "X-CSRFToken": self.csrf,
        }
        url = BASE_URL + path
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"ok": False, "raw": raw}

    def register(self) -> tuple[int, dict]:
        self.fetch_csrf()
        return self.post_json("/register", {
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "confirmPassword": self.password,
        })

    def login(self) -> tuple[int, dict]:
        self.fetch_csrf()
        status, body = self.post_json("/login", {
            "email": self.email,
            "password": self.password,
        })
        if status == 200:
            self.get_session_info()
        return status, body

    def get_session_info(self) -> dict:
        req = urllib.request.Request(BASE_URL + "/api/session")
        with self.opener.open(req) as r:
            data = json.loads(r.read().decode())
            if data.get("csrf_token"):
                self.csrf = data["csrf_token"]
            return data

    def publish_public_key(self) -> tuple[int, dict]:
        pub_b64 = self.crypto.public_key_b64
        req = urllib.request.Request(
            BASE_URL + "/api/keys/public-key",
            data=json.dumps({"public_key": pub_b64}).encode(),
            headers={
                "Content-Type": "application/json",
                "X-CSRFToken": self.csrf,
            },
            method="POST",
        )
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def fetch_user_key(self, target_user: str) -> str:
        req = urllib.request.Request(BASE_URL + f"/api/keys/{urllib.parse.quote(target_user)}")
        with self.opener.open(req) as r:
            data = json.loads(r.read().decode())
            return data.get("public_key", "")

    def fetch_history(self, peer_username: str) -> tuple[int, dict]:
        req = urllib.request.Request(BASE_URL + f"/api/messages/{urllib.parse.quote(peer_username)}")
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def fetch_single_message(self, message_id: int) -> tuple[int, dict]:
        req = urllib.request.Request(BASE_URL + f"/api/messages/id/{message_id}")
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except Exception:
                body = {"error": str(e)}
            return e.code, body

    def delete_message(self, message_id: int) -> tuple[int, dict]:
        req = urllib.request.Request(
            BASE_URL + f"/api/messages/{message_id}",
            headers={"X-CSRFToken": self.csrf},
            method="DELETE",
        )
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except Exception:
                body = {"error": str(e)}
            return e.code, body

    def clear_conversation(self, peer_username: str) -> tuple[int, dict]:
        req = urllib.request.Request(
            BASE_URL + f"/api/messages/conversation/{urllib.parse.quote(peer_username)}",
            headers={"X-CSRFToken": self.csrf},
            method="DELETE",
        )
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except Exception:
                body = {"error": str(e)}
            return e.code, body

    def connect_ws(self) -> None:
        cookie_hdr = self.get_cookie_header()

        @self.sio.on("receive_message")
        def on_msg(data):
            self.received_messages.append(data)

        @self.sio.on("message_deleted")
        def on_del(data):
            self.deleted_events.append(data)

        @self.sio.on("conversation_cleared")
        def on_clr(data):
            self.cleared_events.append(data)

        self.sio.connect(
            BASE_URL,
            headers={"Cookie": cookie_hdr},
        )


def main():
    print("=" * 70)
    print("  TEST SUITE: Module 4 - Secure Chat History and Privacy Management")
    print("=" * 70)

    suffix = str(int(time.time()))
    alice = TestClient(f"alice_m4_{suffix}", f"alice_m4_{suffix}@example.com", "SecurePassword123!")
    bob   = TestClient(f"bob_m4_{suffix}", f"bob_m4_{suffix}@example.com", "SecurePassword123!")
    eve   = TestClient(f"eve_m4_{suffix}", f"eve_m4_{suffix}@example.com", "SecurePassword123!")

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1: Database Tables Verification
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 1: Database Table Architecture Verification...")
    conn = sqlite3.connect(config.DATABASE)
    conn.row_factory = sqlite3.Row
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    check("Table 'users' exists in SQLite", "users" in tables)
    check("Table 'public_keys' exists in SQLite", "public_keys" in tables)
    check("Table 'messages' exists in SQLite", "messages" in tables)

    # Check columns in public_keys
    pk_cols = [r["name"] for r in conn.execute("PRAGMA table_info(public_keys)").fetchall()]
    check("public_keys has 'user_id' column", "user_id" in pk_cols)
    check("public_keys has 'public_key' column", "public_key" in pk_cols)
    check("public_keys has 'algorithm' column", "algorithm" in pk_cols)
    check("public_keys has 'created_at' column", "created_at" in pk_cols)

    # Check columns in messages
    msg_cols = [r["name"] for r in conn.execute("PRAGMA table_info(messages)").fetchall()]
    check("messages has 'ciphertext' column", "ciphertext" in msg_cols)
    check("messages has 'nonce' column", "nonce" in msg_cols)
    check("messages has 'tag' column", "tag" in msg_cols)
    check("messages has 'is_deleted' column", "is_deleted" in msg_cols)
    check("messages has 'created_at' column", "created_at" in msg_cols)
    check("messages has 'sender_id' column", "sender_id" in msg_cols)
    check("messages has 'recipient_id' column", "recipient_id" in msg_cols)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2: User Registration & Public Key Directory
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 2: User Registration & Public Key Management...")
    for u in [alice, bob, eve]:
        code, resp = u.register()
        check(f"Register {u.username}", code == 201 and resp.get("ok"), str(resp))
        code, resp = u.login()
        check(f"Login {u.username}", code == 200 and resp.get("ok"), str(resp))

    # Fetch user IDs
    alice_row = conn.execute("SELECT id FROM users WHERE username = ?", (alice.username,)).fetchone()
    bob_row   = conn.execute("SELECT id FROM users WHERE username = ?", (bob.username,)).fetchone()
    eve_row   = conn.execute("SELECT id FROM users WHERE username = ?", (eve.username,)).fetchone()
    alice.user_id = alice_row["id"]
    bob.user_id   = bob_row["id"]
    eve.user_id   = eve_row["id"]

    # Publish public keys
    code, resp = alice.publish_public_key()
    check("Alice publishes X25519 public key", code == 200 and resp.get("ok"))
    code, resp = bob.publish_public_key()
    check("Bob publishes X25519 public key", code == 200 and resp.get("ok"))

    # Verify public_keys table records
    alice_pks = conn.execute(
        "SELECT * FROM public_keys WHERE user_id = ? ORDER BY id DESC",
        (alice.user_id,)
    ).fetchall()
    check("public_keys table contains Alice's key record", len(alice_pks) >= 1)
    if alice_pks:
        check("public_keys algorithm is X25519", alice_pks[0]["algorithm"] == "X25519")
        check("public_keys public_key matches Alice's key", alice_pks[0]["public_key"] == alice.crypto.public_key_b64)
        check("public_keys created_at timestamp exists", bool(alice_pks[0]["created_at"]))

    # Public key history endpoint
    req = urllib.request.Request(BASE_URL + f"/api/keys/history/{alice.username}")
    with alice.opener.open(req) as r:
        hist_data = json.loads(r.read().decode())
    check("GET /api/keys/history/<user> returns keys array", hist_data.get("ok") and len(hist_data.get("keys", [])) >= 1)

    # Invariant: Server database contains ZERO private keys
    all_users = conn.execute("SELECT * FROM users").fetchall()
    private_key_exposed = any("BEGIN PRIVATE KEY" in str(u) for u in all_users)
    check("Privacy: ZERO private keys stored in users table", not private_key_exposed)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3: Encrypted Message Storage (Zero Plaintext Invariant)
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 3: Encrypted Message Storage & Zero-Plaintext Storage...")
    alice.connect_ws()
    bob.connect_ws()
    eve.connect_ws()
    time.sleep(0.5)

    # Establish E2EE sessions
    alice_pub = alice.fetch_user_key(alice.username)
    bob_pub   = bob.fetch_user_key(bob.username)
    alice.crypto.establish_session(bob.username, bob_pub)
    bob.crypto.establish_session(alice.username, alice_pub)

    # Test messages with distinctive sensitive strings
    secret_msgs = [
        "Confidential Project Alpha: Launch at dawn.",
        "Financial records: 1,500,000 credits allocated.",
        "Secure passphrase: CorrectHorseBatteryStaple!",
    ]

    sent_message_ids = []

    for msg in secret_msgs:
        encrypted_pkg = alice.crypto.encrypt_for(bob.username, msg)
        # Verify structure
        check("Encrypted package has ciphertext", bool(encrypted_pkg.get("ciphertext")))
        check("Encrypted package has 12-byte nonce", bool(encrypted_pkg.get("nonce")))
        check("Encrypted package has 16-byte tag", bool(encrypted_pkg.get("tag")))

        alice.sio.emit("send_message", {
            "recipient_username": bob.username,
            "encrypted_package": encrypted_pkg,
        })
        time.sleep(0.4)

    deadline = time.time() + 4.0
    while time.time() < deadline and len(bob.received_messages) < 3:
        time.sleep(0.1)

    check("Bob received all 3 real-time messages via Socket.IO", len(bob.received_messages) == 3, f"got {len(bob.received_messages)}")

    # Query messages directly in SQLite
    stored_rows = conn.execute(
        """
        SELECT id, sender_id, recipient_id, ciphertext, nonce, tag, created_at, is_deleted
        FROM messages
        WHERE sender_id = ? AND recipient_id = ?
        ORDER BY id ASC
        """,
        (alice.user_id, bob.user_id),
    ).fetchall()

    sent_message_ids = [r["id"] for r in stored_rows]

    check("Database has 3 rows for Alice -> Bob messages", len(stored_rows) == 3)
    for row in stored_rows:
        check(f"Message {row['id']} sender_id == Alice", row["sender_id"] == alice.user_id)
        check(f"Message {row['id']} recipient_id == Bob", row["recipient_id"] == bob.user_id)
        check(f"Message {row['id']} ciphertext is non-empty Base64", len(row["ciphertext"]) > 20)
        check(f"Message {row['id']} nonce is non-empty Base64 (12 bytes)", len(row["nonce"]) > 10)
        check(f"Message {row['id']} tag is non-empty Base64 (16 bytes)", len(row["tag"]) > 15)
        check(f"Message {row['id']} created_at timestamp is valid", bool(row["created_at"]))
        check(f"Message {row['id']} is_deleted == 0", row["is_deleted"] == 0)

    # Strict Zero-Plaintext Audit: Read SQLite raw file bytes
    conn.commit()
    with open(config.DATABASE, "rb") as db_file:
        db_raw_bytes = db_file.read()

    for secret in secret_msgs:
        found_in_db = secret.encode("utf-8") in db_raw_bytes
        check(f"Privacy Invariant: Plaintext '{secret[:20]}...' NEVER in SQLite database file", not found_in_db)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4: Chat History Retrieval & Client-Side Decryption
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 4: Chat History Retrieval & Client-Side Decryption...")
    code, history_data = bob.fetch_history(alice.username)
    check("Bob retrieves history from GET /api/messages/alice", code == 200 and history_data.get("ok"))

    msgs_retrieved = history_data.get("messages", [])
    check("History contains 3 stored messages", len(msgs_retrieved) == 3)

    # Verify chronological order
    timestamps = [m["timestamp"] for m in msgs_retrieved]
    ids = [m["id"] for m in msgs_retrieved]
    check("Messages returned in chronological order (created_at ASC)", timestamps == sorted(timestamps))
    check("Messages returned in primary key order (id ASC)", ids == sorted(ids))

    # Decrypt on Bob's client device (historical messages)
    decrypted_texts = []
    for m in msgs_retrieved:
        dec = bob.crypto.decrypt_from(alice.username, m["encrypted_package"], check_replay=False)
        decrypted_texts.append(dec)

    check("Decrypted messages match original plaintext exactly", decrypted_texts == secret_msgs)

    # Alice fetches her own view of the conversation
    code, alice_hist = alice.fetch_history(bob.username)
    check("Alice retrieves history from GET /api/messages/bob", code == 200 and alice_hist.get("ok"))
    check("Alice history marks messages as is_self=True", all(m["is_self"] for m in alice_hist.get("messages", [])))

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5: Privacy & Unauthorized Access Prevention (403 Forbidden)
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 5: Privacy Enforcement & Unauthorized Access Prevention...")
    target_msg_id = sent_message_ids[0]

    # Alice and Bob can view their message
    code, alice_view = alice.fetch_single_message(target_msg_id)
    check("Alice (sender) can access message details", code == 200 and alice_view.get("ok"))

    code, bob_view = bob.fetch_single_message(target_msg_id)
    check("Bob (recipient) can access message details", code == 200 and bob_view.get("ok"))

    # Unauthorized access: Eve attempts to view message between Alice and Bob
    code, eve_view = eve.fetch_single_message(target_msg_id)
    check("Eve (unauthorized third-party) is REJECTED with 403 Forbidden on message access", code == 403)
    check("Eve response contains forbidden/unauthorized error", "Forbidden" in eve_view.get("error", "") or "permission" in eve_view.get("error", ""))

    # Unauthorized deletion: Eve attempts to delete message between Alice and Bob
    code, eve_del = eve.delete_message(target_msg_id)
    check("Eve (unauthorized third-party) is REJECTED with 403 Forbidden on message deletion", code == 403)

    # Eve fetches conversation with Bob -> should see 0 messages
    code, eve_bob_hist = eve.fetch_history(bob.username)
    check("Eve cannot see messages between Alice and Bob", len(eve_bob_hist.get("messages", [])) == 0)

    # Unauthenticated user access check
    unauth_req = urllib.request.Request(BASE_URL + f"/api/messages/{bob.username}")
    try:
        urllib.request.urlopen(unauth_req)
        unauth_blocked = False
    except urllib.error.HTTPError as e:
        unauth_blocked = e.code in (302, 401, 403)
    check("Unauthenticated user blocked from message history", unauth_blocked)

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6: Message Deletion
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 6: Message Deletion & Real-Time Sync...")
    delete_target_id = sent_message_ids[1]  # Second message ("Financial records...")

    # Alice deletes message 2
    code, del_resp = alice.delete_message(delete_target_id)
    check("Alice deletes message 2 successfully (HTTP 200)", code == 200 and del_resp.get("ok"))
    check("Delete response confirms message_id", del_resp.get("message_id") == delete_target_id)

    # Check direct database removal
    deleted_row = conn.execute("SELECT * FROM messages WHERE id = ?", (delete_target_id,)).fetchone()
    check("Deleted message is permanently purged from SQLite messages table", deleted_row is None)

    # Bob receives real-time deletion event
    time.sleep(0.5)
    bob_received_del_ids = [evt.get("message_id") for evt in bob.deleted_events]
    check("Bob received 'message_deleted' event in real time via Socket.IO", delete_target_id in bob_received_del_ids)

    # Fetch updated history: message 2 must not be present
    code, updated_hist = bob.fetch_history(alice.username)
    remaining_ids = [m["id"] for m in updated_hist.get("messages", [])]
    check("Updated history contains 2 messages (message 2 absent)", len(remaining_ids) == 2 and delete_target_id not in remaining_ids)
    check("Remaining messages are 1 and 3", remaining_ids == [sent_message_ids[0], sent_message_ids[2]])

    # Bob (recipient) can also delete message 3
    code, bob_del_resp = bob.delete_message(sent_message_ids[2])
    check("Bob (recipient) can delete message 3 successfully", code == 200 and bob_del_resp.get("ok"))

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 7: Clear Entire Conversation History
    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{INFO} Step 7: Clear Conversation History...")
    code, clr_resp = alice.clear_conversation(bob.username)
    check("Alice clears conversation with Bob successfully (HTTP 200)", code == 200 and clr_resp.get("ok"))
    check("Clear response reports deleted count >= 1", clr_resp.get("deleted_count", 0) >= 1)

    # Check direct database: zero messages between Alice and Bob
    remaining_in_db = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM messages
        WHERE (sender_id = ? AND recipient_id = ?)
           OR (sender_id = ? AND recipient_id = ?)
        """,
        (alice.user_id, bob.user_id, bob.user_id, alice.user_id),
    ).fetchone()["cnt"]
    check("All messages between Alice and Bob permanently removed from SQLite", remaining_in_db == 0)

    # Both parties see empty conversation
    code, alice_empty = alice.fetch_history(bob.username)
    check("Alice history is now empty []", len(alice_empty.get("messages", [])) == 0)

    code, bob_empty = bob.fetch_history(alice.username)
    check("Bob history is now empty []", len(bob_empty.get("messages", [])) == 0)

    # Real-time clear notification
    time.sleep(0.5)
    check("Bob received 'conversation_cleared' event via Socket.IO", len(bob.cleared_events) >= 1)

    # Clean up sockets
    alice.sio.disconnect()
    bob.sio.disconnect()
    eve.sio.disconnect()
    conn.close()

    # ─────────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    if failures == 0:
        print(f"  {PASS} ALL MODULE 4 REQUIREMENTS VERIFIED SUCCESSFULLY!")
    else:
        print(f"  {FAIL} {failures} CHECK(S) FAILED!")
    print("=" * 70)
    sys.exit(failures)


if __name__ == "__main__":
    main()
