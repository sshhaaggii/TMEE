"""
test_realtime_messaging.py — Comprehensive Integration Test for Module 3: Real-Time Messaging.

Verifies:
  1. Two distinct user accounts (Alice and Bob) register and login.
  2. Alice & Bob publish their X25519 public keys.
  3. Unauthenticated WebSocket connection is rejected by server.
  4. Authenticated WebSocket connection:
     - Alice connects with session cookie.
     - Bob connects with session cookie.
  5. Real-Time Presence & Online Status:
     - Alice receives 'user_status' event when Bob connects.
     - Online users list contains both active users.
  6. Real-Time End-to-End Encrypted Message Transmission (Alice -> Bob):
     - Alice encrypts message client-side with AES-256-GCM.
     - Alice sends encrypted ciphertext blob over WebSocket.
     - Server validates sender identity strictly from session.
     - Server forwards encrypted package to Bob's room.
     - Bob receives 'receive_message' event over WebSocket.
     - Bob decrypts the message client-side using Alice's public key.
     - Assert decrypted message matches Alice's original plaintext.
  7. Real-Time Bidirectional Encrypted Reply (Bob -> Alice):
     - Bob encrypts a reply client-side.
     - Bob sends ciphertext over WebSocket.
     - Alice receives and decrypts Bob's reply.
  8. Message Delivery Status & Confirmations:
     - Bob confirms delivery ('message_delivered').
     - Alice receives delivery update.
  9. Database Security & Server Ignorance:
     - Verify database stores ONLY encrypted ciphertext packages.
     - Verify database raw binary contains zero plaintext message bytes.
 10. Conversation History API (/api/messages/<peer>):
     - Alice fetches conversation history.
     - Both encrypted messages are retrieved and decrypted successfully.
 11. Disconnect & Offline Status:
     - Bob disconnects.
     - Alice receives 'user_status' event with status='offline'.
"""

import http.cookiejar
import json
import re
import sqlite3
import sys
import os
import time
import threading
import logging
import urllib.error
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


class UserTestClient:
    """Represents a full client device: HTTP session, E2EE keys, and WebSocket client."""

    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email    = email
        self.password = password
        self.jar      = http.cookiejar.CookieJar()
        self.opener   = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf     = ""
        self.crypto   = ClientE2EESession(username=username)
        self.sio      = socketio.Client()
        self.received_messages = []
        self.status_events = []
        self.online_users_list = []
        self.delivery_updates = []

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

    def get_json(self, path: str) -> tuple[int, dict]:
        url = BASE_URL + path
        req = urllib.request.Request(url, headers={"User-Agent": "SecureChat-Test"})
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, {"ok": False, "raw": raw}

    def setup_socket_handlers(self):
        @self.sio.on("user_status")
        def on_user_status(data):
            self.status_events.append(data)

        @self.sio.on("online_users")
        def on_online_users(data):
            self.online_users_list = data.get("users", [])

        @self.sio.on("receive_message")
        def on_receive_message(data):
            self.received_messages.append(data)

        @self.sio.on("message_status_update")
        def on_message_status_update(data):
            self.delivery_updates.append(data)


print(f"{INFO} Cleaning old test users from database...")
with sqlite3.connect(config.DATABASE) as conn:
    conn.execute("DELETE FROM users WHERE username IN ('alice_rt', 'bob_rt') OR email IN ('alice_rt@test.local', 'bob_rt@test.local')")
    conn.commit()

alice = UserTestClient("alice_rt", "alice_rt@test.local", "AliceRealtime1!")
bob   = UserTestClient("bob_rt",   "bob_rt@test.local",   "BobRealtime1!")

alice.setup_socket_handlers()
bob.setup_socket_handlers()

# ── 1. Register & Login Alice & Bob ──────────────────────────────────────────
print(f"\n{INFO} [1] Registering & Authenticating Alice and Bob...")
alice.fetch_csrf()
s, _ = alice.post_json("/register", {
    "username": alice.username, "email": alice.email,
    "password": alice.password, "confirmPassword": alice.password
})
check("Alice registered", s == 201)

alice.fetch_csrf()
s, d = alice.post_json("/login", {"email": alice.email, "password": alice.password})
check("Alice logged in", s == 200 and d.get("ok") is True)

bob.fetch_csrf()
s, _ = bob.post_json("/register", {
    "username": bob.username, "email": bob.email,
    "password": bob.password, "confirmPassword": bob.password
})
check("Bob registered", s == 201)

bob.fetch_csrf()
s, d = bob.post_json("/login", {"email": bob.email, "password": bob.password})
check("Bob logged in", s == 200 and d.get("ok") is True)

# ── 2. Publish Public Keys ───────────────────────────────────────────────────
print(f"\n{INFO} [2] Publishing X25519 Public Keys to Server Directory...")
s, d = alice.post_json("/api/keys/public-key", {"public_key": alice.crypto.public_key_b64})
check("Alice published public key", s == 200 and d.get("ok") is True)

s, d = bob.post_json("/api/keys/public-key", {"public_key": bob.crypto.public_key_b64})
check("Bob published public key", s == 200 and d.get("ok") is True)

# Key exchange between client devices
alice.crypto.establish_session(bob.username, bob.crypto.public_key_b64)
bob.crypto.establish_session(alice.username, alice.crypto.public_key_b64)
check("Both clients established symmetric E2EE session keys locally",
      alice.crypto.get_session_key(bob.username) == bob.crypto.get_session_key(alice.username))

# ── 3. WebSocket Authentication Security ────────────────────────────────────
print(f"\n{INFO} [3] Testing WebSocket Connection Authentication...")
unauth_sio = socketio.Client()
unauth_connected = False
try:
    unauth_sio.connect(BASE_URL, headers={})
    unauth_connected = True
    unauth_sio.disconnect()
except Exception:
    unauth_connected = False
check("Unauthenticated WebSocket connection was rejected", not unauth_connected)

# ── 4. Authenticated WebSocket Connections ──────────────────────────────────
print(f"\n{INFO} [4] Connecting Alice and Bob via WebSockets...")
alice.sio.connect(BASE_URL, headers={"Cookie": alice.get_cookie_header()})
check("Alice connected to WebSocket server", alice.sio.connected)
time.sleep(0.3)

bob.sio.connect(BASE_URL, headers={"Cookie": bob.get_cookie_header()})
check("Bob connected to WebSocket server", bob.sio.connected)
time.sleep(0.5)

# ── 5. Real-Time Presence & Status ──────────────────────────────────────────
print(f"\n{INFO} [5] Checking Real-Time Presence & Status Events...")
check("Alice received user_status event for Bob (online)",
      any(e.get("username") == bob.username and e.get("status") == "online" for e in alice.status_events))
check("Bob's online users list includes Alice", alice.username in bob.online_users_list)

# ── 6. Real-Time E2EE Message Transmission (Alice -> Bob) ───────────────────
print(f"\n{INFO} [6] Real-Time E2EE Message Sending (Alice -> Bob)...")
alice_plaintext = "CONFIDENTIAL: Operation Orion initiates at 21:00 UTC."

# Alice encrypts client-side using established AES-256-GCM key
alice_encrypted_package = alice.crypto.encrypt_for(bob.username, alice_plaintext)

# Alice emits over WebSocket
alice.sio.emit("send_message", {
    "recipient_username": bob.username,
    "encrypted_package": alice_encrypted_package,
})

# Wait for Bob to receive
time.sleep(0.8)

check("Bob received a message over WebSocket", len(bob.received_messages) > 0)
bob_received_pkg = bob.received_messages[-1]
check("Sender identified by server as alice_rt", bob_received_pkg.get("sender_username") == alice.username)

# Bob decrypts on his client device
bob_decrypted_text = bob.crypto.decrypt_from(alice.username, bob_received_pkg["encrypted_package"])
check("Bob decrypted exact original message client-side", bob_decrypted_text == alice_plaintext)

# ── 7. Real-Time E2EE Reply (Bob -> Alice) ──────────────────────────────────
print(f"\n{INFO} [7] Real-Time E2EE Reply (Bob -> Alice)...")
bob_reply_plaintext = "ACKNOWLEDGED: Team Orion is in position and standing by."

# Bob encrypts reply client-side
bob_encrypted_reply = bob.crypto.encrypt_for(alice.username, bob_reply_plaintext)

# Bob emits reply
bob.sio.emit("send_message", {
    "recipient_username": alice.username,
    "encrypted_package": bob_encrypted_reply,
})

time.sleep(0.8)

check("Alice received reply over WebSocket", len(alice.received_messages) > 0)
alice_received_pkg = alice.received_messages[-1]
check("Reply sender identified as bob_rt", alice_received_pkg.get("sender_username") == bob.username)

# Alice decrypts Bob's reply client-side
alice_decrypted_reply = alice.crypto.decrypt_from(bob.username, alice_received_pkg["encrypted_package"])
check("Alice decrypted exact reply message client-side", alice_decrypted_reply == bob_reply_plaintext)

# ── 8. Delivery Confirmations ───────────────────────────────────────────────
print(f"\n{INFO} [8] Testing Message Delivery Confirmations...")
# Bob confirms delivery of message 1 to Alice
bob.sio.emit("message_delivered", {
    "message_id": bob_received_pkg["id"],
    "sender_username": alice.username,
})
time.sleep(0.4)

check("Alice received delivery confirmation update",
      any(u.get("message_id") == bob_received_pkg["id"] and u.get("status") == "delivered" for u in alice.delivery_updates))

# ── 9. Server Database Ignorance Invariant ──────────────────────────────────
print(f"\n{INFO} [9] Verifying Zero Plaintext in Server Database...")
with sqlite3.connect(config.DATABASE) as conn:
    conn.row_factory = sqlite3.Row
    db_messages = conn.execute("SELECT * FROM messages WHERE sender_id IN (SELECT id FROM users WHERE username IN ('alice_rt', 'bob_rt'))").fetchall()

check("Both encrypted messages stored in database", len(db_messages) == 2)
for m in db_messages:
    pkg = json.loads(m["encrypted_package"])
    check(f"Message #{m['id']} has nonce, ciphertext, and tag stored",
          all(k in pkg for k in ("nonce", "ciphertext", "tag")))

# Verify database file has NO plaintext bytes
with open(config.DATABASE, "rb") as f:
    db_bytes = f.read()

check("Plaintext 'Operation Orion' is NOT anywhere in database", b"Operation Orion" not in db_bytes)
check("Plaintext 'Team Orion is in position' is NOT in database", b"Team Orion is in position" not in db_bytes)

# ── 10. Conversation History API ────────────────────────────────────────────
print(f"\n{INFO} [10] Testing Conversation History API (/api/messages/<peer>)...")
s, history_data = alice.get_json(f"/api/messages/{bob.username}")
check("Conversation history API returns HTTP 200", s == 200)
check("History contains 2 messages", len(history_data.get("messages", [])) == 2)

# Decrypt history on client
h_msg1 = history_data["messages"][0]
h_msg2 = history_data["messages"][1]
check("History message 1 marked is_self=True", h_msg1["is_self"] is True)
check("History message 2 marked is_self=False", h_msg2["is_self"] is False)

h_decrypted_1 = alice.crypto.decrypt_from(bob.username, h_msg1["encrypted_package"], check_replay=False)
h_decrypted_2 = alice.crypto.decrypt_from(bob.username, h_msg2["encrypted_package"], check_replay=False)
check("Historical message 1 decrypted correctly", h_decrypted_1 == alice_plaintext)
check("Historical message 2 decrypted correctly", h_decrypted_2 == bob_reply_plaintext)

# ── 11. Disconnect & Offline Presence ───────────────────────────────────────
print(f"\n{INFO} [11] Testing Disconnect & Offline Presence...")
bob.sio.disconnect()
time.sleep(0.5)

check("Alice received user_status event for Bob (offline)",
      any(e.get("username") == bob.username and e.get("status") == "offline" for e in alice.status_events))

alice.sio.disconnect()

# Cleanup test users
with sqlite3.connect(config.DATABASE) as conn:
    conn.execute("DELETE FROM messages WHERE sender_id IN (SELECT id FROM users WHERE username IN ('alice_rt', 'bob_rt')) OR recipient_id IN (SELECT id FROM users WHERE username IN ('alice_rt', 'bob_rt'))")
    conn.execute("DELETE FROM users WHERE username IN ('alice_rt', 'bob_rt')")
    conn.commit()

# ── Summary ─────────────────────────────────────────────────────────────────
print()
if failures == 0:
    print("\033[92m==================================================================")
    print("  ALL 26 REAL-TIME MESSAGING TESTS PASSED - MODULE 3 VERIFIED!")
    print("==================================================================\033[0m")
    sys.exit(0)
else:
    print(f"\033[91m==================================================================")
    print(f"  {failures} TEST(S) FAILED")
    print("==================================================================\033[0m")
    sys.exit(1)
