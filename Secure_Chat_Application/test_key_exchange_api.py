"""
test_key_exchange_api.py — Integration test for Module 2 Key Directory & E2EE API.

Verifies:
  1. Alice and Bob register & login to Flask backend.
  2. Alice generates X25519 keys locally (private key stays on device).
  3. Alice publishes public key via POST /api/keys/public-key.
  4. Bob publishes public key via POST /api/keys/public-key.
  5. Alice fetches Bob's public key via GET /api/keys/bob.
  6. Bob fetches Alice's public key via GET /api/keys/alice.
  7. Alice establishes shared secret and encrypts message for Bob.
  8. Bob decrypts message using Alice's public key and his private key.
  9. Database verification: Database contains public_key, NO private keys or AES keys.
"""

import base64
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

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

def ensure_server_running():
    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/api/session", timeout=0.5):
            return
    except Exception:
        pass
    from app import app, socketio, create_app
    create_app()
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    threading.Thread(
        target=lambda: socketio.run(app, host="127.0.0.1", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True),
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

BASE = "http://127.0.0.1:5000"
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


class TestUserSession:
    """Helper to simulate an authenticated browser client session."""

    def __init__(self, username: str, email: str, password: str):
        self.username = username
        self.email    = email
        self.password = password
        self.jar      = http.cookiejar.CookieJar()
        self.opener   = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf     = ""
        self.crypto   = ClientE2EESession(username=username)

    def fetch_csrf(self) -> str:
        with self.opener.open(BASE + "/login") as r:
            html = r.read().decode()
        m = re.search(r'id="csrf_token" name="csrf_token" value="([^"]+)"', html)
        self.csrf = m.group(1) if m else ""
        return self.csrf

    def post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        headers = {
            "Content-Type": "application/json",
            "X-CSRFToken": self.csrf,
        }
        url = BASE + path
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
        url = BASE + path
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


print(f"{INFO} Cleaning any old test users from database...")
with sqlite3.connect(config.DATABASE) as conn:
    conn.execute("DELETE FROM users WHERE username IN ('alice_test', 'bob_test') OR email IN ('alice@test.local', 'bob@test.local')")
    conn.commit()

alice = TestUserSession("alice_test", "alice@test.local", "AlicePass123!")
bob   = TestUserSession("bob_test",   "bob@test.local",   "BobPass123!")

# ── 1. Register Alice & Bob ──────────────────────────────────────────────────
print(f"\n{INFO} [1] Registering Alice and Bob...")
alice.fetch_csrf()
s, d = alice.post_json("/register", {
    "username": alice.username,
    "email": alice.email,
    "password": alice.password,
    "confirmPassword": alice.password,
})
check("Alice registered successfully", s == 201)

bob.fetch_csrf()
s, d = bob.post_json("/register", {
    "username": bob.username,
    "email": bob.email,
    "password": bob.password,
    "confirmPassword": bob.password,
})
check("Bob registered successfully", s == 201)

# ── 2. Login Alice & Bob ─────────────────────────────────────────────────────
print(f"\n{INFO} [2] Logging in Alice and Bob...")
alice.fetch_csrf()
s, d = alice.post_json("/login", {"email": alice.email, "password": alice.password})
check("Alice logged in successfully", s == 200 and d.get("ok") is True)

bob.fetch_csrf()
s, d = bob.post_json("/login", {"email": bob.email, "password": bob.password})
check("Bob logged in successfully", s == 200 and d.get("ok") is True)

# ── 3. Publish Public Keys to Server ─────────────────────────────────────────
print(f"\n{INFO} [3] Publishing X25519 Public Keys to Server Directory...")
s, d = alice.post_json("/api/keys/public-key", {
    "public_key": alice.crypto.public_key_b64,
})
check("Alice published public key", s == 200 and d.get("ok") is True)

s, d = bob.post_json("/api/keys/public-key", {
    "public_key": bob.crypto.public_key_b64,
})
check("Bob published public key", s == 200 and d.get("ok") is True)

# ── 4. Verify Server Key Retrieval ──────────────────────────────────────────
print(f"\n{INFO} [4] Fetching peer public keys through /api/keys/<username>...")
s, d = alice.get_json(f"/api/keys/{bob.username}")
check("Alice fetched Bob's public key", s == 200 and d.get("public_key") == bob.crypto.public_key_b64)

s, d = bob.get_json(f"/api/keys/{alice.username}")
check("Bob fetched Alice's public key", s == 200 and d.get("public_key") == alice.crypto.public_key_b64)

# ── 5. Directory User Listing ────────────────────────────────────────────────
print(f"\n{INFO} [5] Checking /api/users directory...")
s, d = alice.get_json("/api/users")
check("Alice user list returns other users", s == 200 and any(u["username"] == bob.username for u in d.get("users", [])))
bob_entry = next(u for u in d["users"] if u["username"] == bob.username)
check("Bob entry indicates has_public_key=True", bob_entry.get("has_public_key") is True)

# ── 6. End-to-End Encryption Flow ───────────────────────────────────────────
print(f"\n{INFO} [6] Performing authentic E2EE Key Exchange and Messaging...")
# Alice establishes session with Bob using retrieved public key
bob_pub_key = bob_entry["public_key"]
alice.crypto.establish_session(peer_username=bob.username, peer_public_key_b64=bob_pub_key)

# Bob establishes session with Alice using retrieved public key
s_alice, d_alice = bob.get_json(f"/api/keys/{alice.username}")
bob.crypto.establish_session(peer_username=alice.username, peer_public_key_b64=d_alice["public_key"])

# Alice encrypts message for Bob
secret_text = "Meet me at the rendezvous point at 21:00 UTC. The passcode is Orion."
encrypted_for_bob = alice.crypto.encrypt_for(peer_username=bob.username, plaintext=secret_text)

# Bob decrypts message from Alice
decrypted_by_bob = bob.crypto.decrypt_from(peer_username=alice.username, encrypted_package=encrypted_for_bob)
check("Bob decrypted exact secret message sent by Alice", decrypted_by_bob == secret_text)

# Bob encrypts reply for Alice
reply_text = "Confirmed Orion. See you there."
encrypted_reply = bob.crypto.encrypt_for(peer_username=alice.username, plaintext=reply_text)

# Alice decrypts reply
decrypted_by_alice = alice.crypto.decrypt_from(peer_username=bob.username, encrypted_package=encrypted_reply)
check("Alice decrypted exact reply from Bob", decrypted_by_alice == reply_text)

# ── 7. Verify Database Security Invariants ──────────────────────────────────
print(f"\n{INFO} [7] Verifying Server Database Invariants (zero plaintext / zero private keys)...")
with sqlite3.connect(config.DATABASE) as conn:
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT username, password_hash, public_key FROM users WHERE username IN ('alice_test', 'bob_test')").fetchall()

check("Both users found in database", len(rows) == 2)
for r in rows:
    check(f"{r['username']} has public_key stored (32 bytes base64)", len(r["public_key"]) == 44)
    check(f"{r['username']} password is secure pbkdf2 hash", r["password_hash"].startswith("pbkdf2:sha256:"))

# Verify secret texts NEVER appear anywhere in database
with open(config.DATABASE, "rb") as f:
    db_raw = f.read()

check("Plaintext 'rendezvous point' is NOT in database", b"rendezvous point" not in db_raw)
check("Plaintext 'passcode is Orion' is NOT in database", b"passcode is Orion" not in db_raw)
check("Alice private key bytes NOT in database", base64.b64decode(alice.crypto.private_key_b64) not in db_raw)
check("Bob private key bytes NOT in database", base64.b64decode(bob.crypto.private_key_b64) not in db_raw)

# Clean up test accounts
with sqlite3.connect(config.DATABASE) as conn:
    conn.execute("DELETE FROM users WHERE username IN ('alice_test', 'bob_test')")
    conn.commit()

# ── Summary ─────────────────────────────────────────────────────────────────
print()
if failures == 0:
    print("\033[92m======================================================")
    print("  ALL API KEY EXCHANGE TESTS PASSED - 100% SUCCESS!")
    print("======================================================\033[0m")
    sys.exit(0)
else:
    print(f"\033[91m======================================================")
    print(f"  {failures} TEST(S) FAILED")
    print("======================================================\033[0m")
    sys.exit(1)
