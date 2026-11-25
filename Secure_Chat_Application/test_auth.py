"""
test_auth.py — Integration smoke test for Module 1 (Registration / Login / Logout)
Run with: python test_auth.py
Flask server must be running on http://127.0.0.1:5000
"""

import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import re
import sys
import os
import time
import threading
import logging

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

BASE   = "http://127.0.0.1:5000"
jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [("User-Agent", "SecureChat-TestClient/1.0")]

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

failures = 0


def check(label, condition, detail=""):
    global failures
    if condition:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label}  {detail}")
        failures += 1


import sqlite3
from config import config

# Clean any prior test users so test is reproducible
try:
    with sqlite3.connect(config.DATABASE) as conn:
        conn.execute("DELETE FROM users WHERE email IN ('test@example.com', 'newguy@example.com', 'other@example.com') OR username IN ('testuser', 'anotheruser', 'newguy')")
        conn.commit()
except Exception as e:
    pass


def post_json(path, payload, extra_headers=None):
    headers = {
        "Content-Type": "application/json",
        "X-CSRFToken": csrf_token,
    }
    if extra_headers:
        headers.update(extra_headers)
    url  = BASE + path
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"ok": False, "raw": raw}



# ── Step 1: Fetch CSRF token from register page ──────────────────────────────
print(f"\n{INFO} [1] Fetching CSRF token from GET /register …")
with opener.open(BASE + "/register") as r:
    html_text = r.read().decode()

match = re.search(r'id="csrf_token" name="csrf_token" value="([^"]+)"', html_text)
csrf_token = match.group(1) if match else ""
check("CSRF token present in register page", bool(csrf_token), repr(csrf_token[:20]))

# ── Step 2: Register a new user ───────────────────────────────────────────────
print(f"\n{INFO} [2] Registering new user (test@example.com) …")
status, data = post_json("/register", {
    "username":        "testuser",
    "email":           "test@example.com",
    "password":        "StrongPass1!",
    "confirmPassword": "StrongPass1!",
})
check("Registration returns HTTP 201",   status == 201, f"got {status}")
check("Response ok=true",                data.get("ok") is True, str(data))
print(f"       server message: {data.get('message', '')}")

# ── Step 3: Duplicate email ───────────────────────────────────────────────────
print(f"\n{INFO} [3] Duplicate email registration check …")
status, data = post_json("/register", {
    "username":        "anotheruser",
    "email":           "test@example.com",
    "password":        "StrongPass1!",
    "confirmPassword": "StrongPass1!",
})
check("Duplicate email returns HTTP 400", status == 400, f"got {status}")
check("Response ok=false",               data.get("ok") is False, str(data))
print(f"       server error: {data.get('error', '')}")

# ── Step 4: Duplicate username ────────────────────────────────────────────────
print(f"\n{INFO} [4] Duplicate username check …")
status, data = post_json("/register", {
    "username":        "testuser",
    "email":           "other@example.com",
    "password":        "StrongPass1!",
    "confirmPassword": "StrongPass1!",
})
check("Duplicate username returns HTTP 400", status == 400, f"got {status}")
print(f"       server error: {data.get('error', '')}")

# ── Step 5: Login with wrong password ────────────────────────────────────────
print(f"\n{INFO} [5] Login with incorrect password …")
status, data = post_json("/login", {
    "email":    "test@example.com",
    "password": "WrongPassword999",
})
check("Wrong password returns HTTP 400 (ok=false)", status == 400, f"got {status}")
check("Response ok=false",                          data.get("ok") is False, str(data))
print(f"       server error: {data.get('error', '')}")

# ── Step 6: Login with correct credentials ────────────────────────────────────
print(f"\n{INFO} [6] Login with correct credentials …")
status, data = post_json("/login", {
    "email":    "test@example.com",
    "password": "StrongPass1!",
})
check("Correct login returns HTTP 200",   status == 200, f"got {status}")
check("Response ok=true",                 data.get("ok") is True, str(data))
check("Redirect URL provided",            "redirect" in data, str(data))
print(f"       welcome: {data.get('message', '')} | redirect: {data.get('redirect', '')}")

# ── Step 7: Access /chat (protected, session active) ─────────────────────────
print(f"\n{INFO} [7] Accessing /chat with active session …")
with opener.open(BASE + "/chat") as r:
    final_url = r.url
    chat_status = r.status
check("/chat returns HTTP 200",          chat_status == 200,     f"got {chat_status}")
check("Final URL is /chat",              "/chat" in final_url,  f"got {final_url}")

# ── Step 8: Logout ────────────────────────────────────────────────────────────
print(f"\n{INFO} [8] Logging out …")
with opener.open(BASE + "/logout") as r:
    logout_url = r.url
check("Logout redirects to /login", "/login" in logout_url, f"got {logout_url}")

# ── Step 9: /chat after logout must redirect to /login ───────────────────────
print(f"\n{INFO} [9] Accessing /chat after logout (should redirect to /login) …")
with opener.open(BASE + "/chat") as r:
    after_logout_url = r.url
check("Unauthenticated /chat redirects to /login", "/login" in after_logout_url, f"got {after_logout_url}")

# ── Step 10: Input validation — short password ────────────────────────────────
print(f"\n{INFO} [10] Validation: password too short …")
status, data = post_json("/register", {
    "username":        "newguy",
    "email":           "newguy@example.com",
    "password":        "abc",
    "confirmPassword": "abc",
})
check("Short password returns 400", status in (400, 422), f"got {status}")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
if failures == 0:
    print("\033[92m==========================================")
    print("  ALL TESTS PASSED - Module 1 is working!")
    print("==========================================\033[0m")
    sys.exit(0)
else:
    print(f"\033[91m==========================================")
    print(f"  {failures} TEST(S) FAILED")
    print(f"==========================================\033[0m")
    sys.exit(1)
