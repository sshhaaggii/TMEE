"""
app.py — SecureChat Flask Application
Module 1: User Registration, Login, and Logout with full security.

Routes:
    GET  /              → redirect to /login
    GET  /register      → registration page
    POST /register      → process registration
    GET  /login         → login page
    POST /login         → process login
    GET  /chat          → chat page (login required)
    GET  /logout        → logout and clear session

Security features:
    - Werkzeug pbkdf2:sha256 password hashing
    - Flask-WTF CSRF protection on all POST forms
    - Parameterized SQLite queries (no raw string interpolation)
    - Secure, HttpOnly, SameSite=Lax session cookies
    - Input validation and sanitisation before DB writes
    - Login-required decorator for protected routes
"""

import os
import json
import time
import sqlite3
from functools import wraps
from datetime import datetime, timezone
import threading

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, g
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect

from config import config
from encryption.crypto import (
    hash_password, verify_password,
    sanitise_username, sanitise_email,
    is_valid_username, is_valid_email, is_valid_password,
    import_public_key, CryptoError,
)

# ─── App Setup ──────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key          = config.SECRET_KEY
app.config["WTF_CSRF_TIME_LIMIT"] = config.WTF_CSRF_TIME_LIMIT
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_SECURE"]   = config.SESSION_COOKIE_SECURE
app.config["PERMANENT_SESSION_LIFETIME"] = config.PERMANENT_SESSION_LIFETIME

csrf = CSRFProtect(app)

# Real-time WebSocket support (Module 3)
socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins="*",
    max_http_buffer_size=20 * 1024 * 1024,
)

# In-memory presence tracking: username -> set of active socket connection IDs
online_users: dict[str, set[str]] = {}

# Rate-limiting for authentication: IP -> (failure_count, first_failure_timestamp)
_login_failures: dict[str, tuple[int, float]] = {}
_MAX_LOGIN_FAILURES = 10
_LOCKOUT_SECONDS = 60.0

@app.after_request
def apply_security_headers(response):
    """Inject defense-in-depth HTTP security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ─── Database Helpers ───────────────────────────────────────────────────────
from database.db import (
    get_db,
    close_db,
    init_db,
    get_active_engine,
    record_user_session,
    update_user_profile_status,
    record_message_status,
    update_message_read_status,
    add_or_toggle_reaction,
    get_message_reactions,
    get_reactions_for_messages,
    record_call_start,
    record_call_end,
    get_call_history_for_user,
    get_call_history_between_users,
    create_scheduled_message,
    get_scheduled_messages_for_user,
    get_scheduled_messages_between,
    get_scheduled_message_by_id,
    update_scheduled_message,
    cancel_scheduled_message,
    get_due_scheduled_messages,
    mark_scheduled_message_sent,
    create_group,
    get_group_by_id,
    get_user_groups,
    get_group_members,
    is_group_member,
    get_group_member_role,
    add_group_member,
    remove_group_member,
    update_group_info,
    update_group_member_role,
    update_group_epoch,
    store_group_epoch_keys,
    get_group_epoch_key_for_user,
    create_group_message,
    get_group_messages,
    add_or_toggle_group_reaction,
    get_group_message_reactions,
    delete_group_message,
    get_conversation_settings,
    set_conversation_settings,
    get_group_disappearing_timer,
    set_group_disappearing_timer,
    mark_message_viewed,
    purge_expired_messages,
)


@app.teardown_appcontext
def teardown_db(exc=None) -> None:
    """Close or release DB connection at the end of every request."""
    close_db(exc)


# Initialize database tables on app startup
with app.app_context():
    init_db()


# ─── Decorators ─────────────────────────────────────────────────────────────

def login_required(f):
    """
    Protect routes from unauthenticated access.
    Returns 401 JSON for /api/ routes; redirects to login page for HTML pages.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return _json_error("Authentication required. Please sign in.", 401)
            flash("Please sign in to access the chat.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─── Helpers ────────────────────────────────────────────────────────────────

def _json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def _json_ok(data: dict = None, status: int = 200):
    payload = {"ok": True}
    if data:
        payload.update(data)
    return jsonify(payload), status


def get_user_by_email(email: str):
    """Fetch a user row by email (parameterized). Returns None if not found."""
    return get_db().execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()


def get_user_by_id(user_id: int):
    """Fetch a user row by primary key. Returns None if not found."""
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Root: redirect authenticated users to chat, others to login."""
    if "user_id" in session:
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


# ── Registration ─────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET"])
def register():
    """Show the registration page. Redirect if already logged in."""
    if "user_id" in session:
        return redirect(url_for("chat"))
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register_post():
    """
    Process registration form.
    Accepts JSON (AJAX from auth.js) or form-encoded data.
    Returns JSON so the frontend can display the response via toast.
    """
    # ── Parse input ─────────────────────────────────────────────
    if request.is_json:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
    else:
        data = request.form

    if not isinstance(data, dict):
        return _json_error("Invalid payload format", 400)

    username         = sanitise_username(data.get("username", ""))
    email            = sanitise_email(data.get("email", ""))
    password         = str(data.get("password") or "")
    confirm_password = str(data.get("confirmPassword") or "")

    # ── Server-side validation ───────────────────────────────────
    errors = {}

    if not is_valid_username(username):
        errors["username"] = "Username must be 3–20 alphanumeric characters or underscores."

    if not is_valid_email(email):
        errors["email"] = "Please provide a valid email address."

    if not is_valid_password(password):
        errors["password"] = "Password must be at least 8 characters long."

    if password != confirm_password:
        errors["confirmPassword"] = "Passwords do not match."

    if errors:
        return _json_error("Validation failed", 422)

    db = get_db()

    # ── Uniqueness checks (parameterized) ────────────────────────
    existing_email = db.execute(
        "SELECT id FROM users WHERE email = ?", (email,)
    ).fetchone()
    if existing_email:
        return _json_error("An account with that email address already exists.")

    existing_username = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing_username:
        return _json_error("That username is already taken. Please choose another.")

    # ── Hash password & insert ───────────────────────────────────
    pw_hash = hash_password(password)
    now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    cursor = db.execute(
        """
        INSERT INTO users (username, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (username, email, pw_hash, now),
    )
    db.commit()
    new_user_id = cursor.lastrowid
    if new_user_id:
        update_user_profile_status(new_user_id, status="offline")

    return _json_ok({"message": "Account created successfully! Redirecting to login…"}, 201)


# ── Login ─────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login():
    """Show the login page. Redirect if already authenticated."""
    if "user_id" in session:
        return redirect(url_for("chat"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    """
    Authenticate the user.
    Returns JSON so the frontend can display toasts and redirect.
    Timing-safe: always calls verify_password even if user is not found,
    to prevent user-enumeration via response timing.
    """
    if request.is_json:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
    else:
        data = request.form

    if not isinstance(data, dict):
        return _json_error("Invalid payload format", 400)

    # ── Rate limiting check ──────────────────────────────────────
    client_ip = request.remote_addr or "127.0.0.1"
    now_ts = time.time()
    fail_record = _login_failures.get(client_ip)
    if fail_record:
        count, first_ts = fail_record
        if now_ts - first_ts < _LOCKOUT_SECONDS:
            if count >= _MAX_LOGIN_FAILURES:
                return _json_error("Too many failed login attempts. Please try again later.", 429)
        else:
            _login_failures.pop(client_ip, None)

    email    = sanitise_email(data.get("email", ""))
    password = str(data.get("password") or "")

    # ── Basic format checks ──────────────────────────────────────
    if not email or not password:
        return _json_error("Email and password are required.")

    if not is_valid_email(email):
        return _json_error("Invalid email or password.")   # deliberate generic message

    # ── Lookup user (parameterized) ──────────────────────────────
    user = get_user_by_email(email)

    # Always run verify even on miss (constant-time behaviour)
    dummy_hash = "pbkdf2:sha256:600000$x$" + "a" * 64
    stored_hash = user["password_hash"] if user else dummy_hash

    if not verify_password(password, stored_hash) or user is None:
        rec = _login_failures.get(client_ip)
        if rec and (now_ts - rec[1] < _LOCKOUT_SECONDS):
            _login_failures[client_ip] = (rec[0] + 1, rec[1])
        else:
            _login_failures[client_ip] = (1, now_ts)
        return _json_error("Invalid email or password.")

    # Successful login: reset failed attempts
    _login_failures.pop(client_ip, None)

    # ── Create session ───────────────────────────────────────────
    session.clear()                          # invalidate any prior session
    session.permanent = True
    session["user_id"]   = user["id"]
    session["username"]  = user["username"]
    session["email"]     = user["email"]

    # ── Update last_login, user_sessions & presence ──────────────
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute(
        "UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"])
    )
    db.commit()
    record_user_session(user["id"], session.get("_id", ""))
    update_user_profile_status(user["id"], status="online")

    return _json_ok({
        "message":  f"Welcome back, {user['username']}!",
        "redirect": url_for("chat"),
    })


# ── Chat (protected) ─────────────────────────────────────────────────────────

@app.route("/chat")
@login_required
def chat():
    """Main chat page — only accessible to authenticated users."""
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template("chat.html", current_user=user)


# ── Logout ────────────────────────────────────────────────────────────────────

@app.route("/logout")
@login_required
def logout():
    """Clear the session and redirect to the login page."""
    user_id = session.get("user_id")
    if user_id:
        update_user_profile_status(user_id, status="offline")
    session.clear()
    flash("You have been securely signed out.", "success")
    return redirect(url_for("login"))


# ── Key Directory & User Discovery API (Module 2) ───────────────────────────

@app.route("/api/keys/public-key", methods=["POST"])
@csrf.exempt
@login_required
def publish_public_key():
    """
    Publish or update the authenticated user's X25519 public key.
    Public keys are stored in the database for other users to fetch.
    Private keys are NEVER transmitted or stored on the server.
    """
    data = request.get_json(silent=True) or request.form
    public_key_b64 = (data.get("public_key") or "").strip()

    if not public_key_b64:
        return _json_error("public_key is required")

    # Validate that it is a genuine 32-byte X25519 public key
    try:
        import_public_key(public_key_b64)
    except CryptoError as e:
        return _json_error(f"Invalid X25519 public key: {e}", 400)

    db = get_db()
    db.execute(
        "UPDATE users SET public_key = ? WHERE id = ?",
        (public_key_b64, session["user_id"]),
    )
    # Record in public_keys table
    db.execute(
        "INSERT INTO public_keys (user_id, public_key, algorithm, created_at) VALUES (?, ?, 'X25519', datetime('now'))",
        (session["user_id"], public_key_b64),
    )
    db.commit()

    return _json_ok({
        "message": "X25519 public key published successfully.",
        "username": session["username"],
        "public_key": public_key_b64,
    })


@app.route("/api/keys/<username>", methods=["GET"])
@login_required
def get_user_public_key(username: str):
    """
    Retrieve the active public key of any registered user.
    Used by client to establish an X25519 Diffie-Hellman shared secret.
    """
    user = get_db().execute(
        "SELECT id, username, public_key FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),),
    ).fetchone()

    if not user:
        return _json_error(f"User '{username}' not found", 404)

    if not user["public_key"]:
        return _json_error(f"User '{username}' has not published an encryption key yet", 404)

    return _json_ok({
        "username": user["username"],
        "public_key": user["public_key"],
    })


@app.route("/api/keys/history/<username>", methods=["GET"])
@login_required
def get_user_public_key_history(username: str):
    """
    Retrieve historical public keys published by a user.
    """
    user = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),),
    ).fetchone()

    if not user:
        return _json_error(f"User '{username}' not found", 404)

    rows = get_db().execute(
        "SELECT id, public_key, algorithm, created_at FROM public_keys WHERE user_id = ? ORDER BY id DESC",
        (user["id"],),
    ).fetchall()

    keys = [
        {
            "id": r["id"],
            "public_key": r["public_key"],
            "algorithm": r["algorithm"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]

    return _json_ok({
        "username": user["username"],
        "keys": keys,
    })


@app.route("/api/users", methods=["GET"])
@login_required
def list_chat_users():
    """
    List all other registered users for the chat sidebar.
    Returns username, id, public_key status, bio, profile image, and last_login.
    """
    current_id = session.get("user_id")
    rows = get_db().execute(
        """
        SELECT u.id, u.username, u.email, u.public_key, u.last_login, u.created_at,
               p.profile_picture_url, p.bio, p.online_status
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE u.id != ?
        ORDER BY u.username ASC
        """,
        (current_id,),
    ).fetchall()

    users = [
        {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "has_public_key": bool(row["public_key"]),
            "public_key": row["public_key"],
            "is_online": row["username"] in online_users and len(online_users[row["username"]]) > 0,
            "last_login": row["last_login"],
            "bio": row.get("bio", ""),
            "profile_picture_url": row.get("profile_picture_url", ""),
        }
        for row in rows
    ]

    return _json_ok({"users": users})


@app.route("/api/me", methods=["GET"])
@login_required
def get_my_profile():
    """Return the profile and public key status of the authenticated user."""
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, public_key, created_at, last_login FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    if not user:
        return _json_error("User not found", 404)

    profile = db.execute(
        "SELECT profile_picture_url, bio, online_status FROM user_profiles WHERE user_id = ?",
        (session["user_id"],),
    ).fetchone()

    return _json_ok({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "public_key": user["public_key"],
        "bio": profile.get("bio", "") if profile else "",
        "profile_picture_url": profile.get("profile_picture_url", "") if profile else "",
        "db_engine": get_active_engine(),
    })


# ── Session status (AJAX helper for JS) ──────────────────────────────────────

@app.route("/api/session")
def api_session():
    """Return current session state as JSON. Used by chat.js to verify auth."""
    if "user_id" in session:
        return _json_ok({
            "authenticated": True,
            "username": session.get("username"),
            "csrf_token": generate_csrf(),
        })
    return _json_ok({
        "authenticated": False,
        "csrf_token": generate_csrf(),
    })


# ─── CSRF Error Handler ─────────────────────────────────────────────────────

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return _json_error("CSRF token missing or invalid. Please refresh the page.", 400)


# ─── Generic Error Handlers ─────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for("login"))


@app.errorhandler(500)
def server_error(e):
    app.logger.error("Internal server error: %s", e)
    return _json_error("An internal server error occurred.", 500)


# ── Message History & Privacy Management API (Module 4) ─────────────────────

@app.route("/api/messages/<username>", methods=["GET"])
@login_required
def get_conversation_history(username: str):
    """
    Retrieve encrypted message history between current user and specified peer.
    The server returns ONLY the stored encrypted packages, ciphertext, nonce, and tag.
    Chronological ordering: created_at ASC, id ASC.
    Decryption occurs strictly on the client device.
    """
    current_id = session["user_id"]
    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()

    if not peer:
        return _json_error("Peer not found", 404)

    peer_id = peer["id"]
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = get_db().execute(
        """
        SELECT m.id, m.sender_id, m.receiver_id, m.ciphertext, m.nonce,
               m.authentication_tag, m.encrypted_package, m.created_at, m.delivered,
               m.is_edited, m.edited_at, m.reply_to_id, m.is_pinned, m.message_type, m.media_meta,
               m.expires_at, m.expiration_seconds, m.is_view_once, m.is_vanish, m.viewed_at,
               ms.read_at,
               u_sender.username as sender_username,
               u_recipient.username as recipient_username
        FROM messages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        JOIN users u_recipient ON m.receiver_id = u_recipient.id
        LEFT JOIN message_status ms ON m.id = ms.message_id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?)
           OR (m.sender_id = ? AND m.receiver_id = ?))
          AND m.is_deleted = 0
          AND (m.expires_at IS NULL OR m.expires_at > ?)
        ORDER BY m.created_at ASC, m.id ASC
        LIMIT 300
        """,
        (current_id, peer_id, peer_id, current_id, now_iso),
    ).fetchall()

    message_ids = [r["id"] for r in rows]
    reactions_map = get_reactions_for_messages(message_ids)

    messages = []
    for r in rows:
        try:
            pkg = json.loads(r["encrypted_package"])
        except Exception:
            pkg = r["encrypted_package"]

        # Parse media_meta if present
        media_meta = {}
        raw_meta = r.get("media_meta")
        if raw_meta:
            try:
                media_meta = json.loads(raw_meta) if isinstance(raw_meta, str) else raw_meta
            except Exception:
                media_meta = {}

        # Mark read if received by current user
        is_read = bool(r.get("read_at"))
        if not is_read and r["receiver_id"] == current_id:
            update_message_read_status(r["id"])
            is_read = True

        messages.append({
            "id": r["id"],
            "sender_id": r["sender_id"],
            "receiver_id": r["receiver_id"],
            "recipient_id": r["receiver_id"],
            "sender_username": r["sender_username"],
            "recipient_username": r["recipient_username"],
            "ciphertext": r["ciphertext"],
            "nonce": r["nonce"],
            "tag": r.get("tag") or r.get("authentication_tag"),
            "authentication_tag": r.get("authentication_tag") or r.get("tag"),
            "encrypted_package": pkg,
            "timestamp": r["created_at"],
            "is_self": r["sender_id"] == current_id,
            "delivered": bool(r["delivered"]),
            "read": is_read,
            "read_at": r.get("read_at") or "",
            "is_edited": bool(r.get("is_edited")),
            "edited_at": r.get("edited_at") or "",
            "reply_to_id": r.get("reply_to_id"),
            "is_pinned": bool(r.get("is_pinned")),
            "message_type": r.get("message_type") or "text",
            "media_meta": media_meta,
            "expires_at": r.get("expires_at"),
            "expiration_seconds": int(r.get("expiration_seconds") or 0),
            "is_view_once": bool(r.get("is_view_once")),
            "is_vanish": bool(r.get("is_vanish")),
            "viewed_at": r.get("viewed_at") or "",
            "reactions": reactions_map.get(r["id"], [])
        })

    conv_settings = get_conversation_settings(current_id, peer_id)
    return _json_ok({"messages": messages, "peer": peer["username"], "settings": conv_settings})


@app.route("/api/messages/id/<int:message_id>", methods=["GET"])
@login_required
def get_single_message(message_id: int):
    """
    Retrieve single encrypted message with strict privacy authorization.
    Unauthorized users receive 403 Forbidden. Expired messages return 404.
    """
    current_id = session["user_id"]
    row = get_db().execute(
        """
        SELECT m.id, m.sender_id, m.receiver_id, m.ciphertext, m.nonce,
               m.authentication_tag, m.encrypted_package, m.created_at, m.delivered, m.is_deleted,
               m.expires_at, m.expiration_seconds, m.is_view_once, m.is_vanish, m.viewed_at,
               u_sender.username as sender_username,
               u_recipient.username as recipient_username
        FROM messages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        JOIN users u_recipient ON m.receiver_id = u_recipient.id
        WHERE m.id = ?
        """,
        (message_id,),
    ).fetchone()

    if not row or row["is_deleted"] == 1:
        return _json_error("Message not found", 404)

    now_iso = datetime.now(timezone.utc).isoformat()
    if row.get("expires_at") and row["expires_at"] <= now_iso:
        return _json_error("Message has expired", 404)

    # Strict privacy check: only the sender or recipient can access this message!
    if current_id not in (row["sender_id"], row["receiver_id"]):
        return _json_error("Forbidden: You do not have permission to access this message", 403)

    try:
        pkg = json.loads(row["encrypted_package"])
    except Exception:
        pkg = row["encrypted_package"]

    return _json_ok({
        "id": row["id"],
        "sender_id": row["sender_id"],
        "receiver_id": row["receiver_id"],
        "recipient_id": row["receiver_id"],
        "sender_username": row["sender_username"],
        "recipient_username": row["recipient_username"],
        "ciphertext": row["ciphertext"],
        "nonce": row["nonce"],
        "tag": row.get("tag") or row.get("authentication_tag"),
        "authentication_tag": row.get("authentication_tag") or row.get("tag"),
        "encrypted_package": pkg,
        "timestamp": row["created_at"],
        "is_self": row["sender_id"] == current_id,
        "delivered": bool(row["delivered"]),
        "expires_at": row.get("expires_at"),
        "expiration_seconds": int(row.get("expiration_seconds") or 0),
        "is_view_once": bool(row.get("is_view_once")),
        "is_vanish": bool(row.get("is_vanish")),
        "viewed_at": row.get("viewed_at") or "",
    })


@app.route("/api/messages/<int:message_id>", methods=["DELETE"])
@csrf.exempt
@login_required
def delete_message(message_id: int):
    """
    Delete a specific message.
    Strict privacy check: only the sender or recipient can delete.
    Unauthorized users receive 403 Forbidden.
    Completely erases the message ciphertext from database.
    """
    current_id = session["user_id"]
    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()

    if not row:
        return _json_error("Message not found", 404)

    # Strict authorization check
    if current_id not in (row["sender_id"], row["receiver_id"]):
        return _json_error("Forbidden: You do not have permission to delete this message", 403)

    sender_id = row["sender_id"]
    recipient_id = row["receiver_id"]

    # Permanently delete ciphertext from database
    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()

    # Notify both user rooms via WebSockets in real time
    socketio.emit("message_deleted", {"message_id": message_id}, room=f"user_{sender_id}")
    socketio.emit("message_deleted", {"message_id": message_id}, room=f"user_{recipient_id}")

    return _json_ok({
        "message": "Message deleted successfully",
        "message_id": message_id,
    })


@app.route("/api/messages/conversation/<username>", methods=["DELETE"])
@csrf.exempt
@login_required
def clear_conversation(username: str):
    """
    Clear all message history between current user and specified peer.
    Permanently erases all ciphertext packages between the two parties.
    """
    current_id = session["user_id"]
    db = get_db()
    peer = db.execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()

    if not peer:
        return _json_error("Peer not found", 404)

    peer_id = peer["id"]
    cursor = db.execute(
        """
        DELETE FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        """,
        (current_id, peer_id, peer_id, current_id),
    )
    deleted_count = cursor.rowcount
    db.commit()

    # Notify both users via WebSockets
    socketio.emit("conversation_cleared", {"with_user": session["username"]}, room=f"user_{peer_id}")
    socketio.emit("conversation_cleared", {"with_user": peer["username"]}, room=f"user_{current_id}")

    return _json_ok({
        "message": "Conversation history cleared successfully",
        "deleted_count": deleted_count,
        "peer": peer["username"],
    })


# ─── Socket.IO Real-Time Messaging Handlers (Module 3) ──────────────────────

@socketio.on("connect")
def handle_connect():
    """
    Authenticate WebSocket connection using the session cookie.
    Rejects unauthenticated connections.
    """
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        app.logger.warning("Rejecting unauthenticated WebSocket connection: sid=%s", request.sid)
        return False  # Disconnect immediately

    # Track presence in memory and Supabase user_profiles
    if username not in online_users:
        online_users[username] = set()
    online_users[username].add(request.sid)

    update_user_profile_status(user_id, status="online")
    record_user_session(user_id, request.sid)

    # Join private user rooms for targeted message forwarding
    join_room(f"user_{user_id}")
    join_room(f"user_{username}")

    app.logger.info("User '%s' connected (sid=%s). Total online: %d", username, request.sid, len(online_users))

    # Broadcast online status to all connected users
    emit("user_status", {"username": username, "status": "online"}, broadcast=True)

    # Send current list of online users to the newly connected user
    emit("online_users", {"users": list(online_users.keys())})


@socketio.on("disconnect")
def handle_disconnect():
    """
    Handle user disconnection. If all sessions for a username are closed,
    broadcast offline status.
    """
    user_id = session.get("user_id")
    username = session.get("username")
    if username and username in online_users:
        online_users[username].discard(request.sid)
        if len(online_users[username]) == 0:
            del online_users[username]
            if user_id:
                update_user_profile_status(user_id, status="offline")
            emit("user_status", {"username": username, "status": "offline"}, broadcast=True)
            app.logger.info("User '%s' is now offline", username)


@socketio.on("send_message")
def handle_send_message(data):
    """
    Relay an encrypted message from the authenticated sender to the recipient.
    Security:
      - Authenticated sender is enforced via session['username'] / session['user_id'].
      - Client cannot spoof sender identity.
      - Plaintext is NEVER received or accessed by the server.
    """
    sender_id = session.get("user_id")
    sender_username = session.get("username")
    if not sender_id or not sender_username:
        emit("error", {"message": "Authentication required"})
        return

    if not isinstance(data, dict):
        emit("error", {"message": "Invalid message format: expected JSON object"})
        return

    recipient_username = str(data.get("recipient_username") or "").strip()
    encrypted_package  = data.get("encrypted_package")

    if not recipient_username or not encrypted_package:
        emit("error", {"message": "Invalid message: recipient and encrypted_package are required"})
        return

    # Payload size safeguard (20 MB max per encrypted package for images/videos/documents)
    raw_pkg_len = len(json.dumps(encrypted_package)) if isinstance(encrypted_package, dict) else len(str(encrypted_package))
    if raw_pkg_len > 20971520:
        emit("error", {"message": "Message package exceeds maximum allowed size (20MB)"})
        return

    # Validate that recipient exists in database
    db = get_db()
    recipient = db.execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (recipient_username,),
    ).fetchone()

    if not recipient:
        emit("error", {"message": f"Recipient '{recipient_username}' not found"})
        return

    recipient_id = recipient["id"]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    reply_to_id = data.get("reply_to_id")
    if reply_to_id:
        try:
            reply_to_id = int(reply_to_id)
        except Exception:
            reply_to_id = None

    message_type = str(data.get("message_type") or "text").strip().lower()
    media_meta = data.get("media_meta", {})
    media_meta_str = json.dumps(media_meta) if isinstance(media_meta, dict) else str(media_meta or "")

    # Extract ciphertext, nonce, and tag encryption metadata
    ciphertext = ""
    nonce = ""
    tag = ""
    if isinstance(encrypted_package, dict):
        ciphertext = str(encrypted_package.get("ciphertext", "") or "")
        nonce      = str(encrypted_package.get("nonce", "") or "")
        tag        = str(encrypted_package.get("tag", "") or "")
        pkg_str    = json.dumps(encrypted_package)
    else:
        pkg_str = str(encrypted_package)
        try:
            parsed = json.loads(encrypted_package)
            if isinstance(parsed, dict):
                ciphertext = str(parsed.get("ciphertext", "") or "")
                nonce      = str(parsed.get("nonce", "") or "")
                tag        = str(parsed.get("tag", "") or "")
        except Exception:
            ciphertext = str(encrypted_package)

    # Check recipient presence
    is_recipient_online = recipient["username"] in online_users and len(online_users[recipient["username"]]) > 0
    delivered_val = 1 if is_recipient_online else 0

    # Disappearing messages & Vanish mode logic
    conv_settings = get_conversation_settings(sender_id, recipient_id)
    is_view_once = 1 if data.get("is_view_once") else 0
    is_vanish = 1 if (data.get("is_vanish") or conv_settings.get("vanish_mode")) else 0

    expiration_seconds = 0
    if data.get("expiration_seconds") is not None:
        try:
            expiration_seconds = int(data.get("expiration_seconds"))
        except (ValueError, TypeError):
            expiration_seconds = 0
    elif conv_settings.get("disappearing_timer"):
        expiration_seconds = int(conv_settings.get("disappearing_timer"))

    expires_at = None
    if expiration_seconds > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds)).isoformat()

    # Store encrypted ciphertext and encryption metadata in database (zero plaintext)
    cursor = db.execute(
        """
        INSERT INTO messages (
            sender_id, receiver_id, ciphertext, nonce, authentication_tag,
            encrypted_package, created_at, delivered, is_deleted,
            reply_to_id, message_type, media_meta,
            expires_at, expiration_seconds, is_view_once, is_vanish
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender_id, recipient_id, ciphertext, nonce, tag, pkg_str, timestamp, delivered_val,
            reply_to_id, message_type, media_meta_str,
            expires_at, expiration_seconds, is_view_once, is_vanish
        ),
    )
    db.commit()
    message_id = cursor.lastrowid

    # Record delivery receipt in message_status
    record_message_status(message_id, delivered=is_recipient_online, read=False)

    message_payload = {
        "id": message_id,
        "sender_username": sender_username,
        "recipient_username": recipient["username"],
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag,
        "encrypted_package": encrypted_package,
        "timestamp": timestamp,
        "reply_to_id": reply_to_id,
        "message_type": message_type,
        "media_meta": media_meta if isinstance(media_meta, dict) else {},
        "is_edited": False,
        "is_pinned": False,
        "reactions": [],
        "delivered": bool(delivered_val),
        "read": False,
        "expires_at": expires_at,
        "expiration_seconds": expiration_seconds,
        "is_view_once": bool(is_view_once),
        "is_vanish": bool(is_vanish),
        "viewed_at": None,
    }

    # Forward to recipient's private room (WebSockets)
    emit("receive_message", message_payload, room=f"user_{recipient_id}")
    emit("receive_message", message_payload, room=f"user_{recipient['username']}")

    # Acknowledge to sender
    emit("message_sent", {
        "id": message_id,
        "recipient_username": recipient["username"],
        "timestamp": timestamp,
        "status": "delivered" if is_recipient_online else "sent",
        "reply_to_id": reply_to_id,
        "message_type": message_type,
        "media_meta": media_meta if isinstance(media_meta, dict) else {},
        "expires_at": expires_at,
        "expiration_seconds": expiration_seconds,
        "is_view_once": bool(is_view_once),
        "is_vanish": bool(is_vanish),
        "viewed_at": None,
    })


@socketio.on("edit_message")
def handle_edit_message(data):
    """
    Handle real-time message editing.
    Only the original author can edit their encrypted message.
    """
    sender_id = session.get("user_id")
    sender_username = session.get("username")
    if not sender_id or not isinstance(data, dict):
        emit("error", {"message": "Authentication required"})
        return

    message_id = data.get("message_id")
    encrypted_package = data.get("encrypted_package")
    if not message_id or not encrypted_package:
        emit("error", {"message": "message_id and encrypted_package are required"})
        return

    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        emit("error", {"message": "Message not found"})
        return

    if row["sender_id"] != sender_id:
        emit("error", {"message": "Forbidden: You can only edit your own messages"})
        return

    ciphertext = ""
    nonce = ""
    tag = ""
    if isinstance(encrypted_package, dict):
        ciphertext = str(encrypted_package.get("ciphertext", "") or "")
        nonce      = str(encrypted_package.get("nonce", "") or "")
        tag        = str(encrypted_package.get("tag", "") or "")
        pkg_str    = json.dumps(encrypted_package)
    else:
        pkg_str = str(encrypted_package)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        """
        UPDATE messages
        SET ciphertext = ?, nonce = ?, authentication_tag = ?, encrypted_package = ?, is_edited = 1, edited_at = ?
        WHERE id = ?
        """,
        (ciphertext, nonce, tag, pkg_str, now, message_id)
    )
    db.commit()

    recipient_id = row["receiver_id"]
    edit_payload = {
        "message_id": message_id,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag,
        "encrypted_package": encrypted_package,
        "edited_at": now,
        "is_edited": True,
        "sender_username": sender_username
    }

    emit("message_edited", edit_payload, room=f"user_{sender_id}")
    emit("message_edited", edit_payload, room=f"user_{recipient_id}")


@socketio.on("unsend_message")
def handle_unsend_message(data):
    """
    Handle unsend message event.
    Author retracts their message in real time for everyone.
    """
    sender_id = session.get("user_id")
    sender_username = session.get("username")
    if not sender_id or not isinstance(data, dict):
        return

    message_id = data.get("message_id")
    if not message_id:
        return

    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row or row["sender_id"] != sender_id:
        emit("error", {"message": "Cannot unsend this message"})
        return

    recipient_id = row["receiver_id"]
    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()

    payload = {"message_id": message_id, "unsent_by": sender_username}
    emit("message_unsent", payload, room=f"user_{sender_id}")
    emit("message_unsent", payload, room=f"user_{recipient_id}")
    emit("message_deleted", {"message_id": message_id}, room=f"user_{sender_id}")
    emit("message_deleted", {"message_id": message_id}, room=f"user_{recipient_id}")


@socketio.on("react_message")
def handle_react_message(data):
    """
    Handle adding or toggling an emoji reaction on a message.
    """
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not isinstance(data, dict):
        return

    message_id = data.get("message_id")
    emoji = (data.get("emoji") or "").strip()
    if not message_id or not emoji:
        return

    db = get_db()
    msg = db.execute("SELECT sender_id, receiver_id FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not msg or user_id not in (msg["sender_id"], msg["receiver_id"]):
        return

    res = add_or_toggle_reaction(message_id, user_id, emoji)
    payload = {
        "message_id": message_id,
        "reactions": res["reactions"],
        "action": res["action"],
        "emoji": emoji,
        "username": username
    }

    emit("message_reaction_update", payload, room=f"user_{msg['sender_id']}")
    emit("message_reaction_update", payload, room=f"user_{msg['receiver_id']}")


@socketio.on("pin_message")
def handle_pin_message(data):
    """
    Handle pin or unpin action on a message.
    """
    user_id = session.get("user_id")
    if not user_id or not isinstance(data, dict):
        return

    message_id = data.get("message_id")
    is_pinned = bool(data.get("is_pinned", True))
    if not message_id:
        return

    db = get_db()
    msg = db.execute("SELECT sender_id, receiver_id FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not msg or user_id not in (msg["sender_id"], msg["receiver_id"]):
        return

    db.execute("UPDATE messages SET is_pinned = ? WHERE id = ?", (1 if is_pinned else 0, message_id))
    db.commit()

    payload = {"message_id": message_id, "is_pinned": is_pinned}
    emit("message_pin_update", payload, room=f"user_{msg['sender_id']}")
    emit("message_pin_update", payload, room=f"user_{msg['receiver_id']}")


@socketio.on("message_read")
def handle_message_read(data):
    """
    Confirm recipient has read an encrypted message.
    """
    user_id = session.get("user_id")
    if not user_id or not isinstance(data, dict):
        return

    message_id = data.get("message_id")
    sender_username = (data.get("sender_username") or "").strip()
    if not message_id:
        return

    update_message_read_status(message_id)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    row = db.execute("SELECT sender_id FROM messages WHERE id = ?", (message_id,)).fetchone()
    if row:
        emit(
            "message_status_update",
            {"message_id": message_id, "status": "read", "read_at": now},
            room=f"user_{row['sender_id']}"
        )
    if sender_username:
        emit(
            "message_status_update",
            {"message_id": message_id, "status": "read", "read_at": now},
            room=f"user_{sender_username}"
        )


@app.route("/api/messages/pinned/<username>", methods=["GET"])
@login_required
def get_pinned_messages(username: str):
    """Return all pinned encrypted messages in this conversation."""
    current_id = session["user_id"]
    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()
    if not peer:
        return _json_error("Peer not found", 404)

    peer_id = peer["id"]
    rows = get_db().execute(
        """
        SELECT m.id, m.sender_id, m.receiver_id, m.ciphertext, m.nonce,
               m.authentication_tag, m.encrypted_package, m.created_at, m.message_type,
               u_sender.username as sender_username
        FROM messages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
          AND m.is_deleted = 0 AND m.is_pinned = 1
        ORDER BY m.created_at DESC
        LIMIT 20
        """,
        (current_id, peer_id, peer_id, current_id)
    ).fetchall()

    items = []
    for r in rows:
        try:
            pkg = json.loads(r["encrypted_package"])
        except Exception:
            pkg = r["encrypted_package"]
        items.append({
            "id": r["id"],
            "sender_username": r["sender_username"],
            "ciphertext": r["ciphertext"],
            "nonce": r["nonce"],
            "tag": r.get("tag") or r.get("authentication_tag"),
            "encrypted_package": pkg,
            "timestamp": r["created_at"],
            "message_type": r.get("message_type") or "text"
        })
    return _json_ok({"pinned_messages": items})



@socketio.on("delete_message")
def handle_delete_message(data):
    """
    Handle real-time message deletion event via WebSocket.
    Enforces that user is either sender or recipient.
    """
    user_id = session.get("user_id")
    if not user_id:
        emit("error", {"message": "Authentication required"})
        return

    if not isinstance(data, dict):
        emit("error", {"message": "Invalid payload format: expected JSON object"})
        return

    message_id = data.get("message_id")
    if not message_id:
        emit("error", {"message": "message_id is required"})
        return

    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if not row:
        emit("error", {"message": "Message not found"})
        return

    # Strict authorization check
    if user_id not in (row["sender_id"], row["receiver_id"]):
        emit("error", {"message": "Forbidden: You do not have permission to delete this message"})
        return

    sender_id = row["sender_id"]
    recipient_id = row["receiver_id"]

    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()

    emit("message_deleted", {"message_id": message_id}, room=f"user_{sender_id}")
    emit("message_deleted", {"message_id": message_id}, room=f"user_{recipient_id}")


@socketio.on("message_delivered")
def handle_message_delivered(data):
    """
    Confirm delivery of an encrypted message to receiver's device.
    Updates DB and notifies sender.
    """
    if not isinstance(data, dict):
        return
    message_id = data.get("message_id")
    sender_username = (data.get("sender_username") or "").strip()
    if message_id:
        db = get_db()
        db.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,))
        db.commit()
        record_message_status(message_id, delivered=True, read=False)
        if sender_username:
            emit(
                "message_status_update",
                {"message_id": message_id, "status": "delivered"},
                room=f"user_{sender_username}",
            )


@socketio.on("typing")
def handle_typing(data):
    """Relay typing indicator to recipient."""
    if not isinstance(data, dict):
        return
    sender_username = session.get("username")
    recipient_username = (data.get("recipient_username") or "").strip()
    is_typing = bool(data.get("is_typing", True))
    if sender_username and recipient_username:
        emit(
            "user_typing",
            {"sender_username": sender_username, "is_typing": is_typing},
            room=f"user_{recipient_username}",
        )


# ─── Call History REST Endpoints ─────────────────────────────────────────────

@app.route("/api/calls/history", methods=["GET"])
def get_user_call_history():
    """Retrieve recent call history for the currently authenticated user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    calls = get_call_history_for_user(user_id, limit=50)
    return jsonify({"ok": True, "calls": calls})


@app.route("/api/calls/history/<username>", methods=["GET"])
def get_peer_call_history(username):
    """Retrieve call history between current user and a specific contact."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = get_db()
    peer = db.execute("SELECT id FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not peer:
        return jsonify({"ok": False, "error": "User not found"}), 404

    calls = get_call_history_between_users(user_id, peer["id"], limit=30)
    return jsonify({"ok": True, "calls": calls})


# ─── Scheduled Messaging Endpoints & Dispatcher ──────────────────────────────

_dispatcher_started = False
_dispatcher_lock = threading.Lock()


def dispatch_scheduled_message(sched_msg: Dict[str, Any]) -> Optional[int]:
    """
    Deliver a scheduled message when due.
    Preserves end-to-end encryption: inserts encrypted ciphertext/package into messages
    and broadcasts to sender and recipient without decrypting plaintext.
    """
    try:
        db = get_db()
        msg_id = sched_msg["id"]
        sender_id = sched_msg["sender_id"]
        receiver_id = sched_msg["receiver_id"]
        sender_username = sched_msg.get("sender_username", "")
        recipient_username = sched_msg.get("recipient_username", "")

        if not sender_username or not recipient_username:
            u_send = db.execute("SELECT username FROM users WHERE id = ?", (sender_id,)).fetchone()
            u_rec = db.execute("SELECT username FROM users WHERE id = ?", (receiver_id,)).fetchone()
            if u_send:
                sender_username = u_send["username"]
            if u_rec:
                recipient_username = u_rec["username"]

        ciphertext = sched_msg.get("ciphertext", "")
        nonce = sched_msg.get("nonce", "")
        tag = sched_msg.get("tag") or sched_msg.get("authentication_tag", "")
        pkg_str = sched_msg.get("encrypted_package", "")
        message_type = sched_msg.get("message_type") or "text"
        media_meta_raw = sched_msg.get("media_meta") or ""

        now_iso = datetime.now(timezone.utc).isoformat()
        is_recipient_online = recipient_username in online_users and len(online_users[recipient_username]) > 0
        delivered_val = 1 if is_recipient_online else 0

        # Insert into permanent messages table
        cursor = db.execute(
            """
            INSERT INTO messages (
                sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                encrypted_package, created_at, delivered, is_deleted,
                reply_to_id, message_type, media_meta
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
            """,
            (sender_id, receiver_id, ciphertext, nonce, tag, pkg_str, now_iso, delivered_val, message_type, media_meta_raw),
        )
        db.commit()
        new_message_id = cursor.lastrowid

        # Mark scheduled message as sent
        mark_scheduled_message_sent(msg_id, actual_message_id=new_message_id)

        # Record message status
        record_message_status(new_message_id, delivered=is_recipient_online, read=False)

        # Prepare payload for real-time delivery
        try:
            pkg_obj = json.loads(pkg_str) if isinstance(pkg_str, str) and (pkg_str.startswith("{") or pkg_str.startswith("[")) else pkg_str
        except Exception:
            pkg_obj = pkg_str

        try:
            media_meta_obj = json.loads(media_meta_raw) if isinstance(media_meta_raw, str) and media_meta_raw.startswith("{") else {}
        except Exception:
            media_meta_obj = {}

        message_payload = {
            "id": new_message_id,
            "sender_username": sender_username,
            "recipient_username": recipient_username,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "encrypted_package": pkg_obj,
            "timestamp": now_iso,
            "reply_to_id": None,
            "message_type": message_type,
            "media_meta": media_meta_obj,
            "is_edited": False,
            "is_pinned": False,
            "reactions": [],
            "delivered": bool(delivered_val),
            "read": False,
            "is_scheduled_delivery": True,
        }

        # Deliver to recipient
        socketio.emit("receive_message", message_payload, room=f"user_{receiver_id}")
        socketio.emit("receive_message", message_payload, room=f"user_{recipient_username}")

        # Deliver confirmation to sender
        socketio.emit("message_sent", {
            "id": new_message_id,
            "recipient_username": recipient_username,
            "timestamp": now_iso,
            "status": "delivered" if is_recipient_online else "sent",
            "reply_to_id": None,
            "message_type": message_type,
            "media_meta": media_meta_obj,
        }, room=f"user_{sender_id}")
        socketio.emit("message_sent", {
            "id": new_message_id,
            "recipient_username": recipient_username,
            "timestamp": now_iso,
            "status": "delivered" if is_recipient_online else "sent",
            "reply_to_id": None,
            "message_type": message_type,
            "media_meta": media_meta_obj,
        }, room=f"user_{sender_username}")

        # Emit scheduled message delivered notification
        notice = {
            "scheduled_id": msg_id,
            "message_id": new_message_id,
            "sender_username": sender_username,
            "recipient_username": recipient_username,
            "status": "sent",
            "sent_at": now_iso,
        }
        socketio.emit("scheduled_message_delivered", notice, room=f"user_{sender_id}")
        socketio.emit("scheduled_message_delivered", notice, room=f"user_{sender_username}")

        app.logger.info("Delivered scheduled message #%s as message #%s from %s to %s", msg_id, new_message_id, sender_username, recipient_username)
        return new_message_id
    except Exception as e:
        app.logger.error("Error dispatching scheduled message #%s: %s", sched_msg.get("id"), e)
        return None


def _scheduled_message_worker():
    """Background polling worker checking for due scheduled messages."""
    while True:
        try:
            with app.app_context():
                due_list = get_due_scheduled_messages()
                for due_msg in due_list:
                    dispatch_scheduled_message(due_msg)
        except Exception as e:
            app.logger.error("Error in scheduled message worker: %s", e)
        socketio.sleep(2)


def ensure_scheduled_dispatcher_started():
    """Start background scheduled message dispatcher if not already running."""
    global _dispatcher_started
    with _dispatcher_lock:
        if not _dispatcher_started:
            _dispatcher_started = True
            socketio.start_background_task(_scheduled_message_worker)
            app.logger.info("Scheduled message background dispatcher started.")


@app.route("/api/messages/schedule", methods=["POST"])
def api_schedule_message():
    """Create a new encrypted scheduled message."""
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    recipient_username = (data.get("recipient_username") or "").strip()
    scheduled_for = (data.get("scheduled_for") or "").strip()
    ciphertext = str(data.get("ciphertext") or "")
    nonce = str(data.get("nonce") or "")
    tag = str(data.get("tag") or "")
    encrypted_package = data.get("encrypted_package", "")
    message_type = data.get("message_type") or "text"
    media_meta = data.get("media_meta") or ""

    if not recipient_username:
        return jsonify({"ok": False, "error": "Recipient username is required."}), 400
    if not scheduled_for:
        return jsonify({"ok": False, "error": "Scheduled date/time is required."}), 400

    # Validate scheduled_for is valid ISO string and in future
    try:
        target_dt = datetime.fromisoformat(scheduled_for.replace("Z", "+00:00"))
        if target_dt.tzinfo is None:
            target_dt = target_dt.replace(tzinfo=timezone.utc)
        now_utc = datetime.now(timezone.utc)
        if target_dt <= now_utc:
            return jsonify({"ok": False, "error": "Scheduled time must be in the future."}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid ISO datetime: {e}"}), 400

    db = get_db()
    recipient = db.execute("SELECT id, username FROM users WHERE username = ?", (recipient_username,)).fetchone()
    if not recipient:
        return jsonify({"ok": False, "error": "Recipient user not found."}), 404

    if isinstance(encrypted_package, dict):
        pkg_str = json.dumps(encrypted_package)
        if not ciphertext:
            ciphertext = str(encrypted_package.get("ciphertext", "") or "")
        if not nonce:
            nonce = str(encrypted_package.get("nonce", "") or "")
        if not tag:
            tag = str(encrypted_package.get("tag", "") or "")
    else:
        pkg_str = str(encrypted_package)

    media_meta_str = json.dumps(media_meta) if isinstance(media_meta, dict) else str(media_meta)

    sched_id = create_scheduled_message(
        sender_id=user_id,
        receiver_id=recipient["id"],
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        encrypted_package=pkg_str,
        scheduled_for=scheduled_for,
        message_type=message_type,
        media_meta=media_meta_str,
    )

    if not sched_id:
        return jsonify({"ok": False, "error": "Failed to store scheduled message."}), 500

    ensure_scheduled_dispatcher_started()

    return jsonify({
        "ok": True,
        "scheduled_id": sched_id,
        "scheduled_for": scheduled_for,
        "recipient_username": recipient["username"],
        "message_type": message_type,
        "status": "pending",
        "message": "Message scheduled successfully",
    }), 201


@app.route("/api/messages/scheduled", methods=["GET"])
def api_get_scheduled_messages():
    """Retrieve scheduled messages for the authenticated user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    peer = request.args.get("peer", "").strip()
    status = request.args.get("status", "pending").strip()
    if status.lower() == "all":
        status = None

    db = get_db()
    if peer:
        peer_user = db.execute("SELECT id FROM users WHERE username = ?", (peer,)).fetchone()
        if not peer_user:
            return jsonify({"ok": True, "scheduled_messages": []})
        messages = get_scheduled_messages_between(user_id, peer_user["id"], status=status or "pending")
    else:
        messages = get_scheduled_messages_for_user(user_id, status=status)

    parsed_messages = []
    for m in messages:
        item = dict(m)
        try:
            if item.get("encrypted_package") and isinstance(item["encrypted_package"], str) and item["encrypted_package"].startswith("{"):
                item["encrypted_package"] = json.loads(item["encrypted_package"])
        except Exception:
            pass
        try:
            if item.get("media_meta") and isinstance(item["media_meta"], str) and item["media_meta"].startswith("{"):
                item["media_meta"] = json.loads(item["media_meta"])
        except Exception:
            pass
        parsed_messages.append(item)

    return jsonify({"ok": True, "scheduled_messages": parsed_messages})


@app.route("/api/messages/schedule/<int:msg_id>", methods=["PUT"])
def api_update_scheduled_message(msg_id):
    """Update scheduled time or re-encrypted ciphertext for a pending scheduled message."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    scheduled_for = data.get("scheduled_for")
    if scheduled_for:
        try:
            target_dt = datetime.fromisoformat(str(scheduled_for).replace("Z", "+00:00"))
            if target_dt.tzinfo is None:
                target_dt = target_dt.replace(tzinfo=timezone.utc)
            if target_dt <= datetime.now(timezone.utc):
                return jsonify({"ok": False, "error": "Scheduled time must be in the future."}), 400
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid ISO datetime: {e}"}), 400

    ciphertext = data.get("ciphertext")
    nonce = data.get("nonce")
    tag = data.get("tag")
    encrypted_package = data.get("encrypted_package")
    pkg_str = None
    if encrypted_package is not None:
        pkg_str = json.dumps(encrypted_package) if isinstance(encrypted_package, dict) else str(encrypted_package)

    success = update_scheduled_message(
        msg_id=msg_id,
        user_id=user_id,
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        encrypted_package=pkg_str,
        scheduled_for=scheduled_for,
    )
    if not success:
        return jsonify({"ok": False, "error": "Unable to update scheduled message. It may have already been sent or cancelled."}), 400

    return jsonify({"ok": True, "message": "Scheduled message updated successfully."})


@app.route("/api/messages/schedule/<int:msg_id>", methods=["DELETE"])
def api_cancel_scheduled_message(msg_id):
    """Cancel a pending scheduled message."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    success = cancel_scheduled_message(msg_id=msg_id, user_id=user_id)
    if not success:
        return jsonify({"ok": False, "error": "Unable to cancel scheduled message. It may have already been sent or cancelled."}), 400

    return jsonify({"ok": True, "message": "Scheduled message cancelled."})


@app.route("/api/messages/schedule/<int:msg_id>/send-now", methods=["POST"])
def api_send_scheduled_now(msg_id):
    """Immediately deliver a scheduled message."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    sched_msg = get_scheduled_message_by_id(msg_id, user_id=user_id)
    if not sched_msg or sched_msg.get("status") != "pending":
        return jsonify({"ok": False, "error": "Scheduled message not found or not pending."}), 404

    new_msg_id = dispatch_scheduled_message(sched_msg)
    if not new_msg_id:
        return jsonify({"ok": False, "error": "Failed to send scheduled message."}), 500

    return jsonify({"ok": True, "message": "Message sent immediately", "message_id": new_msg_id})


# ─── Disappearing Messages & Vanish Mode Background Purger ───────────────────

_disappearing_purger_started = False
_disappearing_lock = threading.Lock()


def _disappearing_message_worker():
    """Background polling worker hard-purging expired messages and encrypted media every 2 seconds."""
    while True:
        try:
            with app.app_context():
                purged = purge_expired_messages()
                for direct in purged.get("expired_direct", []):
                    msg_id = direct["id"]
                    payload = {"message_id": msg_id, "reason": "expired"}
                    socketio.emit("message_expired", payload, room=f"user_{direct['sender_id']}")
                    socketio.emit("message_expired", payload, room=f"user_{direct['receiver_id']}")

                for grp in purged.get("expired_groups", []):
                    msg_id = grp["id"]
                    payload = {"message_id": msg_id, "group_id": grp["group_id"], "reason": "expired"}
                    socketio.emit("message_expired", payload, room=f"group_{grp['group_id']}")
        except Exception as e:
            app.logger.error("Error in disappearing message worker: %s", e)
        socketio.sleep(2)


def ensure_disappearing_purger_started():
    """Start background disappearing message purger if not already running."""
    global _disappearing_purger_started
    with _disappearing_lock:
        if not _disappearing_purger_started:
            _disappearing_purger_started = True
            socketio.start_background_task(_disappearing_message_worker)
            app.logger.info("Disappearing message background purger started.")


# ─── Disappearing Messages & Vanish Mode Endpoints ───────────────────────────

@app.route("/api/conversations/<username>/settings", methods=["GET"])
@login_required
def api_get_conversation_settings(username: str):
    """Get disappearing messages timer and vanish mode state for this conversation."""
    current_id = session["user_id"]
    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()
    if not peer:
        return _json_error("Peer not found", 404)
    settings = get_conversation_settings(current_id, peer["id"])
    return _json_ok({"settings": settings, "peer": peer["username"]})


@app.route("/api/conversations/<username>/disappearing", methods=["POST"])
@csrf.exempt
@login_required
def api_set_disappearing_timer(username: str):
    """
    Set disappearing messages timer for a 1-on-1 conversation.
    Options: 0 (off), 10 (10s), 60 (1m), 3600 (1h), 86400 (24h).
    """
    current_id = session["user_id"]
    current_user = session["username"]
    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()
    if not peer:
        return _json_error("Peer not found", 404)

    data = request.get_json(silent=True) or {}
    try:
        timer = int(data.get("timer", 0))
    except (ValueError, TypeError):
        return _json_error("Invalid timer value", 400)

    if timer < 0:
        return _json_error("Timer must be non-negative", 400)

    res = set_conversation_settings(current_id, peer["id"], disappearing_timer=timer)
    ensure_disappearing_purger_started()

    # Real-time synchronization to both users
    sync_payload_peer = {
        "peer": current_user,
        "disappearing_timer": timer,
        "changed_by": current_user,
    }
    socketio.emit("disappearing_timer_changed", sync_payload_peer, room=f"user_{peer['id']}")
    socketio.emit("disappearing_timer_changed", sync_payload_peer, room=f"user_{peer['username']}")

    sync_payload_self = {
        "peer": peer["username"],
        "disappearing_timer": timer,
        "changed_by": current_user,
    }
    socketio.emit("disappearing_timer_changed", sync_payload_self, room=f"user_{current_id}")
    socketio.emit("disappearing_timer_changed", sync_payload_self, room=f"user_{current_user}")

    return _json_ok({
        "message": f"Disappearing timer set to {timer}s",
        "settings": res,
        "notice": "Disappearing messages cannot prevent screenshots or external recording."
    })


@app.route("/api/conversations/<username>/vanish-mode", methods=["POST"])
@csrf.exempt
@login_required
def api_toggle_vanish_mode(username: str):
    """Toggle Vanish Mode for a temporary, ephemeral 1-on-1 conversation."""
    current_id = session["user_id"]
    current_user = session["username"]
    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (username.strip(),)
    ).fetchone()
    if not peer:
        return _json_error("Peer not found", 404)

    data = request.get_json(silent=True) or {}
    if "enabled" in data:
        vanish_mode = bool(data.get("enabled"))
    else:
        current_settings = get_conversation_settings(current_id, peer["id"])
        vanish_mode = not current_settings.get("vanish_mode", False)

    res = set_conversation_settings(current_id, peer["id"], vanish_mode=vanish_mode)
    ensure_disappearing_purger_started()

    sync_payload_peer = {
        "peer": current_user,
        "vanish_mode": vanish_mode,
        "toggled_by": current_user,
    }
    socketio.emit("vanish_mode_toggled", sync_payload_peer, room=f"user_{peer['id']}")
    socketio.emit("vanish_mode_toggled", sync_payload_peer, room=f"user_{peer['username']}")

    sync_payload_self = {
        "peer": peer["username"],
        "vanish_mode": vanish_mode,
        "toggled_by": current_user,
    }
    socketio.emit("vanish_mode_toggled", sync_payload_self, room=f"user_{current_id}")
    socketio.emit("vanish_mode_toggled", sync_payload_self, room=f"user_{current_user}")

    return _json_ok({
        "message": f"Vanish mode {'enabled' if vanish_mode else 'disabled'}",
        "settings": res,
        "notice": "Vanish mode messages disappear after they are seen. Cannot prevent external recording."
    })


@app.route("/api/groups/<int:group_id>/disappearing", methods=["POST"])
@csrf.exempt
@login_required
def api_set_group_disappearing_timer(group_id: int):
    """Set disappearing messages timer for a group chat."""
    current_id = session["user_id"]
    current_user = session["username"]
    if not is_group_member(group_id, current_id):
        return _json_error("Forbidden: Not a group member", 403)

    data = request.get_json(silent=True) or {}
    try:
        timer = int(data.get("timer", 0))
    except (ValueError, TypeError):
        return _json_error("Invalid timer value", 400)

    if timer < 0:
        return _json_error("Timer must be non-negative", 400)

    success = set_group_disappearing_timer(group_id, timer)
    if not success:
        return _json_error("Failed to update group timer", 500)

    ensure_disappearing_purger_started()
    socketio.emit("group_disappearing_timer_changed", {
        "group_id": group_id,
        "disappearing_timer": timer,
        "changed_by": current_user,
    }, room=f"group_{group_id}")

    return _json_ok({
        "message": f"Group disappearing timer set to {timer}s",
        "disappearing_timer": timer,
        "notice": "Disappearing messages cannot prevent screenshots or external recording."
    })


@app.route("/api/messages/<int:message_id>/view", methods=["POST"])
@csrf.exempt
@login_required
def api_view_message(message_id: int):
    """
    Mark a message as viewed (used for view-once media or vanish mode).
    Starts 10-second expiration countdown for view-once content.
    """
    current_id = session["user_id"]
    data = request.get_json(silent=True) or {}
    is_group = bool(data.get("is_group", False))

    res = mark_message_viewed(message_id, is_group=is_group, viewer_id=current_id)
    if not res.get("ok"):
        return _json_error(res.get("error", "Error marking message viewed"), 400)

    ensure_disappearing_purger_started()
    db = get_db()
    if is_group:
        msg = db.execute("SELECT group_id FROM group_messages WHERE id = ?", (message_id,)).fetchone()
        if msg:
            socketio.emit("message_viewed_update", {
                "message_id": message_id,
                "viewed_at": res["viewed_at"],
                "expires_at": res.get("expires_at"),
                "is_group": True,
                "group_id": msg["group_id"],
            }, room=f"group_{msg['group_id']}")
    else:
        msg = db.execute("SELECT sender_id, receiver_id FROM messages WHERE id = ?", (message_id,)).fetchone()
        if msg:
            payload = {
                "message_id": message_id,
                "viewed_at": res["viewed_at"],
                "expires_at": res.get("expires_at"),
                "is_group": False,
            }
            socketio.emit("message_viewed_update", payload, room=f"user_{msg['sender_id']}")
            socketio.emit("message_viewed_update", payload, room=f"user_{msg['receiver_id']}")

    return _json_ok(res)


# ─── Disappearing Messages & Vanish Mode Sockets ─────────────────────────────

@socketio.on("toggle_vanish_mode")
def handle_socket_toggle_vanish(data):
    """WebSocket handler to toggle vanish mode."""
    if not isinstance(data, dict):
        return
    current_id = session.get("user_id")
    current_user = session.get("username")
    peer_name = (data.get("peer") or "").strip()
    if not current_id or not current_user or not peer_name:
        return

    peer = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
        (peer_name,)
    ).fetchone()
    if not peer:
        return

    vanish_mode = data.get("enabled")
    if vanish_mode is None:
        curr = get_conversation_settings(current_id, peer["id"])
        vanish_mode = not curr.get("vanish_mode", False)
    else:
        vanish_mode = bool(vanish_mode)

    set_conversation_settings(current_id, peer["id"], vanish_mode=vanish_mode)
    ensure_disappearing_purger_started()

    sync_peer = {"peer": current_user, "vanish_mode": vanish_mode, "toggled_by": current_user}
    sync_self = {"peer": peer["username"], "vanish_mode": vanish_mode, "toggled_by": current_user}
    emit("vanish_mode_toggled", sync_peer, room=f"user_{peer['id']}")
    emit("vanish_mode_toggled", sync_peer, room=f"user_{peer['username']}")
    emit("vanish_mode_toggled", sync_self, room=f"user_{current_id}")
    emit("vanish_mode_toggled", sync_self, room=f"user_{current_user}")


@socketio.on("set_disappearing_timer")
def handle_socket_set_timer(data):
    """WebSocket handler to set disappearing message timer."""
    if not isinstance(data, dict):
        return
    current_id = session.get("user_id")
    current_user = session.get("username")
    if not current_id or not current_user:
        return

    timer = int(data.get("timer", 0))
    if data.get("group_id"):
        group_id = int(data["group_id"])
        if is_group_member(group_id, current_id):
            set_group_disappearing_timer(group_id, timer)
            ensure_disappearing_purger_started()
            emit("group_disappearing_timer_changed", {
                "group_id": group_id,
                "disappearing_timer": timer,
                "changed_by": current_user,
            }, room=f"group_{group_id}")
    elif data.get("peer"):
        peer_name = str(data["peer"]).strip()
        peer = get_db().execute("SELECT id, username FROM users WHERE username = ? COLLATE NOCASE", (peer_name,)).fetchone()
        if peer:
            set_conversation_settings(current_id, peer["id"], disappearing_timer=timer)
            ensure_disappearing_purger_started()
            emit("disappearing_timer_changed", {
                "peer": current_user,
                "disappearing_timer": timer,
                "changed_by": current_user,
            }, room=f"user_{peer['id']}")
            emit("disappearing_timer_changed", {
                "peer": peer["username"],
                "disappearing_timer": timer,
                "changed_by": current_user,
            }, room=f"user_{current_id}")


@socketio.on("view_message")
def handle_socket_view_message(data):
    """WebSocket handler for recipient viewing a view-once or vanish message."""
    if not isinstance(data, dict):
        return
    msg_id = data.get("message_id")
    is_group = bool(data.get("is_group", False))
    if not msg_id:
        return
    current_id = session.get("user_id")
    res = mark_message_viewed(int(msg_id), is_group=is_group, viewer_id=current_id)
    if res.get("ok"):
        ensure_disappearing_purger_started()
        db = get_db()
        if is_group:
            msg = db.execute("SELECT group_id FROM group_messages WHERE id = ?", (int(msg_id),)).fetchone()
            if msg:
                emit("message_viewed_update", {
                    "message_id": int(msg_id),
                    "viewed_at": res["viewed_at"],
                    "expires_at": res.get("expires_at"),
                    "is_group": True,
                    "group_id": msg["group_id"],
                }, room=f"group_{msg['group_id']}")
        else:
            msg = db.execute("SELECT sender_id, receiver_id FROM messages WHERE id = ?", (int(msg_id),)).fetchone()
            if msg:
                payload = {
                    "message_id": int(msg_id),
                    "viewed_at": res["viewed_at"],
                    "expires_at": res.get("expires_at"),
                    "is_group": False,
                }
                emit("message_viewed_update", payload, room=f"user_{msg['sender_id']}")
                emit("message_viewed_update", payload, room=f"user_{msg['receiver_id']}")


# ─── Group Conversation Endpoints & SocketIO Handlers ────────────────────────

@app.route("/api/groups", methods=["POST"])
def api_create_group():
    """Create a new group with creator as admin and optional initial members and epoch keys."""
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    avatar_url = (data.get("avatar_url") or "").strip()
    member_usernames = data.get("member_usernames") or data.get("members") or []
    initial_epoch_keys = data.get("initial_epoch_keys") or []

    if not name or len(name) < 2:
        return jsonify({"ok": False, "error": "Group name must be at least 2 characters long."}), 400

    group_id = create_group(name=name, creator_id=user_id, description=description, avatar_url=avatar_url)
    if not group_id:
        return jsonify({"ok": False, "error": "Failed to create group."}), 500

    db = get_db()
    for m_name in member_usernames:
        m_name_clean = sanitise_username(str(m_name).strip())
        if not m_name_clean or m_name_clean.lower() == username.lower():
            continue
        user_row = db.execute("SELECT id FROM users WHERE username = ?", (m_name_clean,)).fetchone()
        if user_row:
            add_group_member(group_id, user_row["id"], role="member")

    # Store wrapped epoch 1 keys if provided
    if initial_epoch_keys:
        prepared_keys = []
        for k_entry in initial_epoch_keys:
            target_uid = k_entry.get("user_id")
            target_uname = k_entry.get("username")
            if not target_uid and target_uname:
                urow = db.execute("SELECT id FROM users WHERE username = ?", (target_uname,)).fetchone()
                if urow:
                    target_uid = urow["id"]
            if target_uid and "encrypted_key" in k_entry:
                prepared_keys.append({
                    "user_id": target_uid,
                    "encrypted_key": k_entry["encrypted_key"],
                })
        if prepared_keys:
            store_group_epoch_keys(group_id, epoch=1, creator_id=user_id, member_keys=prepared_keys)

    group_info = get_group_by_id(group_id)
    members = get_group_members(group_id)

    # Notify members via SocketIO
    for m in members:
        socketio.emit("group_created", {
            "group": group_info,
            "created_by": username,
        }, room=f"user_{m['username']}")
        socketio.emit("group_created", {
            "group": group_info,
            "created_by": username,
        }, room=f"user_{m['user_id']}")

    return jsonify({"ok": True, "group": group_info, "members": members}), 201


@app.route("/api/groups", methods=["GET"])
def api_get_user_groups():
    """Retrieve all groups the authenticated user is a member of."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    groups = get_user_groups(user_id)
    return jsonify({"ok": True, "groups": groups})


@app.route("/api/groups/<int:group_id>", methods=["GET"])
def api_get_group_details(group_id):
    """Retrieve group details and member list for group members."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not is_group_member(group_id, user_id):
        return jsonify({"ok": False, "error": "Access denied: You are not a member of this group."}), 403

    group = get_group_by_id(group_id)
    if not group:
        return jsonify({"ok": False, "error": "Group not found."}), 404
    members = get_group_members(group_id)
    role = get_group_member_role(group_id, user_id)
    return jsonify({"ok": True, "group": group, "members": members, "my_role": role})


@app.route("/api/groups/<int:group_id>", methods=["PUT"])
def api_update_group(group_id):
    """Update group name, description, or avatar (admin only)."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    role = get_group_member_role(group_id, user_id)
    if role != "admin":
        return jsonify({"ok": False, "error": "Only group administrators can modify group information."}), 403

    data = request.get_json(silent=True) or {}
    name = data.get("name")
    description = data.get("description")
    avatar_url = data.get("avatar_url")

    ok = update_group_info(group_id, name=name, description=description, avatar_url=avatar_url)
    if not ok:
        return jsonify({"ok": False, "error": "Failed to update group information."}), 500

    updated_group = get_group_by_id(group_id)
    socketio.emit("group_updated", {"group": updated_group}, room=f"group_{group_id}")
    return jsonify({"ok": True, "group": updated_group})


@app.route("/api/groups/<int:group_id>/members", methods=["POST"])
def api_add_group_members(group_id):
    """Add member(s) to a group and store rotated epoch keys for all current members."""
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    role = get_group_member_role(group_id, user_id)
    if role != "admin":
        return jsonify({"ok": False, "error": "Only group administrators can add members."}), 403

    data = request.get_json(silent=True) or {}
    usernames = data.get("new_members") or data.get("members") or []
    if not usernames and "username" in data:
        usernames = [data["username"]]
    new_epoch_keys = data.get("new_epoch_keys") or data.get("member_keys") or []
    new_epoch = data.get("new_epoch") or data.get("epoch")

    db = get_db()
    added = []
    for uname in usernames:
        uname_clean = sanitise_username(str(uname).strip())
        urow = db.execute("SELECT id, username FROM users WHERE username = ?", (uname_clean,)).fetchone()
        if urow and not is_group_member(group_id, urow["id"]):
            add_group_member(group_id, urow["id"], role="member")
            added.append(urow["username"])

    # Rotate group key to new epoch if provided
    if new_epoch and new_epoch_keys:
        prepared_keys = []
        for k_entry in new_epoch_keys:
            target_uid = k_entry.get("user_id")
            target_uname = k_entry.get("username")
            if not target_uid and target_uname:
                urow = db.execute("SELECT id FROM users WHERE username = ?", (target_uname,)).fetchone()
                if urow:
                    target_uid = urow["id"]
            if target_uid and "encrypted_key" in k_entry:
                prepared_keys.append({"user_id": target_uid, "encrypted_key": k_entry["encrypted_key"]})
        if prepared_keys:
            store_group_epoch_keys(group_id, epoch=int(new_epoch), creator_id=user_id, member_keys=prepared_keys)

    updated_members = get_group_members(group_id)
    group_info = get_group_by_id(group_id)

    socketio.emit("group_member_added", {
        "group_id": group_id,
        "added_members": added,
        "new_epoch": new_epoch or (group_info.get("current_epoch") if group_info else 1),
        "members": updated_members,
        "actor": username,
    }, room=f"group_{group_id}")

    for uname in added:
        socketio.emit("group_joined", {
            "group": group_info,
            "added_by": username,
        }, room=f"user_{uname}")

    return jsonify({"ok": True, "added": added, "members": updated_members, "group": group_info})


@app.route("/api/groups/<int:group_id>/members/<target_username>", methods=["DELETE"])
def api_remove_group_member(group_id, target_username):
    """Remove a member (admin only) or leave the group (self), rotating epoch key for remaining members."""
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = get_db()
    target_user = db.execute("SELECT id, username FROM users WHERE username = ?", (target_username.strip(),)).fetchone()
    if not target_user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    target_id = target_user["id"]
    is_self = (target_id == user_id)
    my_role = get_group_member_role(group_id, user_id)

    if not is_self and my_role != "admin":
        return jsonify({"ok": False, "error": "Only group administrators can remove other members."}), 403

    # Remove the member from the group
    remove_group_member(group_id, target_id)

    # Key rotation for backward secrecy: rotate key for remaining members only
    data = request.get_json(silent=True) or {}
    new_epoch = data.get("new_epoch") or data.get("epoch")
    new_epoch_keys = data.get("new_epoch_keys") or data.get("member_keys") or []
    if new_epoch and new_epoch_keys:
        prepared_keys = []
        for k_entry in new_epoch_keys:
            t_uid = k_entry.get("user_id")
            t_uname = k_entry.get("username")
            if not t_uid and t_uname:
                urow = db.execute("SELECT id FROM users WHERE username = ?", (t_uname,)).fetchone()
                if urow:
                    t_uid = urow["id"]
            if t_uid and t_uid != target_id and "encrypted_key" in k_entry:
                prepared_keys.append({"user_id": t_uid, "encrypted_key": k_entry["encrypted_key"]})
        if prepared_keys:
            store_group_epoch_keys(group_id, epoch=int(new_epoch), creator_id=user_id, member_keys=prepared_keys)

    remaining_members = get_group_members(group_id)
    group_info = get_group_by_id(group_id)

    event_type = "group_member_left" if is_self else "group_member_removed"
    socketio.emit(event_type, {
        "group_id": group_id,
        "removed_username": target_username,
        "new_epoch": new_epoch or (group_info.get("current_epoch") if group_info else 1),
        "members": remaining_members,
        "actor": username,
    }, room=f"group_{group_id}")

    socketio.emit(event_type, {
        "group_id": group_id,
        "removed_username": target_username,
        "actor": username,
    }, room=f"user_{target_username}")

    return jsonify({"ok": True, "message": f"Member {target_username} removed.", "members": remaining_members})


@app.route("/api/groups/<int:group_id>/members/<target_username>/role", methods=["PUT"])
def api_update_member_role(group_id, target_username):
    """Promote or demote a member to/from admin (admin only)."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if get_group_member_role(group_id, user_id) != "admin":
        return jsonify({"ok": False, "error": "Only group administrators can change member roles."}), 403

    data = request.get_json(silent=True) or {}
    new_role = (data.get("role") or "").lower()
    if new_role not in ("admin", "member"):
        return jsonify({"ok": False, "error": "Role must be 'admin' or 'member'."}), 400

    db = get_db()
    t_user = db.execute("SELECT id FROM users WHERE username = ?", (target_username.strip(),)).fetchone()
    if not t_user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    ok = update_group_member_role(group_id, t_user["id"], new_role)
    if not ok:
        return jsonify({"ok": False, "error": "Failed to update member role."}), 500

    members = get_group_members(group_id)
    socketio.emit("group_member_role_changed", {
        "group_id": group_id,
        "username": target_username,
        "role": new_role,
        "members": members,
    }, room=f"group_{group_id}")

    return jsonify({"ok": True, "members": members})


@app.route("/api/groups/<int:group_id>/keys/<int:epoch>", methods=["GET"])
def api_get_group_key(group_id, epoch):
    """Retrieve the wrapped group encryption key for the authenticated user for the requested epoch."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not is_group_member(group_id, user_id):
        return jsonify({"ok": False, "error": "Access denied: Not a member of this group."}), 403

    key_entry = get_group_epoch_key_for_user(group_id, epoch, user_id)
    if not key_entry:
        return jsonify({"ok": False, "error": "No key package found for this epoch."}), 404

    enc_key = key_entry["encrypted_key"]
    try:
        if isinstance(enc_key, str) and (enc_key.startswith("{") or enc_key.startswith("[")):
            enc_key = json.loads(enc_key)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "group_id": group_id,
        "epoch": epoch,
        "creator_id": key_entry["creator_id"],
        "creator_username": key_entry.get("creator_username", ""),
        "encrypted_key": enc_key,
    })


@app.route("/api/groups/<int:group_id>/rotate-keys", methods=["POST"])
def api_rotate_group_keys(group_id):
    """Store fresh wrapped keys for a new epoch (triggered on membership changes or manual rotation)."""
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not is_group_member(group_id, user_id):
        return jsonify({"ok": False, "error": "Access denied: Not a member of this group."}), 403

    data = request.get_json(silent=True) or {}
    new_epoch = data.get("epoch")
    member_keys = data.get("member_keys") or []
    if not new_epoch or not member_keys:
        return jsonify({"ok": False, "error": "epoch and member_keys are required."}), 400

    db = get_db()
    prepared_keys = []
    for k_entry in member_keys:
        t_uid = k_entry.get("user_id")
        t_uname = k_entry.get("username")
        if not t_uid and t_uname:
            urow = db.execute("SELECT id FROM users WHERE username = ?", (t_uname,)).fetchone()
            if urow:
                t_uid = urow["id"]
        if t_uid and "encrypted_key" in k_entry:
            prepared_keys.append({"user_id": t_uid, "encrypted_key": k_entry["encrypted_key"]})

    store_group_epoch_keys(group_id, epoch=int(new_epoch), creator_id=user_id, member_keys=prepared_keys)

    socketio.emit("group_key_distribution", {
        "group_id": group_id,
        "epoch": int(new_epoch),
        "rotated_by": username,
    }, room=f"group_{group_id}")

    return jsonify({"ok": True, "epoch": int(new_epoch)})


@app.route("/api/groups/<int:group_id>/messages", methods=["GET"])
def api_get_group_messages_list(group_id):
    """Retrieve encrypted message history for a group."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not is_group_member(group_id, user_id):
        return jsonify({"ok": False, "error": "Access denied: Not a member of this group."}), 403

    messages = get_group_messages(group_id, limit=100)
    parsed = []
    for m in messages:
        item = dict(m)
        try:
            if item.get("media_meta") and isinstance(item["media_meta"], str) and item["media_meta"].startswith("{"):
                item["media_meta"] = json.loads(item["media_meta"])
        except Exception:
            pass
        parsed.append(item)
    grp_timer = get_group_disappearing_timer(group_id)
    return jsonify({"ok": True, "messages": parsed, "disappearing_timer": grp_timer})


# ─── Group Real-Time WebSocket Handlers ─────────────────────────────────────

@socketio.on("join_group")
def handle_join_group(data):
    """Join real-time room for a group conversation after verifying membership."""
    if not isinstance(data, dict):
        return
    user_id = session.get("user_id")
    if not user_id:
        return
    group_id = data.get("group_id")
    if not group_id or not is_group_member(int(group_id), user_id):
        return
    from flask_socketio import join_room
    join_room(f"group_{group_id}")


@socketio.on("leave_group_room")
def handle_leave_group_room(data):
    """Leave the real-time group room."""
    if not isinstance(data, dict):
        return
    group_id = data.get("group_id")
    if group_id:
        from flask_socketio import leave_room
        leave_room(f"group_{group_id}")


@socketio.on("send_group_message")
def handle_send_group_message(data):
    """Broadcast an encrypted group message to all group members."""
    if not isinstance(data, dict):
        return
    sender_id = session.get("user_id")
    sender_username = session.get("username")
    if not sender_id or not sender_username:
        emit("message_error", {"error": "Authentication required."})
        return

    group_id = data.get("group_id")
    if not group_id or not is_group_member(int(group_id), sender_id):
        emit("message_error", {"error": "Access denied: Not a group member."})
        return

    epoch = int(data.get("epoch") or 1)
    ciphertext = str(data.get("ciphertext") or "")
    nonce = str(data.get("nonce") or "")
    tag = str(data.get("tag") or "")
    encrypted_package = data.get("encrypted_package") or {}
    message_type = data.get("message_type") or "text"
    media_meta = data.get("media_meta") or {}
    reply_to_id = data.get("reply_to_id")

    pkg_str = json.dumps(encrypted_package) if isinstance(encrypted_package, dict) else str(encrypted_package)
    media_meta_str = json.dumps(media_meta) if isinstance(media_meta, dict) else str(media_meta)

    # Group disappearing timer and ephemeral options
    grp_timer = get_group_disappearing_timer(int(group_id))
    is_view_once = 1 if data.get("is_view_once") else 0
    is_vanish = 1 if data.get("is_vanish") else 0

    expiration_seconds = 0
    if data.get("expiration_seconds") is not None:
        try:
            expiration_seconds = int(data.get("expiration_seconds"))
        except (ValueError, TypeError):
            expiration_seconds = 0
    elif grp_timer > 0:
        expiration_seconds = grp_timer

    expires_at = None
    if expiration_seconds > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds)).isoformat()

    msg_id = create_group_message(
        group_id=int(group_id),
        sender_id=sender_id,
        epoch=epoch,
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag,
        encrypted_package=pkg_str,
        message_type=message_type,
        media_meta=media_meta_str,
        reply_to_id=reply_to_id,
        expires_at=expires_at,
        expiration_seconds=expiration_seconds,
        is_view_once=is_view_once,
        is_vanish=is_vanish,
    )

    if not msg_id:
        emit("message_error", {"error": "Failed to store group message."})
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "id": msg_id,
        "group_id": int(group_id),
        "sender_username": sender_username,
        "epoch": epoch,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag,
        "encrypted_package": encrypted_package,
        "message_type": message_type,
        "media_meta": media_meta if isinstance(media_meta, dict) else {},
        "reply_to_id": reply_to_id,
        "created_at": now_iso,
        "timestamp": now_iso,
        "reactions": [],
        "is_group": True,
        "expires_at": expires_at,
        "expiration_seconds": expiration_seconds,
        "is_view_once": bool(is_view_once),
        "is_vanish": bool(is_vanish),
        "viewed_at": None,
    }

    emit("receive_group_message", payload, room=f"group_{group_id}")
    emit("group_message_sent", {
        "id": msg_id,
        "group_id": int(group_id),
        "timestamp": now_iso,
        "expires_at": expires_at,
        "expiration_seconds": expiration_seconds,
        "is_view_once": bool(is_view_once),
        "is_vanish": bool(is_vanish),
    })


@socketio.on("group_message_reaction")
def handle_group_message_reaction(data):
    """Toggle emoji reaction on a group message."""
    if not isinstance(data, dict):
        return
    user_id = session.get("user_id")
    username = session.get("username")
    if not user_id or not username:
        return

    message_id = data.get("message_id")
    group_id = data.get("group_id")
    emoji = (data.get("emoji") or "").strip()
    if not message_id or not emoji or not group_id:
        return
    if not is_group_member(int(group_id), user_id):
        return

    res = add_or_toggle_group_reaction(int(message_id), user_id, emoji)
    emit("group_reaction_update", {
        "group_id": int(group_id),
        "message_id": int(message_id),
        "reactions": res["reactions"],
        "actor": username,
    }, room=f"group_{group_id}")


@socketio.on("delete_group_message")
def handle_delete_group_message(data):
    """Delete a group message (sender or admin only)."""
    if not isinstance(data, dict):
        return
    user_id = session.get("user_id")
    if not user_id:
        return
    message_id = data.get("message_id")
    group_id = data.get("group_id")
    if not message_id or not group_id:
        return

    ok = delete_group_message(int(message_id), user_id)
    if ok:
        emit("group_message_deleted", {
            "group_id": int(group_id),
            "message_id": int(message_id),
        }, room=f"group_{group_id}")



# ─── WebRTC Voice & Video Calling Signaling Handlers ─────────────────────────

@socketio.on("webrtc_call_user")
def handle_webrtc_call_user(data):
    """
    Caller initiates a WebRTC voice or video call to target_username.
    """
    if not isinstance(data, dict):
        return
    caller_id = session.get("user_id")
    caller_username = session.get("username")
    if not caller_id or not caller_username:
        emit("call_error", {"error": "Authentication required."})
        return

    target_username = (data.get("target_username") or "").strip()
    call_type = (data.get("call_type") or "voice").lower()
    if call_type not in ("voice", "video"):
        call_type = "voice"

    if not target_username or target_username.lower() == caller_username.lower():
        emit("call_error", {"error": "Invalid call recipient."})
        return

    db = get_db()
    target_user = db.execute("SELECT id, username FROM users WHERE username = ?", (target_username,)).fetchone()
    if not target_user:
        emit("call_error", {"error": "Recipient user not found."})
        return

    # Check if target is online
    is_online = target_username in online_users and len(online_users[target_username]) > 0
    if not is_online:
        call_id = record_call_start(caller_id, target_user["id"], call_type)
        if call_id:
            record_call_end(call_id, status="missed", duration_seconds=0)
        emit("call_unavailable", {
            "target_username": target_username,
            "reason": "offline",
            "message": f"@{target_username} is currently offline."
        })
        return

    # Record call start
    call_id = record_call_start(caller_id, target_user["id"], call_type)
    app.logger.info("Call [%s] initiated: %s -> %s (call_id=%s)", call_type, caller_username, target_username, call_id)

    # Relay incoming call alert to target recipient
    emit(
        "incoming_call",
        {
            "call_id": call_id,
            "caller_id": caller_id,
            "caller_username": caller_username,
            "call_type": call_type,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
        room=f"user_{target_username}",
    )

    # Acknowledge caller that ringing has started
    emit("call_ringing", {
        "call_id": call_id,
        "target_username": target_username,
        "call_type": call_type,
    })


@socketio.on("webrtc_accept_call")
def handle_webrtc_accept_call(data):
    """
    Recipient accepts incoming call. Notifies caller to start peer negotiation.
    """
    if not isinstance(data, dict):
        return
    callee_username = session.get("username")
    if not callee_username:
        return

    call_id = data.get("call_id")
    caller_username = (data.get("caller_username") or "").strip()
    call_type = data.get("call_type", "voice")

    app.logger.info("Call accepted by %s from caller %s (call_id=%s)", callee_username, caller_username, call_id)

    emit(
        "call_accepted",
        {
            "call_id": call_id,
            "callee_username": callee_username,
            "call_type": call_type,
        },
        room=f"user_{caller_username}",
    )


@socketio.on("webrtc_reject_call")
def handle_webrtc_reject_call(data):
    """
    Recipient declines incoming call or is busy.
    """
    if not isinstance(data, dict):
        return
    callee_username = session.get("username")
    if not callee_username:
        return

    call_id = data.get("call_id")
    caller_username = (data.get("caller_username") or "").strip()
    reason = data.get("reason", "rejected")

    if call_id:
        record_call_end(call_id, status=reason, duration_seconds=0)

    app.logger.info("Call %s rejected by %s (reason=%s)", call_id, callee_username, reason)

    emit(
        "call_rejected",
        {
            "call_id": call_id,
            "callee_username": callee_username,
            "reason": reason,
        },
        room=f"user_{caller_username}",
    )


@socketio.on("webrtc_signal")
def handle_webrtc_signal(data):
    """
    Relays WebRTC signaling payloads (SDP offer, SDP answer, ICE candidates)
    between authenticated callers. DTLS-SRTP negotiation occurs purely peer-to-peer.
    """
    if not isinstance(data, dict):
        return
    sender_username = session.get("username")
    if not sender_username:
        return

    target_username = (data.get("target_username") or "").strip()
    call_id = data.get("call_id")
    signal_type = data.get("signal_type")
    payload = data.get("payload")

    if not target_username or not signal_type:
        return

    emit(
        "webrtc_signal",
        {
            "sender_username": sender_username,
            "call_id": call_id,
            "signal_type": signal_type,
            "payload": payload,
        },
        room=f"user_{target_username}",
    )


@socketio.on("webrtc_end_call")
def handle_webrtc_end_call(data):
    """
    Either participant ends an active call or cancels an outgoing call.
    """
    if not isinstance(data, dict):
        return
    sender_username = session.get("username")
    if not sender_username:
        return

    call_id = data.get("call_id")
    target_username = (data.get("target_username") or "").strip()
    duration_seconds = int(data.get("duration_seconds") or 0)
    status = data.get("status", "completed")

    if call_id:
        record_call_end(call_id, status=status, duration_seconds=duration_seconds)

    app.logger.info("Call %s ended by %s (duration=%ss, status=%s)", call_id, sender_username, duration_seconds, status)

    if target_username:
        emit(
            "call_ended",
            {
                "call_id": call_id,
                "ended_by": sender_username,
                "duration_seconds": duration_seconds,
                "status": status,
            },
            room=f"user_{target_username}",
        )


@socketio.on("webrtc_toggle_media")
def handle_webrtc_toggle_media(data):
    """
    Inform peer when user mutes/unmutes audio or turns camera on/off.
    """
    if not isinstance(data, dict):
        return
    sender_username = session.get("username")
    target_username = (data.get("target_username") or "").strip()
    media_type = data.get("media_type")
    enabled = bool(data.get("enabled", True))

    if sender_username and target_username:
        emit(
            "peer_media_toggle",
            {
                "sender_username": sender_username,
                "media_type": media_type,
                "enabled": enabled,
            },
            room=f"user_{target_username}",
        )


# ─── Startup ────────────────────────────────────────────────────────────────

def create_app():
    """Factory: ensure the DB and schema exist, then return the app."""
    os.makedirs(os.path.dirname(config.DATABASE), exist_ok=True)
    with app.app_context():
        init_db()
    ensure_scheduled_dispatcher_started()
    ensure_disappearing_purger_started()
    return app


if __name__ == "__main__":
    import sys
    if "--reset-db" in sys.argv:
        with app.app_context():
            db = get_db()
            db.execute("DROP TABLE IF EXISTS messages;")
            db.execute("DROP TABLE IF EXISTS public_keys;")
            db.execute("DROP TABLE IF EXISTS users;")
            db.commit()
            init_db()
            print("[OK] Database reset successfully! Fresh tables initialized.")
            sys.exit(0)
    elif "--init-db" in sys.argv:
        create_app()
        print("[OK] Database schema initialized successfully.")
        sys.exit(0)

    create_app()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
    socketio.run(
        app,
        host=host,
        port=port,
        debug=config.DEBUG,
        allow_unsafe_werkzeug=True,
    )
