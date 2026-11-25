"""
encryption/crypto.py — Server-side cryptographic utilities.

Responsibilities (server scope):
  - Password hashing and verification using Werkzeug's pbkdf2-sha256.
  - Input sanitisation helpers.
  - (Future) Server-side signature / nonce validation for key-exchange handshake.

NOTE: True E2EE private keys are NEVER sent to or stored on the server.
      This module only handles authentication-layer security.
"""

import re
import html
from werkzeug.security import generate_password_hash, check_password_hash

# ─── E2EE Cryptographic Primitives (Module 2) ──────────────────────────────
from encryption.e2ee import (
    generate_key_pair,
    export_public_key,
    import_public_key,
    export_private_key,
    import_private_key,
    derive_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message,
    ClientE2EESession,
    CryptoError,
    AuthenticationError,
    NonceReuseError,
    NONCE_SIZE_BYTES,
    KEY_SIZE_BYTES,
    TAG_SIZE_BYTES,
    generate_group_epoch_key,
    wrap_group_key,
    unwrap_group_key,
    encrypt_group_message,
    decrypt_group_message,
    ClientGroupSession,
)


# ─── Password Utilities ─────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using Werkzeug's pbkdf2:sha256.
    The returned hash is safe to store in the database.

    Args:
        plain_password: The raw password string from the registration form.

    Returns:
        A secure hash string (method + salt + digest).
    """
    return generate_password_hash(plain_password, method="pbkdf2:sha256", salt_length=16)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verify a plain-text password against its stored hash.

    Args:
        plain_password: The password string from the login form.
        password_hash:  The hash retrieved from the database.

    Returns:
        True if the password matches, False otherwise.
    """
    return check_password_hash(password_hash, plain_password)


# ─── Input Sanitisation ─────────────────────────────────────────────────────

def sanitise_username(username: str) -> str:
    """Strip and escape a username string safely."""
    if not isinstance(username, str):
        return ""
    return html.escape(username.strip())


def sanitise_email(email: str) -> str:
    """Strip and lowercase an email string safely."""
    if not isinstance(email, str):
        return ""
    return email.strip().lower()


# ─── Validation Helpers ─────────────────────────────────────────────────────

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
_EMAIL_RE    = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_valid_username(username: str) -> bool:
    """Return True if username matches the allowed pattern (3-20 alphanumeric/underscore)."""
    if not isinstance(username, str):
        return False
    return bool(_USERNAME_RE.match(username))


def is_valid_email(email: str) -> bool:
    """Return True if email is structurally valid."""
    if not isinstance(email, str):
        return False
    return bool(_EMAIL_RE.match(email)) and len(email) <= 254


def is_valid_password(password: str) -> bool:
    """Return True if password meets length requirements (8-128 chars)."""
    return isinstance(password, str) and 8 <= len(password) <= 128
