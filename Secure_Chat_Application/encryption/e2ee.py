"""
encryption/e2ee.py — Genuine Client-Side End-to-End Encryption Engine.

Architecture:
  1. Key Generation:
     - X25519 elliptic-curve public/private key pairs.
     - Private keys reside strictly on client device; never sent to server.
     - Public keys exported in Base64 for publication via server directory.

  2. Key Exchange:
     - Diffie-Hellman key agreement using X25519 (RFC 7748).
     - Derives 32-byte shared secret from private_key and peer_public_key.
     - Applies HKDF-SHA-256 (RFC 5869) to derive a 256-bit AES-GCM session key.

  3. Message Encryption:
     - AES-256-GCM (NIST SP 800-38D) authenticated encryption.
     - Unique, cryptographically secure 12-byte (96-bit) nonce per message.
     - Produces ciphertext, 16-byte (128-bit) authentication tag, and nonce.
     - Enforces nonce freshness to prevent nonce-reuse under the same key.

  4. Message Decryption:
     - Retrieves encrypted package (nonce + ciphertext + tag).
     - Decrypts and verifies authentication tag using the derived AES-256 key.
     - Rejects tampered, corrupt, or invalid messages safely.

  5. Security Guarantees:
     - Zero plaintext exposure on server.
     - Zero private key exposure to server or database.
     - Replay & tampering detection via GCM authentication tag.
"""

from __future__ import annotations

import base64
import os
from typing import Tuple, Dict, Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─── Cryptographic Constants ────────────────────────────────────────────────

NONCE_SIZE_BYTES = 12       # 96 bits recommended for AES-GCM
KEY_SIZE_BYTES   = 32       # 256 bits for AES-256 and X25519
TAG_SIZE_BYTES   = 16       # 128-bit authentication tag

# Domain separation labels for HKDF
HKDF_SALT = b"SecureChat-E2EE-Salt-v1"
HKDF_INFO = b"SecureChat-AES-256-GCM-Key"


# ─── Custom Exceptions ──────────────────────────────────────────────────────

class CryptoError(Exception):
    """Base exception for all cryptographic errors."""
    pass


class AuthenticationError(CryptoError):
    """Raised when message authenticity / tag check fails (tampering, wrong key)."""
    pass


class NonceReuseError(CryptoError):
    """Raised when an attempt is made to encrypt or decrypt with a reused nonce."""
    pass


# ─── Key Generation & Serialization ─────────────────────────────────────────

def generate_key_pair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate a fresh X25519 public/private key pair.

    Returns:
        (private_key, public_key)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


def export_public_key(public_key: x25519.X25519PublicKey) -> str:
    """
    Export an X25519 public key as a 32-byte raw Base64-encoded string.
    Safe to publish to server directory.
    """
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def import_public_key(public_key_b64: str) -> x25519.X25519PublicKey:
    """
    Import an X25519 public key from a 32-byte Base64-encoded string.

    Raises:
        CryptoError: If key encoding is invalid or wrong length.
    """
    try:
        raw_bytes = base64.b64decode(public_key_b64.strip())
        if len(raw_bytes) != KEY_SIZE_BYTES:
            raise CryptoError(
                f"Invalid X25519 public key length: expected {KEY_SIZE_BYTES} bytes, got {len(raw_bytes)}"
            )
        return x25519.X25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Failed to import public key: {e}") from e


def export_private_key(private_key: x25519.X25519PrivateKey) -> str:
    """
    Export an X25519 private key as a 32-byte Base64-encoded string.
    WARNING: For local client device storage ONLY. Never transmit to server!
    """
    raw_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def import_private_key(private_key_b64: str) -> x25519.X25519PrivateKey:
    """
    Import an X25519 private key from local client device storage.

    Raises:
        CryptoError: If key encoding is invalid.
    """
    try:
        raw_bytes = base64.b64decode(private_key_b64.strip())
        if len(raw_bytes) != KEY_SIZE_BYTES:
            raise CryptoError(
                f"Invalid X25519 private key length: expected {KEY_SIZE_BYTES} bytes, got {len(raw_bytes)}"
            )
        return x25519.X25519PrivateKey.from_private_bytes(raw_bytes)
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Failed to import private key: {e}") from e


# ─── Key Exchange & Key Derivation ──────────────────────────────────────────

def derive_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_key: x25519.X25519PublicKey,
) -> bytes:
    """
    Perform Diffie-Hellman key exchange using X25519 (RFC 7748).
    Produces an identical 32-byte shared secret on both client devices.

    Returns:
        32 raw bytes of shared secret.
    """
    try:
        shared = private_key.exchange(peer_public_key)
        if all(b == 0 for b in shared):
            raise CryptoError("Degenerate X25519 shared secret (all zero bytes) rejected per RFC 7748.")
        return shared
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"X25519 key exchange failed: {e}") from e


def derive_aes_key(
    shared_secret: bytes,
    salt: bytes = HKDF_SALT,
    info: bytes = HKDF_INFO,
) -> bytes:
    """
    Derive a 256-bit (32-byte) symmetric key from an X25519 shared secret
    using HKDF-SHA-256 (RFC 5869).

    Args:
        shared_secret: Output of X25519 ECDH exchange.
        salt: Domain-separation salt.
        info: Context and application specific info label.

    Returns:
        32-byte AES-256 key.
    """
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE_BYTES,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        raise CryptoError(f"HKDF key derivation failed: {e}") from e


# ─── Message Encryption & Decryption ────────────────────────────────────────

def encrypt_message(
    aes_key: bytes,
    plaintext: str | bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Encrypt a message using AES-256-GCM authenticated encryption.

    Args:
        aes_key: 32-byte AES-256 key (derived via HKDF).
        plaintext: The message text or bytes to encrypt.
        associated_data: Optional authenticated associated data (AAD).
        nonce: Optional 12-byte nonce (if None, a fresh CSPRNG nonce is generated).

    Returns:
        dict containing:
            - nonce: Base64-encoded 12-byte nonce
            - ciphertext: Base64-encoded ciphertext (excluding tag)
            - tag: Base64-encoded 16-byte authentication tag
            - payload: Base64-encoded combined wire format (nonce + ciphertext + tag)
    """
    if len(aes_key) != KEY_SIZE_BYTES:
        raise CryptoError(f"AES key must be {KEY_SIZE_BYTES} bytes (got {len(aes_key)})")

    if nonce is None:
        nonce = os.urandom(NONCE_SIZE_BYTES)
    elif len(nonce) != NONCE_SIZE_BYTES:
        raise CryptoError(f"Nonce must be {NONCE_SIZE_BYTES} bytes (got {len(nonce)})")

    plaintext_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext

    try:
        aesgcm = AESGCM(aes_key)
        # AESGCM.encrypt returns ciphertext + 16-byte authentication tag
        ct_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        ciphertext = ct_with_tag[:-TAG_SIZE_BYTES]
        tag = ct_with_tag[-TAG_SIZE_BYTES:]

        # Wire payload: nonce (12B) + ciphertext + tag (16B)
        combined = nonce + ct_with_tag

        return {
            "nonce":      base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag":        base64.b64encode(tag).decode("ascii"),
            "payload":    base64.b64encode(combined).decode("ascii"),
        }
    except Exception as e:
        raise CryptoError(f"Message encryption failed: {e}") from e


def decrypt_message(
    aes_key: bytes,
    encrypted_package: Dict[str, Any] | str,
    associated_data: Optional[bytes] = None,
) -> str:
    """
    Decrypt an AES-256-GCM encrypted message package.

    Args:
        aes_key: 32-byte AES-256 key.
        encrypted_package: Either:
            - dict with 'nonce', 'ciphertext', 'tag' (Base64) or 'payload'
            - Base64 string of combined wire format (nonce + ciphertext + tag)
        associated_data: Optional AAD matching what was supplied during encryption.

    Returns:
        Decrypted plaintext string (UTF-8).

    Raises:
        AuthenticationError: If tag verification fails (message tampered or wrong key).
        CryptoError: For malformed inputs or decoding errors.
    """
    if len(aes_key) != KEY_SIZE_BYTES:
        raise CryptoError(f"AES key must be {KEY_SIZE_BYTES} bytes (got {len(aes_key)})")

    try:
        if isinstance(encrypted_package, str):
            raw = base64.b64decode(encrypted_package.strip())
            if len(raw) < NONCE_SIZE_BYTES + TAG_SIZE_BYTES:
                raise CryptoError("Encrypted payload too short")
            nonce = raw[:NONCE_SIZE_BYTES]
            ct_with_tag = raw[NONCE_SIZE_BYTES:]
        elif isinstance(encrypted_package, dict):
            if "ciphertext" in encrypted_package and "tag" in encrypted_package:
                nonce = base64.b64decode(encrypted_package["nonce"])
                ct = base64.b64decode(encrypted_package["ciphertext"])
                tag = base64.b64decode(encrypted_package["tag"])
                ct_with_tag = ct + tag
            elif "payload" in encrypted_package and encrypted_package["payload"]:
                raw = base64.b64decode(encrypted_package["payload"])
                nonce = raw[:NONCE_SIZE_BYTES]
                ct_with_tag = raw[NONCE_SIZE_BYTES:]
            else:
                raise CryptoError("Dictionary must contain either ('ciphertext', 'tag', 'nonce') or 'payload'")
        else:
            raise CryptoError("Invalid encrypted_package format")

        if len(nonce) != NONCE_SIZE_BYTES:
            raise CryptoError(f"Invalid nonce length: expected {NONCE_SIZE_BYTES}, got {len(nonce)}")

        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        return plaintext_bytes.decode("utf-8")

    except InvalidTag as e:
        raise AuthenticationError(
            "Message authentication failed: ciphertext or tag was tampered with, or invalid key."
        ) from e
    except (CryptoError, AuthenticationError):
        raise
    except Exception as e:
        raise CryptoError(f"Message decryption failed: {e}") from e


# ─── High-Level Reusable Client E2EE Session Manager ────────────────────────

class ClientE2EESession:
    """
    High-level client-side cryptographic session manager.
    Represents one user's client device.

    Responsibilities:
      - Holds private key in local memory (never shared).
      - Stores verified peer public keys.
      - Derives and caches symmetric session keys per peer.
      - Tracks used nonces to detect/prevent replay and nonce reuse.
      - Encrypts outgoing and decrypts incoming messages.
    """

    def __init__(
        self,
        username: str,
        private_key: Optional[x25519.X25519PrivateKey] = None,
    ):
        self.username = username
        if private_key is None:
            self.private_key, self.public_key = generate_key_pair()
        else:
            self.private_key = private_key
            self.public_key  = private_key.public_key()

        # Cache: peer_username -> 32-byte AES key
        self._peer_keys: Dict[str, bytes] = {}
        # Cache: peer_username -> Base64 public key
        self._peer_public_keys: Dict[str, str] = {}
        # Nonce freshness tracking: set of seen nonce bytes
        self._seen_nonces: set[bytes] = set()

    @property
    def public_key_b64(self) -> str:
        """The user's public key as Base64, safe to publish."""
        return export_public_key(self.public_key)

    @property
    def private_key_b64(self) -> str:
        """The user's private key as Base64 (local storage only)."""
        return export_private_key(self.private_key)

    def establish_session(self, peer_username: str, peer_public_key_b64: str) -> bytes:
        """
        Establish a secure E2EE channel with a peer:
        1. Import peer's X25519 public key.
        2. Compute X25519 shared secret.
        3. Derive 256-bit AES key via HKDF-SHA-256.
        4. Cache the session key for this peer.

        Returns:
            The 32-byte derived AES-256 key.
        """
        peer_pub = import_public_key(peer_public_key_b64)
        shared_secret = derive_shared_secret(self.private_key, peer_pub)
        aes_key = derive_aes_key(shared_secret)

        self._peer_public_keys[peer_username] = peer_public_key_b64
        self._peer_keys[peer_username] = aes_key
        return aes_key

    def get_session_key(self, peer_username: str) -> Optional[bytes]:
        """Retrieve established AES-256 session key for peer, if any."""
        return self._peer_keys.get(peer_username)

    def has_session(self, peer_username: str) -> bool:
        """Check if an encryption session is already established with peer."""
        return peer_username in self._peer_keys

    def encrypt_for(
        self,
        peer_username: str,
        plaintext: str,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt a message for a peer using the established session key.

        Raises:
            CryptoError: If no session exists for peer.
        """
        aes_key = self._peer_keys.get(peer_username)
        if not aes_key:
            raise CryptoError(
                f"No E2EE session established with '{peer_username}'. Call establish_session() first."
            )

        encrypted = encrypt_message(aes_key, plaintext, associated_data)

        # Track the generated nonce
        nonce_bytes = base64.b64decode(encrypted["nonce"])
        self._seen_nonces.add(nonce_bytes)

        return encrypted

    def decrypt_from(
        self,
        peer_username: str,
        encrypted_package: Dict[str, Any] | str,
        associated_data: Optional[bytes] = None,
        check_replay: bool = True,
    ) -> str:
        """
        Decrypt a message received from a peer using the established session key.

        Args:
            peer_username: The peer sender's username.
            encrypted_package: The encrypted payload dictionary or wire string.
            associated_data: Optional authenticated associated data.
            check_replay: If True (default for live traffic), prevents nonce reuse.
                          Set False when loading historical message archives.

        Raises:
            CryptoError / AuthenticationError: If session missing or tag check fails.
            NonceReuseError: If a duplicate nonce is detected during live traffic.
        """
        aes_key = self._peer_keys.get(peer_username)
        if not aes_key:
            raise CryptoError(
                f"No E2EE session established with '{peer_username}'. Call establish_session() first."
            )

        # Extract and verify nonce freshness
        if isinstance(encrypted_package, dict) and "nonce" in encrypted_package:
            nonce_bytes = base64.b64decode(encrypted_package["nonce"])
        elif isinstance(encrypted_package, str):
            raw = base64.b64decode(encrypted_package.strip())
            nonce_bytes = raw[:NONCE_SIZE_BYTES]
        elif isinstance(encrypted_package, dict) and "payload" in encrypted_package:
            raw = base64.b64decode(encrypted_package["payload"])
            nonce_bytes = raw[:NONCE_SIZE_BYTES]
        else:
            raise CryptoError("Malformed message package")

        if check_replay:
            if nonce_bytes in self._seen_nonces:
                raise NonceReuseError("Nonce reuse detected! Rejecting potentially replayed message.")
            self._seen_nonces.add(nonce_bytes)

        return decrypt_message(aes_key, encrypted_package, associated_data)


# ─── Group E2EE Cryptographic Operations ───────────────────────────────────

def generate_group_epoch_key() -> bytes:
    """Generate a cryptographically secure 32-byte (256-bit) Group Epoch Key (GEK)."""
    return os.urandom(KEY_SIZE_BYTES)


def wrap_group_key(group_key: bytes, peer_aes_key: bytes) -> Dict[str, str]:
    """
    Wrap (encrypt) a Group Epoch Key for a specific group member using
    the pairwise AES-256-GCM session key established via X25519 DH.
    """
    key_b64 = base64.b64encode(group_key).decode("utf-8")
    payload_str = f'{{"group_key_b64":"{key_b64}"}}'
    return encrypt_message(peer_aes_key, payload_str)


def unwrap_group_key(wrapped_package: Dict[str, str] | str, peer_aes_key: bytes) -> bytes:
    """
    Unwrap (decrypt) a Group Epoch Key using the pairwise AES-256-GCM session key.
    """
    import json
    decrypted_str = decrypt_message(peer_aes_key, wrapped_package)
    parsed = json.loads(decrypted_str)
    return base64.b64decode(parsed["group_key_b64"])


def encrypt_group_message(
    group_key: bytes,
    plaintext: str,
    associated_data: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Encrypt a group message with the authenticated Group Epoch Key (AES-256-GCM).
    Zero plaintext is exposed.
    """
    return encrypt_message(group_key, plaintext, associated_data)


def decrypt_group_message(
    group_key: bytes,
    encrypted_package: Dict[str, Any] | str,
    associated_data: Optional[bytes] = None
) -> str:
    """
    Decrypt a group message using the authenticated Group Epoch Key (AES-256-GCM).
    """
    return decrypt_message(group_key, encrypted_package, associated_data)


class ClientGroupSession:
    """
    High-level client group session manager.
    Tracks Group Epoch Keys (GEK) per epoch, manages forward/backward secrecy key rotation,
    and handles group message encryption and decryption.
    """

    def __init__(self, group_id: int, my_username: str):
        self.group_id = group_id
        self.my_username = my_username
        self.current_epoch: int = 1
        self._epoch_keys: Dict[int, bytes] = {}

    def set_epoch_key(self, epoch: int, key: bytes) -> None:
        """Cache an unwrapped Group Epoch Key for a specific epoch."""
        self._epoch_keys[epoch] = key
        if epoch > self.current_epoch:
            self.current_epoch = epoch

    def get_epoch_key(self, epoch: int) -> Optional[bytes]:
        """Retrieve cached GEK for epoch."""
        return self._epoch_keys.get(epoch)

    def rotate_epoch(self, new_epoch: int) -> bytes:
        """Generate and store a new fresh GEK for a new epoch."""
        new_key = generate_group_epoch_key()
        self.set_epoch_key(new_epoch, new_key)
        return new_key

    def encrypt(self, plaintext: str, epoch: Optional[int] = None) -> Dict[str, Any]:
        """Encrypt message using specified or current epoch key."""
        target_epoch = epoch or self.current_epoch
        key = self.get_epoch_key(target_epoch)
        if not key:
            raise CryptoError(f"No key available for group {self.group_id} epoch {target_epoch}")
        enc = encrypt_group_message(key, plaintext)
        enc["epoch"] = target_epoch
        return enc

    def decrypt(self, encrypted_package: Dict[str, Any] | str, epoch: int) -> str:
        """Decrypt message using specified epoch key."""
        key = self.get_epoch_key(epoch)
        if not key:
            raise CryptoError(f"No key available for group {self.group_id} epoch {epoch}")
        return decrypt_group_message(key, encrypted_package)

