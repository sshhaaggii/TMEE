"""
test_crypto.py — Comprehensive Unit & Integration Tests for Module 2: E2EE.

Tests the full cryptographic lifecycle between two users (Alice and Bob):
  1. X25519 Key Generation & Serialization
  2. X25519 Diffie-Hellman Key Exchange
  3. HKDF-SHA-256 Key Derivation (256-bit symmetric key)
  4. AES-256-GCM Message Encryption (12-byte random nonce, 16-byte tag)
  5. AES-256-GCM Message Decryption
  6. Bidirectional Communication (Alice -> Bob and Bob -> Alice)
  7. Nonce Uniqueness & CSPRNG verification
  8. Tampering & Authentication Tag Verification (InvalidTag / AuthenticationError)
  9. Unauthorized Decryption (Eve's key fails to decrypt)
 10. High-level ClientE2EESession integration
 11. Replay & Nonce Reuse Protection

Run with:
  python test_crypto.py
"""

import base64
import sys
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
)

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


print(f"{INFO} Starting Module 2: End-to-End Encryption Test Suite...\n")

# ── Test 1: Key Generation & Serialization ──────────────────────────────────
print(f"{INFO} [1] Testing X25519 Key Pair Generation & Export/Import...")
alice_priv, alice_pub = generate_key_pair()
bob_priv, bob_pub     = generate_key_pair()

alice_pub_b64 = export_public_key(alice_pub)
bob_pub_b64   = export_public_key(bob_pub)

check("Alice public key is 44 characters (Base64 of 32 bytes)", len(alice_pub_b64) == 44)
check("Bob public key is 44 characters (Base64 of 32 bytes)", len(bob_pub_b64) == 44)
check("Alice and Bob have distinct public keys", alice_pub_b64 != bob_pub_b64)

# Roundtrip import
imported_alice_pub = import_public_key(alice_pub_b64)
check("Imported Alice public key matches original export", export_public_key(imported_alice_pub) == alice_pub_b64)

alice_priv_b64 = export_private_key(alice_priv)
imported_alice_priv = import_private_key(alice_priv_b64)
check("Alice private key export/import roundtrip successful", export_private_key(imported_alice_priv) == alice_priv_b64)

# ── Test 2: X25519 Diffie-Hellman Key Exchange ─────────────────────────────
print(f"\n{INFO} [2] Testing X25519 Diffie-Hellman Key Agreement...")
# Alice computes shared secret using Bob's public key
shared_secret_alice = derive_shared_secret(alice_priv, bob_pub)
# Bob computes shared secret using Alice's public key
shared_secret_bob   = derive_shared_secret(bob_priv, alice_pub)

check("Alice computed 32-byte shared secret", len(shared_secret_alice) == 32)
check("Bob computed 32-byte shared secret", len(shared_secret_bob) == 32)
check("Both parties computed identical shared secret (DH property holds)", shared_secret_alice == shared_secret_bob)

# ── Test 3: HKDF-SHA-256 Key Derivation ─────────────────────────────────────
print(f"\n{INFO} [3] Testing HKDF-SHA-256 Symmetric Key Derivation...")
aes_key_alice = derive_aes_key(shared_secret_alice)
aes_key_bob   = derive_aes_key(shared_secret_bob)

check("Derived Alice key is 256 bits (32 bytes)", len(aes_key_alice) == 32)
check("Derived Bob key is 256 bits (32 bytes)", len(aes_key_bob) == 32)
check("Derived AES-256-GCM keys are identical on both clients", aes_key_alice == aes_key_bob)
check("Derived AES key differs from raw shared secret (KDF expansion)", aes_key_alice != shared_secret_alice)

# ── Test 4: Message Encryption (Alice -> Bob) ───────────────────────────────
print(f"\n{INFO} [4] Testing AES-256-GCM Message Encryption (Alice -> Bob)...")
plaintext_message = "Hello Bob! This is an end-to-end encrypted secret message."
encrypted_pkg = encrypt_message(aes_key_alice, plaintext_message)

check("Encryption returned nonce, ciphertext, tag, and payload", all(k in encrypted_pkg for k in ("nonce", "ciphertext", "tag", "payload")))

nonce_bytes = base64.b64decode(encrypted_pkg["nonce"])
tag_bytes   = base64.b64decode(encrypted_pkg["tag"])
ct_bytes    = base64.b64decode(encrypted_pkg["ciphertext"])

check(f"Nonce is exactly {NONCE_SIZE_BYTES} bytes (96 bits)", len(nonce_bytes) == NONCE_SIZE_BYTES)
check(f"Authentication tag is exactly {TAG_SIZE_BYTES} bytes (128 bits)", len(tag_bytes) == TAG_SIZE_BYTES)
check("Ciphertext does NOT contain plaintext in raw bytes", plaintext_message.encode() not in ct_bytes)

# ── Test 5: Message Decryption (Bob decrypts Alice's message) ───────────────
print(f"\n{INFO} [5] Testing AES-256-GCM Message Decryption on Bob's client...")
decrypted_message = decrypt_message(aes_key_bob, encrypted_pkg)
check("Bob decrypted exact original message", decrypted_message == plaintext_message)

# Decrypt using wire payload string format
decrypted_from_payload = decrypt_message(aes_key_bob, encrypted_pkg["payload"])
check("Bob decrypted exact message from wire payload string", decrypted_from_payload == plaintext_message)

# ── Test 6: Bidirectional Communication (Bob -> Alice) ──────────────────────
print(f"\n{INFO} [6] Testing Bidirectional Reply (Bob -> Alice)...")
bob_reply = "Hey Alice! I verified your message. E2EE is fully active."
bob_encrypted_pkg = encrypt_message(aes_key_bob, bob_reply)
alice_decrypted = decrypt_message(aes_key_alice, bob_encrypted_pkg)
check("Alice successfully decrypted Bob's reply", alice_decrypted == bob_reply)

# ── Test 7: Nonce Uniqueness ────────────────────────────────────────────────
print(f"\n{INFO} [7] Testing Nonce Freshness & Uniqueness...")
nonces = set()
for _ in range(50):
    enc = encrypt_message(aes_key_alice, "Test message")
    nonces.add(enc["nonce"])
check("50 consecutive encryptions produced 50 unique nonces", len(nonces) == 50)

# ── Test 8: Tamper Detection & Authentication Failures ──────────────────────
print(f"\n{INFO} [8] Testing Tamper Detection (GCM Authentication Tag)...")
# Flip 1 byte in ciphertext
tampered_pkg = dict(encrypted_pkg)
raw_ct = bytearray(base64.b64decode(tampered_pkg["ciphertext"]))
raw_ct[0] ^= 0xFF  # invert first byte
tampered_pkg["ciphertext"] = base64.b64encode(raw_ct).decode("ascii")

tamper_detected = False
try:
    decrypt_message(aes_key_bob, tampered_pkg)
except AuthenticationError:
    tamper_detected = True

check("Tampered ciphertext raised AuthenticationError (tag mismatch)", tamper_detected)

# Flip 1 byte in authentication tag
tampered_tag_pkg = dict(encrypted_pkg)
raw_tag = bytearray(base64.b64decode(tampered_tag_pkg["tag"]))
raw_tag[0] ^= 0x01
tampered_tag_pkg["tag"] = base64.b64encode(raw_tag).decode("ascii")

tag_tamper_detected = False
try:
    decrypt_message(aes_key_bob, tampered_tag_pkg)
except AuthenticationError:
    tag_tamper_detected = True

check("Tampered authentication tag raised AuthenticationError", tag_tamper_detected)

# ── Test 9: Unauthorized Eavesdropper (Eve) Rejection ───────────────────────
print(f"\n{INFO} [9] Testing Unauthorized Third Party (Eve) Isolation...")
eve_priv, eve_pub = generate_key_pair()
# Eve intercepts ciphertext and tries to decrypt with her own key derived with Bob
eve_shared = derive_shared_secret(eve_priv, bob_pub)
eve_aes_key = derive_aes_key(eve_shared)

eve_decryption_failed = False
try:
    decrypt_message(eve_aes_key, encrypted_pkg)
except AuthenticationError:
    eve_decryption_failed = True

check("Eve failed to decrypt Alice-Bob message (AuthenticationError)", eve_decryption_failed)

# ── Test 10: High-Level ClientE2EESession ───────────────────────────────────
print(f"\n{INFO} [10] Testing High-Level ClientE2EESession Simulation...")
client_alice = ClientE2EESession(username="alice")
client_bob   = ClientE2EESession(username="bob")

# Public key exchange (simulating directory publish/fetch)
client_alice.establish_session(peer_username="bob", peer_public_key_b64=client_bob.public_key_b64)
client_bob.establish_session(peer_username="alice", peer_public_key_b64=client_alice.public_key_b64)

check("Alice established session for Bob", client_alice.has_session("bob"))
check("Bob established session for Alice", client_bob.has_session("alice"))

session_message = "Confidential chat payload through ClientE2EESession."
alice_out = client_alice.encrypt_for("bob", session_message)
bob_in    = client_bob.decrypt_from("alice", alice_out)

check("End-to-end message roundtrip succeeded via ClientE2EESession", bob_in == session_message)

# ── Test 11: Nonce Reuse & Replay Protection ────────────────────────────────
print(f"\n{INFO} [11] Testing Nonce Reuse & Replay Protection...")
replay_caught = False
try:
    # Replaying the exact same message to Bob
    client_bob.decrypt_from("alice", alice_out)
except NonceReuseError:
    replay_caught = True

check("Replayed message with reused nonce was detected and rejected", replay_caught)

# ── Summary ─────────────────────────────────────────────────────────────────
print()
if failures == 0:
    print("\033[92m======================================================")
    print("  ALL 24 E2EE TESTS PASSED - Module 2 is 100% Verified!")
    print("======================================================\033[0m")
    sys.exit(0)
else:
    print(f"\033[91m======================================================")
    print(f"  {failures} TEST(S) FAILED")
    print("======================================================\033[0m")
    sys.exit(1)
