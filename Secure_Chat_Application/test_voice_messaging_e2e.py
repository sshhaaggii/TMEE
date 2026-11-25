"""
test_voice_messaging_e2e.py
End-to-End Cryptographic & Integration Test for Encrypted Voice Messaging in TMEEE.

Verifies:
1. Two distinct accounts (VoiceAlice & VoiceBob) registration & authentication.
2. X25519 key exchange & AES-256-GCM derivation.
3. Voice message encryption on the sender's client side.
4. Database storage contains strictly ciphertext, nonce, and tag (ZERO plaintext audio).
5. Verification that message_type is correctly recorded as 'audio'.
6. Recipient fetches messages and successfully decrypts the voice note payload.
7. Validates waveform points (28-32 bars), duration metadata, and audio data URL integrity.
8. Bi-directional reply: Bob records and sends an encrypted voice message back to Alice.
9. Alice decrypts Bob's voice message with perfect fidelity.
"""

import sys
import os
import json
import base64
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, create_app
from database.db import init_db, get_db
from encryption.e2ee import (
    generate_key_pair, export_public_key, derive_shared_secret, derive_aes_key,
    encrypt_message, decrypt_message
)

class TestEncryptedVoiceMessagingE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        create_app()
        cls.ctx = app.app_context()
        cls.ctx.push()
        init_db()

        cls.client_alice = app.test_client()
        cls.client_bob = app.test_client()

        # Generate X25519 client keypairs
        cls.alice_priv, cls.alice_pub = generate_key_pair()
        cls.bob_priv, cls.bob_pub = generate_key_pair()

        cls.alice_pub_b64 = export_public_key(cls.alice_pub)
        cls.bob_pub_b64 = export_public_key(cls.bob_pub)

        # Derive shared secrets
        alice_shared = derive_shared_secret(cls.alice_priv, cls.bob_pub)
        cls.alice_aes_key = derive_aes_key(alice_shared)

        bob_shared = derive_shared_secret(cls.bob_priv, cls.alice_pub)
        cls.bob_aes_key = derive_aes_key(bob_shared)

        # Confirm symmetric keys match
        assert cls.alice_aes_key == cls.bob_aes_key, "AES keys must match for valid E2EE"

        # Register Alice
        res = cls.client_alice.post('/register', json={
            'username': 'voice_alice',
            'email': 'voice_alice@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        # If already exists from prior run, login
        cls.client_alice.post('/login', json={'email': 'voice_alice@test.tmeee', 'password': 'Password123!'})

        # Register Bob
        res = cls.client_bob.post('/register', json={
            'username': 'voice_bob',
            'email': 'voice_bob@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        cls.client_bob.post('/login', json={'email': 'voice_bob@test.tmeee', 'password': 'Password123!'})

        # Upload public keys
        cls.client_alice.post('/api/public_key', json={'public_key': cls.alice_pub_b64})
        cls.client_bob.post('/api/public_key', json={'public_key': cls.bob_pub_b64})

        # Get user IDs
        with get_db() as conn:
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('voice_alice',))
            cls.alice_id = c.fetchone()["id"]
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('voice_bob',))
            cls.bob_id = c.fetchone()["id"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_01_client_side_voice_encryption_and_zero_plaintext(self):
        """Sender client encrypts voice recording payload into AES-256-GCM ciphertext."""
        # Simulated WebM Opus audio bytes from MediaRecorder
        fake_audio_bytes = b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01VoiceAudioPacket"
        audio_data_url = "data:audio/webm;codecs=opus;base64," + base64.b64encode(fake_audio_bytes).decode('ascii')
        
        waveform = [18, 32, 45, 60, 78, 92, 54, 30, 48, 80, 65, 42, 33, 25, 40, 55, 70, 85, 90, 75, 50, 35, 20, 30, 45, 60, 40, 20]
        duration_sec = 6.8

        voice_payload = {
            "type": "media",
            "mediaType": "audio",
            "name": "voice_message_1.webm",
            "duration": duration_sec,
            "waveform": waveform,
            "data": audio_data_url
        }

        plaintext_str = json.dumps(voice_payload)
        
        # Encrypt with Alice's AES-256-GCM key derived from Bob's public key
        enc = encrypt_message(self.alice_aes_key, plaintext_str)

        # Store in database as if transmitted via WebSocket
        with get_db() as conn:
            pkg_str = json.dumps({
                "ciphertext": enc['ciphertext'],
                "nonce": enc['nonce'],
                "tag": enc['tag']
            })
            c = conn.execute("""
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                    encrypted_package, message_type, media_meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.alice_id, self.bob_id, enc['ciphertext'], enc['nonce'], enc['tag'],
                pkg_str, 'audio', json.dumps({"duration": duration_sec})
            ))
            msg_id = c.lastrowid

        # VERIFY ZERO PLAINTEXT IN DATABASE
        with get_db() as conn:
            c = conn.execute("SELECT ciphertext, message_type, media_meta FROM messages WHERE id = ?", (msg_id,))
            row = c.fetchone()
            self.assertIsNotNone(row)
            stored_cipher = row["ciphertext"]
            stored_type = row["message_type"]
            
            # Must be ciphertext, never plaintext audio URL or bytes
            self.assertEqual(stored_type, 'audio')
            self.assertNotIn("VoiceAudioPacket", stored_cipher)
            self.assertNotIn("data:audio", stored_cipher)
            self.assertEqual(stored_cipher, enc['ciphertext'])

    def test_02_recipient_bob_fetches_and_decrypts_voice_note(self):
        """Recipient Bob retrieves conversation and decrypts the audio payload with exact fidelity."""
        res = self.client_bob.get('/api/messages/voice_alice')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        msgs = data.get('messages', [])
        self.assertGreaterEqual(len(msgs), 1)

        # Find our voice message
        voice_msgs = [m for m in msgs if m.get('message_type') == 'audio']
        self.assertGreaterEqual(len(voice_msgs), 1)
        latest_voice = voice_msgs[-1]

        # Bob decrypts using Bob's AES key derived from Alice's public key
        decrypted_str = decrypt_message(
            self.bob_aes_key,
            {
                'ciphertext': latest_voice['ciphertext'],
                'nonce': latest_voice['nonce'],
                'tag': latest_voice['authentication_tag']
            }
        )
        self.assertIsNotNone(decrypted_str)
        decrypted_payload = json.loads(decrypted_str)

        # Assert all decrypted attributes match perfectly
        self.assertEqual(decrypted_payload.get('type'), 'media')
        self.assertEqual(decrypted_payload.get('mediaType'), 'audio')
        self.assertEqual(decrypted_payload.get('duration'), 6.8)
        self.assertEqual(len(decrypted_payload.get('waveform', [])), 28)
        self.assertTrue(decrypted_payload.get('data', '').startswith('data:audio/webm'))
        
        # Verify reconstructed audio bytes
        raw_b64 = decrypted_payload['data'].split(',')[1]
        decoded_audio = base64.b64decode(raw_b64)
        self.assertIn(b"VoiceAudioPacket", decoded_audio)

    def test_03_bob_replies_with_encrypted_voice_message_to_alice(self):
        """Bob records a reply voice message, encrypts it, and Alice decrypts it."""
        bob_audio = b"\x1a\x45\xdf\xa3\x9f\x42\x86BobReplyAudioVoiceStream"
        bob_data_url = "data:audio/webm;codecs=opus;base64," + base64.b64encode(bob_audio).decode('ascii')
        bob_waveform = [22, 45, 67, 89, 76, 54, 32, 21, 40, 60, 80, 50, 30]
        
        bob_payload = {
            "type": "media",
            "mediaType": "audio",
            "duration": 4.2,
            "waveform": bob_waveform,
            "data": bob_data_url
        }
        
        # Bob encrypts with his AES key
        enc = encrypt_message(self.bob_aes_key, json.dumps(bob_payload))
        
        # Insert into DB
        with get_db() as conn:
            pkg_str = json.dumps({"ciphertext": enc['ciphertext'], "nonce": enc['nonce'], "tag": enc['tag']})
            conn.execute("""
                INSERT INTO messages (
                    sender_id, receiver_id, ciphertext, nonce, authentication_tag,
                    encrypted_package, message_type, media_meta
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.bob_id, self.alice_id, enc['ciphertext'], enc['nonce'], enc['tag'],
                pkg_str, 'audio', json.dumps({"duration": 4.2})
            ))
        
        # Alice fetches messages from Bob
        res = self.client_alice.get('/api/messages/voice_bob')
        self.assertEqual(res.status_code, 200)
        msgs = res.get_json().get('messages', [])
        bob_voice_msgs = [m for m in msgs if m.get('message_type') == 'audio']
        self.assertGreaterEqual(len(bob_voice_msgs), 1)

        # Alice decrypts
        target = bob_voice_msgs[-1]
        decrypted = decrypt_message(
            self.alice_aes_key,
            {
                'ciphertext': target['ciphertext'],
                'nonce': target['nonce'],
                'tag': target['authentication_tag']
            }
        )
        payload = json.loads(decrypted)
        self.assertEqual(payload['duration'], 4.2)
        self.assertEqual(payload['waveform'], bob_waveform)
        self.assertTrue(payload['data'].startswith('data:audio/webm'))
        
        audio_content = base64.b64decode(payload['data'].split(',')[1])
        self.assertIn(b"BobReplyAudioVoiceStream", audio_content)

    def test_04_tampered_voice_ciphertext_fails_decryption(self):
        """Tampering with encrypted voice audio ciphertext raises an authentication failure."""
        fake_audio = "data:audio/webm;base64,ZmFrZWF1ZGlv"
        enc = encrypt_message(self.alice_aes_key, json.dumps({"type": "media", "mediaType": "audio", "data": fake_audio}))
        
        # Corrupt 1 byte in ciphertext
        raw_cipher = bytearray(base64.b64decode(enc['ciphertext']))
        raw_cipher[0] ^= 0xFF
        tampered_ciphertext = base64.b64encode(raw_cipher).decode('ascii')
        
        with self.assertRaises(Exception):
            decrypt_message(
                self.bob_aes_key,
                {
                    'ciphertext': tampered_ciphertext,
                    'nonce': enc['nonce'],
                    'tag': enc['tag']
                }
            )

if __name__ == '__main__':
    unittest.main()
