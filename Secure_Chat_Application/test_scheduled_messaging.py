"""
test_scheduled_messaging.py
Comprehensive End-to-End Test Suite for Scheduled Messaging in TMEEE.

Verifies:
1. User registration & authentication for two distinct users (sched_alice & sched_bob).
2. Client-side E2EE encryption preparation with X25519 & AES-256-GCM.
3. Scheduling an encrypted message via REST API (POST /api/messages/schedule).
4. Zero-knowledge cryptographic storage: database stores ONLY ciphertext/nonce/tag; ZERO plaintext.
5. Validation: rejects invalid recipients, missing fields, or past scheduled timestamps.
6. Fetching scheduled messages (GET /api/messages/scheduled) with status & peer filters.
7. Editing a scheduled message (PUT /api/messages/schedule/<id>).
8. Cancelling a scheduled message (DELETE /api/messages/schedule/<id>).
9. Immediate delivery (POST /api/messages/schedule/<id>/send-now).
10. Automated delivery via dispatch_scheduled_message and get_due_scheduled_messages.
11. Decryption verification on recipient side ensuring perfect E2EE preservation.
"""

import sys
import os
import json
import time
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, create_app, socketio, online_users, dispatch_scheduled_message
from database.db import (
    init_db, get_db,
    create_scheduled_message,
    get_scheduled_messages_for_user,
    get_scheduled_messages_between,
    get_scheduled_message_by_id,
    update_scheduled_message,
    cancel_scheduled_message,
    get_due_scheduled_messages,
    mark_scheduled_message_sent
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64


def generate_test_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode('utf-8')
    return priv, pub, pub_b64


def derive_aes_key(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"TMEEE_E2EE_KEY_EXCHANGE_SALT_V1",
        info=b"TMEEE_E2EE_SESSION_KEY_V1",
    )
    return hkdf.derive(shared)


def encrypt_payload(aes_key, plaintext: str):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    }


def decrypt_payload(aes_key, pkg: dict) -> str:
    aesgcm = AESGCM(aes_key)
    ciphertext = base64.b64decode(pkg["ciphertext"])
    nonce = base64.b64decode(pkg["nonce"])
    tag = base64.b64decode(pkg["tag"])
    ct_with_tag = ciphertext + tag
    dec = aesgcm.decrypt(nonce, ct_with_tag, None)
    return dec.decode('utf-8')


class TestScheduledMessaging(unittest.TestCase):
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

        # Generate X25519 keypairs for Alice and Bob
        cls.alice_priv, cls.alice_pub, cls.alice_pub_b64 = generate_test_keypair()
        cls.bob_priv, cls.bob_pub, cls.bob_pub_b64 = generate_test_keypair()

        # Alice & Bob derive symmetric session key
        cls.alice_session_key = derive_aes_key(cls.alice_priv, cls.bob_pub)
        cls.bob_session_key = derive_aes_key(cls.bob_priv, cls.alice_pub)
        assert cls.alice_session_key == cls.bob_session_key

        # Register Alice
        cls.client_alice.post('/register', json={
            'username': 'sched_alice',
            'email': 'sched_alice@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        cls.client_alice.post('/login', json={'email': 'sched_alice@test.tmeee', 'password': 'Password123!'})

        # Register Bob
        cls.client_bob.post('/register', json={
            'username': 'sched_bob',
            'email': 'sched_bob@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        cls.client_bob.post('/login', json={'email': 'sched_bob@test.tmeee', 'password': 'Password123!'})

        # Lookup user IDs
        with get_db() as conn:
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('sched_alice',))
            cls.alice_id = c.fetchone()["id"]
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('sched_bob',))
            cls.bob_id = c.fetchone()["id"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_01_schedule_validation(self):
        """Test API validation for scheduling messages."""
        # 1. Missing recipient
        res = self.client_alice.post('/api/messages/schedule', json={
            'scheduled_for': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Recipient username is required", res.get_json()["error"])

        # 2. Missing scheduled_for
        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob'
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Scheduled date/time is required", res.get_json()["error"])

        # 3. Scheduled time in the past
        past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob',
            'scheduled_for': past_time,
            'ciphertext': 'test_ct'
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("future", res.get_json()["error"].lower())

    def test_02_schedule_message_e2ee_zero_plaintext(self):
        """Test scheduling an E2EE encrypted message and verify zero plaintext in DB."""
        plaintext = "Confidential meeting tomorrow at 10 AM UTC"
        enc = encrypt_payload(self.alice_session_key, plaintext)

        future_dt = datetime.now(timezone.utc) + timedelta(hours=2)
        future_iso = future_dt.isoformat()

        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'encrypted_package': enc,
            'scheduled_for': future_iso,
            'message_type': 'text'
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data['ok'])
        sched_id = data['scheduled_id']
        self.assertGreater(sched_id, 0)

        # Verify Database Content (ZERO PLAINTEXT)
        with get_db() as conn:
            row = conn.execute("SELECT * FROM scheduled_messages WHERE id = ?", (sched_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row['sender_id'], self.alice_id)
            self.assertEqual(row['receiver_id'], self.bob_id)
            self.assertEqual(row['status'], 'pending')
            self.assertEqual(row['ciphertext'], enc['ciphertext'])
            self.assertEqual(row['nonce'], enc['nonce'])

            # Verify plaintext NEVER exists anywhere in table
            all_cols_str = " ".join(str(v) for v in row)
            self.assertNotIn("Confidential meeting", all_cols_str)
            self.assertNotIn(plaintext, all_cols_str)

        # Verify sender can decrypt client-side using derived key
        decrypted = decrypt_payload(self.alice_session_key, {
            "ciphertext": row["ciphertext"],
            "nonce": row["nonce"],
            "tag": row["tag"] or row["authentication_tag"]
        })
        self.assertEqual(decrypted, plaintext)

    def test_03_get_scheduled_messages_filtering(self):
        """Test retrieving scheduled messages with status and peer filters."""
        # Query Alice's scheduled messages for Bob
        res = self.client_alice.get('/api/messages/scheduled?peer=sched_bob&status=pending')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['ok'])
        self.assertGreater(len(data['scheduled_messages']), 0)
        first = data['scheduled_messages'][0]
        self.assertEqual(first['recipient_username'], 'sched_bob')
        self.assertEqual(first['status'], 'pending')

    def test_04_edit_scheduled_message(self):
        """Test editing a pending scheduled message's ciphertext and time."""
        # Create message to edit
        enc = encrypt_payload(self.alice_session_key, "Original secret")
        t1 = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'encrypted_package': enc,
            'scheduled_for': t1
        })
        sched_id = res.get_json()['scheduled_id']

        # Update message
        updated_plain = "Updated secret after edit"
        updated_enc = encrypt_payload(self.alice_session_key, updated_plain)
        t2 = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()

        put_res = self.client_alice.put(f'/api/messages/schedule/{sched_id}', json={
            'ciphertext': updated_enc['ciphertext'],
            'nonce': updated_enc['nonce'],
            'tag': updated_enc['tag'],
            'encrypted_package': updated_enc,
            'scheduled_for': t2
        })
        self.assertEqual(put_res.status_code, 200)
        self.assertTrue(put_res.get_json()['ok'])

        # Check DB has updated ciphertext
        with get_db() as conn:
            row = conn.execute("SELECT * FROM scheduled_messages WHERE id = ?", (sched_id,)).fetchone()
            self.assertEqual(row['ciphertext'], updated_enc['ciphertext'])
            self.assertEqual(row['scheduled_for'], t2)

            # Decrypt verify
            dec = decrypt_payload(self.alice_session_key, {
                "ciphertext": row["ciphertext"],
                "nonce": row["nonce"],
                "tag": row["tag"]
            })
            self.assertEqual(dec, updated_plain)

    def test_05_cancel_scheduled_message(self):
        """Test cancelling a pending scheduled message."""
        enc = encrypt_payload(self.alice_session_key, "To be cancelled")
        t = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'encrypted_package': enc,
            'scheduled_for': t
        })
        sched_id = res.get_json()['scheduled_id']

        # Cancel
        del_res = self.client_alice.delete(f'/api/messages/schedule/{sched_id}')
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.get_json()['ok'])

        # Verify DB status is 'cancelled'
        with get_db() as conn:
            row = conn.execute("SELECT status FROM scheduled_messages WHERE id = ?", (sched_id,)).fetchone()
            self.assertEqual(row['status'], 'cancelled')

        # Attempt to edit cancelled message should fail
        edit_res = self.client_alice.put(f'/api/messages/schedule/{sched_id}', json={'ciphertext': 'new'})
        self.assertEqual(edit_res.status_code, 400)

    def test_06_send_now_immediate_delivery(self):
        """Test sending a scheduled message immediately via send-now endpoint."""
        plaintext = "Urgent scheduled message sent early!"
        enc = encrypt_payload(self.alice_session_key, plaintext)
        t = (datetime.now(timezone.utc) + timedelta(hours=10)).isoformat()
        res = self.client_alice.post('/api/messages/schedule', json={
            'recipient_username': 'sched_bob',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'encrypted_package': enc,
            'scheduled_for': t
        })
        sched_id = res.get_json()['scheduled_id']

        # Trigger send-now
        send_now_res = self.client_alice.post(f'/api/messages/schedule/{sched_id}/send-now')
        self.assertEqual(send_now_res.status_code, 200)
        data = send_now_res.get_json()
        self.assertTrue(data['ok'])
        new_msg_id = data['message_id']
        self.assertIsNotNone(new_msg_id)

        # Verify scheduled message marked as 'sent'
        with get_db() as conn:
            sched_row = conn.execute("SELECT status, actual_message_id FROM scheduled_messages WHERE id = ?", (sched_id,)).fetchone()
            self.assertEqual(sched_row['status'], 'sent')
            self.assertEqual(sched_row['actual_message_id'], new_msg_id)

            # Verify row exists in messages table
            msg_row = conn.execute("SELECT * FROM messages WHERE id = ?", (new_msg_id,)).fetchone()
            self.assertIsNotNone(msg_row)
            self.assertEqual(msg_row['sender_id'], self.alice_id)
            self.assertEqual(msg_row['receiver_id'], self.bob_id)
            self.assertEqual(msg_row['ciphertext'], enc['ciphertext'])

        # Verify Bob (recipient) can decrypt it
        bob_decrypted = decrypt_payload(self.bob_session_key, {
            "ciphertext": msg_row["ciphertext"],
            "nonce": msg_row["nonce"],
            "tag": msg_row["authentication_tag"] or msg_row["tag"]
        })
        self.assertEqual(bob_decrypted, plaintext)

    def test_07_automated_dispatcher_delivery(self):
        """Test background scheduled message delivery mechanism for due messages."""
        plaintext = "Automated arrival right on time!"
        enc = encrypt_payload(self.alice_session_key, plaintext)

        # Set scheduled_for to 5 seconds in the past to simulate due delivery
        due_time = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        sched_id = create_scheduled_message(
            sender_id=self.alice_id,
            receiver_id=self.bob_id,
            ciphertext=enc['ciphertext'],
            nonce=enc['nonce'],
            tag=enc['tag'],
            encrypted_package=json.dumps(enc),
            scheduled_for=due_time,
            message_type='text'
        )
        self.assertIsNotNone(sched_id)

        # Check that get_due_scheduled_messages detects it
        due_list = get_due_scheduled_messages()
        due_ids = [m['id'] for m in due_list]
        self.assertIn(sched_id, due_ids)

        target_due = next(m for m in due_list if m['id'] == sched_id)
        # Dispatch it
        delivered_msg_id = dispatch_scheduled_message(target_due)
        self.assertIsNotNone(delivered_msg_id)

        # Verify scheduled_messages status updated to 'sent'
        sched_check = get_scheduled_message_by_id(sched_id)
        self.assertEqual(sched_check['status'], 'sent')
        self.assertEqual(sched_check['actual_message_id'], delivered_msg_id)

        # Verify it is no longer due
        due_list_after = get_due_scheduled_messages()
        due_ids_after = [m['id'] for m in due_list_after]
        self.assertNotIn(sched_id, due_ids_after)

        # Verify recipient can decrypt the delivered message
        with get_db() as conn:
            delivered_row = conn.execute("SELECT * FROM messages WHERE id = ?", (delivered_msg_id,)).fetchone()
            self.assertIsNotNone(delivered_row)
            dec = decrypt_payload(self.bob_session_key, {
                "ciphertext": delivered_row["ciphertext"],
                "nonce": delivered_row["nonce"],
                "tag": delivered_row["authentication_tag"] or delivered_row["tag"]
            })
            self.assertEqual(dec, plaintext)


if __name__ == '__main__':
    unittest.main()
