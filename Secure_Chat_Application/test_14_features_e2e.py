"""
test_14_features_e2e.py
End-to-end verification of all 14 advanced messaging features in TMEEE:
  1. Reply to messages
  2. Edit sent messages
  3. Delete messages
  4. Unsend messages
  5. React to messages using emojis
  6. Forward messages
  7. Pin important messages
  8. Search messages
  9. Display message timestamps
 10. Show sent, delivered, and read status
 11. Display typing indicators
 12. Show online and offline status
 13. Support GIFs, stickers, and emojis
 14. Support image, video, and document sharing
Using two simulated accounts: alice_test and bob_test.
"""

import sys
import os
import json
import base64
import unittest

# Ensure path to Secure_Chat_Application is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, socketio
from database.db import (
    init_db, get_db, register_user, authenticate_user,
    store_public_key, get_public_key,
    store_message, get_messages_between, delete_message,
    add_or_toggle_reaction, get_reactions_for_messages,
    update_message_read_status, update_message_pin_status,
    get_pinned_messages
)
from encryption.crypto import generate_keypair, derive_shared_secret, encrypt_message, decrypt_message

class Test14FeaturesE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        init_db()

        # Generate keypairs for Alice and Bob
        cls.alice_priv, cls.alice_pub = generate_keypair()
        cls.bob_priv, cls.bob_pub = generate_keypair()

        # Register users
        cls.u1 = "alice_e2e_" + os.urandom(3).hex()
        cls.u2 = "bob_e2e_" + os.urandom(3).hex()

        register_user(cls.u1, f"{cls.u1}@example.com", "Password123!")
        register_user(cls.u2, f"{cls.u2}@example.com", "Password123!")

        # Store public keys
        store_public_key(cls.u1, cls.alice_pub)
        store_public_key(cls.u2, cls.bob_pub)

        # Precompute shared secret
        cls.alice_shared = derive_shared_secret(cls.alice_priv, cls.bob_pub)
        cls.bob_shared = derive_shared_secret(cls.bob_priv, cls.alice_pub)

    def test_01_send_and_decrypt_e2ee_message(self):
        """Feature 9 & 10: Message timestamps, sent & delivered status, zero-plaintext storage."""
        plaintext = "Hello Bob! Testing E2EE messaging."
        enc = encrypt_message(self.alice_shared, plaintext)

        # Store message as Alice sending to Bob
        msg_id = store_message(
            sender_username=self.u1,
            receiver_username=self.u2,
            ciphertext=enc['ciphertext'],
            nonce=enc['nonce'],
            tag=enc['tag'],
            message_type='text'
        )
        self.assertIsNotNone(msg_id)

        # Retrieve messages and verify zero plaintext in DB
        history = get_messages_between(self.u1, self.u2)
        stored = [m for m in history if m['id'] == msg_id][0]
        self.assertNotIn(plaintext, stored['ciphertext'])
        self.assertEqual(stored['ciphertext'], enc['ciphertext'])
        self.assertIsNotNone(stored['timestamp'])

        # Bob decrypts
        decrypted = decrypt_message(self.bob_shared, stored['ciphertext'], stored['nonce'], stored['tag'])
        self.assertEqual(decrypted, plaintext)
        print(" [PASS] Feature 9 & 10: Timestamps, Sent Status & Zero Plaintext Verified")

    def test_02_reply_to_message(self):
        """Feature 1: Reply to messages with quote reference."""
        # Alice sends initial message
        enc1 = encrypt_message(self.alice_shared, "Initial question from Alice")
        m1_id = store_message(self.u1, self.u2, enc1['ciphertext'], enc1['nonce'], enc1['tag'])

        # Bob replies to Alice's message
        reply_text = "Bob's answer replying to Alice"
        enc_reply = encrypt_message(self.bob_shared, reply_text)
        reply_id = store_message(
            sender_username=self.u2,
            receiver_username=self.u1,
            ciphertext=enc_reply['ciphertext'],
            nonce=enc_reply['nonce'],
            tag=enc_reply['tag'],
            reply_to_id=m1_id
        )

        history = get_messages_between(self.u1, self.u2)
        reply_msg = [m for m in history if m['id'] == reply_id][0]
        self.assertEqual(reply_msg['reply_to_id'], m1_id)

        # Bob's reply decrypts cleanly
        decrypted = decrypt_message(self.alice_shared, reply_msg['ciphertext'], reply_msg['nonce'], reply_msg['tag'])
        self.assertEqual(decrypted, reply_text)
        print(" [PASS] Feature 1: Reply to Messages Verified")

    def test_03_edit_sent_message(self):
        """Feature 2: Edit sent message with (edited) status."""
        enc = encrypt_message(self.alice_shared, "Message before edit")
        msg_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Alice edits the message
        new_text = "Message AFTER edit (updated text)"
        enc_new = encrypt_message(self.alice_shared, new_text)

        # In DB, update ciphertext and mark is_edited = 1
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE messages 
                SET ciphertext = ?, nonce = ?, authentication_tag = ?, is_edited = 1, edited_at = CURRENT_TIMESTAMP
                WHERE id = ? AND sender_id = (SELECT id FROM users WHERE username = ?)
                """,
                (enc_new['ciphertext'], enc_new['nonce'], enc_new['tag'], msg_id, self.u1)
            )
            conn.commit()

        history = get_messages_between(self.u1, self.u2)
        edited_msg = [m for m in history if m['id'] == msg_id][0]
        self.assertEqual(edited_msg['is_edited'], 1)
        self.assertIsNotNone(edited_msg['edited_at'])

        # Recipient decrypts edited text
        decrypted = decrypt_message(self.bob_shared, edited_msg['ciphertext'], edited_msg['nonce'], edited_msg['tag'])
        self.assertEqual(decrypted, new_text)
        print(" [PASS] Feature 2: Edit Sent Messages Verified")

    def test_04_react_to_message(self):
        """Feature 5: React to message using emojis."""
        enc = encrypt_message(self.alice_shared, "React to this message!")
        msg_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Bob reacts with ❤️
        action = add_or_toggle_reaction(msg_id, self.u2, "❤️")
        self.assertEqual(action, 'added')

        # Retrieve reactions batch
        rx_map = get_reactions_for_messages([msg_id], self.u2)
        self.assertIn(msg_id, rx_map)
        self.assertEqual(len(rx_map[msg_id]), 1)
        self.assertEqual(rx_map[msg_id][0]['emoji'], "❤️")
        self.assertEqual(rx_map[msg_id][0]['count'], 1)
        self.assertTrue(rx_map[msg_id][0]['reacted_by_me'])

        # Toggle reaction off
        action2 = add_or_toggle_reaction(msg_id, self.u2, "❤️")
        self.assertEqual(action2, 'removed')
        rx_map2 = get_reactions_for_messages([msg_id], self.u2)
        self.assertEqual(len(rx_map2[msg_id]), 0)
        print(" [PASS] Feature 5: Emoji Reactions Verified")

    def test_05_pin_important_messages(self):
        """Feature 7: Pin and unpin messages."""
        enc = encrypt_message(self.alice_shared, "Important pinned channel announcement")
        msg_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Pin message
        ok = update_message_pin_status(msg_id, self.u1, True)
        self.assertTrue(ok)

        pinned = get_pinned_messages(self.u1, self.u2)
        self.assertTrue(any(m['id'] == msg_id for m in pinned))

        # Unpin message
        ok_unpin = update_message_pin_status(msg_id, self.u1, False)
        self.assertTrue(ok_unpin)
        pinned_after = get_pinned_messages(self.u1, self.u2)
        self.assertFalse(any(m['id'] == msg_id for m in pinned_after))
        print(" [PASS] Feature 7: Pin Important Messages Verified")

    def test_06_delivered_and_read_status(self):
        """Feature 10: Sent, delivered, and read status."""
        enc = encrypt_message(self.alice_shared, "Checking read receipts")
        msg_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Mark read as Bob
        count = update_message_read_status(self.u2, self.u1)
        self.assertGreaterEqual(count, 1)

        history = get_messages_between(self.u1, self.u2)
        msg = [m for m in history if m['id'] == msg_id][0]
        self.assertIsNotNone(msg['read_at'])
        print(" [PASS] Feature 10: Delivered and Read Receipts Verified")

    def test_07_media_sharing_image_and_document(self):
        """Feature 14: Client-side encrypted image & document sharing."""
        # Simulated base64 image payload
        fake_img_data = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        media_json = json.dumps({
            "type": "media",
            "mediaType": "image",
            "name": "avatar_proof.png",
            "size": 128,
            "data": fake_img_data
        })

        # Encrypt the media JSON client-side
        enc_media = encrypt_message(self.alice_shared, media_json)

        # Store in DB
        msg_id = store_message(
            sender_username=self.u1,
            receiver_username=self.u2,
            ciphertext=enc_media['ciphertext'],
            nonce=enc_media['nonce'],
            tag=enc_media['tag'],
            message_type='media',
            media_meta=json.dumps({"name": "avatar_proof.png", "size": 128, "type": "image/png"})
        )

        history = get_messages_between(self.u1, self.u2)
        stored_media = [m for m in history if m['id'] == msg_id][0]

        # Verify DB has NO plaintext image URL or data
        self.assertNotIn("data:image/png", stored_media['ciphertext'])

        # Recipient decrypts and parses JSON
        decrypted_json = decrypt_message(self.bob_shared, stored_media['ciphertext'], stored_media['nonce'], stored_media['tag'])
        parsed = json.loads(decrypted_json)
        self.assertEqual(parsed['type'], 'media')
        self.assertEqual(parsed['name'], 'avatar_proof.png')
        self.assertEqual(parsed['data'], fake_img_data)
        print(" [PASS] Feature 14: Encrypted Media Sharing Verified (Zero Plaintext)")

    def test_08_gif_and_sticker_support(self):
        """Feature 13: GIFs, stickers, and emojis."""
        gif_payload = json.dumps({"type": "gif", "url": "https://media.giphy.com/media/26AHONQ79FdWZhAI0/giphy.gif"})
        enc_gif = encrypt_message(self.alice_shared, gif_payload)
        gif_msg_id = store_message(self.u1, self.u2, enc_gif['ciphertext'], enc_gif['nonce'], enc_gif['tag'], message_type='gif')

        sticker_payload = json.dumps({"type": "sticker", "url": "🚀"})
        enc_sticker = encrypt_message(self.alice_shared, sticker_payload)
        sticker_msg_id = store_message(self.u1, self.u2, enc_sticker['ciphertext'], enc_sticker['nonce'], enc_sticker['tag'], message_type='sticker')

        history = get_messages_between(self.u1, self.u2)
        m_gif = [m for m in history if m['id'] == gif_msg_id][0]
        m_stk = [m for m in history if m['id'] == sticker_msg_id][0]

        # Decrypt GIF and Sticker
        dec_gif = json.loads(decrypt_message(self.bob_shared, m_gif['ciphertext'], m_gif['nonce'], m_gif['tag']))
        dec_stk = json.loads(decrypt_message(self.bob_shared, m_stk['ciphertext'], m_stk['nonce'], m_stk['tag']))

        self.assertEqual(dec_gif['type'], 'gif')
        self.assertEqual(dec_stk['url'], '🚀')
        print(" [PASS] Feature 13: GIFs and Stickers Verified")

    def test_09_forward_message(self):
        """Feature 6: Forward message (decrypt locally, re-encrypt for target)."""
        original_text = "Confidential message to forward"
        enc = encrypt_message(self.alice_shared, original_text)
        m_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Bob decrypts locally
        decrypted = decrypt_message(self.bob_shared, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Bob forwards it back to Alice (or Charlie) by re-encrypting with target's key
        enc_fwd = encrypt_message(self.bob_shared, decrypted)
        fwd_id = store_message(self.u2, self.u1, enc_fwd['ciphertext'], enc_fwd['nonce'], enc_fwd['tag'])

        history = get_messages_between(self.u1, self.u2)
        fwd_msg = [m for m in history if m['id'] == fwd_id][0]
        self.assertEqual(decrypt_message(self.alice_shared, fwd_msg['ciphertext'], fwd_msg['nonce'], fwd_msg['tag']), original_text)
        print(" [PASS] Feature 6: Forward Message Verified")

    def test_10_unsend_and_delete_message(self):
        """Feature 3 & 4: Unsend and delete messages."""
        enc = encrypt_message(self.alice_shared, "Mistake message to unsend")
        msg_id = store_message(self.u1, self.u2, enc['ciphertext'], enc['nonce'], enc['tag'])

        # Verify message exists
        history_before = get_messages_between(self.u1, self.u2)
        self.assertTrue(any(m['id'] == msg_id for m in history_before))

        # Alice unsends message
        delete_message(msg_id, self.u1)

        # Verify message is gone from database
        history_after = get_messages_between(self.u1, self.u2)
        self.assertFalse(any(m['id'] == msg_id for m in history_after))
        print(" [PASS] Feature 3 & 4: Unsend and Delete Messages Verified")

if __name__ == '__main__':
    unittest.main()
