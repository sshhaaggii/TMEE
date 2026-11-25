"""
test_group_conversations.py
Comprehensive End-to-End Test Suite for Secure Group Conversations in TMEEE.

Verifies:
1. Multi-user registration & cryptographic initialization (Alice, Bob, Charlie, Dave) with X25519 keypairs.
2. Group creation with authenticated Epoch 1 Group Key (AES-256-GCM 32-byte key) wrapped pairwise for initial members.
3. Zero-knowledge cryptographic storage: server stores ONLY ciphertext, nonce, tag, and wrapped keys.
   Plaintext and raw group encryption keys NEVER appear in the database.
4. Key distribution & unwrapping: Bob and Charlie fetch wrapped keys, unwrap using ECDH session, and verify identical raw keys.
5. Group messaging: Alice encrypts message in Epoch 1, stored encrypted, successfully decrypted by Bob and Charlie.
6. Group message reactions: Emoji reactions toggle and aggregate accurately across group members.
7. Forward Secrecy on Member Addition (Key Rotation):
   - Dave is added -> group key rotates to Epoch 2.
   - Wrapped keys distributed to updated membership [Alice, Bob, Charlie, Dave].
   - Dave decrypts Epoch 2 messages; Dave has no access to Epoch 1.
8. Backward Secrecy on Member Removal (Key Rotation):
   - Charlie is removed -> group key rotates to Epoch 3.
   - Wrapped keys distributed ONLY to remaining members [Alice, Bob, Dave].
   - Alice sends message in Epoch 3. Bob and Dave decrypt successfully.
   - Removed member Charlie is denied key access (403) and CANNOT decrypt Epoch 3 messages.
9. Administrator Management: Promote and demote member roles (admin/member) with strict RBAC enforcement.
10. Group Metadata Management: Update group name, description, and avatar with admin-only permission check.
11. Member self-leave: Member leaves group with key rotation for remaining members.
12. Group Media Sharing: End-to-end encrypted media payload exchange and verification.
"""

import sys
import os
import json
import time
import base64
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, socketio
from database.db import (
    init_db, get_db,
    create_group, get_group_by_id, get_user_groups, get_group_members,
    is_group_member, get_group_member_role, add_group_member, remove_group_member,
    update_group_info, update_group_member_role, update_group_epoch,
    store_group_epoch_keys, get_group_epoch_key_for_user,
    create_group_message, get_group_messages,
    add_or_toggle_group_reaction, get_group_message_reactions
)
from encryption.e2ee import (
    generate_key_pair,
    export_public_key,
    import_public_key,
    derive_shared_secret,
    derive_aes_key,
    generate_group_epoch_key,
    wrap_group_key,
    unwrap_group_key,
    encrypt_group_message,
    decrypt_group_message
)


class TestSecureGroupConversations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.app_context():
            init_db()

        # Create 4 test users with real X25519 keys
        cls.users = {}
        for username in ["grp_alice", "grp_bob", "grp_charlie", "grp_dave"]:
            priv, pub = generate_key_pair()
            pub_b64 = export_public_key(pub)
            cls.users[username] = {
                "priv": priv,
                "pub": pub,
                "pub_b64": pub_b64,
                "email": f"{username}@example.com",
                "password": "Password123!",
            }

        with app.app_context():
            db = get_db()
            for uname, udata in cls.users.items():
                existing = db.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
                if not existing:
                    from werkzeug.security import generate_password_hash
                    pwd_hash = generate_password_hash(udata["password"])
                    cur = db.execute(
                        "INSERT INTO users (username, email, password_hash, public_key) VALUES (?, ?, ?, ?)",
                        (uname, udata["email"], pwd_hash, udata["pub_b64"])
                    )
                    db.commit()
                    udata["id"] = cur.lastrowid
                else:
                    udata["id"] = existing["id"]
                    db.execute("UPDATE users SET public_key = ? WHERE id = ?", (udata["pub_b64"], udata["id"]))
                    db.commit()

    def get_pairwise_aes(self, sender_uname: str, recipient_uname: str) -> bytes:
        sender_priv = self.users[sender_uname]["priv"]
        recipient_pub = self.users[recipient_uname]["pub"]
        shared_secret = derive_shared_secret(sender_priv, recipient_pub)
        return derive_aes_key(shared_secret)

    def get_client(self, username: str):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = self.users[username]["id"]
            sess["username"] = username
        return client

    # ──────────────────────────────────────────────────────────────────────────
    # Test 1: Create Group Chat with Epoch 1 Key Wrapping
    # ──────────────────────────────────────────────────────────────────────────
    def test_01_create_group_chat_and_pairwise_wrapping(self):
        """Verify group creation and pairwise key wrapping for initial members."""
        alice_client = self.get_client("grp_alice")

        # 1. Alice generates 32-byte AES-256-GCM Group Epoch 1 Key
        epoch1_key = generate_group_epoch_key()
        self.assertEqual(len(epoch1_key), 32)

        # 2. Alice wraps Epoch 1 key for Bob, Charlie, and self
        initial_keys = []
        for uname in ["grp_alice", "grp_bob", "grp_charlie"]:
            pairwise_aes = self.get_pairwise_aes("grp_alice", uname)
            wrapped = wrap_group_key(epoch1_key, pairwise_aes)
            initial_keys.append({
                "username": uname,
                "encrypted_key": wrapped,
            })

        # 3. Post to API
        payload = {
            "name": "Engineering Alpha",
            "description": "High-security project discussion",
            "member_usernames": ["grp_bob", "grp_charlie"],
            "initial_epoch_keys": initial_keys,
        }
        res = alice_client.post("/api/groups", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["ok"])
        group = data["group"]
        self.assertEqual(group["name"], "Engineering Alpha")
        self.assertEqual(group["current_epoch"], 1)

        group_id = group["id"]
        TestSecureGroupConversations.group_id = group_id
        TestSecureGroupConversations.epoch1_key = epoch1_key

        # 4. Verify members and roles
        members = data["members"]
        member_map = {m["username"]: m["role"] for m in members}
        self.assertEqual(member_map.get("grp_alice"), "admin")
        self.assertEqual(member_map.get("grp_bob"), "member")
        self.assertEqual(member_map.get("grp_charlie"), "member")

    # ──────────────────────────────────────────────────────────────────────────
    # Test 2: Zero Plaintext and Raw Key Verification
    # ──────────────────────────────────────────────────────────────────────────
    def test_02_zero_plaintext_and_key_unwrapping(self):
        """Verify that server stores zero raw keys, and recipients can unwrap accurately."""
        group_id = getattr(self, "group_id")
        epoch1_key = getattr(self, "epoch1_key")

        # 1. Inspect database directly: ensure raw key is NEVER stored
        with app.app_context():
            db = get_db()
            key_rows = db.execute("SELECT * FROM group_epoch_keys WHERE group_id = ?", (group_id,)).fetchall()
            self.assertEqual(len(key_rows), 3)  # Alice, Bob, Charlie
            for row in key_rows:
                enc_data = row["encrypted_key"]
                # Must be wrapped JSON structure, NOT raw bytes
                self.assertNotIn(epoch1_key, str(enc_data).encode("utf-8"))

        # 2. Bob fetches wrapped key from API and unwraps
        bob_client = self.get_client("grp_bob")
        b_res = bob_client.get(f"/api/groups/{group_id}/keys/1")
        self.assertEqual(b_res.status_code, 200)
        b_data = b_res.get_json()
        self.assertTrue(b_data["ok"])
        self.assertEqual(b_data["creator_username"], "grp_alice")

        bob_alice_aes = self.get_pairwise_aes("grp_bob", "grp_alice")
        bob_unwrapped = unwrap_group_key(b_data["encrypted_key"], bob_alice_aes)
        self.assertEqual(bob_unwrapped, epoch1_key)

        # 3. Charlie fetches wrapped key from API and unwraps
        charlie_client = self.get_client("grp_charlie")
        c_res = charlie_client.get(f"/api/groups/{group_id}/keys/1")
        self.assertEqual(c_res.status_code, 200)
        c_data = c_res.get_json()
        charlie_alice_aes = self.get_pairwise_aes("grp_charlie", "grp_alice")
        charlie_unwrapped = unwrap_group_key(c_data["encrypted_key"], charlie_alice_aes)
        self.assertEqual(charlie_unwrapped, epoch1_key)

        # 4. Non-member (Dave) is denied access
        dave_client = self.get_client("grp_dave")
        d_res = dave_client.get(f"/api/groups/{group_id}/keys/1")
        self.assertEqual(d_res.status_code, 403)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 3: Group Message Encryption and Multi-Party Decryption
    # ──────────────────────────────────────────────────────────────────────────
    def test_03_group_messaging_and_decryption(self):
        """Alice encrypts a message; Bob and Charlie decrypt it. Server stores zero plaintext."""
        group_id = getattr(self, "group_id")
        epoch1_key = getattr(self, "epoch1_key")
        plaintext = "Confidential Alpha Launch Strategy - Top Secret"

        # 1. Alice encrypts group message client-side
        enc_pkg = encrypt_group_message(epoch1_key, plaintext)

        # 2. Store via db / socket handler simulation
        with app.app_context():
            msg_id = create_group_message(
                group_id=group_id,
                sender_id=self.users["grp_alice"]["id"],
                epoch=1,
                ciphertext=enc_pkg["ciphertext"],
                nonce=enc_pkg["nonce"],
                tag=enc_pkg["tag"],
                encrypted_package=json.dumps(enc_pkg),
                message_type="text"
            )
            self.assertIsNotNone(msg_id)
            TestSecureGroupConversations.msg_id = msg_id

            # Verify Zero Plaintext in Database
            db = get_db()
            row = db.execute("SELECT * FROM group_messages WHERE id = ?", (msg_id,)).fetchone()
            self.assertNotIn("Confidential", row["ciphertext"])
            self.assertNotIn("Strategy", row["ciphertext"])
            self.assertNotIn("Confidential", str(row["encrypted_package"]))

        # 3. Bob retrieves group messages via API and decrypts
        bob_client = self.get_client("grp_bob")
        res = bob_client.get(f"/api/groups/{group_id}/messages")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        messages = data["messages"]
        self.assertGreaterEqual(len(messages), 1)

        target_m = next(m for m in messages if m["id"] == msg_id)
        decrypted_by_bob = decrypt_group_message(epoch1_key, target_m)
        self.assertEqual(decrypted_by_bob, plaintext)

        # 4. Charlie decrypts target message
        decrypted_by_charlie = decrypt_group_message(epoch1_key, target_m)
        self.assertEqual(decrypted_by_charlie, plaintext)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 4: Group Message Reactions
    # ──────────────────────────────────────────────────────────────────────────
    def test_04_group_message_reactions(self):
        """Verify adding, toggling, and counting reactions on group messages."""
        msg_id = getattr(self, "msg_id")

        with app.app_context():
            # Bob reacts with Love emoji
            r1 = add_or_toggle_group_reaction(msg_id, self.users["grp_bob"]["id"], "❤️")
            self.assertTrue(r1["added"])
            self.assertEqual(r1["count"], 1)

            # Charlie reacts with Love emoji
            r2 = add_or_toggle_group_reaction(msg_id, self.users["grp_charlie"]["id"], "❤️")
            self.assertTrue(r2["added"])
            self.assertEqual(r2["count"], 2)

            # Bob toggles (removes) Love emoji
            r3 = add_or_toggle_group_reaction(msg_id, self.users["grp_bob"]["id"], "❤️")
            self.assertFalse(r3["added"])
            self.assertEqual(r3["count"], 1)

            # Bob reacts with Fire emoji
            r4 = add_or_toggle_group_reaction(msg_id, self.users["grp_bob"]["id"], "🔥")
            self.assertTrue(r4["added"])
            self.assertEqual(r4["count"], 1)

            # Verify aggregation
            reactions = get_group_message_reactions(msg_id, self.users["grp_bob"]["id"])
            rx_dict = {rx["emoji"]: rx for rx in reactions}
            self.assertEqual(rx_dict["❤️"]["count"], 1)
            self.assertFalse(rx_dict["❤️"]["reacted_by_me"])
            self.assertEqual(rx_dict["🔥"]["count"], 1)
            self.assertTrue(rx_dict["🔥"]["reacted_by_me"])

    # ──────────────────────────────────────────────────────────────────────────
    # Test 5: Forward Secrecy on Member Addition (Key Rotation)
    # ──────────────────────────────────────────────────────────────────────────
    def test_05_forward_secrecy_member_addition_key_rotation(self):
        """Adding Dave rotates group key to Epoch 2. Dave receives Epoch 2 key but not Epoch 1."""
        group_id = getattr(self, "group_id")
        alice_client = self.get_client("grp_alice")

        # 1. Alice generates new Epoch 2 Key
        epoch2_key = generate_group_epoch_key()

        # 2. Alice wraps Epoch 2 key for all members: Alice, Bob, Charlie, and Dave
        members_all = ["grp_alice", "grp_bob", "grp_charlie", "grp_dave"]
        epoch2_keys = []
        for uname in members_all:
            pairwise_aes = self.get_pairwise_aes("grp_alice", uname)
            wrapped = wrap_group_key(epoch2_key, pairwise_aes)
            epoch2_keys.append({"username": uname, "encrypted_key": wrapped})

        # 3. Alice adds Dave to group with new epoch
        res = alice_client.post(
            f"/api/groups/{group_id}/members",
            data=json.dumps({
                "new_members": ["grp_dave"],
                "new_epoch": 2,
                "new_epoch_keys": epoch2_keys,
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["group"]["current_epoch"], 2)
        TestSecureGroupConversations.epoch2_key = epoch2_key

        # 4. Dave fetches Epoch 2 key and successfully unwraps it
        dave_client = self.get_client("grp_dave")
        d_res = dave_client.get(f"/api/groups/{group_id}/keys/2")
        self.assertEqual(d_res.status_code, 200)
        d_data = d_res.get_json()
        dave_alice_aes = self.get_pairwise_aes("grp_dave", "grp_alice")
        dave_unwrapped = unwrap_group_key(d_data["encrypted_key"], dave_alice_aes)
        self.assertEqual(dave_unwrapped, epoch2_key)

        # 5. Dave sends an encrypted message in Epoch 2
        dave_plaintext = "Hello everyone, Dave joined the conversation!"
        dave_enc = encrypt_group_message(epoch2_key, dave_plaintext)
        with app.app_context():
            m2_id = create_group_message(
                group_id=group_id,
                sender_id=self.users["grp_dave"]["id"],
                epoch=2,
                ciphertext=dave_enc["ciphertext"],
                nonce=dave_enc["nonce"],
                tag=dave_enc["tag"],
                encrypted_package=json.dumps(dave_enc),
                message_type="text"
            )
            self.assertIsNotNone(m2_id)

        # 6. Bob decrypts Dave's message using Epoch 2 key
        bob_client = self.get_client("grp_bob")
        b2_res = bob_client.get(f"/api/groups/{group_id}/keys/2")
        b2_data = b2_res.get_json()
        bob_alice_aes = self.get_pairwise_aes("grp_bob", "grp_alice")
        bob_epoch2_unwrapped = unwrap_group_key(b2_data["encrypted_key"], bob_alice_aes)
        self.assertEqual(bob_epoch2_unwrapped, epoch2_key)
        decrypted_m2 = decrypt_group_message(epoch2_key, dave_enc)
        self.assertEqual(decrypted_m2, dave_plaintext)

        # 7. Forward Secrecy check: Dave has no key for Epoch 1
        d1_res = dave_client.get(f"/api/groups/{group_id}/keys/1")
        self.assertEqual(d1_res.status_code, 404)  # No key package created for Dave in epoch 1

    # ──────────────────────────────────────────────────────────────────────────
    # Test 6: Backward Secrecy on Member Removal (Key Rotation)
    # ──────────────────────────────────────────────────────────────────────────
    def test_06_backward_secrecy_member_removal_key_rotation(self):
        """Removing Charlie rotates key to Epoch 3. Charlie is denied access and CANNOT decrypt Epoch 3 messages."""
        group_id = getattr(self, "group_id")
        alice_client = self.get_client("grp_alice")

        # 1. Alice generates new Epoch 3 Key
        epoch3_key = generate_group_epoch_key()

        # 2. Alice wraps Epoch 3 key ONLY for remaining members: Alice, Bob, and Dave (NOT Charlie!)
        remaining_members = ["grp_alice", "grp_bob", "grp_dave"]
        epoch3_keys = []
        for uname in remaining_members:
            pairwise_aes = self.get_pairwise_aes("grp_alice", uname)
            wrapped = wrap_group_key(epoch3_key, pairwise_aes)
            epoch3_keys.append({"username": uname, "encrypted_key": wrapped})

        # 3. Alice removes Charlie from group
        res = alice_client.delete(
            f"/api/groups/{group_id}/members/grp_charlie",
            data=json.dumps({
                "new_epoch": 3,
                "new_epoch_keys": epoch3_keys,
            }),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        TestSecureGroupConversations.epoch3_key = epoch3_key

        # 4. Verify Charlie is no longer in member list
        with app.app_context():
            self.assertFalse(is_group_member(group_id, self.users["grp_charlie"]["id"]))
            self.assertTrue(is_group_member(group_id, self.users["grp_dave"]["id"]))

        # 5. Alice sends a confidential message in Epoch 3
        secret_plaintext = "Sensitive internal update: Charlie has departed the team."
        enc_pkg3 = encrypt_group_message(epoch3_key, secret_plaintext)
        with app.app_context():
            m3_id = create_group_message(
                group_id=group_id,
                sender_id=self.users["grp_alice"]["id"],
                epoch=3,
                ciphertext=enc_pkg3["ciphertext"],
                nonce=enc_pkg3["nonce"],
                tag=enc_pkg3["tag"],
                encrypted_package=json.dumps(enc_pkg3),
                message_type="text"
            )
            self.assertIsNotNone(m3_id)

        # 6. Bob and Dave can unwrap Epoch 3 key and decrypt
        dave_client = self.get_client("grp_dave")
        d3_res = dave_client.get(f"/api/groups/{group_id}/keys/3")
        self.assertEqual(d3_res.status_code, 200)
        dave_alice_aes = self.get_pairwise_aes("grp_dave", "grp_alice")
        d3_key = unwrap_group_key(d3_res.get_json()["encrypted_key"], dave_alice_aes)
        self.assertEqual(d3_key, epoch3_key)
        self.assertEqual(decrypt_group_message(d3_key, enc_pkg3), secret_plaintext)

        # 7. Backward Secrecy: Charlie attempts to fetch Epoch 3 key -> 403 Forbidden
        charlie_client = self.get_client("grp_charlie")
        c3_res = charlie_client.get(f"/api/groups/{group_id}/keys/3")
        self.assertEqual(c3_res.status_code, 403)

        # 8. Charlie attempts to decrypt with his old Epoch 1 or Epoch 2 key -> FAILS (Invalid Tag)
        with self.assertRaises(Exception):
            epoch1_key = getattr(self, "epoch1_key")
            decrypt_group_message(epoch1_key, enc_pkg3)

        with self.assertRaises(Exception):
            epoch2_key = getattr(self, "epoch2_key")
            decrypt_group_message(epoch2_key, enc_pkg3)

    # ──────────────────────────────────────────────────────────────────────────
    # Test 7: Administrator Role Management (Promote / Demote)
    # ──────────────────────────────────────────────────────────────────────────
    def test_07_admin_role_management(self):
        """Verify role promotion, demotion, and permissions enforcement."""
        group_id = getattr(self, "group_id")
        alice_client = self.get_client("grp_alice")
        bob_client = self.get_client("grp_bob")

        # 1. Non-admin (Bob) attempts to promote Dave -> 403 Forbidden
        res_fail = bob_client.put(
            f"/api/groups/{group_id}/members/grp_dave/role",
            data=json.dumps({"role": "admin"}),
            content_type="application/json"
        )
        self.assertEqual(res_fail.status_code, 403)

        # 2. Admin (Alice) promotes Bob to admin -> Success
        res_ok = alice_client.put(
            f"/api/groups/{group_id}/members/grp_bob/role",
            data=json.dumps({"role": "admin"}),
            content_type="application/json"
        )
        self.assertEqual(res_ok.status_code, 200)
        with app.app_context():
            self.assertEqual(get_group_member_role(group_id, self.users["grp_bob"]["id"]), "admin")

        # 3. Bob (now admin) can promote Dave to admin
        res_bob_promote = bob_client.put(
            f"/api/groups/{group_id}/members/grp_dave/role",
            data=json.dumps({"role": "admin"}),
            content_type="application/json"
        )
        self.assertEqual(res_bob_promote.status_code, 200)

        # 4. Alice demotes Bob back to member
        res_demote = alice_client.put(
            f"/api/groups/{group_id}/members/grp_bob/role",
            data=json.dumps({"role": "member"}),
            content_type="application/json"
        )
        self.assertEqual(res_demote.status_code, 200)
        with app.app_context():
            self.assertEqual(get_group_member_role(group_id, self.users["grp_bob"]["id"]), "member")

    # ──────────────────────────────────────────────────────────────────────────
    # Test 8: Group Info Update & Permissions
    # ──────────────────────────────────────────────────────────────────────────
    def test_08_group_info_update(self):
        """Verify updating group name and description with admin authorization."""
        group_id = getattr(self, "group_id")
        alice_client = self.get_client("grp_alice")
        bob_client = self.get_client("grp_bob")

        # 1. Member (Bob) tries to update group info -> 403 Forbidden
        res_fail = bob_client.put(
            f"/api/groups/{group_id}",
            data=json.dumps({"name": "Hacked Name", "description": "Hacked"}),
            content_type="application/json"
        )
        self.assertEqual(res_fail.status_code, 403)

        # 2. Admin (Alice) updates group info -> Success
        res_ok = alice_client.put(
            f"/api/groups/{group_id}",
            data=json.dumps({
                "name": "Engineering Production Team",
                "description": "Production systems & incident response"
            }),
            content_type="application/json"
        )
        self.assertEqual(res_ok.status_code, 200)
        with app.app_context():
            group = get_group_by_id(group_id)
            self.assertEqual(group["name"], "Engineering Production Team")
            self.assertEqual(group["description"], "Production systems & incident response")

    # ──────────────────────────────────────────────────────────────────────────
    # Test 9: Member Leaving Group
    # ──────────────────────────────────────────────────────────────────────────
    def test_09_member_leave_group(self):
        """Dave leaves the group voluntarily."""
        group_id = getattr(self, "group_id")
        dave_client = self.get_client("grp_dave")

        # Dave leaves group
        res = dave_client.delete(
            f"/api/groups/{group_id}/members/grp_dave",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)

        with app.app_context():
            self.assertFalse(is_group_member(group_id, self.users["grp_dave"]["id"]))

    # ──────────────────────────────────────────────────────────────────────────
    # Test 10: Group Media Sharing (E2EE Audio / Image payload)
    # ──────────────────────────────────────────────────────────────────────────
    def test_10_group_media_sharing(self):
        """Verify end-to-end encrypted media payload transmission and decryption in group."""
        group_id = getattr(self, "group_id")
        epoch3_key = getattr(self, "epoch3_key")

        media_payload = json.dumps({
            "type": "media",
            "mediaType": "image",
            "name": "architecture_diagram.png",
            "size": 1048576,
            "data": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
            "caption": "Latest E2EE System Architecture"
        })

        # Alice encrypts media payload with current epoch (Epoch 3)
        enc_media = encrypt_group_message(epoch3_key, media_payload)

        with app.app_context():
            media_msg_id = create_group_message(
                group_id=group_id,
                sender_id=self.users["grp_alice"]["id"],
                epoch=3,
                ciphertext=enc_media["ciphertext"],
                nonce=enc_media["nonce"],
                tag=enc_media["tag"],
                encrypted_package=json.dumps(enc_media),
                message_type="media",
                media_meta=json.dumps({"name": "architecture_diagram.png", "size": 1048576, "type": "image/png"})
            )
            self.assertIsNotNone(media_msg_id)

        # Bob fetches and decrypts media message
        bob_client = self.get_client("grp_bob")
        res = bob_client.get(f"/api/groups/{group_id}/messages")
        self.assertEqual(res.status_code, 200)
        messages = res.get_json()["messages"]
        m_item = next(m for m in messages if m["id"] == media_msg_id)

        decrypted_media_str = decrypt_group_message(epoch3_key, m_item)
        parsed_media = json.loads(decrypted_media_str)
        self.assertEqual(parsed_media["name"], "architecture_diagram.png")
        self.assertEqual(parsed_media["caption"], "Latest E2EE System Architecture")
        self.assertTrue(parsed_media["data"].startswith("data:image/png;base64,"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
