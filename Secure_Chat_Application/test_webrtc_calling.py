"""
test_webrtc_calling.py
Comprehensive End-to-End Test Suite for WebRTC Voice & Video Calling in TMEEE.

Tests:
1. User registration & authentication for two distinct users (call_alice & call_bob).
2. Database call recording (record_call_start, record_call_end, get_call_history).
3. Call history REST API endpoints (/api/calls/history, /api/calls/history/<username>).
4. Socket.IO WebRTC signaling exchange:
   - Call initiation (webrtc_call_user -> incoming_call)
   - Call acceptance (webrtc_accept_call -> call_accepted)
   - SDP Offer relay (webrtc_signal offer)
   - SDP Answer relay (webrtc_signal answer)
   - ICE Candidate relay (webrtc_signal candidate)
   - Media toggle relay (webrtc_toggle_media -> peer_media_toggle)
   - Call termination (webrtc_end_call -> call_ended)
5. Video call rejection and busy status tracking.
6. Offline user call handling with automatic missed call recording.
"""

import sys
import os
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, create_app, socketio, online_users
from database.db import (
    init_db, get_db,
    record_call_start, record_call_end,
    get_call_history_for_user, get_call_history_between_users
)

class TestWebRTCCalling(unittest.TestCase):
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

        # Register Alice
        cls.client_alice.post('/register', json={
            'username': 'call_alice',
            'email': 'call_alice@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        cls.client_alice.post('/login', json={'email': 'call_alice@test.tmeee', 'password': 'Password123!'})

        # Register Bob
        cls.client_bob.post('/register', json={
            'username': 'call_bob',
            'email': 'call_bob@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        cls.client_bob.post('/login', json={'email': 'call_bob@test.tmeee', 'password': 'Password123!'})

        # Lookup user IDs
        with get_db() as conn:
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('call_alice',))
            cls.alice_id = c.fetchone()["id"]
            c = conn.execute("SELECT id FROM users WHERE username = ?", ('call_bob',))
            cls.bob_id = c.fetchone()["id"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.pop()

    def test_01_database_call_records(self):
        """Verify database helper operations for recording call start and call completion."""
        call_id = record_call_start(self.alice_id, self.bob_id, "voice")
        self.assertIsNotNone(call_id)

        # End call with duration
        res = record_call_end(call_id, status="completed", duration_seconds=145)
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["duration_seconds"], 145)
        self.assertIsNotNone(res["ended_at"])

        # Fetch history between users
        history = get_call_history_between_users(self.alice_id, self.bob_id)
        self.assertGreaterEqual(len(history), 1)
        latest = history[0]
        self.assertEqual(latest["call_type"], "voice")
        self.assertEqual(latest["caller_username"], "call_alice")
        self.assertEqual(latest["callee_username"], "call_bob")

    def test_02_call_history_rest_api(self):
        """Verify /api/calls/history and /api/calls/history/<peer> endpoints."""
        # Alice fetches her call history
        res = self.client_alice.get('/api/calls/history')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertIn("calls", data)

        # Alice fetches specific history with Bob
        res2 = self.client_alice.get('/api/calls/history/call_bob')
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2.get("ok"))
        self.assertGreaterEqual(len(data2.get("calls", [])), 1)

    def test_03_webrtc_signaling_voice_call_full_lifecycle(self):
        """Test Socket.IO WebRTC signaling flow between Alice and Bob."""
        # Create SocketIO test clients with session cookies
        socket_alice = socketio.test_client(app, flask_test_client=self.client_alice)
        socket_bob = socketio.test_client(app, flask_test_client=self.client_bob)

        self.assertTrue(socket_alice.is_connected())
        self.assertTrue(socket_bob.is_connected())

        # Clear initial connect events
        socket_alice.get_received()
        socket_bob.get_received()

        # 1. Alice calls Bob (Voice Call)
        socket_alice.emit("webrtc_call_user", {
            "target_username": "call_bob",
            "call_type": "voice"
        })

        # Alice receives ringing acknowledgement
        alice_events = socket_alice.get_received()
        ringing_ev = next((e for e in alice_events if e['name'] == 'call_ringing'), None)
        self.assertIsNotNone(ringing_ev, "Alice must receive call_ringing")
        call_id = ringing_ev['args'][0]['call_id']

        # Bob receives incoming_call alert
        bob_events = socket_bob.get_received()
        incoming_ev = next((e for e in bob_events if e['name'] == 'incoming_call'), None)
        self.assertIsNotNone(incoming_ev, "Bob must receive incoming_call")
        self.assertEqual(incoming_ev['args'][0]['caller_username'], 'call_alice')
        self.assertEqual(incoming_ev['args'][0]['call_type'], 'voice')
        self.assertEqual(incoming_ev['args'][0]['call_id'], call_id)

        # 2. Bob accepts the call
        socket_bob.emit("webrtc_accept_call", {
            "call_id": call_id,
            "caller_username": "call_alice",
            "call_type": "voice"
        })

        # Alice receives call_accepted
        alice_events2 = socket_alice.get_received()
        accept_ev = next((e for e in alice_events2 if e['name'] == 'call_accepted'), None)
        self.assertIsNotNone(accept_ev, "Alice must receive call_accepted")
        self.assertEqual(accept_ev['args'][0]['callee_username'], 'call_bob')

        # 3. Alice relays SDP Offer
        mock_sdp_offer = {"type": "offer", "sdp": "v=0\r\no=Alice 1234 2 IN IP4 127.0.0.1..."}
        socket_alice.emit("webrtc_signal", {
            "target_username": "call_bob",
            "call_id": call_id,
            "signal_type": "offer",
            "payload": mock_sdp_offer
        })

        # Bob receives SDP Offer
        bob_events2 = socket_bob.get_received()
        offer_ev = next((e for e in bob_events2 if e['name'] == 'webrtc_signal'), None)
        self.assertIsNotNone(offer_ev, "Bob must receive SDP Offer via webrtc_signal")
        self.assertEqual(offer_ev['args'][0]['signal_type'], 'offer')
        self.assertEqual(offer_ev['args'][0]['payload']['sdp'], mock_sdp_offer['sdp'])

        # 4. Bob relays SDP Answer
        mock_sdp_answer = {"type": "answer", "sdp": "v=0\r\no=Bob 5678 2 IN IP4 127.0.0.1..."}
        socket_bob.emit("webrtc_signal", {
            "target_username": "call_alice",
            "call_id": call_id,
            "signal_type": "answer",
            "payload": mock_sdp_answer
        })

        # Alice receives SDP Answer
        alice_events3 = socket_alice.get_received()
        answer_ev = next((e for e in alice_events3 if e['name'] == 'webrtc_signal'), None)
        self.assertIsNotNone(answer_ev, "Alice must receive SDP Answer via webrtc_signal")
        self.assertEqual(answer_ev['args'][0]['signal_type'], 'answer')

        # 5. ICE Candidate Exchange
        mock_candidate = {"candidate": "candidate:1 1 UDP 2130706431 127.0.0.1 50000 typ host", "sdpMid": "0"}
        socket_alice.emit("webrtc_signal", {
            "target_username": "call_bob",
            "call_id": call_id,
            "signal_type": "candidate",
            "payload": mock_candidate
        })
        bob_events3 = socket_bob.get_received()
        cand_ev = next((e for e in bob_events3 if e['name'] == 'webrtc_signal'), None)
        self.assertIsNotNone(cand_ev)
        self.assertEqual(cand_ev['args'][0]['signal_type'], 'candidate')

        # 6. Media State Toggle (Alice mutes mic)
        socket_alice.emit("webrtc_toggle_media", {
            "target_username": "call_bob",
            "call_id": call_id,
            "media_type": "audio",
            "enabled": False
        })
        bob_events4 = socket_bob.get_received()
        toggle_ev = next((e for e in bob_events4 if e['name'] == 'peer_media_toggle'), None)
        self.assertIsNotNone(toggle_ev)
        self.assertEqual(toggle_ev['args'][0]['media_type'], 'audio')
        self.assertFalse(toggle_ev['args'][0]['enabled'])

        # 7. Alice terminates call
        socket_alice.emit("webrtc_end_call", {
            "call_id": call_id,
            "target_username": "call_bob",
            "duration_seconds": 92,
            "status": "completed"
        })
        bob_events5 = socket_bob.get_received()
        ended_ev = next((e for e in bob_events5 if e['name'] == 'call_ended'), None)
        self.assertIsNotNone(ended_ev, "Bob must receive call_ended")
        self.assertEqual(ended_ev['args'][0]['ended_by'], 'call_alice')
        self.assertEqual(ended_ev['args'][0]['duration_seconds'], 92)

        # Verify DB has recorded call as completed
        with get_db() as conn:
            c = conn.execute("SELECT status, duration_seconds FROM call_history WHERE id = ?", (call_id,))
            row = c.fetchone()
            self.assertEqual(row["status"], "completed")
            self.assertEqual(row["duration_seconds"], 92)

        socket_alice.disconnect()
        socket_bob.disconnect()

    def test_04_webrtc_video_call_rejection_flow(self):
        """Test video call initiation and rejection (busy/decline) flow."""
        socket_alice = socketio.test_client(app, flask_test_client=self.client_alice)
        socket_bob = socketio.test_client(app, flask_test_client=self.client_bob)

        socket_alice.get_received()
        socket_bob.get_received()

        # Alice initiates Video Call
        socket_alice.emit("webrtc_call_user", {
            "target_username": "call_bob",
            "call_type": "video"
        })

        alice_evs = socket_alice.get_received()
        call_id = alice_evs[0]['args'][0]['call_id']

        # Bob declines call
        socket_bob.emit("webrtc_reject_call", {
            "call_id": call_id,
            "caller_username": "call_alice",
            "reason": "busy"
        })

        # Alice receives call_rejected
        alice_evs2 = socket_alice.get_received()
        rej_ev = next((e for e in alice_evs2 if e['name'] == 'call_rejected'), None)
        self.assertIsNotNone(rej_ev)
        self.assertEqual(rej_ev['args'][0]['reason'], 'busy')

        # Verify in DB
        with get_db() as conn:
            c = conn.execute("SELECT status, call_type FROM call_history WHERE id = ?", (call_id,))
            row = c.fetchone()
            self.assertEqual(row["status"], "busy")
            self.assertEqual(row["call_type"], "video")

        socket_alice.disconnect()
        socket_bob.disconnect()

    def test_05_call_offline_user_recorded_as_missed(self):
        """Calling an offline user emits call_unavailable and records a missed call."""
        # Ensure offline_user is registered but offline
        self.client_alice.post('/register', json={
            'username': 'call_ghost',
            'email': 'call_ghost@test.tmeee',
            'password': 'Password123!',
            'confirmPassword': 'Password123!'
        })
        online_users.pop('call_ghost', None)

        socket_alice = socketio.test_client(app, flask_test_client=self.client_alice)
        socket_alice.get_received()

        socket_alice.emit("webrtc_call_user", {
            "target_username": "call_ghost",
            "call_type": "voice"
        })

        evs = socket_alice.get_received()
        unavail = next((e for e in evs if e['name'] == 'call_unavailable'), None)
        self.assertIsNotNone(unavail)
        self.assertEqual(unavail['args'][0]['reason'], 'offline')

        # Verify missed call logged in DB
        with get_db() as conn:
            c = conn.execute("""
                SELECT ch.status, ch.call_type
                FROM call_history ch
                JOIN users u ON ch.callee_id = u.id
                WHERE u.username = 'call_ghost'
                ORDER BY ch.id DESC LIMIT 1
            """)
            row = c.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "missed")

        socket_alice.disconnect()

if __name__ == '__main__':
    unittest.main()
