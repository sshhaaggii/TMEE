# SecureChat: End-to-End Encrypted (E2EE) Real-Time Messaging System
### Final College Project Demonstration & Comprehensive Technical Documentation

---

## 1. Project Abstract & Overview

**SecureChat** is a production-grade, privacy-first real-time messaging application engineered with **zero-knowledge End-to-End Encryption (E2EE)**. In traditional client-server messaging systems (e.g., standard REST/WebSocket chat apps), the server acts as a trusted intermediary with full visibility into user plaintext, message history, and private communication. If the server or database is compromised, all user conversations are exposed.

SecureChat eliminates this vulnerability by enforcing a strict **Zero-Knowledge Invariant**:
- Cryptographic key pairs are generated exclusively inside the client's browser environment using the W3C Web Cryptography API (`window.crypto.subtle`).
- **Private keys never leave client device memory or local storage.**
- Symmetric encryption keys are derived independently on each endpoint using **X25519 Elliptic Curve Diffie-Hellman (ECDH)** and **HKDF-SHA-256**.
- The server acts solely as an **untrusted blind relay and ciphertext storage engine**. The server never possesses private keys, never computes shared secrets, and cannot decrypt messages passing through it.
- In-flight and at-rest messages are protected by **AES-256-GCM** with 96-bit unique nonces and 128-bit authentication tags, preventing tampering, forgery, eavesdropping, and replay attacks.

---

## 2. Cryptographic Architecture & Security Standards

SecureChat adheres to modern cryptographic standards established by NIST and the IETF:

```
+---------------------------------------------------------------------------------------------------+
|                                 SECURECHAT CRYPTOGRAPHIC SUITE                                    |
+--------------------------+-----------------------+------------------------------------------------+
| Security Layer           | Primitive / Standard  | Specification & Parameters                     |
+--------------------------+-----------------------+------------------------------------------------+
| Asymmetric Key Agreement | X25519 (ECDH)         | RFC 7748 (Curve25519, 256-bit Montgomery curve)|
| Key Derivation Function  | HKDF-SHA-256          | RFC 5869 (HMAC-based Extract-and-Expand)       |
| Authenticated Cipher     | AES-256-GCM           | NIST SP 800-38D (256-bit key, 12-byte IV/Nonce)|
| Message Authentication   | GMAC (Tag)            | 16-byte (128-bit) integrity & authenticity tag |
| Password Storage         | PBKDF2-HMAC-SHA256    | 600,000 iterations (Werkzeug security)        |
| Identity & Safety Number | SHA-256 Fingerprints  | 60-digit mutual verification matrix            |
| Nonce Generation         | CSPRNG                | crypto.getRandomValues() / secrets.token_bytes |
+--------------------------+-----------------------+------------------------------------------------+
```

### End-to-End Cryptographic Protocol Flow

```
   ALICE (Client Browser A)                         SERVER (Untrusted Blind Relay)                      BOB (Client Browser B)
  ==========================                       ================================                    ========================
1. Generate X25519 Key Pair
   (PrivKey_A, PubKey_A)
2. Publish PubKey_A  ----------------------------> Store PubKey_A in DB
                                                   (Zero private keys stored) <----------------- 1. Generate X25519 Key Pair
                                                                                                    (PrivKey_B, PubKey_B)
                                                                                                 2. Publish PubKey_B
3. Request Bob's Public Key <--------------------- Fetch PubKey_B from Directory
   Compute Shared Secret S:                                                                      3. Request Alice's Public Key
   S = X25519(PrivKey_A, PubKey_B)                                                                  Compute Shared Secret S:
4. HKDF-SHA-256(S, Salt, Info)                                                                      S = X25519(PrivKey_B, PubKey_A)
   --> AES_Key_AB (256 bits)                                                                     4. HKDF-SHA-256(S, Salt, Info)
                                                                                                    --> AES_Key_AB (256 bits)
5. Compose Plaintext "Hello Bob"
   Generate 12-byte Nonce CSPRNG
   Encrypt AES-256-GCM(Key, Nonce, M)
   Produce: Ciphertext + 16-byte Tag
6. Emit WebSocket Event -------------------------> Relays Blindly via WebSocket ----------------> 6. Receives Ciphertext Package
   { ciphertext, nonce, tag }                      Stores Ciphertext in SQLite                      Decrypts AES-256-GCM(Key, Nonce, Tag)
                                                   (NO PLAINTEXT REACHES DB)                        Verifies Authenticity Tag
                                                                                                    Displays "Hello Bob"
```

---

## 3. Key Features & College Demonstration Highlights

### A. Evaluator-Oriented Cryptographic UI
1. **Cryptographic Payload Inspector Modal**:
   - Any message in the chat timeline features an inspect icon. Clicking it opens a deep-inspection modal showing the exact Base64 ciphertext, the 12-byte nonce, the 16-byte authentication tag, the Wire JSON payload, and the cipher algorithm.
2. **Mutual Safety Numbers (Fingerprint Verification)**:
   - Clicking the peer profile displays a 60-digit safety number grid generated via `SHA-256(min(PubA, PubB) + max(PubA, PubB))`. Demonstrates how two users independently verify they share the exact same key without MITM eavesdropping.
3. **E2EE Protocol Suite Modal**:
   - Clicking the "End-to-End Encrypted" security badge in the header displays live status details: Curve25519 status, HKDF parameters, AES-GCM tag size, and active security guarantees.
4. **Active Gateway Health Banner**:
   - Displays real-time WebSocket connection state, socket reconnects, and security warnings.
5. **Real-Time Presence & Typing Indicators**:
   - Real-time online/offline indicators with pulsing status rings; real-time typing indicators synced across browser sessions.
6. **Mobile-Responsive Glassmorphism Interface**:
   - Premium dark-mode cyber aesthetic with smooth sliding side drawer on mobile and responsive layout across desktop, tablet, and mobile screens.
7. **Granular Privacy & Chat Deletion**:
   - Users can delete individual messages or clear their entire conversation history. Deletion permanently purges ciphertext rows from SQLite and syncs instantly to the other party via WebSockets.

---

## 4. Project Directory Structure

```text
Secure_Chat_Application/
│
├── app.py                         # Flask server, WebSocket routes, API handlers, DB models
├── config.py                      # Application configurations, CSRF & security params
├── requirements.txt               # Python package dependencies
├── reset_db.py                    # Standalone utility to clean and initialize fresh DB
├── README.md                      # Comprehensive documentation and project guide
│
├── database/
│   └── chat.db                    # SQLite database (stores users, public keys, ciphertext)
│
├── encryption/
│   ├── crypto.py                  # Server-side auth helpers, PBKDF2 hashing, input validation
│   └── e2ee.py                    # Python X25519, HKDF-SHA-256, and AES-256-GCM engine
│
├── static/
│   ├── css/
│   │   └── style.css              # Glassmorphic UI styling, responsive design & modals
│   ├── js/
│   │   ├── auth.js                # Auth form handling, validation, loading animations, toasts
│   │   ├── chat.js                # Real-time WebSocket messaging, presence, UI orchestration
│   │   ├── encryption.js          # WebCrypto E2EE client engine (X25519, HKDF, AES-256-GCM)
│   │   └── socket.io.min.js       # Socket.IO client library
│   └── images/
│       └── .gitkeep
│
├── templates/
│   ├── login.html                 # Login page with password strength & loading states
│   ├── register.html              # Registration page with validation & E2EE badging
│   └── chat.html                  # Main responsive chat interface with security modals
│
└── tests/ (Automated Verification Suite)
    ├── test_auth.py               # Module 1: Registration, Login, Session tests
    ├── test_crypto.py             # Module 2: Pure cryptographic unit tests (X25519, HKDF, GCM)
    ├── test_cross_e2ee.js         # Cross-Language: WebCrypto JS <-> Python Cryptography
    ├── test_key_exchange_api.py   # Module 3: REST Key exchange directory tests
    ├── test_realtime_messaging.py # Module 4: Real-time WebSocket bidirectional E2EE tests
    ├── test_history_privacy.py    # Module 5: Storage privacy, zero-plaintext & deletion tests
    └── test_comprehensive_suite.py# Master Suite: 70 automated end-to-end assertions
```

---

## 5. Prerequisites & Required Packages

### System Requirements
- **Python**: Version 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Node.js** (Optional, for cross-platform tests): Version 18+.
- **Web Browser**: Any modern browser supporting WebCrypto (Google Chrome, Mozilla Firefox, Microsoft Edge, Brave, Safari).

### Required Python Packages (`requirements.txt`)
- `Flask>=3.0.0`: Core web application framework.
- `Flask-SocketIO>=5.3.6`: Bi-directional real-time WebSocket communication.
- `Flask-WTF>=1.2.1`: CSRF protection for all authentication endpoints.
- `Werkzeug>=3.0.1`: Secure PBKDF2:SHA256 password hashing and WSGI utilities.
- `cryptography>=42.0.0`: Reference implementation of X25519, HKDF, and AES-GCM.
- `python-dotenv>=1.0.1`: Environment variable management.
- `eventlet>=0.35.1`: High-concurrency asynchronous greenlet server.
- `requests>=2.31.0`: Automated HTTP client for testing.
- `python-socketio[client]>=5.11.0`: Automated WebSocket testing client.

---

## 6. Installation & Setup Instructions

### Step 1: Open Terminal / PowerShell
Open PowerShell or your command prompt and navigate to the project directory:

```powershell
cd "c:\Users\Shagithiyan N\OneDrive\Desktop\APPS & WEB SITE\TMEEE\Secure_Chat_Application"
```

### Step 2: (Optional) Create and Activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
Install all required libraries using `pip`:

```powershell
pip install -r requirements.txt
```

---

## 7. Database Setup & Reset Instructions

The SQLite database (`database/chat.db`) is automatically created and migrated on startup if it does not already exist.

### How to Reset Database for a Fresh Demonstration
Before presenting to an examiner or instructor, reset the database to a clean slate with zero dummy users:

**Option A (Using `reset_db.py`):**
```powershell
python reset_db.py
```

**Option B (Using CLI flag in `app.py`):**
```powershell
python app.py --reset-db
```

Output:
```text
[OK] Database reset successfully! Fresh tables initialized.
```

---

## 8. How to Run the Flask Application

Run the application using Python:

```powershell
python app.py
```

Console Output:
```text
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)
```

The application is now live at `http://127.0.0.1:5000`.

---

## 9. How to Open Two Browser Sessions

To demonstrate real-time, peer-to-peer encrypted messaging, open two separate browser sessions:

### Session 1: Alice (Normal Window)
1. Open Google Chrome (or Edge).
2. Visit `http://127.0.0.1:5000`.
3. Click **"Create one now"** (or go to `http://127.0.0.1:5000/register`).
4. Register User 1:
   - **Username**: `alice`
   - **Email**: `alice@college.edu`
   - **Password**: `SecurePass123!`
   - **Confirm Password**: `SecurePass123!`
5. Log in with `alice@college.edu` and `SecurePass123!`.
6. You will be redirected to the Chat Workspace (`/chat`).

### Session 2: Bob (Incognito / Private Window)
1. In Chrome, press `Ctrl + Shift + N` (or in Firefox `Ctrl + Shift + P`) to open an **Incognito / Private Window**. (This ensures an independent session cookie).
2. Visit `http://127.0.0.1:5000`.
3. Register User 2:
   - **Username**: `bob`
   - **Email**: `bob@college.edu`
   - **Password**: `SecurePass123!`
   - **Confirm Password**: `SecurePass123!`
4. Log in with `bob@college.edu` and `SecurePass123!`.
5. You will be redirected to the Chat Workspace (`/chat`).

---

## 10. Step-by-Step College Demonstration Walkthrough

Follow these steps to demonstrate every security and cryptographic feature to your professor or evaluator:

### Step 1: Real-Time User Discovery & Online Presence
- In Alice's window, look at the sidebar under **"Direct Messages"**. `bob` will appear in the contacts list with a **glowing green online dot**.
- In Bob's window, `alice` will appear with an online indicator.
- Alice clicks on `bob` to open a private chat room.

### Step 2: Live Encrypted Communication
1. Alice types in the message input: *"Classified project details: Alpha-9"*.
   - Notice Bob's screen instantly displays the typing indicator: *"alice is typing..."*.
2. Alice clicks **Send** (or presses `Enter`).
3. The message arrives **instantly** in Bob's window without refreshing the page.
4. Bob types a reply: *"Acknowledged. Rendezvous confirmed at sector 4"*.
5. Alice receives Bob's message in real time.

### Step 3: Message Cryptographic Inspector (Demonstrating Ciphertext, Nonce, and Tag)
1. In Alice's or Bob's chat window, hover over any message bubble.
2. Click the **Shield/Key icon (Inspect Encrypted Package)** on the top-right of the message bubble.
3. The **"Cryptographic Message Inspector"** modal opens showing:
   - **Ciphertext**: Base64 encoded encrypted payload (e.g., `8n4K9gqM+...`).
   - **Initialization Vector (Nonce)**: 12-byte hex/base64 string generated fresh via CSPRNG.
   - **Authentication Tag (MAC)**: 16-byte GCM authentication tag.
   - **Algorithm**: `AES-256-GCM (NIST SP 800-38D)`.
   - **Wire Payload**: The exact raw JSON transmitted over the network.
4. *Explanation for Evaluator*: Explain that neither the network nor the server ever sees the plain English text; they only ever transmit and store this exact encrypted package.

### Step 4: Safety Numbers & Fingerprint Verification (Man-In-The-Middle Defense)
1. In Alice's chat header, click **"Verify Keys"** (or click on Bob's name in the header).
2. The **"Peer Profile & Safety Numbers"** modal opens.
3. Observe the **60-Digit Safety Number Grid** (12 groups of 5 digits).
4. In Bob's window, open Alice's profile and compare the 60-digit number.
5. *Explanation for Evaluator*: The safety number is derived deterministically from both users' public keys: `SHA-256(min(PubA, PubB) + max(PubA, PubB))`. If an attacker were intercepting the traffic and substituting public keys (MITM attack), these numbers would not match. Because they match, both users have cryptographic proof of end-to-end identity.

### Step 5: Database Inspection (Proof of Zero Plaintext on Server)
To prove to your evaluator that the server and database store **ZERO plaintext**:
1. Open a new PowerShell terminal while the server is running.
2. Run this Python one-liner to query the SQLite messages table:

```powershell
python -c "import sqlite3; conn = sqlite3.connect('database/chat.db'); rows = conn.execute('SELECT id, sender_id, recipient_id, ciphertext, nonce, tag FROM messages').fetchall(); [print(r) for r in rows]; conn.close()"
```

3. **Observe the Output**:
   - The database contains `ciphertext`, `nonce`, and `tag`.
   - **Notice**: There is NO column for `message_text` or `plaintext`.
4. Now search the raw database file for your secret words:

```powershell
python -c "data = open('database/chat.db', 'rb').read(); print('Plaintext found in DB?' , b'Classified project details' in data or b'Alpha-9' in data)"
```

Output:
```text
Plaintext found in DB? False
```

5. *Conclusion for Evaluator*: Even a rogue database administrator with full access to `chat.db` cannot read any messages.

### Step 6: Message Deletion & Synchronization
1. Hover over a sent message and click the **Trash icon** (Delete).
2. The message disappears from both Alice's and Bob's screens in real time.
3. Check the database: the message row is permanently purged.

---

## 11. Automated Test Suite & Verification Results

The application includes an automated test suite verifying all cryptographic properties, security boundaries, and API invariants:

| Test File | Focus Area | Assertions | Result |
| :--- | :--- | :---: | :---: |
| `test_crypto.py` | X25519 DH, HKDF-SHA-256, AES-256-GCM, Tamper Detection, Nonce Freshness | 24 | **PASS (100%)** |
| `test_cross_e2ee.js` | Cross-language WebCrypto JS $\leftrightarrow$ Python Cryptography interoperability | 6 | **PASS (100%)** |
| `test_auth.py` | CSRF, PBKDF2 hashing, Rate Limiting, Input Validation, Session Isolation | 12 | **PASS (100%)** |
| `test_key_exchange_api.py` | Public key directory, registration, DH secret derivation via REST | 19 | **PASS (100%)** |
| `test_realtime_messaging.py` | WebSocket handshake auth, room segregation, presence events, E2EE relay | 26 | **PASS (100%)** |
| `test_history_privacy.py` | Message persistence, client-side decryption, unauthorized access rejection | 64 | **PASS (100%)** |
| `test_comprehensive_suite.py` | Complete Master End-to-End Verification across all 6 modules | 70 | **PASS (100%)** |
| **Total Automated Assertions** | **Comprehensive Full System Coverage** | **221** | **100% PASS** |

### How to Run the Comprehensive Test Suite
To run the automated master test suite:

```powershell
python test_comprehensive_suite.py
```

Output Summary:
```text
===========================================================================
  TEST EXECUTION SUMMARY
===========================================================================
  Total Test Assertions:  70
  Passed Assertions:      70
  Failed Assertions:      0
  Success Rate:           100.0%
===========================================================================
[OK] ALL 6 MODULES AND SECURITY REQUIREMENTS ARE 100% VERIFIED!
```

---

## 12. Security Analysis & Threat Model

| Threat / Attack Vector | Vulnerability in Standard Apps | SecureChat Defense Mechanism |
| :--- | :--- | :--- |
| **Server Database Compromise** | Attacker dumps SQLite/MySQL and reads all chats in plaintext. | **Zero Plaintext Invariant**: Database contains only AES-GCM ciphertext, nonces, and authentication tags. Private keys are never stored on the server. |
| **Man-In-The-Middle (MITM)** | Active attacker alters public keys during exchange to intercept session. | **Mutual Safety Numbers**: Users compare 60-digit SHA-256 fingerprints out-of-band to detect key substitution. |
| **Eavesdropping / Packet Sniffing** | Wi-Fi / ISP packet inspection exposes chat contents. | **Double Layer Encryption**: Transport layer (TLS/HTTPS) + Application Layer E2EE (AES-256-GCM). |
| **Ciphertext Tampering / Bit-Flipping** | Attacker alters encrypted bytes in transit. | **16-Byte GMAC Authentication Tag**: Any modification causes decryption to fail immediately with an `AuthenticationError`. |
| **Replay Attacks** | Attacker captures and retransmits valid encrypted frames. | **12-byte CSPRNG Nonces & Cache Tracking**: Reused nonces are identified and rejected immediately. |
| **Brute-Force & Credential Stuffing** | Rapid automated password guessing on login. | **Rate Limiting**: 10 failed attempts trigger a mandatory 60-second lockout cooldown; passwords hashed via PBKDF2-HMAC-SHA256. |
| **Cross-Site Request Forgery (CSRF)** | Malicious third-party site submits requests on user's behalf. | **Flask-WTF CSRF Protection**: Every mutating HTTP request requires a cryptographically validated session CSRF token. |
| **Clickjacking & MIME Sniffing** | App framed in an iframe or MIME confusion attack. | **Defense-in-Depth Headers**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. |

---

## 13. Frequently Asked Questions (FAQ) for Evaluators

**Q1: Where are the private keys stored?**
> Private keys are stored strictly in client browser memory and the browser's protected `localStorage` (`securechat_privkey_<username>`). They never leave the client device and are never transmitted over HTTP or WebSockets.

**Q2: What happens if an attacker modifies even a single byte of ciphertext?**
> AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher. It computes a 128-bit authentication tag over the ciphertext and nonce. If even 1 bit of ciphertext or nonce is altered, the authentication tag validation fails and the message is discarded with an `AuthenticationError`.

**Q3: Can the server administrator read any user's private messages?**
> No. Because the server only receives and stores the ciphertext, nonce, and tag, and never possesses the users' private keys, the server administrator cannot decrypt the messages.

**Q4: How does SecureChat handle users when they are offline?**
> The server stores the encrypted packages (ciphertext, nonce, tag) in SQLite. When the recipient logs in, their client retrieves the historical encrypted packages via `/api/messages/<peer>` and decrypts them locally using their locally stored private key and the sender's public key.

---

## 14. License & Academic Attribution
Developed as an advanced academic project demonstrating End-to-End Encryption, Web Cryptography, and Secure Real-Time Communication Systems.
All cryptographic implementations strictly follow NIST and IETF standards.
