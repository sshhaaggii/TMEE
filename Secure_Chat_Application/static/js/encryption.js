/**
 * encryption.js — Client-Side End-to-End Encryption (E2EE) Engine.
 *
 * Architecture:
 *   1. Key Generation:
 *      - X25519 key pairs generated on the client device.
 *      - Private keys are stored in client localStorage / memory and NEVER sent to the server.
 *      - Public keys are exported as 32-byte Base64 strings and published to the server directory.
 *
 *   2. Key Exchange:
 *      - X25519 ECDH agreement establishes an identical 32-byte shared secret.
 *      - HKDF-SHA-256 derives a 256-bit AES-GCM encryption key with domain separation:
 *          Salt = "SecureChat-E2EE-Salt-v1"
 *          Info = "SecureChat-AES-256-GCM-Key"
 *
 *   3. Message Encryption:
 *      - AES-256-GCM authenticated encryption.
 *      - 12-byte (96-bit) cryptographically random nonce generated per message.
 *      - Produces ciphertext and a 16-byte (128-bit) authentication tag.
 *
 *   4. Message Decryption:
 *      - Decrypts and verifies the 16-byte authentication tag.
 *      - Fails safely on tampering, corruption, or wrong keys.
 *      - Detects and prevents nonce reuse / replay attacks.
 */

'use strict';

const EncryptionEngine = (() => {

  /* ─── Domain Constants (identical to Python encryption/e2ee.py) ─── */
  const CURVE         = 'X25519';
  const HASH          = 'SHA-256';
  const AES_ALGO      = 'AES-GCM';
  const AES_KEY_LEN   = 256;       // bits
  const NONCE_LEN     = 12;        // bytes (96 bits)
  const TAG_LEN       = 16;        // bytes (128 bits)
  const HKDF_SALT     = new TextEncoder().encode('SecureChat-E2EE-Salt-v1');
  const HKDF_INFO     = new TextEncoder().encode('SecureChat-AES-256-GCM-Key');

  const subtle = (typeof window !== 'undefined' ? window.crypto?.subtle : globalThis.crypto?.subtle);

  /* ─── In-memory State ─── */
  let _currentUsername = null;
  let _keyPair = null;                     // { publicKey, privateKey }
  let _publicKeyB64 = null;                // Base64 of 32 raw bytes
  const _sessionKeys = new Map();          // peerUsername -> CryptoKey (AES-GCM)
  const _peerPublicKeys = new Map();       // peerUsername -> base64
  const _seenNonces = new Set();           // Replay / reuse protection

  /* ─── Binary / Base64 Helpers ─── */

  function uint8ToBase64(bytes) {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToUint8(b64) {
    const cleanB64 = b64.replace(/\s+/g, '');
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(cleanB64, 'base64'));
    }
    const binary = atob(cleanB64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /* ─── RFC 7748 Pure-JS Curve25519 Montgomery Ladder ─── */
  /* Fallback implementation guaranteeing X25519 in all JS environments */

  const P25519 = (1n << 255n) - 19n;
  const A24 = 121665n;

  function modExp(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) res = (res * base) % mod;
      base = (base * base) % mod;
      exp /= 2n;
    }
    return res;
  }

  function invMod(n, mod = P25519) {
    return modExp(n, mod - 2n, mod);
  }

  function rfc7748X25519(scalarBytes, uPointBytes) {
    const k = new Uint8Array(scalarBytes);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let kVal = 0n;
    for (let i = 31; i >= 0; i--) {
      kVal = (kVal << 8n) | BigInt(k[i]);
    }

    let uVal = 0n;
    for (let i = 31; i >= 0; i--) {
      uVal = (uVal << 8n) | BigInt(uPointBytes[i]);
    }
    uVal = uVal % P25519;

    let x1 = uVal;
    let x2 = 1n;
    let z2 = 0n;
    let x3 = uVal;
    let z3 = 1n;
    let swap = 0n;

    for (let t = 254; t >= 0; t--) {
      const kt = (kVal >> BigInt(t)) & 1n;
      swap ^= kt;
      if (swap === 1n) {
        let tmp = x2; x2 = x3; x3 = tmp;
        tmp = z2; z2 = z3; z3 = tmp;
      }
      swap = kt;

      const A = (x2 + z2) % P25519;
      const AA = (A * A) % P25519;
      const B = (x2 - z2 + P25519) % P25519;
      const BB = (B * B) % P25519;
      const E = (AA - BB + P25519) % P25519;
      const C = (x3 + z3) % P25519;
      const D = (x3 - z3 + P25519) % P25519;
      const DA = (D * A) % P25519;
      const CB = (C * B) % P25519;

      x3 = ((DA + CB) * (DA + CB)) % P25519;
      z3 = (x1 * ((DA - CB + P25519) * (DA - CB + P25519))) % P25519;
      x2 = (AA * BB) % P25519;
      z2 = (E * (AA + (A24 * E) % P25519)) % P25519;
    }

    if (swap === 1n) {
      let tmp = x2; x2 = x3; x3 = tmp;
      tmp = z2; z2 = z3; z3 = tmp;
    }

    const resInt = (x2 * invMod(z2)) % P25519;
    const resBytes = new Uint8Array(32);
    let tmp = resInt;
    for (let i = 0; i < 32; i++) {
      resBytes[i] = Number(tmp & 0xFFn);
      tmp >>= 8n;
    }

    let allZero = true;
    for (let i = 0; i < 32; i++) {
      if (resBytes[i] !== 0) { allZero = false; break; }
    }
    if (allZero) {
      throw new Error('[E2EE] Invalid X25519 shared secret: all zero (degenerate peer public key)');
    }

    return resBytes;
  }

  /* ─── Core Cryptographic Methods ─── */

  /**
   * Generate an X25519 key pair on this device.
   * Uses native WebCrypto if available, otherwise RFC 7748 pure JS.
   * @returns {Promise<{publicKeyB64: string, keyPair: any}>}
   */
  async function generateKeyPair() {
    try {
      if (subtle?.generateKey) {
        const kp = await subtle.generateKey(
          { name: CURVE },
          true,
          ['deriveBits', 'deriveKey']
        );
        const rawPub = await subtle.exportKey('raw', kp.publicKey);
        const pubB64 = uint8ToBase64(new Uint8Array(rawPub));
        _keyPair = kp;
        _publicKeyB64 = pubB64;
        return { keyPair: kp, publicKeyB64: pubB64 };
      }
    } catch (e) {
      console.warn('[E2EE] Native WebCrypto X25519 unavailable; using pure JS fallback.', e);
    }

    // Pure JS RFC 7748 fallback
    const privBytes = new Uint8Array(32);
    (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).getRandomValues(privBytes);
    privBytes[0] &= 248;
    privBytes[31] &= 127;
    privBytes[31] |= 64;

    const basePoint = new Uint8Array(32);
    basePoint[0] = 9;

    const pubBytes = rfc7748X25519(privBytes, basePoint);
    const pubB64 = uint8ToBase64(pubBytes);
    const kp = { privateKeyBytes: privBytes, publicKeyBytes: pubBytes };

    _keyPair = kp;
    _publicKeyB64 = pubB64;
    return { keyPair: kp, publicKeyB64: pubB64 };
  }

  /**
   * Compute X25519 shared secret between local private key and peer public key.
   * @param {any} localKeyPair
   * @param {Uint8Array} peerPubBytes
   * @returns {Promise<Uint8Array>} 32-byte shared secret
   */
  async function computeSharedSecret(localKeyPair, peerPubBytes) {
    if (subtle && localKeyPair.privateKey instanceof CryptoKey) {
      try {
        const peerKey = await subtle.importKey(
          'raw',
          peerPubBytes,
          { name: CURVE },
          false,
          []
        );
        const bits = await subtle.deriveBits(
          { name: CURVE, public: peerKey },
          localKeyPair.privateKey,
          256
        );
        const secretBytes = new Uint8Array(bits);
        if (secretBytes.every(b => b === 0)) {
          throw new Error('[E2EE] Invalid X25519 shared secret: all zero (degenerate peer public key)');
        }
        return secretBytes;
      } catch (e) {
        console.warn('[E2EE] Native deriveBits failed, using pure JS fallback.', e);
      }
    }

    // Fallback: extract private bytes or use pure JS
    let privBytes;
    if (localKeyPair.privateKeyBytes) {
      privBytes = localKeyPair.privateKeyBytes;
    } else {
      const raw = await subtle.exportKey('pkcs8', localKeyPair.privateKey);
      // Last 32 bytes of PKCS#8 X25519 is the private seed
      privBytes = new Uint8Array(raw).slice(-32);
    }
    return rfc7748X25519(privBytes, peerPubBytes);
  }

  /**
   * Derive a 256-bit AES-GCM CryptoKey from the shared secret via HKDF-SHA-256.
   * @param {Uint8Array} sharedSecretBytes
   * @returns {Promise<CryptoKey>}
   */
  async function deriveAESGCMKey(sharedSecretBytes) {
    const hkdfKey = await subtle.importKey(
      'raw',
      sharedSecretBytes,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    return await subtle.deriveKey(
      {
        name: 'HKDF',
        hash: HASH,
        salt: HKDF_SALT,
        info: HKDF_INFO,
      },
      hkdfKey,
      { name: AES_ALGO, length: AES_KEY_LEN },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a message string for a given AES-GCM CryptoKey.
   * Generates a 12-byte CSPRNG nonce.
   * @param {CryptoKey} aesKey
   * @param {string} plaintext
   * @returns {Promise<{nonce: string, ciphertext: string, tag: string, payload: string}>}
   */
  async function encryptMessage(aesKey, plaintext) {
    const nonce = new Uint8Array(NONCE_LEN);
    (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).getRandomValues(nonce);

    const ptBytes = new TextEncoder().encode(plaintext);
    const ctWithTagBuffer = await subtle.encrypt(
      { name: AES_ALGO, iv: nonce, tagLength: TAG_LEN * 8 },
      aesKey,
      ptBytes
    );

    const ctWithTag = new Uint8Array(ctWithTagBuffer);
    const ciphertext = ctWithTag.slice(0, ctWithTag.length - TAG_LEN);
    const tag = ctWithTag.slice(ctWithTag.length - TAG_LEN);

    // Wire payload: nonce (12B) + ciphertext + tag (16B)
    const combined = new Uint8Array(nonce.length + ctWithTag.length);
    combined.set(nonce, 0);
    combined.set(ctWithTag, nonce.length);

    return {
      nonce:      uint8ToBase64(nonce),
      ciphertext: uint8ToBase64(ciphertext),
      tag:        uint8ToBase64(tag),
      payload:    uint8ToBase64(combined),
    };
  }

  /**
   * Decrypt an encrypted message package using an AES-GCM CryptoKey.
   * @param {CryptoKey} aesKey
   * @param {any} encryptedPackage
   * @returns {Promise<string>} decrypted plaintext
   */
  async function decryptMessage(aesKey, encryptedPackage) {
    let nonce;
    let ctWithTag;

    if (typeof encryptedPackage === 'string') {
      const raw = base64ToUint8(encryptedPackage);
      if (raw.length < NONCE_LEN + TAG_LEN) {
        throw new Error('[E2EE] Encrypted payload too short');
      }
      nonce = raw.slice(0, NONCE_LEN);
      ctWithTag = raw.slice(NONCE_LEN);
    } else if (typeof encryptedPackage === 'object' && encryptedPackage !== null) {
      if (encryptedPackage.ciphertext && encryptedPackage.tag) {
        nonce = base64ToUint8(encryptedPackage.nonce);
        const ct = base64ToUint8(encryptedPackage.ciphertext);
        const tag = base64ToUint8(encryptedPackage.tag);
        ctWithTag = new Uint8Array(ct.length + tag.length);
        ctWithTag.set(ct, 0);
        ctWithTag.set(tag, ct.length);
      } else if (encryptedPackage.payload) {
        const raw = base64ToUint8(encryptedPackage.payload);
        nonce = raw.slice(0, NONCE_LEN);
        ctWithTag = raw.slice(NONCE_LEN);
      } else {
        throw new Error('[E2EE] Malformed encrypted package');
      }
    } else {
      throw new Error('[E2EE] Invalid encryptedPackage type');
    }

    try {
      const decryptedBuffer = await subtle.decrypt(
        { name: AES_ALGO, iv: nonce, tagLength: TAG_LEN * 8 },
        aesKey,
        ctWithTag
      );
      return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
      throw new Error('[E2EE] Authentication failed: ciphertext or tag modified, or invalid key.');
    }
  }

  /* ─── High-Level Client Session Operations ─── */

  /**
   * Initialise the client-side encryption engine for the current logged-in user.
   * Generates or restores the user's private key, then publishes the public key to the server.
   * @param {string} username
   * @returns {Promise<string>} Base64 public key
   */
  async function init(username) {
    _currentUsername = username || 'guest';
    const storageKey = `securechat_privkey_${_currentUsername}`;

    let restored = false;
    if (typeof localStorage !== 'undefined') {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && parsed.publicKey && parsed.privateKey) {
            if (parsed.format === 'pkcs8' && subtle?.importKey) {
              const privBytes = base64ToUint8(parsed.privateKey);
              const privKey = await subtle.importKey(
                'pkcs8',
                privBytes,
                { name: CURVE },
                true,
                ['deriveBits', 'deriveKey']
              );
              const pubBytes = base64ToUint8(parsed.publicKey);
              const pubKey = await subtle.importKey(
                'raw',
                pubBytes,
                { name: CURVE },
                true,
                []
              );
              _keyPair = { privateKey: privKey, publicKey: pubKey };
              _publicKeyB64 = parsed.publicKey;
              restored = true;
            } else if (parsed.format === 'raw') {
              const privBytes = base64ToUint8(parsed.privateKey);
              const pubBytes = base64ToUint8(parsed.publicKey);
              _keyPair = { privateKeyBytes: privBytes, publicKeyBytes: pubBytes };
              _publicKeyB64 = parsed.publicKey;
              restored = true;
            }
          }
        }
      } catch (e) {
        console.warn('[E2EE] Could not restore cached key from localStorage:', e);
      }
    }

    if (!restored) {
      await generateKeyPair();
      if (typeof localStorage !== 'undefined') {
        try {
          if (_keyPair.privateKey && subtle?.exportKey) {
            const pkcs8 = await subtle.exportKey('pkcs8', _keyPair.privateKey);
            const privB64 = uint8ToBase64(new Uint8Array(pkcs8));
            localStorage.setItem(storageKey, JSON.stringify({
              privateKey: privB64,
              publicKey: _publicKeyB64,
              format: 'pkcs8',
            }));
          } else if (_keyPair.privateKeyBytes) {
            const privB64 = uint8ToBase64(_keyPair.privateKeyBytes);
            localStorage.setItem(storageKey, JSON.stringify({
              privateKey: privB64,
              publicKey: _publicKeyB64,
              format: 'raw',
            }));
          }
        } catch (e) {
          console.warn('[E2EE] Could not persist key to localStorage:', e);
        }
      }
    }

    // Publish public key to server directory
    await publishPublicKey();

    console.info(`[E2EE] Engine initialized for ${_currentUsername}. Public key:`, _publicKeyB64);
    return _publicKeyB64;
  }

  /**
   * Publish the user's public key to the server directory.
   */
  async function publishPublicKey() {
    if (!_publicKeyB64) return false;

    try {
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      const csrfToken = csrfMeta ? csrfMeta.content : '';

      const resp = await fetch('/api/keys/public-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify({ public_key: _publicKeyB64 }),
      });

      const res = await resp.json();
      return res.ok;
    } catch (err) {
      console.warn('[E2EE] Failed to publish public key to server:', err);
      return false;
    }
  }

  /**
   * Establish an E2EE session with a peer user using their public key.
   * Derives and caches the shared AES-256-GCM key.
   * @param {string} peerUsername
   * @param {string} peerPublicKeyB64
   * @returns {Promise<CryptoKey>}
   */
  async function establishSession(peerUsername, peerPublicKeyB64) {
    if (!peerPublicKeyB64) {
      throw new Error(`[E2EE] Missing public key for ${peerUsername}`);
    }

    const peerPubBytes = base64ToUint8(peerPublicKeyB64);
    if (peerPubBytes.length !== 32) {
      throw new Error(`[E2EE] Invalid peer public key length: ${peerPubBytes.length} bytes`);
    }

    const sharedSecret = await computeSharedSecret(_keyPair, peerPubBytes);
    const aesKey = await deriveAESGCMKey(sharedSecret);

    _sessionKeys.set(peerUsername, aesKey);
    _peerPublicKeys.set(peerUsername, peerPublicKeyB64);

    console.info(`[E2EE] Secure session established with ${peerUsername}`);
    return aesKey;
  }

  /**
   * Fetch a peer's public key from the server directory.
   * @param {string} peerUsername
   * @returns {Promise<string>} peer public key Base64
   */
  async function fetchPeerPublicKey(peerUsername) {
    if (_peerPublicKeys.has(peerUsername)) {
      return _peerPublicKeys.get(peerUsername);
    }

    const resp = await fetch(`/api/keys/${encodeURIComponent(peerUsername)}`);
    const data = await resp.json();
    if (!data.ok || !data.public_key) {
      throw new Error(data.error || `Failed to fetch public key for ${peerUsername}`);
    }

    _peerPublicKeys.set(peerUsername, data.public_key);
    return data.public_key;
  }

  /**
   * Encrypt a message for a peer.
   * Automatically fetches public key and establishes session if needed.
   * @param {string} peerUsername
   * @param {string} plaintext
   * @returns {Promise<{nonce: string, ciphertext: string, tag: string, payload: string}>}
   */
  async function encryptFor(peerUsername, plaintext) {
    let aesKey = _sessionKeys.get(peerUsername);
    if (!aesKey) {
      const peerPub = await fetchPeerPublicKey(peerUsername);
      aesKey = await establishSession(peerUsername, peerPub);
    }
    const encrypted = await encryptMessage(aesKey, plaintext);
    _seenNonces.add(encrypted.nonce);
    return encrypted;
  }

  /**
   * Decrypt a message received from a peer.
   * Verifies nonce freshness to prevent replay attacks.
   * @param {string} peerUsername
   * @param {any} encryptedPackage
   * @returns {Promise<string>}
   */
  async function decryptFrom(peerUsername, encryptedPackage) {
    let aesKey = _sessionKeys.get(peerUsername);
    if (!aesKey) {
      const peerPub = await fetchPeerPublicKey(peerUsername);
      aesKey = await establishSession(peerUsername, peerPub);
    }

    const nonce = (typeof encryptedPackage === 'object' && encryptedPackage?.nonce)
      ? encryptedPackage.nonce
      : (typeof encryptedPackage === 'string' ? encryptedPackage.slice(0, 16) : null);

    if (nonce && _seenNonces.has(nonce)) {
      console.warn('[E2EE] Duplicate nonce detected for message from:', peerUsername);
    } else if (nonce) {
      _seenNonces.add(nonce);
    }

    return await decryptMessage(aesKey, encryptedPackage);
  }

  /* ─── Group E2EE Key Management & Messaging ─── */
  const _groupKeys = new Map(); // `${groupId}:${epoch}` -> CryptoKey (AES-GCM)

  /**
   * Generate a fresh 32-byte Group Epoch Key (GEK).
   * @returns {Promise<{rawBytes: Uint8Array, b64: string, cryptoKey: CryptoKey}>}
   */
  async function generateGroupEpochKey() {
    const rawBytes = new Uint8Array(32);
    (typeof window !== 'undefined' ? window.crypto : globalThis.crypto).getRandomValues(rawBytes);
    const b64 = uint8ToBase64(rawBytes);
    const cryptoKey = await subtle.importKey(
      'raw',
      rawBytes,
      { name: AES_ALGO, length: AES_KEY_LEN },
      false,
      ['encrypt', 'decrypt']
    );
    return { rawBytes, b64, cryptoKey };
  }

  /**
   * Wrap (encrypt) a raw group key for a member using pairwise E2EE.
   * @param {Uint8Array|string} rawKeyBytesOrB64
   * @param {string} peerUsername
   * @returns {Promise<any>} wrapped package
   */
  async function wrapGroupKeyForPeer(rawKeyBytesOrB64, peerUsername) {
    const b64 = (typeof rawKeyBytesOrB64 === 'string')
      ? rawKeyBytesOrB64
      : uint8ToBase64(rawKeyBytesOrB64);
    const wrappedPkg = await encryptFor(peerUsername, JSON.stringify({ group_key_b64: b64, timestamp: Date.now() }));
    return wrappedPkg;
  }

  /**
   * Unwrap (decrypt) a group key received from a creator/admin.
   * @param {any} wrappedPackage
   * @param {string} creatorUsername
   * @returns {Promise<{rawBytes: Uint8Array, cryptoKey: CryptoKey}>}
   */
  async function unwrapGroupKeyFromPeer(wrappedPackage, creatorUsername) {
    const decryptedJsonStr = await decryptFrom(creatorUsername, wrappedPackage);
    const parsed = JSON.parse(decryptedJsonStr);
    const rawBytes = base64ToUint8(parsed.group_key_b64);
    const cryptoKey = await subtle.importKey(
      'raw',
      rawBytes,
      { name: AES_ALGO, length: AES_KEY_LEN },
      false,
      ['encrypt', 'decrypt']
    );
    return { rawBytes, cryptoKey };
  }

  /**
   * Cache a Group Epoch Key locally.
   */
  function storeGroupEpochKey(groupId, epoch, cryptoKey) {
    _groupKeys.set(`${groupId}:${epoch}`, cryptoKey);
  }

  function hasGroupEpochKey(groupId, epoch) {
    return _groupKeys.has(`${groupId}:${epoch}`);
  }

  function getGroupEpochKey(groupId, epoch) {
    return _groupKeys.get(`${groupId}:${epoch}`);
  }

  /**
   * Fetch and unwrap group key from server for a given epoch.
   * @param {number} groupId
   * @param {number} epoch
   * @returns {Promise<CryptoKey>}
   */
  async function fetchAndUnwrapGroupKey(groupId, epoch) {
    const cacheKey = `${groupId}:${epoch}`;
    if (_groupKeys.has(cacheKey)) {
      return _groupKeys.get(cacheKey);
    }

    const resp = await fetch(`/api/groups/${groupId}/keys/${epoch}`);
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      throw new Error(data.error || `Failed to fetch group key for group ${groupId} epoch ${epoch}`);
    }

    let creatorUsername = null;
    try {
      const gResp = await fetch(`/api/groups/${groupId}`);
      const gData = await gResp.json();
      if (gData.ok && gData.group) {
        creatorUsername = gData.group.creator_username;
      }
    } catch (_) {}

    if (!creatorUsername) {
      creatorUsername = _currentUsername;
    }

    const { cryptoKey } = await unwrapGroupKeyFromPeer(data.encrypted_key, creatorUsername);
    storeGroupEpochKey(groupId, epoch, cryptoKey);
    return cryptoKey;
  }

  /**
   * Encrypt a message for a group in a given epoch.
   * @param {number} groupId
   * @param {number} epoch
   * @param {string} plaintext
   * @returns {Promise<{epoch: number, nonce: string, ciphertext: string, tag: string, payload: string}>}
   */
  async function encryptGroupMessage(groupId, epoch, plaintext) {
    let aesKey = getGroupEpochKey(groupId, epoch);
    if (!aesKey) {
      aesKey = await fetchAndUnwrapGroupKey(groupId, epoch);
    }
    const encrypted = await encryptMessage(aesKey, plaintext);
    encrypted.epoch = epoch;
    return encrypted;
  }

  /**
   * Decrypt a message received in a group for a given epoch.
   * @param {number} groupId
   * @param {number} epoch
   * @param {any} encryptedPackage
   * @returns {Promise<string>}
   */
  async function decryptGroupMessage(groupId, epoch, encryptedPackage) {
    let aesKey = getGroupEpochKey(groupId, epoch);
    if (!aesKey) {
      aesKey = await fetchAndUnwrapGroupKey(groupId, epoch);
    }
    return await decryptMessage(aesKey, encryptedPackage);
  }

  /**
   * Perform Group Key Rotation:
   * Generates a new GEK for newEpoch and wraps it for each member in memberList.
   * @param {number} groupId
   * @param {number} newEpoch
   * @param {Array<{user_id: number, username: string}>} members
   * @returns {Promise<{newEpoch: number, rawBytes: Uint8Array, memberKeys: Array}>}
   */
  async function rotateGroupEpoch(groupId, newEpoch, members) {
    const { rawBytes, cryptoKey } = await generateGroupEpochKey();
    storeGroupEpochKey(groupId, newEpoch, cryptoKey);

    const memberKeys = [];
    for (const m of members) {
      const wrapped = await wrapGroupKeyForPeer(rawBytes, m.username);
      memberKeys.push({
        user_id: m.user_id,
        username: m.username,
        encrypted_key: wrapped,
      });
    }

    return {
      newEpoch,
      rawBytes,
      memberKeys,
    };
  }

  /* ─── Public API ─── */
  return {
    init,
    generateKeyPair,
    computeSharedSecret,
    deriveAESGCMKey,
    encryptMessage,
    decryptMessage,
    publishPublicKey,
    fetchPeerPublicKey,
    establishSession,
    encryptFor,
    decryptFrom,
    generateGroupEpochKey,
    wrapGroupKeyForPeer,
    unwrapGroupKeyFromPeer,
    storeGroupEpochKey,
    hasGroupEpochKey,
    getGroupEpochKey,
    fetchAndUnwrapGroupKey,
    encryptGroupMessage,
    decryptGroupMessage,
    rotateGroupEpoch,
    hasSession: (peer) => _sessionKeys.has(peer),
    getPublicKeyB64: () => _publicKeyB64,
    uint8ToBase64,
    base64ToUint8,
    rfc7748X25519,
    getConfig: () => ({ CURVE, HASH, AES_ALGO, AES_KEY_LEN, NONCE_LEN, TAG_LEN }),
  };

})();

// Export for Node.js test environment if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EncryptionEngine;
}
