/**
 * test_cross_e2ee.js — Cross-Environment E2EE Verification Test.
 *
 * Verifies:
 *   1. JavaScript Alice and Bob generate X25519 key pairs.
 *   2. Compute shared secret via X25519.
 *   3. Derive 256-bit AES-GCM key via HKDF-SHA-256.
 *   4. Alice encrypts message with AES-256-GCM (12-byte nonce, 16-byte tag).
 *   5. Bob decrypts message successfully.
 *   6. Cross-platform verification: JavaScript ciphertext can be decrypted by Python,
 *      and Python ciphertext can be decrypted by JavaScript!
 */

const fs = require('fs');
const path = require('path');
const { execSync, execFileSync } = require('child_process');
const EncryptionEngine = require('./static/js/encryption.js');

function getPythonPath() {
  if (process.env.PYTHON) return process.env.PYTHON;
  const localAppData = process.env.LOCALAPPDATA || '';
  const winPy = path.join(localAppData, 'Python', 'bin', 'python.exe');
  if (fs.existsSync(winPy)) return winPy;
  const winPy312 = path.join(localAppData, 'Programs', 'Python', 'Python312', 'python.exe');
  if (fs.existsSync(winPy312)) return winPy312;
  return 'python';
}
const pythonCmd = getPythonPath();

const PASS = '\x1b[32m[PASS]\x1b[0m';
const FAIL = '\x1b[31m[FAIL]\x1b[0m';
const INFO = '\x1b[34m[INFO]\x1b[0m';

let failures = 0;

function check(label, condition, detail = '') {
  if (condition) {
    console.log(`  ${PASS} ${label}`);
  } else {
    console.log(`  ${FAIL} ${label} - ${detail}`);
    failures++;
  }
}

async function runTests() {
  console.log(`${INFO} Starting Client-Side JavaScript & Cross-Platform E2EE Test Suite...\n`);

  // ── 1. Key Generation in JS ──
  console.log(`${INFO} [1] Testing JavaScript X25519 Key Generation...`);
  const alice = await EncryptionEngine.generateKeyPair();
  const alicePubB64 = alice.publicKeyB64;
  const aliceKeyPair = alice.keyPair;

  const bob = await EncryptionEngine.generateKeyPair();
  const bobPubB64 = bob.publicKeyB64;
  const bobKeyPair = bob.keyPair;

  check('Alice public key is 44 characters (Base64 of 32 bytes)', alicePubB64.length === 44);
  check('Bob public key is 44 characters (Base64 of 32 bytes)', bobPubB64.length === 44);
  check('Alice and Bob generated distinct public keys', alicePubB64 !== bobPubB64);

  // ── 2. Key Agreement & Derivation ──
  console.log(`\n${INFO} [2] Testing X25519 Diffie-Hellman & HKDF-SHA-256 in JavaScript...`);
  const aliceShared = await EncryptionEngine.computeSharedSecret(
    aliceKeyPair,
    EncryptionEngine.base64ToUint8(bobPubB64)
  );
  const bobShared = await EncryptionEngine.computeSharedSecret(
    bobKeyPair,
    EncryptionEngine.base64ToUint8(alicePubB64)
  );

  check('Shared secrets are 32 bytes', aliceShared.length === 32 && bobShared.length === 32);
  check('Alice and Bob computed identical shared secrets', Buffer.from(aliceShared).equals(Buffer.from(bobShared)));

  const aliceAesKey = await EncryptionEngine.deriveAESGCMKey(aliceShared);
  const bobAesKey   = await EncryptionEngine.deriveAESGCMKey(bobShared);
  check('Derived AES-GCM CryptoKeys successfully', Boolean(aliceAesKey && bobAesKey));

  // ── 3. Encryption & Decryption in JS ──
  console.log(`\n${INFO} [3] Testing AES-256-GCM Message Encryption & Decryption in JavaScript...`);
  const secretText = 'Hello Bob! This message was encrypted client-side in JavaScript with AES-256-GCM.';
  const encryptedPkg = await EncryptionEngine.encryptMessage(aliceAesKey, secretText);

  check('Encrypted package contains nonce, ciphertext, tag, and payload',
    Boolean(encryptedPkg.nonce && encryptedPkg.ciphertext && encryptedPkg.tag && encryptedPkg.payload));

  const decryptedText = await EncryptionEngine.decryptMessage(bobAesKey, encryptedPkg);
  check('Bob decrypted original message in JavaScript', decryptedText === secretText);

  // Decrypt from wire payload
  const decryptedFromPayload = await EncryptionEngine.decryptMessage(bobAesKey, encryptedPkg.payload);
  check('Bob decrypted from wire payload string', decryptedFromPayload === secretText);

  // ── 4. Cross-Platform: Python Decrypts JS Ciphertext ──
  console.log(`\n${INFO} [4] Testing Cross-Platform: Python decrypts JavaScript ciphertext...`);
  // Run python script that imports alicePub, bobKeyPair, and encryptedPkg to decrypt
  const pyCode = `
import json, base64
from encryption.e2ee import (
    import_public_key, import_private_key, derive_shared_secret, derive_aes_key, decrypt_message
)
# Bob's private key and Alice's public key
bob_pub = import_public_key("${bobPubB64}")
alice_pub = import_public_key("${alicePubB64}")

# We derive shared secret using Bob's private key in Python
`;
  // Let's test full Python <-> JS cross-encryption:
  // Step 4a: Python encrypts message for Bob in JS
  console.log(`\n${INFO} [5] Testing Cross-Platform: Python encrypts -> JavaScript decrypts...`);
  const pyScript1 = `
import json
from encryption.e2ee import (
    generate_key_pair, export_public_key, import_public_key,
    derive_shared_secret, derive_aes_key, encrypt_message
)
priv, pub = generate_key_pair()
shared = derive_shared_secret(priv, import_public_key("${bobPubB64}"))
key = derive_aes_key(shared)
enc = encrypt_message(key, "Greetings from Python cryptography!")
print(json.dumps({"py_pub": export_public_key(pub), "enc": enc}))
`;
  const pythonGenOutput = execFileSync(pythonCmd, ['-c', pyScript1], { cwd: __dirname }).toString();
  const pyData = JSON.parse(pythonGenOutput);

  const bobSharedWithPy = await EncryptionEngine.computeSharedSecret(
    bobKeyPair,
    EncryptionEngine.base64ToUint8(pyData.py_pub)
  );
  const bobAesKeyForPy = await EncryptionEngine.deriveAESGCMKey(bobSharedWithPy);
  const jsDecryptedFromPy = await EncryptionEngine.decryptMessage(bobAesKeyForPy, pyData.enc);

  check('JavaScript successfully decrypted message encrypted by Python cryptography!',
    jsDecryptedFromPy === 'Greetings from Python cryptography!');

  // Step 4b: JS encrypts message -> Python decrypts
  console.log(`\n${INFO} [6] Testing Cross-Platform: JavaScript encrypts -> Python decrypts...`);
  const jsEncForPy = await EncryptionEngine.encryptMessage(bobAesKeyForPy, 'Hello from JavaScript Web Crypto!');
  const pyScript2 = `
import json
from encryption.e2ee import derive_aes_key, decrypt_message
shared = bytes(${JSON.stringify([...bobSharedWithPy])})
key = derive_aes_key(shared)
pkg = json.loads('''${JSON.stringify(jsEncForPy)}''')
print(decrypt_message(key, pkg))
`;
  const pythonDecOutput = execFileSync(pythonCmd, ['-c', pyScript2], { cwd: __dirname }).toString().trim();

  check('Python cryptography successfully decrypted message encrypted by JavaScript!',
    pythonDecOutput === 'Hello from JavaScript Web Crypto!');

  // ── Summary ──
  console.log();
  if (failures === 0) {
    console.log('\x1b[32m================================================================');
    console.log('  ALL CROSS-PLATFORM E2EE TESTS PASSED - JS <-> PYTHON VERIFIED!');
    console.log('================================================================\x1b[0m');
    process.exit(0);
  } else {
    console.log(`\x1b[31m================================================================`);
    console.log(`  ${failures} TEST(S) FAILED`);
    console.log(`================================================================\x1b[0m`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
