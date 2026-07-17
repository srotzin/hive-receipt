// Spectral ed25519 sign/verify library
import crypto from 'crypto';
import { canonicalize, sha256hex } from './carnac/canon.js';

let _privKey = null;
let _pubKey = null;
let _pubKeyB64 = null;

export function initKeypair() {
  const privB64 = process.env.SPECTRAL_PRIVKEY_B64;
  const pubB64  = process.env.SPECTRAL_PUBKEY_B64;

  if (privB64 && pubB64) {
    // Restore from env (32-byte seed for ed25519)
    const seed = Buffer.from(privB64, 'base64');
    const keyObj = crypto.createPrivateKey({ key: seed, format: 'raw', type: 'ed25519' });
    _privKey = keyObj;
    const pubObj = crypto.createPublicKey(keyObj);
    _pubKey = pubObj;
    _pubKeyB64 = Buffer.from(pubObj.export({ type: 'spki', format: 'der' })).toString('base64');
    console.log('Spectral keypair loaded from env. pubkey:', _pubKeyB64.slice(0, 20) + '...');
  } else {
    // Generate fresh keypair at deploy time
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    _privKey = privateKey;
    _pubKey = publicKey;
    _pubKeyB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
    const privSeed = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })).toString('base64');
    console.log('Spectral keypair generated fresh.');
    console.log('SPECTRAL_PRIVKEY_B64=' + privSeed);
    console.log('SPECTRAL_PUBKEY_B64=' + _pubKeyB64);
  }
}

export function getPublicKeyB64() {
  return _pubKeyB64;
}

/**
 * Sign a payload object. Returns {signature, public_key, signed_payload_sha256, signature_algo}.
 */
export function signPayload(payload) {
  const payloadStr = JSON.stringify(payload);
  const payloadHash = crypto.createHash('sha256').update(payloadStr).digest('hex');
  const sig = crypto.sign(null, Buffer.from(payloadStr), _privKey);
  return {
    signature: sig.toString('base64'),
    public_key: _pubKeyB64,
    signed_payload_sha256: payloadHash,
    signature_algo: 'ed25519'
  };
}

/**
 * Verify a Spectral envelope. Returns {valid, error?}.
 * envelope must have: payload fields + signature + public_key + signed_payload_sha256 + signature_algo
 */
export function verifyEnvelope(envelope) {
  try {
    const { signature, public_key, signed_payload_sha256, signature_algo, ...payload } = envelope;
    if (signature_algo !== 'ed25519') return { valid: false, error: 'unsupported algo' };

    const payloadStr = JSON.stringify(payload);
    const computedHash = crypto.createHash('sha256').update(payloadStr).digest('hex');
    if (computedHash !== signed_payload_sha256) {
      return { valid: false, error: 'payload hash mismatch' };
    }

    const pubKeyDer = Buffer.from(public_key, 'base64');
    const pubKeyObj = crypto.createPublicKey({ key: pubKeyDer, format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(payloadStr), pubKeyObj, Buffer.from(signature, 'base64'));
    return { valid: ok };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

/**
 * Sign a payload over its DETERMINISTIC CANONICAL form. Unlike signPayload, the
 * signed bytes are canonicalize(payload) (recursively sorted keys), so an
 * envelope verifies no matter what order its fields are stored or re-parsed in.
 * Uses the same ed25519 key. Returns sibling fields under a distinct algo label.
 */
export function signCanonical(payload) {
  const canonical = canonicalize(payload);
  const payloadHash = sha256hex(canonical);
  const sig = crypto.sign(null, Buffer.from(canonical), _privKey);
  return {
    signature: sig.toString('base64'),
    public_key: _pubKeyB64,
    signed_payload_sha256: payloadHash,
    signature_algo: 'ed25519-canonical',
  };
}

/**
 * Verify an envelope signed by signCanonical. Recomputes the canonical form of
 * the remaining payload, so field order is irrelevant. Returns {valid, error?}.
 */
export function verifyCanonical(envelope) {
  try {
    const { signature, public_key, signed_payload_sha256, signature_algo, ...payload } = envelope || {};
    if (signature_algo !== 'ed25519-canonical') return { valid: false, error: 'unsupported algo' };
    const canonical = canonicalize(payload);
    const computedHash = sha256hex(canonical);
    if (computedHash !== signed_payload_sha256) return { valid: false, error: 'payload hash mismatch' };
    const pubKeyObj = crypto.createPublicKey({ key: Buffer.from(public_key, 'base64'), format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(canonical), pubKeyObj, Buffer.from(signature, 'base64'));
    return { valid: ok };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}
