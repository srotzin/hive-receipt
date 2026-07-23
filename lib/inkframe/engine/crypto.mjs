// engine/crypto.mjs
// Hybrid Ed25519 + ML-DSA-65 signing over RFC 8785 JCS canonical JSON + SHA-256.
// InkFrame v1 · Carnac Live Ink™ · Hive Civilization Inc.
// This file is public-safe. It handles canonicalization, hashing, and signing.
// It does NOT contain span-detection, proof-sizing, or routing math.

import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// ---------- RFC 8785 JCS canonicalization ----------
// Deterministic JSON: sorted object keys, no whitespace, canonical number form.
export function jcs(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number');
    // Integer form when representable; JSON number form otherwise.
    if (Number.isInteger(value)) return String(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('JCS: unsupported type ' + typeof value);
}

// ---------- hashing ----------
export function sha256hex(input) {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return bytesToHex(sha256(bytes));
}

export function contentAddress(obj) {
  return 'sha256:' + sha256hex(jcs(obj));
}

// ---------- keygen ----------
export function generateKeypair(seed) {
  // Deterministic if seed is provided (32 bytes). Otherwise random.
  const edSeed = seed ? seed.slice(0, 32) : crypto.getRandomValues(new Uint8Array(32));
  const edPriv = edSeed;
  const edPub = ed25519.getPublicKey(edPriv);

  const mlSeed = seed ? sha256(new Uint8Array([...seed, 1])).slice(0, 32) : crypto.getRandomValues(new Uint8Array(32));
  const mlKeys = ml_dsa65.keygen(mlSeed);

  return {
    ed25519: { publicKey: bytesToHex(edPub), secretKey: bytesToHex(edPriv) },
    mldsa65: { publicKey: bytesToHex(mlKeys.publicKey), secretKey: bytesToHex(mlKeys.secretKey) }
  };
}

// ---------- hybrid sign ----------
// Sign the SHA-256 of the JCS canonical form of `payload` with BOTH keys.
// The signature_set carries both signatures. Verification requires BOTH.
export function hybridSign(payload, keys) {
  const canonical = jcs(payload);
  const digest = sha256(utf8ToBytes(canonical));
  const edSig = ed25519.sign(digest, hexToBytes(keys.ed25519.secretKey));
  const mlSig = ml_dsa65.sign(hexToBytes(keys.mldsa65.secretKey), digest);
  return {
    alg: 'ed25519+ml-dsa-65',
    canon: 'rfc8785+sha256',
    digest: bytesToHex(digest),
    ed25519: {
      publicKey: keys.ed25519.publicKey,
      signature: bytesToHex(edSig)
    },
    mldsa65: {
      publicKey: keys.mldsa65.publicKey,
      signature: bytesToHex(mlSig)
    },
    signed_at: new Date().toISOString()
  };
}

export function hybridVerify(payload, signature_set) {
  const canonical = jcs(payload);
  const digest = sha256(utf8ToBytes(canonical));
  const digestHex = bytesToHex(digest);
  if (digestHex !== signature_set.digest) {
    return { ok: false, reason: 'digest mismatch (payload was mutated)' };
  }
  try {
    const edOk = ed25519.verify(
      hexToBytes(signature_set.ed25519.signature),
      digest,
      hexToBytes(signature_set.ed25519.publicKey)
    );
    if (!edOk) return { ok: false, reason: 'ed25519 verification failed' };

    const mlOk = ml_dsa65.verify(
      hexToBytes(signature_set.mldsa65.publicKey),
      digest,
      hexToBytes(signature_set.mldsa65.signature)
    );
    if (!mlOk) return { ok: false, reason: 'ml-dsa-65 verification failed' };

    return { ok: true, alg: signature_set.alg, canon: signature_set.canon };
  } catch (e) {
    return { ok: false, reason: 'verification threw: ' + e.message };
  }
}
