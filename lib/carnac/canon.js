/**
 * Deterministic canonicalization and domain-separated hashing for the Carnac
 * lifecycle chain.
 *
 * Every commitment and chain link in the lifecycle is a hash over a canonical
 * byte string, so the same logical object always produces the same digest
 * regardless of key insertion order or where it was built (client, edge, or
 * server). Canonical form is JSON with object keys sorted recursively; arrays
 * keep their order because order is meaning.
 *
 * Hashes are domain-separated with a version tag so a digest computed for one
 * purpose (a stage commitment) can never collide with a digest computed for
 * another (a chain link), even over identical bytes.
 */

import crypto from 'crypto';

/**
 * Canonical JSON string: object keys sorted recursively, no incidental
 * whitespace. Rejects values that have no stable serialization.
 * @param {*} value
 * @returns {string}
 */
export function canonicalize(value) {
  return JSON.stringify(normalize(value));
}

function normalize(value) {
  if (value === null) return null;
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonicalize: non-finite number');
    return value;
  }
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new Error(`canonicalize: unsupported type ${t}`);
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (t === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const v = value[key];
      if (v === undefined) continue; // omit undefined so it matches a JSON round trip
      out[key] = normalize(v);
    }
    return out;
  }
  throw new Error(`canonicalize: unsupported value ${String(value)}`);
}

/** sha256 hex over a string or buffer. */
export function sha256hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Domain-separated digest over the canonical form of an object.
 * @param {string} domain a stable tag, e.g. 'carnac.stage.v1'
 * @param {*} obj
 * @returns {string} sha256 hex
 */
export function hashObject(domain, obj) {
  if (!domain || typeof domain !== 'string') throw new Error('hashObject: domain required');
  return sha256hex(`${domain}\n${canonicalize(obj)}`);
}

/**
 * Commit a piece of content by hash only. Accepts a precomputed hex commitment
 * or raw text; when given text it is hashed and the text is discarded by the
 * caller. This function never stores or returns the raw text.
 * @param {{commit?:string, text?:string}} input
 * @param {string} [domain]
 * @returns {string|null} hex commitment, or null when nothing was provided
 */
export function contentCommit({ commit, text } = {}, domain = 'carnac.content.v1') {
  if (typeof commit === 'string' && /^[0-9a-f]{64}$/i.test(commit)) return commit.toLowerCase();
  if (typeof text === 'string') return sha256hex(`${domain}\n${text}`);
  return null;
}
