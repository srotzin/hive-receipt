/**
 * Public-safe verification.
 *
 * Anyone may verify a Carnac artifact's cryptographic validity, in one of two
 * ways:
 *   - by value: POST a complete signed envelope; its ed25519 signature (and the
 *     bound sibling PQ signature, when the signer is reachable) is checked.
 *   - by id: GET with an opaque judgment_id; the stored envelope is looked up and
 *     verified.
 *
 * The response is PUBLIC-SAFE: it exposes only cryptographic validity and a small
 * projection of non-sensitive commitment fields. Raw prompt/output text is never
 * stored and never returned; tenant identity, actor, nonces, and unrelated ledger
 * fields are stripped.
 *
 * By-id verification is rate-limited per client to resist enumeration of the
 * opaque id space (CARNAC_VERIFY_RATE_PER_MIN, default 30/min).
 */

import { verifyEnvelope } from '../spectral.js';
import { fetchJudgment } from './ledger.js';
import { pqVerify } from './pqsign.js';

const RATE_PER_MIN = () => Math.max(1, Number(process.env.CARNAC_VERIFY_RATE_PER_MIN) || 30);
const WINDOW_MS = 60 * 1000;

const buckets = new Map(); // client -> { count, resetAt }

export function _resetVerifyLimiter() {
  buckets.clear();
}

/**
 * Fixed-window rate limit keyed on an opaque client id (e.g. hashed IP).
 * @returns {{ok:true, remaining:number} | {ok:false, retry_after_s:number}}
 */
export function rateLimit(client) {
  const now = Date.now();
  const key = client || 'anon';
  const limit = RATE_PER_MIN();
  let b = buckets.get(key);
  if (!b || now >= b.resetAt) {
    b = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, b);
  }
  if (b.count >= limit) {
    return { ok: false, retry_after_s: Math.ceil((b.resetAt - now) / 1000) };
  }
  b.count += 1;
  return { ok: true, remaining: limit - b.count };
}

// Only these fields ever cross the public boundary. No tenant_id, no actor, no
// nonce, no request/output text (the latter is never stored regardless).
const PUBLIC_FIELDS = [
  'judgment_id', 'trajectory_id', 'phase', 'seq',
  'effective_level', 'primary_route', 'policy_version',
  'feature_digest', 'previous_digest', 'chain_digest', 'howler_id',
  'signed_payload_sha256', 'signature_algo', 'generated_at', 'sandbox',
];

function publicView(envelope) {
  const out = {};
  for (const k of PUBLIC_FIELDS) if (envelope[k] !== undefined) out[k] = envelope[k];
  return out;
}

/**
 * Verify a complete signed envelope by value. Public-safe.
 * @returns {Promise<{ok:true, signature_valid:boolean, signature_error:string|null, pq:object, artifact:object}>}
 */
export async function verifyArtifact(envelope = {}) {
  const { pq, ...env } = envelope || {};
  const sig = verifyEnvelope(env);

  // PQ: the sibling signature is bound to the ed25519 envelope by digest. Only a
  // reachable signer can confirm a real ML-DSA-65 signature; otherwise its state
  // is reported honestly rather than assumed valid.
  const pqResult = { present: Boolean(pq && pq.available), algo: pq?.algo || null, bound: false, valid: null, error: pq?.error || null };
  if (pq && pq.available) {
    pqResult.bound = pq.payload_sha256 === env.signed_payload_sha256;
    if (!pqResult.bound) {
      pqResult.error = 'pq payload digest not bound to ed25519 envelope';
    } else {
      const v = await pqVerify({ payload_sha256: pq.payload_sha256, signature: pq.signature, public_key: pq.public_key, algo: pq.algo });
      if (v.ok) pqResult.valid = v.valid;
      else pqResult.error = v.error;
    }
  }

  return {
    ok: true,
    signature_valid: sig.valid,
    signature_error: sig.error || null,
    pq: pqResult,
    artifact: publicView(env),
  };
}

/**
 * Verify a stored judgment by opaque id. Rate-limited and enumeration-resistant:
 * a miss and a genuine record both return the same shape (no existence oracle
 * beyond the signature result itself), and callers are throttled.
 * @returns {Promise<{ok:true, found:boolean, signature_valid:boolean, ...} | {ok:false, status:number, code:string, message:string, retry_after_s?:number}>}
 */
export async function verifyById(id, { client } = {}) {
  const rl = rateLimit(client);
  if (!rl.ok) {
    return { ok: false, status: 429, code: 'rate_limited', message: 'verification rate limit exceeded', retry_after_s: rl.retry_after_s };
  }
  if (!id || typeof id !== 'string') {
    return { ok: false, status: 400, code: 'invalid_id', message: 'judgment id required' };
  }
  const envelope = await fetchJudgment(id);
  if (!envelope) {
    return { ok: true, found: false, signature_valid: false, signature_error: 'not_found', pq: { present: false }, artifact: null };
  }
  const v = await verifyArtifact(envelope);
  return { ok: true, found: true, ...v };
}
