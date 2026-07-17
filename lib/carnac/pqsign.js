/**
 * Post-quantum (ML-DSA-65) signing via the Hive typed signer service.
 *
 * There is no in-repo ML-DSA implementation and the Node runtime here has no
 * native ML-DSA primitive, so a REAL ML-DSA-65 signature can only be produced by
 * the external Hive typed signer. This module is a thin, honest client for it —
 * it never fabricates a signature and never invents an algorithm label.
 *
 *   HIVE_PQ_SIGNER_URL    — typed signer base URL. POST {url}/sign and {url}/verify.
 *   HIVE_PQ_SIGNER_TOKEN  — optional bearer token for the signer.
 *   HIVE_PQ_SIGNER_ALGO   — algorithm label the signer must return (default ml-dsa-65).
 *
 * Contract with the signer:
 *   POST /sign   {payload_sha256, algo}          -> {signature, public_key, algo}
 *   POST /verify {payload_sha256, signature, public_key, algo} -> {valid}
 *
 * When the signer is unconfigured or unreachable, pqSign returns
 * {available:false} — callers decide policy: protected production routes fail
 * closed, the sandbox may proceed in an explicitly degraded no-PQ state.
 */

import crypto from 'crypto';

const ALGO = () => process.env.HIVE_PQ_SIGNER_ALGO || 'ml-dsa-65';

export function pqConfigured() {
  return Boolean(process.env.HIVE_PQ_SIGNER_URL);
}

function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (process.env.HIVE_PQ_SIGNER_TOKEN) h['X-Hive-Internal-Token'] = process.env.HIVE_PQ_SIGNER_TOKEN;
  return h;
}

/** sha256 hex over the canonical JSON of a payload. */
export function payloadDigest(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

/**
 * Produce a real ML-DSA-65 signature over a payload's digest via the signer.
 * Never throws. Never fabricates.
 * @returns {Promise<{available:true, algo:string, signature:string, public_key:string, payload_sha256:string}
 *          | {available:false, error:string, algo:string}>}
 */
export async function pqSign(payload, { timeoutMs = 5000 } = {}) {
  const algo = ALGO();
  const url = process.env.HIVE_PQ_SIGNER_URL;
  if (!url) return { available: false, error: 'pq_signer_not_configured', algo };
  const payload_sha256 = payloadDigest(payload);
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/sign`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ payload_sha256, algo }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { available: false, error: `pq_signer_http_${res.status}`, algo };
    const body = await res.json().catch(() => null);
    if (!body || typeof body.signature !== 'string' || typeof body.public_key !== 'string') {
      return { available: false, error: 'pq_signer_invalid_response', algo };
    }
    // Never accept a mislabeled algorithm — a fake label is worse than no PQ.
    if (body.algo && body.algo !== algo) {
      return { available: false, error: `pq_signer_algo_mismatch:${body.algo}`, algo };
    }
    return { available: true, algo, signature: body.signature, public_key: body.public_key, payload_sha256 };
  } catch (e) {
    const error = e.name === 'TimeoutError' ? `pq_signer_timeout_${timeoutMs}ms` : e.message;
    return { available: false, error, algo };
  }
}

/**
 * Independently verify an ML-DSA-65 signature via the signer's verify endpoint.
 * Returns {ok:false, ...} when the signer is unavailable — a PQ signature cannot
 * be validated locally, so this is reported honestly rather than assumed valid.
 * @returns {Promise<{ok:true, valid:boolean} | {ok:false, error:string}>}
 */
export async function pqVerify({ payload_sha256, signature, public_key, algo } = {}, { timeoutMs = 5000 } = {}) {
  const url = process.env.HIVE_PQ_SIGNER_URL;
  if (!url) return { ok: false, error: 'pq_signer_not_configured' };
  if (!payload_sha256 || !signature || !public_key) return { ok: false, error: 'pq_verify_missing_fields' };
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/verify`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ payload_sha256, signature, public_key, algo: algo || ALGO() }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { ok: false, error: `pq_signer_http_${res.status}` };
    const body = await res.json().catch(() => null);
    if (!body || typeof body.valid !== 'boolean') return { ok: false, error: 'pq_verify_invalid_response' };
    return { ok: true, valid: body.valid };
  } catch (e) {
    const error = e.name === 'TimeoutError' ? `pq_signer_timeout_${timeoutMs}ms` : e.message;
    return { ok: false, error };
  }
}

/** Health probe of the PQ signer. Never throws. */
export async function pqHealth({ timeoutMs = 4000 } = {}) {
  const algo = ALGO();
  if (!pqConfigured()) {
    return { configured: false, available: false, algo, error: 'pq_signer_not_configured' };
  }
  // A zero-cost probe: sign a fixed sentinel digest.
  const probe = await pqSign({ probe: 'pq-health' }, { timeoutMs });
  return {
    configured: true,
    available: probe.available,
    algo,
    error: probe.available ? null : probe.error,
  };
}
