/**
 * Durable Howler store.
 *
 * A Howler is the severity-bound escalation receipt minted at effective level 3.
 * It is signed with the Hive ed25519 key and bound to its originating judgment by
 * judgment_id + feature_digest. This store mirrors it to Supabase (RLS-gated) and
 * keeps an authoritative in-memory copy, exactly like the judgment ledger.
 * Retrieval is tenant-scoped; a Howler is returned only to a caller allowed to
 * see its tenant.
 */

import { verifyEnvelope } from '../spectral.js';
import { supabaseConfigured, ledgerTokenConfigured, supaInsert, supaSelect } from './supabase.js';

const TABLE = () => process.env.CARNAC_HOWLER_TABLE || 'carnac_howlers';

const memory = new Map(); // howler_id -> howler envelope

export function _resetHowlers() {
  memory.clear();
}

/**
 * Persist a signed Howler envelope. Always writes memory; mirrors to Supabase.
 * @returns {Promise<{ok:boolean, durable:boolean, degraded:boolean, error:string|null}>}
 */
export async function persistHowler(howler, { timeoutMs = 5000 } = {}) {
  if (!howler || !howler.howler_id) return { ok: false, durable: false, degraded: false, error: 'missing howler' };
  memory.set(howler.howler_id, howler);
  const row = {
    howler_id: howler.howler_id,
    tenant_id: howler.tenant_id || null,
    judgment_id: howler.judgment_id || null,
    trajectory_id: howler.trajectory_id || null,
    severity: howler.severity ?? null,
    feature_digest: howler.feature_digest || null,
    policy_version: howler.policy_version || null,
    envelope: howler,
    created_at: howler.raised_at || new Date().toISOString(),
  };
  return supaInsert(TABLE(), row, { timeoutMs });
}

/** Fetch a Howler by id. Memory first, then durable. Never throws. */
export async function fetchHowler(howler_id, { timeoutMs = 5000 } = {}) {
  if (memory.has(howler_id)) return memory.get(howler_id);
  const q = `howler_id=eq.${encodeURIComponent(howler_id)}&select=envelope&limit=1`;
  const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
  return ok && rows[0] ? rows[0].envelope : null;
}

/**
 * Verify a Howler's ed25519 signature and its binding to the originating
 * judgment. Binding holds when the Howler names the judgment and their feature
 * digests match.
 * @param {object} howler
 * @param {object|null} judgment the originating judgment envelope (optional)
 * @returns {{signature_valid:boolean, bound:boolean, binding_error:string|null, signature_error:string|null}}
 */
export function verifyHowler(howler, judgment = null) {
  const sig = verifyEnvelope(howler);
  let bound = false;
  let binding_error = null;
  if (judgment) {
    if (howler.judgment_id !== judgment.judgment_id) {
      binding_error = 'judgment_id mismatch';
    } else if (howler.feature_digest !== judgment.feature_digest) {
      binding_error = 'feature_digest mismatch';
    } else {
      bound = true;
    }
  } else {
    binding_error = 'originating judgment not available';
  }
  return { signature_valid: sig.valid, bound, binding_error, signature_error: sig.error || null };
}
