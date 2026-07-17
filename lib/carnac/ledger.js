/**
 * Judgment ledger — continuity artifact for every classification.
 *
 * The ledger records both escalated and below-threshold judgments, so the
 * absence of a Howler is itself provable. Persistence follows the hardened
 * pattern in lib/carnac/supabase.js: a best-effort durable Supabase mirror
 * (RLS-gated by X-Carnac-Ledger-Token, fail-closed) plus an authoritative
 * in-process store, with health reported truthfully.
 *
 * Rows are tenant-scoped and carry the continuity chain (seq, previous_digest,
 * chain_digest) so a trajectory can be reconstructed and its ordering verified
 * across a restart directly from Supabase, not only from memory. Sandbox
 * judgments never touch the durable ledger.
 */

import {
  supabaseConfigured,
  ledgerTokenConfigured,
  supaInsert,
  supaSelect,
  supabaseHealth,
} from './supabase.js';

const TABLE = () => process.env.CARNAC_LEDGER_TABLE || 'carnac_judgments';

const memory = new Map();          // judgment_id -> envelope
const trajectoryIndex = new Map(); // `${tenant}::${trajectory}` -> judgment_id[]

export { supabaseConfigured, ledgerTokenConfigured };

export function _resetLedger() {
  memory.clear();
  trajectoryIndex.clear();
}

function trajKey(tenant_id, trajectory_id) {
  return `${tenant_id || ''}::${trajectory_id || ''}`;
}

/**
 * Persist a judgment envelope. Always writes memory; mirrors to Supabase when
 * configured and the ledger token is present. Never throws.
 * @returns {Promise<{ok:boolean, durable:boolean, degraded:boolean, error:string|null}>}
 */
export async function persistJudgment(envelope, { timeoutMs = 5000 } = {}) {
  memory.set(envelope.judgment_id, envelope);
  if (envelope.trajectory_id) {
    const k = trajKey(envelope.tenant_id, envelope.trajectory_id);
    if (!trajectoryIndex.has(k)) trajectoryIndex.set(k, []);
    trajectoryIndex.get(k).push(envelope.judgment_id);
  }

  const row = {
    judgment_id: envelope.judgment_id,
    tenant_id: envelope.tenant_id || null,
    trajectory_id: envelope.trajectory_id || null,
    seq: typeof envelope.seq === 'number' ? envelope.seq : null,
    phase: envelope.phase,
    effective_level: envelope.effective_level,
    primary_route: envelope.primary_route,
    disposition: envelope.disposition?.state || null,
    escalated: Boolean(envelope.disposition?.escalated),
    feature_digest: envelope.feature_digest,
    policy_version: envelope.policy_version,
    engine: envelope.engine,
    previous_digest: envelope.previous_digest || null,
    chain_digest: envelope.chain_digest || null,
    howler_id: envelope.howler_id || null,
    envelope,
    created_at: envelope.generated_at,
  };
  return supaInsert(TABLE(), row, { timeoutMs });
}

/**
 * Fetch a judgment by id. Memory first, then durable mirror if configured.
 * @returns {Promise<object|null>}
 */
export async function fetchJudgment(judgment_id, { timeoutMs = 5000 } = {}) {
  if (memory.has(judgment_id)) return memory.get(judgment_id);
  const q = `judgment_id=eq.${encodeURIComponent(judgment_id)}&select=envelope&limit=1`;
  const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
  return ok && rows[0] ? rows[0].envelope : null;
}

/** In-memory trajectory listing (this process). Tenant-filtered when provided. */
export function listByTrajectory(trajectory_id, tenant_id = null) {
  if (tenant_id !== null) {
    const ids = trajectoryIndex.get(trajKey(tenant_id, trajectory_id)) || [];
    return ids.map((id) => memory.get(id)).filter(Boolean);
  }
  // Legacy tenant-agnostic view: union across tenants for this trajectory.
  const out = [];
  for (const [k, ids] of trajectoryIndex) {
    if (k.endsWith(`::${trajectory_id || ''}`)) out.push(...ids.map((id) => memory.get(id)).filter(Boolean));
  }
  return out;
}

/**
 * Durable, tenant-scoped trajectory listing ordered by seq then time. Works
 * after a restart (memory empty) by reading Supabase. Falls back to the
 * in-memory view when durable is unavailable.
 * @returns {Promise<{source:string, judgments:object[], error:string|null}>}
 */
export async function listByTrajectoryDurable(tenant_id, trajectory_id, { timeoutMs = 5000 } = {}) {
  if (supabaseConfigured() && ledgerTokenConfigured()) {
    const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&trajectory_id=eq.${encodeURIComponent(trajectory_id)}&select=envelope,seq,created_at&order=seq.asc.nullsfirst,created_at.asc`;
    const { ok, rows, error } = await supaSelect(TABLE(), q, { timeoutMs });
    if (ok) return { source: 'durable', judgments: rows.map((r) => r.envelope).filter(Boolean), error: null };
    return { source: 'degraded', judgments: listByTrajectory(trajectory_id, tenant_id), error };
  }
  return { source: 'memory', judgments: listByTrajectory(trajectory_id, tenant_id), error: null };
}

/**
 * Does a (tenant, trajectory, seq) already exist? Checks memory then durable,
 * so duplicates are rejected even across a restart.
 * @returns {Promise<boolean>}
 */
export async function trajectorySeqExists(tenant_id, trajectory_id, seq, { timeoutMs = 5000 } = {}) {
  const ids = trajectoryIndex.get(trajKey(tenant_id, trajectory_id)) || [];
  for (const id of ids) {
    const e = memory.get(id);
    if (e && e.seq === seq) return true;
  }
  if (supabaseConfigured() && ledgerTokenConfigured()) {
    const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&trajectory_id=eq.${encodeURIComponent(trajectory_id)}&seq=eq.${encodeURIComponent(seq)}&select=judgment_id&limit=1`;
    const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
    if (ok && rows.length) return true;
  }
  return false;
}

/**
 * The last chain link for a (tenant, trajectory): {chain_digest, seq}. Memory is
 * authoritative in-process; durable is consulted so the chain survives a restart.
 * @returns {Promise<{chain_digest:string|null, seq:number|null}>}
 */
export async function lastChainLink(tenant_id, trajectory_id, { timeoutMs = 5000 } = {}) {
  const ids = trajectoryIndex.get(trajKey(tenant_id, trajectory_id)) || [];
  let best = null;
  for (const id of ids) {
    const e = memory.get(id);
    if (!e) continue;
    if (!best || (e.seq ?? -1) >= (best.seq ?? -1)) best = e;
  }
  if (best) return { chain_digest: best.chain_digest || null, seq: best.seq ?? null };
  if (supabaseConfigured() && ledgerTokenConfigured()) {
    const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&trajectory_id=eq.${encodeURIComponent(trajectory_id)}&select=chain_digest,seq&order=seq.desc.nullslast,created_at.desc&limit=1`;
    const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
    if (ok && rows[0]) return { chain_digest: rows[0].chain_digest || null, seq: rows[0].seq ?? null };
  }
  return { chain_digest: null, seq: null };
}

/**
 * Durable, tenant-scoped listing over a created_at range, ordered by time, with
 * a hard limit. Falls back to an in-memory scan when durable is unavailable.
 * @returns {Promise<{source:string, judgments:object[], error:string|null}>}
 */
export async function listByTimeRange(tenant_id, fromIso, toIso, { limit = 1000, timeoutMs = 5000 } = {}) {
  const cap = Math.max(1, Math.min(5000, limit));
  if (supabaseConfigured() && ledgerTokenConfigured()) {
    let q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&select=envelope,created_at&order=created_at.asc&limit=${cap}`;
    if (fromIso) q += `&created_at=gte.${encodeURIComponent(fromIso)}`;
    if (toIso) q += `&created_at=lte.${encodeURIComponent(toIso)}`;
    const { ok, rows, error } = await supaSelect(TABLE(), q, { timeoutMs });
    if (ok) return { source: 'durable', judgments: rows.map((r) => r.envelope).filter(Boolean), error: null };
    return { source: 'degraded', judgments: memScanRange(tenant_id, fromIso, toIso, cap), error };
  }
  return { source: 'memory', judgments: memScanRange(tenant_id, fromIso, toIso, cap), error: null };
}

function memScanRange(tenant_id, fromIso, toIso, cap) {
  const out = [];
  for (const e of memory.values()) {
    if (e.tenant_id !== tenant_id) continue;
    if (fromIso && e.generated_at < fromIso) continue;
    if (toIso && e.generated_at > toIso) continue;
    out.push(e);
  }
  out.sort((a, b) => String(a.generated_at).localeCompare(String(b.generated_at)));
  return out.slice(0, cap);
}

/** Ledger health probe. Never throws. */
export async function ledgerHealth({ timeoutMs = 4000 } = {}) {
  const h = await supabaseHealth(TABLE(), { timeoutMs });
  return { in_memory_count: memory.size, table: TABLE(), ...h };
}
