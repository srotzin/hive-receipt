/**
 * Judgment ledger — continuity artifact for every classification.
 *
 * The ledger records both escalated and below-threshold judgments, so the
 * absence of a Howler is itself provable. Persistence follows the same hardened
 * pattern as lib/site_store.js: a best-effort Supabase (PostgREST) write plus an
 * authoritative in-process store, with health reported truthfully rather than a
 * failure masquerading as "no data."
 *
 * The in-memory store is always written and is the source of truth for reads in
 * this process (and for tests); Supabase is a durable mirror that engages only
 * when CARNAC_LEDGER_SUPA_URL (or the shared SUPA_URL) is configured. Sandbox
 * judgments never touch the durable ledger — the no-effect sandbox must not
 * pollute production continuity.
 */

const SUPA_URL = process.env.CARNAC_LEDGER_SUPA_URL || process.env.SUPA_URL || '';
const SUPA_KEY = process.env.CARNAC_LEDGER_SUPA_KEY || process.env.SUPA_KEY || '';
const TABLE = process.env.CARNAC_LEDGER_TABLE || 'carnac_judgments';

const memory = new Map();        // judgment_id -> envelope
const trajectoryIndex = new Map(); // trajectory_id -> judgment_id[]

export function _resetLedger() {
  memory.clear();
  trajectoryIndex.clear();
}

export function supabaseConfigured() {
  return Boolean(SUPA_URL && SUPA_KEY);
}

function headers(extra = {}) {
  return { apikey: SUPA_KEY, Authorization: `Bearer ${SUPA_KEY}`, 'Content-Type': 'application/json', ...extra };
}

/**
 * Persist a judgment envelope. Always writes memory; mirrors to Supabase when
 * configured. Never throws.
 * @returns {Promise<{ok:boolean, durable:boolean, degraded:boolean, error:string|null}>}
 */
export async function persistJudgment(envelope, { timeoutMs = 5000 } = {}) {
  // In-memory (authoritative for this process).
  memory.set(envelope.judgment_id, envelope);
  if (envelope.trajectory_id) {
    if (!trajectoryIndex.has(envelope.trajectory_id)) trajectoryIndex.set(envelope.trajectory_id, []);
    trajectoryIndex.get(envelope.trajectory_id).push(envelope.judgment_id);
  }

  if (!supabaseConfigured()) {
    return { ok: true, durable: false, degraded: false, error: null };
  }

  const row = {
    judgment_id: envelope.judgment_id,
    trajectory_id: envelope.trajectory_id || null,
    phase: envelope.phase,
    effective_level: envelope.effective_level,
    primary_route: envelope.primary_route,
    disposition: envelope.disposition?.state || null,
    escalated: Boolean(envelope.disposition?.escalated),
    feature_digest: envelope.feature_digest,
    policy_version: envelope.policy_version,
    engine: envelope.engine,
    envelope,
    created_at: envelope.generated_at,
  };

  try {
    const res = await fetch(`${SUPA_URL}/rest/v1/${TABLE}`, {
      method: 'POST',
      headers: headers({ Prefer: 'return=minimal' }),
      body: JSON.stringify(row),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: true, durable: false, degraded: true, error: `HTTP ${res.status}: ${text.slice(0, 200)}` };
    }
    return { ok: true, durable: true, degraded: false, error: null };
  } catch (e) {
    return { ok: true, durable: false, degraded: true, error: e.message };
  }
}

/**
 * Fetch a judgment by id. Memory first, then durable mirror if configured.
 * @returns {Promise<object|null>}
 */
export async function fetchJudgment(judgment_id, { timeoutMs = 5000 } = {}) {
  if (memory.has(judgment_id)) return memory.get(judgment_id);
  if (!supabaseConfigured()) return null;
  try {
    const url = `${SUPA_URL}/rest/v1/${TABLE}?judgment_id=eq.${encodeURIComponent(judgment_id)}&select=envelope&limit=1`;
    const res = await fetch(url, { headers: headers(), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    const rows = await res.json().catch(() => []);
    return Array.isArray(rows) && rows[0] ? rows[0].envelope : null;
  } catch {
    return null;
  }
}

export function listByTrajectory(trajectory_id) {
  const ids = trajectoryIndex.get(trajectory_id) || [];
  return ids.map((id) => memory.get(id)).filter(Boolean);
}

/** Ledger health probe. Never throws. */
export async function ledgerHealth({ timeoutMs = 4000 } = {}) {
  const base = { in_memory_count: memory.size, durable_configured: supabaseConfigured(), table: TABLE };
  if (!supabaseConfigured()) return { ...base, durable_reachable: false, error: null };
  const started = Date.now();
  try {
    const url = `${SUPA_URL}/rest/v1/${TABLE}?select=judgment_id&limit=1`;
    const res = await fetch(url, { headers: headers({ Prefer: 'count=exact' }), signal: AbortSignal.timeout(timeoutMs) });
    return {
      ...base,
      durable_reachable: res.ok,
      error: res.ok ? null : `HTTP ${res.status}`,
      latency_ms: Date.now() - started,
    };
  } catch (e) {
    return { ...base, durable_reachable: false, error: e.message, latency_ms: Date.now() - started };
  }
}
