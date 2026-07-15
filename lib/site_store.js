/**
 * Site telemetry store — hardened Supabase (PostgREST) access for clarity_hits.
 *
 * Fixes the degraded stream: the previous read swallowed PostgREST errors
 * (no r.ok check), so any auth / schema / outage error surfaced to the owner
 * as "No hits yet" — indistinguishable from an empty table. Here every failure
 * is captured and reported through source_health, never masked.
 *
 * Writes remain best-effort and non-blocking (the beacon must never hang a
 * page load), but write outcome is logged. The collector now also persists a
 * page path and pseudonymous session id when the table has those columns; if
 * the columns are absent, it transparently falls back to the base row shape so
 * existing deployments keep working without a schema migration.
 */

const SUPA_URL = process.env.SUPA_URL || 'https://rdxdcbxeploukweaczrq.supabase.co';
const SUPA_KEY =
  process.env.SUPA_KEY ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJkeGRjYnhlcGxvdWt3ZWFjenJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAwODk5NzcsImV4cCI6MjA5NTY2NTk3N30.5eUIH9xIIzrInHSYz1fuw_niM_qB7L0La79SQJkbjZQ';
const TABLE = 'clarity_hits';

function headers(extra = {}) {
  return {
    apikey: SUPA_KEY,
    Authorization: `Bearer ${SUPA_KEY}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

/**
 * Insert a hit. Best effort. Tries the full row (with path/sid) first; on a
 * PostgREST schema error (unknown column) retries with base columns only so a
 * missing migration never drops telemetry.
 * @returns {Promise<{ok:boolean, status:number|null, degraded:boolean, error:string|null}>}
 */
export async function insertHit(entry, { timeoutMs = 5000 } = {}) {
  const base = {
    ts: entry.ts,
    ip: entry.ip,
    city: entry.city,
    region: entry.region,
    country: entry.country,
    org: entry.org,
    ua: entry.ua,
    ref: entry.ref,
  };
  const extended = { ...base };
  if (entry.path != null) extended.path = entry.path;
  if (entry.sid != null) extended.sid = entry.sid;

  const attempt = async (body) => {
    const res = await fetch(`${SUPA_URL}/rest/v1/${TABLE}`, {
      method: 'POST',
      headers: headers({ Prefer: 'return=minimal' }),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return res;
  };

  try {
    let res = await attempt(extended);
    let degraded = false;
    if (!res.ok && (res.status === 400 || res.status === 404) && extended !== base) {
      // Likely unknown column (PGRST204 / 42703). Fall back to base shape.
      degraded = true;
      res = await attempt(base);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, status: res.status, degraded, error: text.slice(0, 300) || `HTTP ${res.status}` };
    }
    return { ok: true, status: res.status, degraded, error: null };
  } catch (e) {
    return { ok: false, status: null, degraded: false, error: e.message };
  }
}

/**
 * Fetch events since an ISO timestamp, oldest first, with a hard row cap.
 * Reports health explicitly so the intelligence layer can tell the truth.
 * @returns {Promise<{events:Array, health:object}>}
 */
export async function fetchEvents({ sinceIso, limit = 10000, timeoutMs = 8000 } = {}) {
  const started = Date.now();
  const health = {
    reachable: false,
    error: null,
    source: `supabase:${TABLE}`,
    fetched_at: new Date().toISOString(),
    latency_ms: null,
    row_cap: limit,
    row_cap_hit: false,
  };
  const params = new URLSearchParams({ select: '*', order: 'ts.asc' });
  if (sinceIso) params.set('ts', `gte.${sinceIso}`);
  const url = `${SUPA_URL}/rest/v1/${TABLE}?${params.toString()}`;
  try {
    const res = await fetch(url, {
      headers: headers({ Range: `0-${limit - 1}`, Prefer: 'count=exact' }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    health.latency_ms = Date.now() - started;
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      health.error = `HTTP ${res.status}: ${text.slice(0, 300)}`;
      return { events: [], health };
    }
    const data = await res.json();
    if (!Array.isArray(data)) {
      health.error = `unexpected payload shape: ${JSON.stringify(data).slice(0, 200)}`;
      return { events: [], health };
    }
    health.reachable = true;
    const contentRange = res.headers.get('content-range') || '';
    const total = contentRange.includes('/') ? parseInt(contentRange.split('/')[1], 10) : data.length;
    health.total_rows = Number.isNaN(total) ? data.length : total;
    health.row_cap_hit = data.length >= limit;
    return { events: data, health };
  } catch (e) {
    health.latency_ms = Date.now() - started;
    health.error = e.name === 'TimeoutError' ? `timeout after ${timeoutMs}ms` : e.message;
    return { events: [], health };
  }
}

export const _config = { SUPA_URL, TABLE, hasEnvOverride: Boolean(process.env.SUPA_URL) };
