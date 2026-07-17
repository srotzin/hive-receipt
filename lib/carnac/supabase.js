/**
 * Shared Supabase (PostgREST) client for the Carnac durable plane.
 *
 * Every durable Carnac table (judgments, dispositions, howlers, dispatch
 * records, seals) is protected by RLS keyed on the X-Carnac-Ledger-Token request
 * header. This module centralizes that contract so each store behaves identically:
 *
 *   - Configured only when a base URL and service key are present
 *     (CARNAC_LEDGER_SUPA_URL/_KEY, falling back to SUPA_URL/SUPA_KEY).
 *   - Durable operations FAIL CLOSED when CARNAC_LEDGER_TOKEN is absent — the RLS
 *     policy would reject them, so they are skipped and reported truthfully.
 *   - The token is never logged or returned.
 *
 * Env is read at call time so configuration and the fail-closed gate are
 * evaluated per request (and are testable).
 */

const supaUrl = () => process.env.CARNAC_LEDGER_SUPA_URL || process.env.SUPA_URL || '';
const supaKey = () => process.env.CARNAC_LEDGER_SUPA_KEY || process.env.SUPA_KEY || '';
const ledgerToken = () => process.env.CARNAC_LEDGER_TOKEN || '';

export function supabaseConfigured() {
  return Boolean(supaUrl() && supaKey());
}

export function ledgerTokenConfigured() {
  return Boolean(ledgerToken());
}

function headers(extra = {}) {
  const key = supaKey();
  const h = { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', ...extra };
  const token = ledgerToken();
  if (token) h['X-Carnac-Ledger-Token'] = token;
  return h;
}

/**
 * Insert a row (or rows). Fails closed without the ledger token.
 * @returns {Promise<{ok:boolean, durable:boolean, degraded:boolean, error:string|null}>}
 */
export async function supaInsert(table, row, { timeoutMs = 5000 } = {}) {
  if (!supabaseConfigured()) return { ok: true, durable: false, degraded: false, error: null };
  if (!ledgerTokenConfigured()) return { ok: true, durable: false, degraded: true, error: 'ledger token not configured' };
  try {
    const res = await fetch(`${supaUrl()}/rest/v1/${table}`, {
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
 * Select rows with a raw PostgREST query string (already URL-encoded values).
 * Fails closed without the ledger token. Never throws.
 * @returns {Promise<{ok:boolean, rows:object[], error:string|null}>}
 */
export async function supaSelect(table, query = '', { timeoutMs = 5000 } = {}) {
  if (!supabaseConfigured()) return { ok: false, rows: [], error: 'not_configured' };
  if (!ledgerTokenConfigured()) return { ok: false, rows: [], error: 'ledger token not configured' };
  try {
    const url = `${supaUrl()}/rest/v1/${table}${query ? `?${query}` : ''}`;
    const res = await fetch(url, { headers: headers(), signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { ok: false, rows: [], error: `HTTP ${res.status}` };
    const rows = await res.json().catch(() => []);
    return { ok: true, rows: Array.isArray(rows) ? rows : [], error: null };
  } catch (e) {
    return { ok: false, rows: [], error: e.message };
  }
}

/** Health probe for the durable plane. Never throws. */
export async function supabaseHealth(table, { timeoutMs = 4000 } = {}) {
  const base = { durable_configured: supabaseConfigured() };
  if (!supabaseConfigured()) return { ...base, durable_reachable: false, error: null };
  if (!ledgerTokenConfigured()) return { ...base, durable_reachable: false, error: 'ledger token not configured' };
  const started = Date.now();
  try {
    const url = `${supaUrl()}/rest/v1/${table}?select=judgment_id&limit=1`;
    const res = await fetch(url, { headers: headers({ Prefer: 'count=exact' }), signal: AbortSignal.timeout(timeoutMs) });
    return { ...base, durable_reachable: res.ok, error: res.ok ? null : `HTTP ${res.status}`, latency_ms: Date.now() - started };
  } catch (e) {
    return { ...base, durable_reachable: false, error: e.message, latency_ms: Date.now() - started };
  }
}
