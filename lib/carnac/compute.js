/**
 * Approved Hive compute endpoint client for semantic consequence classification.
 *
 * The semantic reader is optional and pluggable, configured via env exactly like
 * the Supabase and RPC integrations elsewhere in this service:
 *   CARNAC_COMPUTE_URL    — approved Hive compute endpoint (POST, JSON)
 *   CARNAC_COMPUTE_TOKEN  — optional internal token, sent as X-Hive-Internal-Token
 *
 * Every response is structurally validated before it is trusted. If the endpoint
 * is unconfigured, unreachable, times out, or returns a shape that fails
 * validation, the caller falls back to the deterministic engine in rules.js.
 * The semantic reader can only RAISE a level, never lower the deterministic
 * floor — so a compromised or misbehaving endpoint cannot weaken judgment.
 */

const VALID_CATEGORY_IDS = new Set([
  'health', 'pii', 'override', 'cyber', 'irrev', 'financial', 'legal', 'outbound', 'datawrite',
]);

export function computeConfigured() {
  return Boolean(process.env.CARNAC_COMPUTE_URL);
}

/**
 * Validate the semantic endpoint's response into a normalized classification, or
 * return a structured error. Never throws.
 * @returns {{ok:true, classification:{level:number, categories:{id:string,label:string,sev:number}[]}} | {ok:false, error:string}}
 */
export function validateComputeResponse(body) {
  if (!body || typeof body !== 'object') return { ok: false, error: 'response not an object' };
  const level = body.level;
  if (!Number.isInteger(level) || level < 0 || level > 3) {
    return { ok: false, error: `invalid level: ${JSON.stringify(level)}` };
  }
  if (!Array.isArray(body.categories)) return { ok: false, error: 'categories not an array' };
  const categories = [];
  for (const c of body.categories) {
    if (!c || typeof c !== 'object') return { ok: false, error: 'category entry not an object' };
    if (!VALID_CATEGORY_IDS.has(c.id)) return { ok: false, error: `unknown category id: ${JSON.stringify(c.id)}` };
    const sev = c.sev;
    if (!Number.isInteger(sev) || sev < 1 || sev > 3) return { ok: false, error: `invalid sev for ${c.id}` };
    categories.push({ id: c.id, label: typeof c.label === 'string' ? c.label : c.id, sev });
  }
  // Level must be consistent with the strongest category (or 0 when none).
  const maxSev = categories.reduce((m, c) => Math.max(m, c.sev), 0);
  if (categories.length && level < maxSev) {
    return { ok: false, error: 'level below strongest category severity' };
  }
  return { ok: true, classification: { level, categories } };
}

/**
 * Call the semantic endpoint. Sends only the text to classify plus a phase hint.
 * @returns {Promise<{ok:true, classification:object, source:string, latency_ms:number} | {ok:false, error:string, source:string, latency_ms:number|null}>}
 */
export async function classifySemantic(text, { phase = 'formation', timeoutMs = 6000 } = {}) {
  const url = process.env.CARNAC_COMPUTE_URL;
  if (!url) return { ok: false, error: 'compute_not_configured', source: 'none', latency_ms: null };

  const started = Date.now();
  try {
    // The approved Hive compute endpoint authenticates the internal service-to-
    // service call via the dedicated X-Hive-Internal-Token header (matched
    // constant-time against HIVE_INTERNAL_LLM_TOKEN on the compute side), not an
    // Authorization bearer scheme.
    const headers = { 'Content-Type': 'application/json' };
    if (process.env.CARNAC_COMPUTE_TOKEN) headers['X-Hive-Internal-Token'] = process.env.CARNAC_COMPUTE_TOKEN;
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ text, phase, task: 'consequence_classification' }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const latency_ms = Date.now() - started;
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      return { ok: false, error: `HTTP ${res.status}: ${detail.slice(0, 200)}`, source: 'compute', latency_ms };
    }
    const body = await res.json().catch(() => null);
    const validated = validateComputeResponse(body);
    if (!validated.ok) {
      return { ok: false, error: `invalid_response: ${validated.error}`, source: 'compute', latency_ms };
    }
    return { ok: true, classification: validated.classification, source: 'compute', latency_ms };
  } catch (e) {
    const latency_ms = Date.now() - started;
    const error = e.name === 'TimeoutError' ? `timeout after ${timeoutMs}ms` : e.message;
    return { ok: false, error, source: 'compute', latency_ms };
  }
}

/**
 * Lightweight health probe of the compute endpoint. Never throws.
 */
export async function computeHealth({ timeoutMs = 4000 } = {}) {
  if (!computeConfigured()) {
    return { configured: false, reachable: false, error: null, source: 'none' };
  }
  const probe = await classifySemantic('health check ping', { phase: 'formation', timeoutMs });
  return {
    configured: true,
    reachable: probe.ok,
    error: probe.ok ? null : probe.error,
    source: 'compute',
    latency_ms: probe.latency_ms ?? null,
  };
}
