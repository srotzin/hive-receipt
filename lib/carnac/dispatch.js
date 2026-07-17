/**
 * Canon dispatch records — honest routing to Hive receipt/signing primitives.
 *
 * A judgment's route names a canonical Hive artifact (ledger_entry, receipt,
 * enrich, verify, hold/confirm, Howler). Where a real in-repo callable exists we
 * mark the dispatch 'dispatched' and name the internal primitive. Where no
 * internal callable exists yet, we persist an explicit signed dispatch record
 * with status 'pending_external' and the target primitive — we NEVER imply an
 * external primitive ran when it did not.
 *
 * Only these primitives have a real internal callable in this repo today:
 *   - ledger_entry   : the durable judgment ledger (lib/carnac/ledger.js)
 *   - receipt        : Spectral ed25519 receipt signing (lib/spectral.js)
 *   - Howler         : signed Howler artifact (lib/carnac/howler.js)
 * Everything else (enrich/verify/hold/confirm) targets an external Canon
 * primitive and is recorded pending_external.
 */

import crypto from 'crypto';
import { signPayload } from '../spectral.js';
import { supaInsert, supaSelect } from './supabase.js';

const TABLE = () => process.env.CARNAC_DISPATCH_TABLE || 'carnac_dispatch';

// route id -> { primitive, internal }
const ROUTE_PRIMITIVE = Object.freeze({
  let_it_run: { primitive: 'ledger_entry', internal: true },
  receipt: { primitive: 'spectral_receipt', internal: true },
  howler: { primitive: 'howler', internal: true },
  enrich: { primitive: 'canon_provenance', internal: false },
  verify: { primitive: 'canon_verification', internal: false },
  hold: { primitive: 'canon_imprimatur', internal: false },
  ask_human: { primitive: 'canon_confirmation', internal: false },
});

const memory = new Map();     // dispatch_id -> record
const byJudgment = new Map(); // `${tenant}::${judgment}` -> dispatch_id[]

export function _resetDispatch() {
  memory.clear();
  byJudgment.clear();
}

export function primitiveFor(route) {
  return ROUTE_PRIMITIVE[route] || { primitive: `canon_${route}`, internal: false };
}

// Channel label for each target primitive, when one applies.
const PRIMITIVE_CHANNEL = Object.freeze({
  ledger_entry: 'ledger',
  spectral_receipt: 'receipt',
  canon_provenance: 'provenance',
  canon_verification: 'verification',
  canon_imprimatur: 'imprimatur',
  canon_confirmation: 'confirmation',
  howler: 'escalation',
});

/**
 * Public-safe Canon dispatch trace for a sandbox judgment.
 *
 * The sandbox runs only the Spectral ed25519 receipt for real; the durable
 * ledger and Howler are selected by policy but never written, and every external
 * Canon primitive is pending_external because it is not invoked here. Statuses
 * are truthful and never imply a primitive ran. No raw prompt is exposed — the
 * trace is derived only from the composed routes. AFiR is emitted only when the
 * engine actually selects fragmented inference, which it never does today, so it
 * is absent by construction.
 *
 * @param {object} envelope signed judgment envelope
 * @returns {Array<{target_primitive:string, status:string, route:string, reason:string, channel?:string}>}
 */
export function sandboxDispatchTrace(envelope = {}) {
  const responses = Array.isArray(envelope.responses) ? envelope.responses : [];
  const trace = [];
  for (const r of responses) {
    const route = r && r.id;
    if (!route) continue;
    const { primitive, internal } = primitiveFor(route);
    let status;
    let reason;
    if (route === 'receipt') {
      status = 'succeeded';
      reason = 'Spectral ed25519 receipt signed over the judgment.';
    } else if (internal) {
      status = 'selected';
      reason = route === 'howler'
        ? 'Escalation selected by policy; a Howler is not minted in the sandbox.'
        : 'Selected by policy; the durable ledger write is disabled in the sandbox.';
    } else {
      status = 'pending_external';
      reason = 'Awaits an external Canon primitive; not invoked in the sandbox.';
    }
    const entry = { target_primitive: primitive, status, route, reason };
    const channel = PRIMITIVE_CHANNEL[primitive];
    if (channel) entry.channel = channel;
    trace.push(entry);
  }
  return trace;
}

/**
 * Persist a signed dispatch record for a judgment's primary route.
 * @returns {Promise<{ok:true, record:object, ledger:object}>}
 */
export async function dispatchRoute({ tenant_id, judgment_id, trajectory_id = null, route } = {}) {
  const { primitive, internal } = primitiveFor(route);
  const payload = {
    dispatch_id: crypto.randomBytes(12).toString('hex'),
    tenant_id: tenant_id || null,
    judgment_id: judgment_id || null,
    trajectory_id,
    route,
    target_primitive: primitive,
    // Honest status: internal callables are dispatched; the rest await an
    // external Canon primitive and are never claimed to have run.
    status: internal ? 'dispatched' : 'pending_external',
    internal_callable: internal,
    dispatched_at: new Date().toISOString(),
  };
  const record = { ...payload, ...signPayload(payload) };
  memory.set(record.dispatch_id, record);
  const k = `${tenant_id || ''}::${judgment_id || ''}`;
  if (!byJudgment.has(k)) byJudgment.set(k, []);
  byJudgment.get(k).push(record.dispatch_id);

  const row = {
    dispatch_id: record.dispatch_id,
    tenant_id: tenant_id || null,
    judgment_id: judgment_id || null,
    trajectory_id,
    route,
    target_primitive: primitive,
    status: record.status,
    envelope: record,
    created_at: record.dispatched_at,
  };
  const ledger = await supaInsert(TABLE(), row);
  return { ok: true, record, ledger };
}

export async function listDispatch(tenant_id, judgment_id, { timeoutMs = 5000 } = {}) {
  const ids = byJudgment.get(`${tenant_id}::${judgment_id}`) || [];
  const mem = ids.map((id) => memory.get(id)).filter(Boolean);
  if (mem.length) return mem;
  const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&judgment_id=eq.${encodeURIComponent(judgment_id)}&select=envelope&order=created_at.asc`;
  const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
  return ok ? rows.map((r) => r.envelope).filter(Boolean) : [];
}
