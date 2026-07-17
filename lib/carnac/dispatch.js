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
