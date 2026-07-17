/**
 * Disposition records — the human/actor effect decision on a judgment.
 *
 * A disposition is bound to a tenant, judgment, and trajectory, names the actor
 * and the action taken (confirm | reject | override | release | unresolved), a
 * reason and timestamp, and is signed with the Hive ed25519 key. Records are
 * APPEND-ONLY and immutable: a new disposition never mutates a prior one, so the
 * full decision history is provable. An override can only RAISE the effective
 * level — it can never silently lower the policy floor.
 */

import crypto from 'crypto';
import { signPayload } from '../spectral.js';
import { supaInsert, supaSelect } from './supabase.js';

const TABLE = () => process.env.CARNAC_DISPOSITION_TABLE || 'carnac_dispositions';

export const DISPOSITION_ACTIONS = new Set(['confirm', 'reject', 'override', 'release', 'unresolved']);

const memory = new Map();          // disposition_id -> record
const byJudgment = new Map();      // `${tenant}::${judgment}` -> disposition_id[]

export function _resetDispositions() {
  memory.clear();
  byJudgment.clear();
}

function key(tenant_id, judgment_id) {
  return `${tenant_id || ''}::${judgment_id || ''}`;
}

/**
 * Record a signed, append-only disposition.
 * @param {object} input
 * @param {string} input.tenant_id
 * @param {string} input.judgment_id
 * @param {string} [input.trajectory_id]
 * @param {string} [input.howler_id]
 * @param {string} input.actor
 * @param {string} input.action confirm|reject|override|release|unresolved
 * @param {string} [input.reason]
 * @param {number} [input.floor_level] the governed floor at decision time
 * @param {number} [input.override_level] requested level when action=override (raise-only)
 * @returns {Promise<{ok:true, record:object, ledger:object} | {ok:false, status:number, code:string, message:string}>}
 */
export async function recordDisposition(input = {}) {
  const { tenant_id, judgment_id, trajectory_id = null, howler_id = null, actor, action, reason = '' } = input;
  if (!tenant_id) return { ok: false, status: 400, code: 'tenant_required', message: 'tenant_id required' };
  if (!judgment_id) return { ok: false, status: 400, code: 'judgment_required', message: 'judgment_id required' };
  if (!actor) return { ok: false, status: 400, code: 'actor_required', message: 'actor identity required' };
  if (!DISPOSITION_ACTIONS.has(action)) {
    return { ok: false, status: 400, code: 'invalid_action', message: `action must be one of ${[...DISPOSITION_ACTIONS].join(', ')}` };
  }

  // An override can only raise. Never let it drop below the governed floor.
  let effective_after = typeof input.floor_level === 'number' ? input.floor_level : null;
  let override_clamped = false;
  if (action === 'override') {
    const requested = Number(input.override_level);
    if (Number.isFinite(requested) && effective_after !== null) {
      if (requested > effective_after) effective_after = requested;
      else override_clamped = true; // attempt to lower/hold below floor is refused
    }
  }

  const payload = {
    disposition_id: crypto.randomBytes(12).toString('hex'),
    tenant_id,
    judgment_id,
    trajectory_id,
    howler_id,
    actor,
    action,
    reason: String(reason).slice(0, 2000),
    floor_level: input.floor_level ?? null,
    effective_after,
    override_clamped,
    decided_at: new Date().toISOString(),
  };
  const record = { ...payload, ...signPayload(payload) };

  // Append-only in memory.
  memory.set(record.disposition_id, record);
  const k = key(tenant_id, judgment_id);
  if (!byJudgment.has(k)) byJudgment.set(k, []);
  byJudgment.get(k).push(record.disposition_id);

  const row = {
    disposition_id: record.disposition_id,
    tenant_id,
    judgment_id,
    trajectory_id,
    howler_id,
    actor,
    action,
    effective_after,
    envelope: record,
    created_at: record.decided_at,
  };
  const ledger = await supaInsert(TABLE(), row);
  return { ok: true, record, ledger };
}

/** List dispositions for a judgment under a tenant (append-only history). */
export async function listDispositions(tenant_id, judgment_id, { timeoutMs = 5000 } = {}) {
  const ids = byJudgment.get(key(tenant_id, judgment_id)) || [];
  const mem = ids.map((id) => memory.get(id)).filter(Boolean);
  if (mem.length) return mem;
  const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&judgment_id=eq.${encodeURIComponent(judgment_id)}&select=envelope&order=created_at.asc`;
  const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
  return ok ? rows.map((r) => r.envelope).filter(Boolean) : [];
}

/** All dispositions for a trajectory under a tenant (for audit export). */
export async function listDispositionsByTrajectory(tenant_id, trajectory_id, { timeoutMs = 5000 } = {}) {
  const out = [];
  for (const [k, ids] of byJudgment) {
    if (!k.startsWith(`${tenant_id}::`)) continue;
    for (const id of ids) {
      const r = memory.get(id);
      if (r && r.trajectory_id === trajectory_id) out.push(r);
    }
  }
  if (out.length) return out;
  const q = `tenant_id=eq.${encodeURIComponent(tenant_id)}&trajectory_id=eq.${encodeURIComponent(trajectory_id)}&select=envelope&order=created_at.asc`;
  const { ok, rows } = await supaSelect(TABLE(), q, { timeoutMs });
  return ok ? rows.map((r) => r.envelope).filter(Boolean) : [];
}
