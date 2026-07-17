/**
 * Audit export — tenant-scoped, privacy-preserving JSON/CSV.
 *
 * Exports a trajectory or a bounded time range for one tenant. Every row is
 * derived from the signed judgment ledger and carries: sequence + continuity
 * status, ed25519 signature validity, policy version, primary route, disposition
 * summary, and Howler binding. Raw prompt/output text is never present — only the
 * feature digest and signed commitments cross the boundary. Results are hard
 * capped.
 */

import { verifyEnvelope } from '../spectral.js';
import { listByTrajectoryDurable, listByTimeRange } from './ledger.js';
import { listDispositionsByTrajectory } from './dispositions.js';
import { verifyChain } from './seal.js';

export const EXPORT_MAX_ROWS = 1000;

function verifySigned(record) {
  const { pq, ...env } = record || {};
  const v = verifyEnvelope(env);
  return v.valid;
}

/**
 * @param {object} q
 * @param {string} q.tenant_id
 * @param {string} [q.trajectory_id]
 * @param {string} [q.from] ISO lower bound (time-range mode)
 * @param {string} [q.to] ISO upper bound
 * @param {number} [q.limit]
 * @returns {Promise<{ok:true, report:object} | {ok:false, status:number, code:string, message:string}>}
 */
export async function buildExport(q = {}) {
  const { tenant_id, trajectory_id } = q;
  if (!tenant_id) return { ok: false, status: 400, code: 'tenant_required', message: 'tenant_id required' };
  const limit = Math.max(1, Math.min(EXPORT_MAX_ROWS, Number(q.limit) || EXPORT_MAX_ROWS));

  let judgments = [];
  let source = 'memory';
  let mode;
  if (trajectory_id) {
    mode = 'trajectory';
    const r = await listByTrajectoryDurable(tenant_id, trajectory_id);
    judgments = r.judgments.slice(0, limit);
    source = r.source;
  } else {
    mode = 'time_range';
    const r = await listByTimeRange(tenant_id, q.from || null, q.to || null, { limit });
    judgments = r.judgments;
    source = r.source;
  }

  const continuity = verifyChain(judgments);

  // Dispositions grouped by judgment (trajectory mode fetches once).
  const dispByJudgment = new Map();
  if (trajectory_id) {
    const disps = await listDispositionsByTrajectory(tenant_id, trajectory_id);
    for (const d of disps) {
      if (!dispByJudgment.has(d.judgment_id)) dispByJudgment.set(d.judgment_id, []);
      dispByJudgment.get(d.judgment_id).push(d);
    }
  }

  const rows = judgments.map((j) => {
    const disps = dispByJudgment.get(j.judgment_id) || [];
    return {
      judgment_id: j.judgment_id,
      tenant_id: j.tenant_id || null,
      trajectory_id: j.trajectory_id || null,
      seq: j.seq ?? null,
      phase: j.phase,
      effective_level: j.effective_level,
      primary_route: j.primary_route,
      feature_digest: j.feature_digest,
      policy_version: j.policy_version,
      previous_digest: j.previous_digest || null,
      chain_digest: j.chain_digest || null,
      howler_id: j.howler_id || null,
      pq_algo: j.pq?.algo || null,
      pq_available: Boolean(j.pq?.available),
      signature_valid: verifySigned(j),
      generated_at: j.generated_at,
      dispositions: disps.map((d) => ({ action: d.action, actor: d.actor, effective_after: d.effective_after, decided_at: d.decided_at })),
    };
  });

  return {
    ok: true,
    report: {
      tenant_id,
      mode,
      trajectory_id: trajectory_id || null,
      from: q.from || null,
      to: q.to || null,
      source,
      count: rows.length,
      limit,
      continuity: { intact: continuity.ok, breaks: continuity.breaks, head_chain_digest: continuity.head },
      all_signatures_valid: rows.every((r) => r.signature_valid),
      rows,
      generated_at: new Date().toISOString(),
    },
  };
}

function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function exportToCsv(report) {
  const header = [
    'judgment_id', 'tenant_id', 'trajectory_id', 'seq', 'phase', 'effective_level',
    'primary_route', 'feature_digest', 'policy_version', 'previous_digest', 'chain_digest',
    'howler_id', 'pq_algo', 'pq_available', 'signature_valid', 'generated_at', 'disposition_actions',
  ];
  const lines = [header.join(',')];
  for (const r of report.rows) {
    lines.push([
      r.judgment_id, r.tenant_id, r.trajectory_id, r.seq, r.phase, r.effective_level,
      r.primary_route, r.feature_digest, r.policy_version, r.previous_digest, r.chain_digest,
      r.howler_id, r.pq_algo, r.pq_available, r.signature_valid, r.generated_at,
      r.dispositions.map((d) => d.action).join('|'),
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}
