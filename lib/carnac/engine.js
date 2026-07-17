/**
 * Carnac engine — the judgment and routing plane.
 *
 * One entry point, judge(), conducts a single read in a request's lifecycle:
 *   formation   — CarnacPrompt reads consequence while the request forms
 *   invocation  — Carnac reads at the model/agent call
 *   output      — Carnac reads the produced output (emergent consequence)
 *   effect      — Carnac reads before an effect commits (pre-effect gate)
 *
 * The read is bound to a trajectory so lifecycle order is enforced. Consequence
 * is classified (deterministic floor + optional semantic reader), the governed
 * floor and any runtime overrides are applied, a response set and disposition are
 * composed, the result is signed with the existing Hive ed25519 key, a Howler is
 * minted at the escalation threshold, and everything is written to the judgment
 * ledger. Carnac decides the disposition; it never commits the effect itself, so
 * an inference outage cannot become a universal denial of service.
 *
 * Production hardening (opt-in, so the sandbox and legacy callers are unchanged):
 *   - tenant binding      — tenant_id is bound into the signed payload + ledger row
 *   - continuity chain    — previous_digest/chain_digest link each read in order
 *   - seq continuity      — missing/duplicate/out-of-order seqs are rejected
 *   - post-quantum sign   — a real ML-DSA-65 signature via the Hive typed signer,
 *                           fail-closed for protected production routes
 *   - durable Howler      — the escalation receipt is persisted, not only returned
 *   - honest dispatch     — the primary route is recorded against a real or
 *                           explicitly-pending Canon primitive
 */

import crypto from 'crypto';
import { signPayload, verifyEnvelope } from '../spectral.js';
import { classify } from './classify.js';
import { applyFloor, currentPolicy } from './policy.js';
import { composeRoute } from './routes.js';
import { buildHowler } from './howler.js';
import {
  checkIdempotency, recordIdempotency,
  checkReplay, recordNonce,
  checkOrder, recordPhase,
} from './idempotency.js';
import {
  persistJudgment, fetchJudgment,
  lastChainLink, trajectorySeqExists,
} from './ledger.js';
import { linkDigest } from './seal.js';
import { pqSign } from './pqsign.js';
import { persistHowler } from './howler_store.js';
import { dispatchRoute } from './dispatch.js';
import { SANDBOX_TENANT } from './auth.js';

const VALID_PHASES = new Set(['formation', 'invocation', 'output', 'effect']);

// Per-process side metadata that must not be part of the signed envelope.
const meta = new Map(); // judgment_id -> { howler, durable }

export function _resetEngine() {
  meta.clear();
}

function textForPhase(phase, request, output) {
  if (phase === 'output') return output || '';
  if (phase === 'effect') return [request, output].filter(Boolean).join('\n');
  return request || '';
}

/**
 * @param {object} input
 * @param {string} [input.trajectory_id]
 * @param {string} [input.phase] formation|invocation|output|effect
 * @param {string} [input.request] the forming request text
 * @param {string} [input.output] the produced output text (output/effect phases)
 * @param {number} [input.seq] monotonic read sequence within the trajectory
 * @param {string} [input.idempotency_key]
 * @param {string} [input.nonce]
 * @param {Object<string,number>} [input.runtime_overrides]
 * @param {boolean} [input.useSemantic]
 * @param {object} [opts]
 * @param {boolean} [opts.sandbox] no-effect sandbox: never persists to the durable ledger
 * @param {string} [opts.tenant_id] authenticated tenant scope (forced to the sandbox tenant in sandbox mode)
 * @param {string} [opts.actor] authenticated caller identity, bound into the signed payload
 * @param {boolean} [opts.requireTenant] fail closed when no tenant is bound (protected production)
 * @param {boolean} [opts.requirePQ] fail closed when a real ML-DSA-65 signature cannot be produced
 * @param {boolean} [opts.enforceContinuity] require a monotonic seq and reject duplicates/gaps
 * @returns {Promise<{ok:true, envelope:object, howler:object|null, idempotent_replay?:boolean, ledger:object} | {ok:false, status:number, code:string, message:string}>}
 */
export async function judge(input = {}, opts = {}) {
  const {
    sandbox = false,
    actor = null,
    requireTenant = false,
    requirePQ = false,
    enforceContinuity = false,
  } = opts;

  const phase = input.phase || 'formation';
  if (!VALID_PHASES.has(phase)) {
    return { ok: false, status: 400, code: 'invalid_phase', message: `phase must be one of ${[...VALID_PHASES].join(', ')}` };
  }

  // Tenant scope: the sandbox is a fixed public tenant and never enters the
  // production ledger; production callers must be bound to a concrete tenant.
  const tenant_id = sandbox ? SANDBOX_TENANT : (opts.tenant_id || input.tenant_id || null);
  if (!sandbox && requireTenant && !tenant_id) {
    return { ok: false, status: 400, code: 'tenant_required', message: 'tenant_id required for this operation' };
  }

  const request = typeof input.request === 'string' ? input.request : '';
  const output = typeof input.output === 'string' ? input.output : '';
  const text = textForPhase(phase, request, output);

  const MAX = 8000;
  if (request.length > MAX || output.length > MAX) {
    return { ok: false, status: 400, code: 'input_too_large', message: `request/output capped at ${MAX} characters` };
  }
  if (phase === 'output' && !output) {
    return { ok: false, status: 400, code: 'missing_output', message: 'output phase requires an output field' };
  }

  // Idempotency: a repeated key yields the same prior judgment.
  const idem = checkIdempotency(input.idempotency_key);
  if (idem.hit) {
    const prior = await fetchJudgment(idem.judgment_id);
    if (prior) {
      const m = meta.get(idem.judgment_id) || {};
      return { ok: true, envelope: prior, howler: m.howler || null, idempotent_replay: true, ledger: { durable: Boolean(m.durable) } };
    }
  }

  // Replay: a nonce is single-use.
  const replay = checkReplay(input.nonce);
  if (!replay.ok) return { ok: false, status: 409, code: replay.code, message: replay.message };

  // Continuity: a protected trajectory read must carry a monotonic seq that has
  // not been used before (checked against memory AND the durable ledger, so a
  // replayed or out-of-order event is rejected even across a restart). This runs
  // before the generic order check so a durable replay is reported as a
  // duplicate_seq rather than a bare out_of_order.
  if (enforceContinuity) {
    if (typeof input.seq !== 'number') {
      return { ok: false, status: 400, code: 'seq_required', message: 'a numeric seq is required for continuity enforcement' };
    }
    if (!input.trajectory_id) {
      return { ok: false, status: 400, code: 'trajectory_required', message: 'trajectory_id is required for continuity enforcement' };
    }
    const exists = await trajectorySeqExists(tenant_id, input.trajectory_id, input.seq);
    if (exists) {
      return { ok: false, status: 409, code: 'duplicate_seq', message: `seq ${input.seq} already exists for this trajectory` };
    }
  }

  // Order: reads within a trajectory must not regress.
  const order = checkOrder(input.trajectory_id, phase, input.seq);
  if (!order.ok) return { ok: false, status: 409, code: order.code, message: order.message };

  // Classify (deterministic floor + optional semantic reader).
  const classification = await classify(text, { phase, useSemantic: input.useSemantic !== false });

  // Governed floor + runtime overrides (raise only).
  const floored = applyFloor(classification, input.runtime_overrides || {});

  // Compose the response set and disposition.
  const routed = composeRoute(floored.effective_level, phase);

  const judgment_id = crypto.randomBytes(16).toString('hex');
  const generated_at = new Date().toISOString();
  const seq = typeof input.seq === 'number' ? input.seq : null;

  // Continuity chain: link this read to the trajectory's prior head.
  let previous_digest = null;
  if (input.trajectory_id) {
    const last = await lastChainLink(tenant_id, input.trajectory_id);
    previous_digest = last.chain_digest;
  }
  const chain_digest = input.trajectory_id
    ? linkDigest(previous_digest, {
        judgment_id,
        feature_digest: classification.feature_digest,
        effective_level: floored.effective_level,
        seq,
      })
    : null;

  // Build the Howler body first so its id can be bound into the signed judgment.
  const howlerBody = sandbox ? null : buildHowler({
    judgment_id,
    trajectory_id: input.trajectory_id || null,
    phase,
    effective_level: floored.effective_level,
    categories: classification.categories,
    feature_digest: classification.feature_digest,
    primary_route: routed.primary_route,
    policy_version: floored.floor_version,
  });

  const payload = {
    judgment_id,
    tenant_id,
    trajectory_id: input.trajectory_id || null,
    actor,
    phase,
    seq,
    request_level: classification.level,
    effective_level: floored.effective_level,
    categories: classification.categories,
    big_amount: classification.big_amount,
    languages: classification.languages,
    feature_digest: classification.feature_digest,
    engine: classification.engine,
    semantic_used: classification.semantic_used,
    semantic_error: classification.semantic_error,
    primary_route: routed.primary_route,
    responses: routed.responses,
    disposition: routed.disposition,
    policy_version: floored.floor_version,
    raised_by_runtime: floored.raised_by_runtime,
    runtime_clamp_attempted: floored.runtime_clamp_attempted,
    previous_digest,
    chain_digest,
    howler_id: howlerBody ? howlerBody.howler_id : null,
    sandbox: Boolean(sandbox),
    effect_committed: false,
    nonce: input.nonce || null,
    generated_at,
  };

  // Post-quantum signature over the finalized payload. A real ML-DSA-65
  // signature can only come from the external Hive typed signer; it is never
  // fabricated. Protected production routes fail closed; the sandbox proceeds in
  // an explicitly degraded no-PQ state.
  const pqRes = await pqSign(payload);
  let pq;
  if (pqRes.available) {
    pq = {
      available: true,
      algo: pqRes.algo,
      signature: pqRes.signature,
      public_key: pqRes.public_key,
      payload_sha256: pqRes.payload_sha256,
    };
  } else if (sandbox) {
    pq = { available: false, degraded: true, algo: pqRes.algo, error: pqRes.error };
  } else if (requirePQ) {
    return { ok: false, status: 503, code: 'pq_unavailable', message: `post-quantum signer unavailable: ${pqRes.error}` };
  } else {
    pq = { available: false, algo: pqRes.algo, error: pqRes.error };
  }

  // Sign with the existing Hive ed25519 key. pq is a sibling of the ed25519
  // envelope (bound by pq.payload_sha256 === signed_payload_sha256) so it never
  // perturbs ed25519 verification.
  const sig = signPayload(payload);
  const envelope = { ...payload, ...sig, pq };

  // Howler at the escalation threshold (never in sandbox). Bind the tenant and
  // sign it, then persist it durably.
  let howler = null;
  if (howlerBody) {
    const boundBody = { ...howlerBody, tenant_id };
    howler = { ...boundBody, ...signPayload(boundBody) };
  }

  // Ledger: durable for real judgments, in-memory only for sandbox.
  let ledgerResult;
  if (sandbox) {
    ledgerResult = { ok: true, durable: false, degraded: false, error: null, sandbox: true };
  } else {
    ledgerResult = await persistJudgment(envelope);
    if (howler) await persistHowler(howler);
    await dispatchRoute({
      tenant_id,
      judgment_id,
      trajectory_id: input.trajectory_id || null,
      route: routed.primary_route,
    });
  }
  meta.set(judgment_id, { howler, durable: Boolean(ledgerResult.durable) });

  // Record controls only after a successful ruling.
  recordIdempotency(input.idempotency_key, judgment_id);
  recordNonce(input.nonce);
  recordPhase(input.trajectory_id, phase, input.seq);

  return { ok: true, envelope, howler, ledger: ledgerResult };
}

/** Verify a judgment envelope's ed25519 signature (stripping the sibling pq). */
export function verifyJudgment(envelope) {
  const { pq, ...env } = envelope || {};
  return verifyEnvelope(env);
}

export { currentPolicy };
