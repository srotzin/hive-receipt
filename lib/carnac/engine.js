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
import { persistJudgment, fetchJudgment } from './ledger.js';

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
 * @returns {Promise<{ok:true, envelope:object, howler:object|null, idempotent_replay?:boolean, ledger:object} | {ok:false, status:number, code:string, message:string}>}
 */
export async function judge(input = {}, { sandbox = false } = {}) {
  const phase = input.phase || 'formation';
  if (!VALID_PHASES.has(phase)) {
    return { ok: false, status: 400, code: 'invalid_phase', message: `phase must be one of ${[...VALID_PHASES].join(', ')}` };
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

  const payload = {
    judgment_id,
    trajectory_id: input.trajectory_id || null,
    phase,
    seq: typeof input.seq === 'number' ? input.seq : null,
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
    sandbox: Boolean(sandbox),
    effect_committed: false,
    nonce: input.nonce || null,
    generated_at,
  };

  // Sign with the existing Hive ed25519 key.
  const sig = signPayload(payload);
  const envelope = { ...payload, ...sig };

  // Howler at the escalation threshold (never in sandbox).
  let howler = null;
  if (!sandbox) {
    const body = buildHowler(payload);
    if (body) howler = { ...body, ...signPayload(body) };
  }

  // Ledger: durable for real judgments, in-memory only for sandbox.
  let ledgerResult;
  if (sandbox) {
    ledgerResult = { ok: true, durable: false, degraded: false, error: null, sandbox: true };
  } else {
    ledgerResult = await persistJudgment(envelope);
  }
  meta.set(judgment_id, { howler, durable: Boolean(ledgerResult.durable) });

  // Record controls only after a successful ruling.
  recordIdempotency(input.idempotency_key, judgment_id);
  recordNonce(input.nonce);
  recordPhase(input.trajectory_id, phase, input.seq);

  return { ok: true, envelope, howler, ledger: ledgerResult };
}

/** Verify a judgment (or Howler) envelope's signature. */
export function verifyJudgment(envelope) {
  return verifyEnvelope(envelope);
}

export { currentPolicy };
