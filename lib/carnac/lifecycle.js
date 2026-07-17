/**
 * Carnac lifecycle chain — one signed chain for one inference, from the prompt
 * window boundary through execution to downstream effect.
 *
 * This composes the existing Hive primitives (the ed25519 spectral signer, the
 * ML-DSA-65 typed signer, the continuity chain, the Supabase-mirrored ledger)
 * into a single append-only chain of TYPED STAGES. It does not reimplement any
 * of them. A stage records only commitments (hashes), origins, and evidence
 * status; raw prompt and raw output are never stored.
 *
 * Latency contract (the serving path is effectively invisible):
 *   appendStage performs ONLY bounded local validation, canonicalization,
 *   domain-separated hashing, and an in-memory append + enqueue. It makes NO
 *   synchronous network call and produces NO synchronous public-key signature.
 *   Signing (ed25519, then best-effort ML-DSA-65), durable persistence, and
 *   Merkle batching happen asynchronously in the finalizer, which moves a stage
 *   from `pending` to `final`. The only intentionally blocking path is an
 *   explicit fail-closed policy gate the customer selected, handled by the
 *   existing Carnac judge()/Imprimatur route, not here.
 *
 * Stage types (evidence is recorded where available, honestly labeled):
 *   receipt_zero    Receipt #0 coverage policy reference (reused across a prefix)
 *   context_commit  structural prompt/context commitment + context-span origin
 *   intent          the committed intent to run
 *   gate            pre-execution gate decision (Imprimatur)
 *   attestation_ref hardware-adjacent attestation reference (S2S), status-labeled
 *   model_identity  model/runtime identity (MiR)
 *   invocation      the inference invocation
 *   output_commit   output commitment (hash only)
 *   tool_call       structured tool-call commitment
 *   braid_link      delegated-agent / braided parent link (AFiR), monotone scope
 *   action          the downstream action/effect
 *   disposition     final disposition
 *   r3pv            optional grouped proof-state vector
 */

import crypto from 'crypto';
import { canonicalize, hashObject, sha256hex, contentCommit } from './canon.js';
import { buildMerkle, verifyInclusion } from './merkle.js';
import { signCanonical, verifyCanonical } from '../spectral.js';
import { pqSign } from './pqsign.js';
import { supaInsert } from './supabase.js';

const STAGE_DOMAIN = 'carnac.stage.v1';
const CHAIN_DOMAIN = 'carnac.chain.v1';
export const ENVELOPE_VERSION = 'carnac-lifecycle/1.0';

export const STAGE_TYPES = new Set([
  'receipt_zero', 'context_commit', 'intent', 'gate', 'attestation_ref',
  'model_identity', 'invocation', 'output_commit', 'tool_call', 'braid_link',
  'action', 'disposition', 'r3pv',
]);

export const ORIGIN_TYPES = new Set(['principal', 'operator', 'retrieval', 'tool', 'agent']);
// Only these origin classes may carry instructions; retrieved documents, tool
// results, and peer-agent messages are data, never instructions.
export const INSTRUCTION_ORIGINS = new Set(['principal', 'operator']);

export const REPLAY_CLASSES = new Set(['R0', 'R1', 'R2']);
export const EVIDENCE_STATUS = new Set(['hardware-rooted', 'simulated', 'unavailable']);

// The immutable, signed fields of a stage. Anything outside this set (status,
// signature, batch, finalize bookkeeping) is not part of the commitment.
const SIGNABLE_KEYS = [
  'envelope_version', 'stage_id', 'lifecycle_id', 'tenant_id', 'parent_lifecycle_id',
  'type', 'seq', 'ts', 'origin', 'instructs', 'commitments', 'evidence',
  'replay_class', 'policy_version', 'policy_receipt', 'privacy',
  'prev_head', 'stage_digest', 'chain_head',
];

const lifecycles = new Map(); // `${tenant}::${lifecycle_id}` -> { meta, stages: [] }
const stageIndex = new Map(); // stage_id -> lifecycleKey
const idempotency = new Map(); // `${tenant}::${lifecycle_id}::${idem}` -> stage_id
const receiptZeroCache = new Map(); // `${tenant}|${policy_version}|${prefix}` -> { receipt_id, uses, first_seen_at }
let queue = []; // pending stage refs awaiting finalization

let persistHook = defaultPersist;
let flushTimer = null;

const TABLE = () => process.env.CARNAC_LIFECYCLE_TABLE || 'carnac_lifecycle_stages';
const BATCH_SIZE = () => Math.max(1, Number(process.env.CARNAC_LIFECYCLE_BATCH || 16));
const MAX_FINALIZE_ATTEMPTS = () => Math.max(1, Number(process.env.CARNAC_LIFECYCLE_MAX_ATTEMPTS || 5));

export function _resetLifecycle() {
  lifecycles.clear();
  stageIndex.clear();
  idempotency.clear();
  receiptZeroCache.clear();
  queue = [];
  persistHook = defaultPersist;
}

/** Test/ops hook: override durable persistence (default mirrors to Supabase). */
export function _setPersistHook(fn) { persistHook = typeof fn === 'function' ? fn : defaultPersist; }

function key(tenant_id, lifecycle_id) { return `${tenant_id || ''}::${lifecycle_id || ''}`; }

async function defaultPersist(stage) {
  // Only the public-safe, hash-only stage is mirrored. Fail-open, never throws.
  const row = {
    stage_id: stage.stage_id,
    lifecycle_id: stage.lifecycle_id,
    tenant_id: stage.tenant_id,
    type: stage.type,
    seq: stage.seq,
    chain_head: stage.chain_head,
    batch_root: stage.batch_root || null,
    envelope: stage,
    created_at: stage.ts,
  };
  return supaInsert(TABLE(), row);
}

/**
 * Get or mint a Receipt #0 for a (tenant, policy_version, prefix_commit). A
 * shared system-prompt prefix under one policy version reuses the same Receipt
 * #0 across calls (prefix-cache-aligned policy reuse), so proof cost amortizes.
 */
export function getOrMintReceiptZero({ tenant_id, policy_version, prefix_commit }) {
  const k = `${tenant_id || ''}|${policy_version || ''}|${prefix_commit || ''}`;
  const existing = receiptZeroCache.get(k);
  if (existing) {
    existing.uses += 1;
    return { receipt_id: existing.receipt_id, reused: true, uses: existing.uses, policy_commit: existing.policy_commit };
  }
  const policy_commit = hashObject('carnac.receipt0.v1', { tenant_id, policy_version, prefix_commit });
  const receipt_id = `r0_${policy_commit.slice(0, 24)}`;
  receiptZeroCache.set(k, { receipt_id, policy_commit, uses: 1, first_seen_at: new Date().toISOString() });
  return { receipt_id, reused: false, uses: 1, policy_commit };
}

/**
 * Open a lifecycle. Local only. Optionally seeds a Receipt #0 stage referencing
 * a cached (reused) policy object.
 * @returns {{ok:true, lifecycle:object}|{ok:false,status:number,code:string,message:string}}
 */
export function openLifecycle(input = {}) {
  const tenant_id = input.tenant_id || null;
  if (!tenant_id) return { ok: false, status: 400, code: 'tenant_required', message: 'tenant_id required' };
  const replay_class = input.replay_class || 'R2';
  if (!REPLAY_CLASSES.has(replay_class)) {
    return { ok: false, status: 400, code: 'invalid_replay_class', message: `replay_class must be one of ${[...REPLAY_CLASSES].join(', ')}` };
  }
  const lifecycle_id = input.lifecycle_id || `lc_${crypto.randomBytes(12).toString('hex')}`;
  const k = key(tenant_id, lifecycle_id);
  if (lifecycles.has(k)) return { ok: false, status: 409, code: 'lifecycle_exists', message: 'lifecycle_id already open' };

  const meta = {
    envelope_version: ENVELOPE_VERSION,
    lifecycle_id,
    tenant_id,
    trajectory_id: input.trajectory_id || null,
    parent_lifecycle_id: input.parent_lifecycle_id || null,
    policy_version: input.policy_version || null,
    replay_class,
    opened_at: new Date().toISOString(),
    next_seq: 0,
    head: null,
  };
  lifecycles.set(k, { meta, stages: [] });

  const seeded = [];
  const prefix_commit = contentCommit({ commit: input.prefix_commit, text: input.prefix_text });
  if (input.policy_version || prefix_commit || input.seed_receipt_zero) {
    const r0 = getOrMintReceiptZero({ tenant_id, policy_version: input.policy_version || null, prefix_commit });
    const res = appendStage({
      tenant_id,
      lifecycle_id,
      type: 'receipt_zero',
      policy_version: input.policy_version || null,
      policy_receipt: r0.receipt_id,
      commitments: { policy_commit: r0.policy_commit, prefix_commit: prefix_commit || null, reused: r0.reused },
      replay_class,
    });
    if (res.ok) seeded.push(res.stage);
  }
  return { ok: true, lifecycle: { ...meta, receipt_zero: seeded[0] || null } };
}

/** Is an origin class allowed to carry instructions? Structural, no prose. */
export function authorizeInstruction(originClass) {
  if (!ORIGIN_TYPES.has(originClass)) return { authorized: false, reason: 'unknown_origin' };
  return { authorized: INSTRUCTION_ORIGINS.has(originClass), reason: INSTRUCTION_ORIGINS.has(originClass) ? 'origin_may_instruct' : 'origin_is_data_only' };
}

function normalizeOrigin(origin) {
  if (!origin) return null;
  const cls = typeof origin === 'string' ? origin : origin.class;
  if (!ORIGIN_TYPES.has(cls)) return { error: `invalid origin class: ${cls}` };
  return { class: cls, id_commit: (origin && origin.id_commit) || null, source_commit: (origin && origin.source_commit) || null };
}

// Fields a caller might send that must never be stored; we hash them into
// commitments and drop the raw values.
const RAW_FIELDS = ['text', 'request', 'output', 'prose', 'prompt', 'args_text'];

/**
 * Append a typed stage. LOCAL ONLY: validate, canonicalize, hash, chain-link,
 * store as pending, enqueue for finalization. No network, no signature here.
 * @returns {{ok:true, stage:object}|{ok:false,status:number,code:string,message:string}}
 */
export function appendStage(input = {}) {
  const tenant_id = input.tenant_id || null;
  const lifecycle_id = input.lifecycle_id || null;
  if (!tenant_id || !lifecycle_id) return { ok: false, status: 400, code: 'invalid_input', message: 'tenant_id and lifecycle_id required' };
  const lc = lifecycles.get(key(tenant_id, lifecycle_id));
  if (!lc) return { ok: false, status: 404, code: 'lifecycle_not_found', message: 'open the lifecycle first' };

  const type = input.type;
  if (!STAGE_TYPES.has(type)) return { ok: false, status: 400, code: 'invalid_stage_type', message: `type must be one of ${[...STAGE_TYPES].join(', ')}` };

  // Idempotency: a repeated key returns the prior stage.
  if (input.idempotency_key) {
    const idemK = `${key(tenant_id, lifecycle_id)}::${input.idempotency_key}`;
    const priorId = idempotency.get(idemK);
    if (priorId) {
      const prior = lc.stages.find((s) => s.stage_id === priorId);
      if (prior) return { ok: true, stage: prior, idempotent_replay: true };
    }
  }

  // Sequencing: monotonic, append-only. Reject a regressed or duplicate seq.
  const seq = typeof input.seq === 'number' ? input.seq : lc.meta.next_seq;
  if (lc.stages.length && seq <= lc.stages[lc.stages.length - 1].seq) {
    return { ok: false, status: 409, code: 'seq_out_of_order', message: `seq ${seq} must exceed ${lc.stages[lc.stages.length - 1].seq}` };
  }

  const origin = normalizeOrigin(input.origin);
  if (origin && origin.error) return { ok: false, status: 400, code: 'invalid_origin', message: origin.error };

  // Origin-gated instruction authority: an instruction-bearing span is only
  // honored from an origin class permitted to instruct. No prose is inspected.
  const instructs = Boolean(input.instructs);
  if (instructs) {
    if (!origin) return { ok: false, status: 400, code: 'origin_required', message: 'instruction-bearing span requires an origin' };
    const auth = authorizeInstruction(origin.class);
    if (!auth.authorized) {
      return { ok: false, status: 403, code: 'instruction_not_authorized', message: `origin ${origin.class} may not instruct (${auth.reason})` };
    }
  }

  // Evidence status (attestation_ref): honestly labeled, never auto-elevated.
  let evidence = null;
  if (input.evidence || type === 'attestation_ref') {
    const status = (input.evidence && input.evidence.status) || 'unavailable';
    if (!EVIDENCE_STATUS.has(status)) return { ok: false, status: 400, code: 'invalid_evidence_status', message: `evidence.status must be one of ${[...EVIDENCE_STATUS].join(', ')}` };
    const source_ref = (input.evidence && input.evidence.source_ref) || null;
    if (status === 'hardware-rooted' && !source_ref) {
      return { ok: false, status: 400, code: 'evidence_ref_required', message: 'hardware-rooted evidence requires a source_ref; otherwise label it simulated or unavailable' };
    }
    evidence = { status, source_ref };
  }

  const replay_class = input.replay_class || lc.meta.replay_class;
  if (!REPLAY_CLASSES.has(replay_class)) return { ok: false, status: 400, code: 'invalid_replay_class', message: 'invalid replay_class' };

  // Commitments: accept precomputed hex commits; hash any raw field locally and
  // drop it. Raw content is never stored.
  const commitments = {};
  const rawIn = input.commitments || {};
  for (const [k2, v] of Object.entries(rawIn)) {
    if (RAW_FIELDS.includes(k2)) continue; // never store raw under these names
    commitments[k2] = v;
  }
  for (const f of RAW_FIELDS) {
    if (typeof input[f] === 'string') {
      commitments[`${f}_commit`] = contentCommit({ text: input[f] });
    }
  }

  const parent_lifecycle_id = input.parent_lifecycle_id || lc.meta.parent_lifecycle_id || null;
  const prev_head = lc.meta.head;
  const stage_id = `st_${crypto.randomBytes(12).toString('hex')}`;
  const ts = new Date().toISOString();

  const core = {
    envelope_version: ENVELOPE_VERSION,
    stage_id,
    lifecycle_id,
    tenant_id,
    parent_lifecycle_id,
    type,
    seq,
    ts,
    origin,
    instructs,
    commitments,
    evidence,
    replay_class,
    policy_version: input.policy_version || lc.meta.policy_version || null,
    policy_receipt: input.policy_receipt || null,
    privacy: { stores_raw: false },
  };
  const stage_digest = hashObject(STAGE_DOMAIN, core);
  const chain_head = hashObject(CHAIN_DOMAIN, { prev_head, stage_digest, seq, lifecycle_id });

  const stage = {
    ...core,
    prev_head,
    stage_digest,
    chain_head,
    status: 'pending',
    signature: null,
    signature_algo: null,
    public_key: null,
    signed_payload_sha256: null,
    pq: null,
    batch_id: null,
    batch_root: null,
    inclusion_proof: null,
    finalized_at: null,
    finalize_attempts: 0,
    finalize_error: null,
  };

  lc.stages.push(stage);
  lc.meta.head = chain_head;
  lc.meta.next_seq = seq + 1;
  stageIndex.set(stage_id, key(tenant_id, lifecycle_id));
  if (input.idempotency_key) idempotency.set(`${key(tenant_id, lifecycle_id)}::${input.idempotency_key}`, stage_id);
  queue.push({ tenant_id, lifecycle_id, stage_id });

  return { ok: true, stage };
}

function signableCore(stage) {
  const out = {};
  for (const k2 of SIGNABLE_KEYS) if (stage[k2] !== undefined) out[k2] = stage[k2];
  return out;
}

/**
 * Finalize all pending stages: batch by BATCH_SIZE, commit one Merkle root per
 * batch, sign each stage (ed25519 canonical), attach a best-effort ML-DSA-65
 * signature and the batch inclusion proof, then persist durably with retry.
 * Runs off the serving path. Never throws.
 * @returns {Promise<{processed:number, batches:number, final:number, failed:number}>}
 */
export async function drainFinalize() {
  if (!queue.length) return { processed: 0, batches: 0, final: 0, failed: 0 };
  const pending = queue;
  queue = [];
  const resolved = pending
    .map((ref) => {
      const lc = lifecycles.get(key(ref.tenant_id, ref.lifecycle_id));
      const stage = lc && lc.stages.find((s) => s.stage_id === ref.stage_id);
      return stage && stage.status === 'pending' ? { ref, stage } : null;
    })
    .filter(Boolean);

  let final = 0, failed = 0, batches = 0;
  const size = BATCH_SIZE();
  for (let i = 0; i < resolved.length; i += size) {
    const group = resolved.slice(i, i + size);
    batches += 1;
    const batch_id = `b_${crypto.randomBytes(8).toString('hex')}`;
    const { root, proofs } = buildMerkle(group.map((g) => g.stage.stage_digest));

    for (let j = 0; j < group.length; j++) {
      const stage = group[j].stage;
      const core = signableCore(stage);
      const sig = signCanonical(core);
      const pqRes = await pqSign(core);
      stage.signature = sig.signature;
      stage.public_key = sig.public_key;
      stage.signed_payload_sha256 = sig.signed_payload_sha256;
      stage.signature_algo = sig.signature_algo;
      stage.pq = pqRes.available
        ? { available: true, algo: pqRes.algo, signature: pqRes.signature, public_key: pqRes.public_key, payload_sha256: pqRes.payload_sha256 }
        : { available: false, algo: pqRes.algo, error: pqRes.error };
      stage.batch_id = batch_id;
      stage.batch_root = root;
      stage.inclusion_proof = proofs[j];

      // Durable persist with bounded retry. Persistence is fail-open: a degraded
      // result is recorded truthfully and does not block finalization.
      let attempts = 0;
      let lastError = null;
      const max = MAX_FINALIZE_ATTEMPTS();
      while (attempts < max) {
        attempts += 1;
        try {
          const r = await persistHook(stage);
          if (r && r.ok !== false) { lastError = r && r.degraded ? (r.error || 'degraded') : null; break; }
          lastError = (r && r.error) || 'persist_failed';
        } catch (e) {
          lastError = e.message;
        }
      }
      stage.finalize_attempts = attempts;
      stage.finalize_error = lastError;
      stage.status = 'final';
      stage.finalized_at = new Date().toISOString();
      final += 1;
    }
  }
  return { processed: resolved.length, batches, final, failed };
}

/** Start a background finalizer that drains on an interval. Idempotent. */
export function startFinalizer() {
  if (flushTimer) return;
  const ms = Math.max(10, Number(process.env.CARNAC_LIFECYCLE_FLUSH_MS || 50));
  flushTimer = setInterval(() => { drainFinalize().catch(() => {}); }, ms);
  if (flushTimer.unref) flushTimer.unref();
}

export function stopFinalizer() {
  if (flushTimer) { clearInterval(flushTimer); flushTimer = null; }
}

/** Read a lifecycle: ordered stages, head, and pending/final counts. */
export function getLifecycle(tenant_id, lifecycle_id) {
  const lc = lifecycles.get(key(tenant_id, lifecycle_id));
  if (!lc) return { ok: false, status: 404, code: 'lifecycle_not_found', message: 'lifecycle not found' };
  const pending = lc.stages.filter((s) => s.status === 'pending').length;
  const final = lc.stages.length - pending;
  return {
    ok: true,
    lifecycle: {
      ...lc.meta,
      count: lc.stages.length,
      pending,
      final,
      stages: lc.stages,
    },
  };
}

/**
 * Verify a complete lifecycle chain (array of stages, in order). Recomputes each
 * stage digest and chain head, verifies each finalized signature over the
 * canonical core, and checks Merkle inclusion where a batch root is present.
 * Pending (unsigned) stages are reported as pending, not as failures.
 */
export function verifyLifecycle(stages) {
  const list = Array.isArray(stages) ? stages : [];
  const breaks = [];
  const signatures = [];
  const merkle = [];
  let prev = null;
  let lastSeq = null;
  let head = null;

  for (let i = 0; i < list.length; i++) {
    const s = list[i];
    const core = signableCore(s);
    const expectedDigest = hashObject(STAGE_DOMAIN, {
      envelope_version: s.envelope_version, stage_id: s.stage_id, lifecycle_id: s.lifecycle_id,
      tenant_id: s.tenant_id, parent_lifecycle_id: s.parent_lifecycle_id, type: s.type,
      seq: s.seq, ts: s.ts, origin: s.origin, instructs: s.instructs, commitments: s.commitments,
      evidence: s.evidence, replay_class: s.replay_class, policy_version: s.policy_version,
      policy_receipt: s.policy_receipt, privacy: s.privacy,
    });
    if (s.stage_digest !== expectedDigest) breaks.push({ index: i, stage_id: s.stage_id, reason: 'stage_digest mismatch' });

    const expectedHead = hashObject(CHAIN_DOMAIN, { prev_head: prev, stage_digest: s.stage_digest, seq: s.seq, lifecycle_id: s.lifecycle_id });
    if (s.chain_head !== expectedHead) breaks.push({ index: i, stage_id: s.stage_id, reason: 'chain_head mismatch' });
    if (s.prev_head !== (prev || null)) breaks.push({ index: i, stage_id: s.stage_id, reason: 'prev_head mismatch' });

    if (typeof s.seq === 'number') {
      if (lastSeq !== null && s.seq <= lastSeq) breaks.push({ index: i, stage_id: s.stage_id, reason: 'seq out of order' });
      lastSeq = s.seq;
    }

    if (s.status === 'final' && s.signature) {
      const v = verifyCanonical({ ...core, signature: s.signature, public_key: s.public_key, signed_payload_sha256: s.signed_payload_sha256, signature_algo: s.signature_algo });
      signatures.push({ stage_id: s.stage_id, valid: v.valid, error: v.error || null });
      if (!v.valid) breaks.push({ index: i, stage_id: s.stage_id, reason: `signature invalid: ${v.error || 'unknown'}` });
      if (s.batch_root && s.inclusion_proof) {
        const included = verifyInclusion(s.stage_digest, s.inclusion_proof, s.batch_root);
        merkle.push({ stage_id: s.stage_id, included, batch_root: s.batch_root });
        if (!included) breaks.push({ index: i, stage_id: s.stage_id, reason: 'merkle inclusion failed' });
      }
    } else {
      signatures.push({ stage_id: s.stage_id, valid: null, pending: true });
    }

    prev = s.chain_head;
    head = prev;
  }

  return { ok: breaks.length === 0, count: list.length, head, breaks, signatures, merkle };
}
