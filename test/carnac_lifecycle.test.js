/**
 * Carnac lifecycle chain — unit and integration tests.
 *
 * These exercise the unified inference receipt chain end to end without any
 * network: canonicalization determinism and order-independence, monotonic stage
 * ordering, chain continuity, idempotent append, origin-gated instruction
 * authority, tenant isolation, the no-raw-prompt/output guarantee, the
 * pending->final transition, ed25519-canonical signature verification, tamper
 * detection, disposition linkage, delegated braid links, replay classes, Receipt
 * #0 prefix reuse, Merkle inclusion, and durable-persist retry/failure behavior.
 *
 * The PQ signer and Supabase are intentionally unconfigured, so pqSign reports an
 * honest unavailable state and persistence is a fail-open no-op — matching the
 * offline posture of the rest of this repo's suite.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalize, hashObject } from '../lib/carnac/canon.js';
import { buildMerkle, verifyInclusion, leafHash } from '../lib/carnac/merkle.js';
import { initKeypair, signCanonical, verifyCanonical } from '../lib/spectral.js';
import {
  openLifecycle,
  appendStage,
  getLifecycle,
  verifyLifecycle,
  drainFinalize,
  getOrMintReceiptZero,
  authorizeInstruction,
  _resetLifecycle,
  _setPersistHook,
} from '../lib/carnac/lifecycle.js';

initKeypair();

beforeEach(() => {
  _resetLifecycle();
});

const TENANT = 'tenant_a';

function openOK(overrides = {}) {
  const r = openLifecycle({ tenant_id: TENANT, ...overrides });
  assert.equal(r.ok, true, `open failed: ${JSON.stringify(r)}`);
  return r.lifecycle;
}

// ── Canonicalization ──────────────────────────────────────────────────────────

test('canonicalize is order-independent for object keys', () => {
  const a = canonicalize({ b: 1, a: 2, nested: { y: 1, x: 2 } });
  const b = canonicalize({ a: 2, nested: { x: 2, y: 1 }, b: 1 });
  assert.equal(a, b);
});

test('canonicalize preserves array order (order is meaning)', () => {
  assert.notEqual(canonicalize([1, 2, 3]), canonicalize([3, 2, 1]));
});

test('canonicalize rejects non-finite numbers and unsupported types', () => {
  assert.throws(() => canonicalize({ x: Infinity }));
  assert.throws(() => canonicalize({ x: 10n }));
});

test('hashObject is domain-separated (same bytes, different tags differ)', () => {
  const obj = { a: 1 };
  assert.notEqual(hashObject('carnac.stage.v1', obj), hashObject('carnac.chain.v1', obj));
});

// ── ed25519-canonical signing ─────────────────────────────────────────────────

test('signCanonical verifies regardless of field order', () => {
  const env = signCanonical({ b: 1, a: 2 });
  const reordered = { a: 2, b: 1, ...env };
  const v = verifyCanonical(reordered);
  assert.equal(v.valid, true);
});

test('verifyCanonical detects a tampered payload', () => {
  const env = signCanonical({ a: 1 });
  const tampered = { a: 2, ...env };
  assert.equal(verifyCanonical(tampered).valid, false);
});

// ── Merkle inclusion ──────────────────────────────────────────────────────────

test('merkle inclusion holds for every leaf, and a wrong value fails', () => {
  const values = Array.from({ length: 7 }, (_, i) => hashObject('x', { i }));
  const { root, proofs } = buildMerkle(values);
  for (let i = 0; i < values.length; i++) {
    assert.equal(verifyInclusion(values[i], proofs[i], root), true);
  }
  assert.equal(verifyInclusion(leafHash('deadbeef'), proofs[0], root), false);
});

// ── Open / append / ordering / continuity ─────────────────────────────────────

test('open then append builds a continuous, verifiable chain', async () => {
  const lc = openOK({ policy_version: 'pol-1', prefix_text: 'system prompt' });
  const lid = lc.lifecycle_id;
  assert.ok(lc.receipt_zero, 'receipt_zero seeded');

  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'context_commit', origin: { class: 'principal' }, text: 'the user prompt' });
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent', origin: { class: 'principal' }, instructs: true });
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'invocation' });
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'output_commit', output: 'the model output' });

  await drainFinalize();
  const got = getLifecycle(TENANT, lid);
  const v = verifyLifecycle(got.lifecycle.stages);
  assert.equal(v.ok, true, `verify breaks: ${JSON.stringify(v.breaks)}`);
  assert.equal(v.count, 5); // receipt_zero + 4
  assert.equal(got.lifecycle.pending, 0);
});

test('seq must be monotonic and append-only', () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  const a = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent', seq: 5 });
  assert.equal(a.ok, true);
  const b = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'invocation', seq: 5 });
  assert.equal(b.ok, false);
  assert.equal(b.code, 'seq_out_of_order');
});

test('append to an unopened lifecycle is rejected', () => {
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: 'lc_missing', type: 'intent' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'lifecycle_not_found');
});

test('unknown stage type is rejected', () => {
  const lc = openOK();
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'nonsense' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'invalid_stage_type');
});

// ── Idempotency ───────────────────────────────────────────────────────────────

test('a repeated idempotency_key returns the same stage, not a new one', () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  const first = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent', idempotency_key: 'k1' });
  const second = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent', idempotency_key: 'k1' });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(second.idempotent_replay, true);
  assert.equal(first.stage.stage_id, second.stage.stage_id);
  assert.equal(getLifecycle(TENANT, lid).lifecycle.count, 1);
});

// ── Instruction authority ─────────────────────────────────────────────────────

test('instruction-bearing span from a data-only origin is refused (403)', () => {
  const lc = openOK();
  for (const cls of ['retrieval', 'tool', 'agent']) {
    const r = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'context_commit', origin: { class: cls }, instructs: true, seq: undefined });
    assert.equal(r.ok, false, `${cls} should not instruct`);
    assert.equal(r.status, 403);
    assert.equal(r.code, 'instruction_not_authorized');
  }
});

test('instruction-bearing span from principal/operator is allowed', () => {
  assert.equal(authorizeInstruction('principal').authorized, true);
  assert.equal(authorizeInstruction('operator').authorized, true);
  assert.equal(authorizeInstruction('retrieval').authorized, false);
  const lc = openOK();
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'intent', origin: { class: 'operator' }, instructs: true });
  assert.equal(r.ok, true);
});

// ── Evidence status honesty (S2S) ─────────────────────────────────────────────

test('hardware-rooted evidence without a source_ref is refused', () => {
  const lc = openOK();
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'attestation_ref', evidence: { status: 'hardware-rooted' } });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'evidence_ref_required');
});

test('attestation defaults to unavailable and accepts simulated honestly', () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  const def = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'attestation_ref' });
  assert.equal(def.ok, true);
  assert.equal(def.stage.evidence.status, 'unavailable');
  const sim = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'attestation_ref', evidence: { status: 'simulated' } });
  assert.equal(sim.ok, true);
  assert.equal(sim.stage.evidence.status, 'simulated');
  const hw = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'attestation_ref', evidence: { status: 'hardware-rooted', source_ref: 'tpm://quote/abc' } });
  assert.equal(hw.ok, true);
  assert.equal(hw.stage.evidence.status, 'hardware-rooted');
});

// ── Replay classes ────────────────────────────────────────────────────────────

test('replay_class is validated on open and on append', () => {
  assert.equal(openLifecycle({ tenant_id: TENANT, replay_class: 'RX' }).ok, false);
  const lc = openOK({ replay_class: 'R1' });
  const bad = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'intent', replay_class: 'nope' });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'invalid_replay_class');
});

// ── No raw prompt/output persistence ──────────────────────────────────────────

test('raw prompt/output text is never stored; only commitments are', () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  const secret = 'PLAINTEXT SECRET PROMPT';
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'context_commit', origin: { class: 'principal' }, text: secret });
  assert.equal(r.ok, true);
  const serialized = JSON.stringify(getLifecycle(TENANT, lid).lifecycle);
  assert.equal(serialized.includes(secret), false, 'raw prompt leaked into stored lifecycle');
  assert.ok(r.stage.commitments.text_commit, 'text_commit missing');
  assert.equal(r.stage.privacy.stores_raw, false);
  // commit is a plain sha256 hash, reversible to nothing.
  assert.match(r.stage.commitments.text_commit, /^[0-9a-f]{64}$/);
});

test('raw fields passed under commitments are dropped, not stored', () => {
  const lc = openOK();
  const r = appendStage({ tenant_id: TENANT, lifecycle_id: lc.lifecycle_id, type: 'output_commit', commitments: { output: 'raw!!', model_commit: 'abc' } });
  assert.equal(r.ok, true);
  assert.equal(r.stage.commitments.output, undefined);
  assert.equal(r.stage.commitments.model_commit, 'abc');
});

// ── Pending -> final transition + signatures ──────────────────────────────────

test('stages start pending and become final and signed after drain', async () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent' });
  let got = getLifecycle(TENANT, lid);
  assert.equal(got.lifecycle.pending, 1);
  assert.equal(got.lifecycle.stages[0].status, 'pending');
  assert.equal(got.lifecycle.stages[0].signature, null);

  const drain = await drainFinalize();
  assert.equal(drain.final, 1);
  got = getLifecycle(TENANT, lid);
  const s = got.lifecycle.stages[0];
  assert.equal(s.status, 'final');
  assert.equal(s.signature_algo, 'ed25519-canonical');
  assert.ok(s.signature);
  assert.ok(s.batch_root);
  // PQ signer is unconfigured here: honestly unavailable, never fabricated.
  assert.equal(s.pq.available, false);
});

// ── Tamper detection ──────────────────────────────────────────────────────────

test('verifyLifecycle detects a mutated commitment after signing', async () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'output_commit', output: 'x' });
  await drainFinalize();
  const stages = JSON.parse(JSON.stringify(getLifecycle(TENANT, lid).lifecycle.stages));
  stages[0].commitments.output_commit = 'f'.repeat(64);
  const v = verifyLifecycle(stages);
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.reason.includes('stage_digest')));
});

test('verifyLifecycle detects a broken chain link (reordering)', async () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent' });
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'invocation' });
  await drainFinalize();
  const stages = getLifecycle(TENANT, lid).lifecycle.stages.slice().reverse();
  const v = verifyLifecycle(stages);
  assert.equal(v.ok, false);
});

// ── Tenant isolation ──────────────────────────────────────────────────────────

test('a lifecycle is invisible to another tenant', () => {
  const lc = openOK();
  const other = getLifecycle('tenant_b', lc.lifecycle_id);
  assert.equal(other.ok, false);
  assert.equal(other.status, 404);
});

test('two tenants may reuse the same lifecycle_id independently', () => {
  const a = openLifecycle({ tenant_id: 'tenant_a', lifecycle_id: 'shared' });
  const b = openLifecycle({ tenant_id: 'tenant_b', lifecycle_id: 'shared' });
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
});

// ── Disposition linkage + braid ───────────────────────────────────────────────

test('disposition stage links into the same chain', async () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'action', commitments: { effect_commit: 'e1' } });
  const disp = appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'disposition', commitments: { action: 'allow' } });
  assert.equal(disp.ok, true);
  await drainFinalize();
  const v = verifyLifecycle(getLifecycle(TENANT, lid).lifecycle.stages);
  assert.equal(v.ok, true);
});

test('a braid_link records a delegated parent lifecycle', () => {
  const parent = openOK();
  const child = openOK({ parent_lifecycle_id: parent.lifecycle_id });
  const r = appendStage({
    tenant_id: TENANT, lifecycle_id: child.lifecycle_id, type: 'braid_link',
    parent_lifecycle_id: parent.lifecycle_id, origin: { class: 'agent' },
    commitments: { delegated_scope_commit: 'scope1' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.stage.parent_lifecycle_id, parent.lifecycle_id);
});

// ── Receipt #0 reuse ──────────────────────────────────────────────────────────

test('Receipt #0 is reused across the same tenant/policy/prefix', () => {
  const base = { tenant_id: TENANT, policy_version: 'pol-1', prefix_commit: 'p'.repeat(64) };
  const first = getOrMintReceiptZero(base);
  const second = getOrMintReceiptZero(base);
  assert.equal(first.reused, false);
  assert.equal(second.reused, true);
  assert.equal(first.receipt_id, second.receipt_id);
  assert.equal(second.uses, 2);
  const different = getOrMintReceiptZero({ ...base, policy_version: 'pol-2' });
  assert.notEqual(different.receipt_id, first.receipt_id);
});

// ── Durable persist retry / failure behavior ──────────────────────────────────

test('persist is retried up to the max, and finalization is fail-open', async () => {
  let calls = 0;
  _setPersistHook(async () => { calls += 1; return { ok: false, error: 'boom' }; });
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent' });
  const drain = await drainFinalize();
  assert.equal(drain.final, 1); // fail-open: still finalized
  const s = getLifecycle(TENANT, lid).lifecycle.stages[0];
  assert.equal(s.status, 'final');
  assert.ok(s.finalize_attempts >= 2, `expected retries, got ${s.finalize_attempts}`);
  assert.equal(s.finalize_error, 'boom');
  assert.ok(calls >= 2);
});

test('a transient persist failure that later succeeds stops retrying', async () => {
  let calls = 0;
  _setPersistHook(async () => { calls += 1; return calls < 2 ? { ok: false, error: 'temp' } : { ok: true, durable: true }; });
  const lc = openOK();
  const lid = lc.lifecycle_id;
  appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'intent' });
  await drainFinalize();
  const s = getLifecycle(TENANT, lid).lifecycle.stages[0];
  assert.equal(s.finalize_attempts, 2);
  assert.equal(s.finalize_error, null);
});

// ── Batch spanning multiple stages ────────────────────────────────────────────

test('a batch across many stages yields one root with per-stage inclusion', async () => {
  const lc = openOK();
  const lid = lc.lifecycle_id;
  for (let i = 0; i < 5; i++) appendStage({ tenant_id: TENANT, lifecycle_id: lid, type: 'tool_call', commitments: { tool_commit: `t${i}` } });
  await drainFinalize();
  const stages = getLifecycle(TENANT, lid).lifecycle.stages;
  const roots = new Set(stages.map((s) => s.batch_root));
  assert.equal(roots.size, 1, 'all stages should share one batch root');
  const v = verifyLifecycle(stages);
  assert.equal(v.ok, true);
  assert.equal(v.merkle.length, stages.length);
  assert.ok(v.merkle.every((m) => m.included));
});
