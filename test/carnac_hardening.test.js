/**
 * Carnac production hardening — focused tests.
 *
 * Offline and deterministic (the semantic reader is disabled and global.fetch is
 * mocked). Covers: protected-route auth, tenant isolation and cross-tenant
 * denial, durable tenant-scoped retrieval after a memory reset, seq replay/order,
 * disposition immutability and raise-only override, Howler binding, public-safe
 * verification and enumeration resistance, audit export limits, continuity chain
 * breaks, PQ signer success/failure (fail-closed), Canon dispatch honesty, and
 * raw-prompt non-persistence — plus an end-to-end fixture.
 */

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { initKeypair } from '../lib/spectral.js';
import { judge, verifyJudgment, _resetEngine } from '../lib/carnac/engine.js';
import { _resetControls } from '../lib/carnac/idempotency.js';
import {
  _resetLedger, listByTrajectoryDurable, trajectorySeqExists,
  persistJudgment,
} from '../lib/carnac/ledger.js';
import { _resetPolicy } from '../lib/carnac/policy.js';
import {
  authenticateCarnac, tenantScopeAllows, carnacAuthConfigured, SANDBOX_TENANT,
} from '../lib/carnac/auth.js';
import { recordDisposition, listDispositions, _resetDispositions } from '../lib/carnac/dispositions.js';
import { verifyHowler, _resetHowlers } from '../lib/carnac/howler_store.js';
import { primitiveFor, dispatchRoute, listDispatch, _resetDispatch } from '../lib/carnac/dispatch.js';
import { verifyChain, sealTrajectory, _resetSeals } from '../lib/carnac/seal.js';
import { buildExport, exportToCsv, EXPORT_MAX_ROWS } from '../lib/carnac/export.js';
import { verifyArtifact, verifyById, rateLimit, _resetVerifyLimiter } from '../lib/carnac/verify.js';

const NO_SEM = { useSemantic: false };

initKeypair();

let realFetch;
function okJson(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
}
function signerMock() {
  global.fetch = async (url) => {
    const u = String(url);
    if (u.endsWith('/sign')) return okJson({ signature: 'pq-signature-b64', public_key: 'pq-public-b64', algo: 'ml-dsa-65' });
    if (u.endsWith('/verify')) return okJson({ valid: true });
    throw new Error(`unexpected fetch ${u}`);
  };
}

beforeEach(() => {
  realFetch = global.fetch;
  _resetEngine();
  _resetControls();
  _resetLedger();
  _resetPolicy();
  _resetDispositions();
  _resetHowlers();
  _resetDispatch();
  _resetSeals();
  _resetVerifyLimiter();
  for (const k of [
    'CARNAC_SERVICE_TOKENS', 'SITE_INTEL_TOKEN', 'OWNER_ADMIN_TOKEN',
    'HIVE_PQ_SIGNER_URL', 'HIVE_PQ_SIGNER_TOKEN',
    'CARNAC_LEDGER_SUPA_URL', 'CARNAC_LEDGER_SUPA_KEY', 'CARNAC_LEDGER_TOKEN',
    'CARNAC_VERIFY_RATE_PER_MIN',
  ]) delete process.env[k];
});

afterEach(() => { global.fetch = realFetch; });

// ── Auth & tenancy ─────────────────────────────────────────────────────────

test('auth: unauthenticated request is rejected before any lookup', () => {
  const r = authenticateCarnac({ headers: {} });
  assert.equal(r.ok, false);
  assert.equal(r.status, 401);
});

test('auth: a service token binds the caller to exactly one tenant', () => {
  process.env.CARNAC_SERVICE_TOKENS = 'tenant-a:tok_aaa,tenant-b:tok_bbb';
  const r = authenticateCarnac({ headers: { authorization: 'Bearer tok_aaa' } });
  assert.equal(r.ok, true);
  assert.equal(r.owner, false);
  assert.equal(r.tenant_id, 'tenant-a');
  assert.equal(tenantScopeAllows(r, 'tenant-a'), true);
  assert.equal(tenantScopeAllows(r, 'tenant-b'), false, 'cross-tenant denied');
});

test('auth: owner may act across tenants and must name one when required', () => {
  process.env.SITE_INTEL_TOKEN = 'owner_secret_token';
  const named = authenticateCarnac({ headers: { authorization: 'Bearer owner_secret_token', 'x-carnac-tenant': 'tenant-x' } });
  assert.equal(named.ok, true);
  assert.equal(named.owner, true);
  assert.equal(named.tenant_id, 'tenant-x');
  assert.equal(tenantScopeAllows(named, 'tenant-x'), true);
  assert.equal(tenantScopeAllows(named, 'tenant-y'), false, 'owner confined to the named tenant');

  const unscoped = authenticateCarnac({ headers: { authorization: 'Bearer owner_secret_token' } });
  assert.equal(unscoped.tenant_id, null);
  assert.equal(tenantScopeAllows(unscoped, 'anything'), true, 'unscoped owner sees all');

  const missingTenant = authenticateCarnac({ headers: { authorization: 'Bearer owner_secret_token' } }, { requireTenant: true });
  assert.equal(missingTenant.ok, false);
  assert.equal(missingTenant.code, 'tenant_required');
});

test('auth: carnacAuthConfigured reflects owner or service configuration', () => {
  assert.equal(carnacAuthConfigured(), false);
  process.env.CARNAC_SERVICE_TOKENS = 't:tok';
  assert.equal(carnacAuthConfigured(), true);
});

// ── Tenant binding in the engine ─────────────────────────────────────────────

test('sandbox forces the fixed public-sandbox tenant and never persists durably', async () => {
  const r = await judge({ request: 'delete production permanently', ...NO_SEM }, { sandbox: true, tenant_id: 'attacker-tenant' });
  assert.equal(r.envelope.tenant_id, SANDBOX_TENANT);
  assert.equal(r.envelope.sandbox, true);
  assert.equal(r.howler, null);
  assert.equal(r.ledger.durable, false);
});

test('production judge binds tenant into the signed payload', async () => {
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: false, tenant_id: 'tenant-a', actor: 'service:tenant-a' });
  assert.equal(r.ok, true);
  assert.equal(r.envelope.tenant_id, 'tenant-a');
  assert.equal(r.envelope.actor, 'service:tenant-a');
  assert.equal(verifyJudgment(r.envelope).valid, true, 'tenant is inside the signed envelope');
});

test('requireTenant fails closed when no tenant is bound', async () => {
  const r = await judge({ request: 'x', ...NO_SEM }, { sandbox: false, requireTenant: true });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'tenant_required');
});

// ── Continuity chain ─────────────────────────────────────────────────────────

test('continuity: chain digests link a trajectory and verifyChain confirms it', async () => {
  const t = 'traj-chain';
  const a = await judge({ request: 'a', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  const b = await judge({ request: 'b', trajectory_id: t, phase: 'output', output: 'o', seq: 2, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  assert.equal(a.envelope.previous_digest, null);
  assert.equal(typeof a.envelope.chain_digest, 'string');
  assert.equal(b.envelope.previous_digest, a.envelope.chain_digest, 'b links to a');
  const { judgments } = await listByTrajectoryDurable('tn', t);
  const v = verifyChain(judgments);
  assert.equal(v.ok, true);
  assert.equal(v.count, 2);
});

test('continuity: a tampered link is detected as a break', async () => {
  const t = 'traj-break';
  const a = await judge({ request: 'a', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  const b = await judge({ request: 'b', trajectory_id: t, phase: 'output', output: 'o', seq: 2, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  const tampered = [a.envelope, { ...b.envelope, previous_digest: 'deadbeef' }];
  const v = verifyChain(tampered);
  assert.equal(v.ok, false);
  assert.ok(v.breaks.length >= 1);
});

test('continuity: enforceContinuity rejects a duplicate seq (replay across restart)', async () => {
  const t = 'traj-dup';
  const first = await judge({ request: 'a', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn', enforceContinuity: true });
  assert.equal(first.ok, true);
  const dup = await judge({ request: 'b', trajectory_id: t, phase: 'invocation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn', enforceContinuity: true });
  assert.equal(dup.ok, false);
  assert.equal(dup.code, 'duplicate_seq');
});

test('continuity: enforceContinuity requires a numeric seq', async () => {
  const r = await judge({ request: 'a', trajectory_id: 't', phase: 'formation', ...NO_SEM }, { sandbox: false, tenant_id: 'tn', enforceContinuity: true });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'seq_required');
});

// ── Durable retrieval after a memory reset ──────────────────────────────────

test('durable: tenant-scoped trajectory listing works after memory is cleared', async () => {
  process.env.CARNAC_LEDGER_SUPA_URL = 'https://ledger.example.test';
  process.env.CARNAC_LEDGER_SUPA_KEY = 'k'.repeat(40);
  process.env.CARNAC_LEDGER_TOKEN = 't'.repeat(40);
  const stored = [];
  global.fetch = async (url, init) => {
    const u = String(url);
    if (init && init.method === 'POST') {
      if (u.includes('carnac_judgments')) stored.push(JSON.parse(init.body));
      return okJson(null, { status: 201 });
    }
    // durable select returns only the stored judgment envelopes, in order.
    return okJson(stored.filter((r) => r.trajectory_id === 'traj-d').map((r) => ({ envelope: r.envelope, seq: r.seq, created_at: r.created_at })));
  };
  await judge({ request: 'a', trajectory_id: 'traj-d', phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  await judge({ request: 'b', trajectory_id: 'traj-d', phase: 'output', output: 'o', seq: 2, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });

  _resetLedger(); // simulate a restart: memory is empty
  const res = await listByTrajectoryDurable('tn', 'traj-d');
  assert.equal(res.source, 'durable');
  assert.equal(res.judgments.length, 2);
  assert.ok(res.judgments.every((j) => verifyJudgment(j).valid), 'durable rows re-verify');

  assert.equal(await trajectorySeqExists('tn', 'traj-d', 1), true, 'durable duplicate detection after restart');
});

// ── Dispositions ─────────────────────────────────────────────────────────────

test('disposition: append-only history, never mutated', async () => {
  const first = await recordDisposition({ tenant_id: 'tn', judgment_id: 'j1', actor: 'alice', action: 'unresolved' });
  const second = await recordDisposition({ tenant_id: 'tn', judgment_id: 'j1', actor: 'bob', action: 'confirm' });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.notEqual(first.record.disposition_id, second.record.disposition_id);
  const hist = await listDispositions('tn', 'j1');
  assert.equal(hist.length, 2, 'both records retained (append-only)');
});

test('disposition: an override can only raise, never lower the floor', async () => {
  const lower = await recordDisposition({ tenant_id: 'tn', judgment_id: 'j2', actor: 'alice', action: 'override', floor_level: 2, override_level: 1 });
  assert.equal(lower.record.effective_after, 2, 'clamped to floor');
  assert.equal(lower.record.override_clamped, true);
  const raise = await recordDisposition({ tenant_id: 'tn', judgment_id: 'j3', actor: 'alice', action: 'override', floor_level: 2, override_level: 3 });
  assert.equal(raise.record.effective_after, 3);
  assert.equal(raise.record.override_clamped, false);
});

test('disposition: invalid action rejected; required fields enforced', async () => {
  assert.equal((await recordDisposition({ tenant_id: 'tn', judgment_id: 'j', actor: 'a', action: 'nope' })).code, 'invalid_action');
  assert.equal((await recordDisposition({ judgment_id: 'j', actor: 'a', action: 'confirm' })).code, 'tenant_required');
  assert.equal((await recordDisposition({ tenant_id: 'tn', actor: 'a', action: 'confirm' })).code, 'judgment_required');
});

// ── Howler binding ───────────────────────────────────────────────────────────

test('howler: verifies signature and binding to its originating judgment', async () => {
  const r = await judge({ request: 'delete production permanently', trajectory_id: 't', phase: 'effect', output: 'boom', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  assert.ok(r.howler, 'howler minted at level 3');
  const good = verifyHowler(r.howler, r.envelope);
  assert.equal(good.signature_valid, true);
  assert.equal(good.bound, true);
  const bad = verifyHowler(r.howler, { ...r.envelope, feature_digest: 'different' });
  assert.equal(bad.bound, false);
  assert.equal(bad.binding_error, 'feature_digest mismatch');
});

// ── Public-safe verification & enumeration resistance ───────────────────────

test('verify: by value returns only public-safe fields (no tenant, no prompt)', async () => {
  const r = await judge({ request: 'wire $500 secret vendor name', ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  const v = await verifyArtifact(r.envelope);
  assert.equal(v.signature_valid, true);
  assert.equal(v.artifact.tenant_id, undefined, 'tenant never crosses the public boundary');
  assert.equal(v.artifact.actor, undefined);
  assert.equal(v.artifact.request, undefined);
  assert.ok(!JSON.stringify(v.artifact).includes('vendor'), 'no raw prompt in public view');
});

test('verify: by id returns found:false for an unknown id (no envelope leak)', async () => {
  const v = await verifyById('does-not-exist', { client: 'c1' });
  assert.equal(v.ok, true);
  assert.equal(v.found, false);
  assert.equal(v.artifact, null);
});

test('verify: by-id is rate limited (enumeration resistance)', async () => {
  process.env.CARNAC_VERIFY_RATE_PER_MIN = '3';
  for (let i = 0; i < 3; i++) assert.equal(rateLimit('same-client').ok, true);
  const blocked = rateLimit('same-client');
  assert.equal(blocked.ok, false);
  assert.ok(blocked.retry_after_s >= 0);
  // A different client is unaffected.
  assert.equal(rateLimit('other-client').ok, true);
});

test('verify: PQ signature is checked and bound when the signer is reachable', async () => {
  process.env.HIVE_PQ_SIGNER_URL = 'https://signer.example.test';
  signerMock();
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: false, tenant_id: 'tn', requirePQ: true });
  assert.equal(r.envelope.pq.available, true);
  const v = await verifyArtifact(r.envelope);
  assert.equal(v.pq.present, true);
  assert.equal(v.pq.bound, true);
  assert.equal(v.pq.valid, true);
});

// ── Audit export ─────────────────────────────────────────────────────────────

test('export: tenant-scoped, capped, with continuity + signature validity, no raw prompt', async () => {
  const t = 'traj-exp';
  await judge({ request: 'a SECRETPROMPT111', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  await judge({ request: 'b SECRETPROMPT222', trajectory_id: t, phase: 'output', output: 'o SECRETPROMPT333', seq: 2, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  const { ok, report } = await buildExport({ tenant_id: 'tn', trajectory_id: t });
  assert.equal(ok, true);
  assert.equal(report.count, 2);
  assert.equal(report.continuity.intact, true);
  assert.equal(report.all_signatures_valid, true);
  const serialized = JSON.stringify(report) + exportToCsv(report);
  assert.ok(!/SECRETPROMPT/.test(serialized), 'raw prompt never appears in the export');
  assert.ok(report.limit <= EXPORT_MAX_ROWS);
});

test('export: requires a tenant', async () => {
  const r = await buildExport({});
  assert.equal(r.ok, false);
  assert.equal(r.code, 'tenant_required');
});

// ── Canon dispatch honesty ──────────────────────────────────────────────────

test('dispatch: internal routes are dispatched; external routes are pending_external', async () => {
  assert.equal(primitiveFor('let_it_run').internal, true);
  assert.equal(primitiveFor('howler').internal, true);
  assert.equal(primitiveFor('enrich').internal, false);
  const internal = await dispatchRoute({ tenant_id: 'tn', judgment_id: 'j', route: 'receipt' });
  assert.equal(internal.record.status, 'dispatched');
  const external = await dispatchRoute({ tenant_id: 'tn', judgment_id: 'j', route: 'verify' });
  assert.equal(external.record.status, 'pending_external');
  assert.equal(external.record.target_primitive, 'canon_verification');
  const list = await listDispatch('tn', 'j');
  assert.equal(list.length, 2);
});

// ── PQ signer: success / failure (fail-closed) ──────────────────────────────

test('pq: protected production fails closed when the signer is unavailable', async () => {
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: false, tenant_id: 'tn', requirePQ: true });
  assert.equal(r.ok, false);
  assert.equal(r.status, 503);
  assert.equal(r.code, 'pq_unavailable');
});

test('pq: sandbox proceeds in an explicitly degraded no-PQ state', async () => {
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: true });
  assert.equal(r.envelope.pq.available, false);
  assert.equal(r.envelope.pq.degraded, true);
});

test('pq: a real signature is attached when the signer is reachable', async () => {
  process.env.HIVE_PQ_SIGNER_URL = 'https://signer.example.test';
  signerMock();
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: false, tenant_id: 'tn', requirePQ: true });
  assert.equal(r.ok, true);
  assert.equal(r.envelope.pq.available, true);
  assert.equal(r.envelope.pq.algo, 'ml-dsa-65');
  assert.equal(r.envelope.pq.payload_sha256, r.envelope.signed_payload_sha256, 'pq bound to ed25519 digest');
});

// ── Outages ──────────────────────────────────────────────────────────────────

test('ledger outage: durable write degrades truthfully, ruling still returned', async () => {
  process.env.CARNAC_LEDGER_SUPA_URL = 'https://ledger.example.test';
  process.env.CARNAC_LEDGER_SUPA_KEY = 'k'.repeat(40);
  process.env.CARNAC_LEDGER_TOKEN = 't'.repeat(40);
  global.fetch = async () => { throw new Error('network down'); };
  const r = await judge({ request: 'wire $500', ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  assert.equal(r.ok, true, 'an outage does not become a denial of service');
  assert.equal(r.ledger.durable, false);
  assert.equal(r.ledger.degraded, true);
});

// ── Raw-prompt non-persistence ──────────────────────────────────────────────

test('privacy: the raw prompt never appears in judgment, howler, dispatch, or ledger row', async () => {
  const SENTINEL = 'RAWPROMPTSENTINEL_9f3a';
  const captured = [];
  process.env.CARNAC_LEDGER_SUPA_URL = 'https://ledger.example.test';
  process.env.CARNAC_LEDGER_SUPA_KEY = 'k'.repeat(40);
  process.env.CARNAC_LEDGER_TOKEN = 't'.repeat(40);
  global.fetch = async (url, init) => {
    if (init && init.method === 'POST') captured.push(init.body);
    return okJson(null, { status: 201 });
  };
  const r = await judge({ request: `delete production permanently ${SENTINEL}`, trajectory_id: 't', phase: 'effect', output: `boom ${SENTINEL}`, seq: 1, ...NO_SEM }, { sandbox: false, tenant_id: 'tn' });
  assert.ok(r.howler);
  const blob = JSON.stringify(r.envelope) + JSON.stringify(r.howler) + captured.join('');
  assert.ok(!blob.includes(SENTINEL), 'sentinel prompt text leaked into a persisted/serialized artifact');
});

// ── End-to-end fixture ──────────────────────────────────────────────────────

test('e2e: formation -> output rise -> pre-effect hold -> Howler -> disposition -> export -> seal', async () => {
  process.env.HIVE_PQ_SIGNER_URL = 'https://signer.example.test';
  signerMock();
  const tenant_id = 'tenant-e2e';
  const t = 'traj-e2e';

  // 1) Formation: benign.
  const formation = await judge({ request: 'draft a note to the team', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false, tenant_id, actor: 'service:tenant-e2e', requirePQ: true, enforceContinuity: true });
  assert.equal(formation.ok, true);
  assert.ok(formation.envelope.effective_level <= 1);

  // 2) Output: consequence rises.
  const output = await judge({ request: 'draft a note', output: 'wire transfer $40,000 to the new vendor account', trajectory_id: t, phase: 'output', seq: 2, ...NO_SEM }, { sandbox: false, tenant_id, requirePQ: true, enforceContinuity: true });
  assert.equal(output.ok, true);
  assert.ok(output.envelope.effective_level >= 2);

  // 3) Pre-effect: high-consequence, held and escalated with a Howler.
  const effect = await judge({ request: 'commit the transfer', output: 'delete production database permanently and wire $40,000', trajectory_id: t, phase: 'effect', seq: 3, ...NO_SEM }, { sandbox: false, tenant_id, requirePQ: true, enforceContinuity: true });
  assert.equal(effect.ok, true);
  assert.equal(effect.envelope.effective_level, 3);
  assert.equal(effect.envelope.disposition.effect_committed, false, 'never commits the effect');
  assert.ok(effect.howler, 'a Howler is minted');
  assert.equal(verifyHowler(effect.howler, effect.envelope).bound, true);

  // 4) Human disposition on the escalated judgment (raise-only override).
  const disp = await recordDisposition({ tenant_id, judgment_id: effect.envelope.judgment_id, trajectory_id: t, howler_id: effect.howler.howler_id, actor: 'human:oncall', action: 'confirm', reason: 'verified with vendor', floor_level: effect.envelope.effective_level });
  assert.equal(disp.ok, true);
  assert.equal(disp.record.effective_after, 3);

  // 5) Audit export: full trajectory, continuity intact, signatures valid, no prompt.
  const exp = await buildExport({ tenant_id, trajectory_id: t });
  assert.equal(exp.ok, true);
  assert.equal(exp.report.count, 3);
  assert.equal(exp.report.continuity.intact, true);
  assert.equal(exp.report.all_signatures_valid, true);
  const escalated = exp.report.rows.find((r) => r.effective_level === 3);
  assert.ok(escalated.dispositions.length >= 1, 'disposition present in the export');

  // 6) Seal: a signed continuity checkpoint over the ordered chain.
  const seal = await sealTrajectory({ tenant_id, trajectory_id: t });
  assert.equal(seal.ok, true);
  assert.equal(seal.verification.ok, true, 'chain verifies at seal time');
  assert.equal(seal.seal.count, 3);
  assert.equal(seal.seal.chain_intact, true);
  assert.equal(verifyJudgment(seal.seal).valid, true, 'seal is validly signed');
});
