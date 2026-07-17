/**
 * Carnac judgment plane — integration tests.
 *
 * These exercise the composed engine end to end without any network: the
 * deterministic floor, routing, disposition, ed25519 signing/verification,
 * idempotency/replay/order controls, the governed policy floor and its
 * multi-party amendment, the Howler threshold, and the no-effect sandbox. The
 * semantic reader is disabled (useSemantic:false) so the tests are deterministic
 * and offline, matching the posture of the rest of this repo's suite.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

import { classifyDeterministic } from '../lib/carnac/rules.js';
import { classify } from '../lib/carnac/classify.js';
import { composeRoute, RESPONSES } from '../lib/carnac/routes.js';
import { judge, verifyJudgment, _resetEngine } from '../lib/carnac/engine.js';
import { _resetControls } from '../lib/carnac/idempotency.js';
import { _resetLedger, listByTrajectory } from '../lib/carnac/ledger.js';
import { _resetPolicy, currentPolicy, applyFloor, amendPolicy, amendmentDigest } from '../lib/carnac/policy.js';
import { validateComputeResponse } from '../lib/carnac/compute.js';
import { buildHowler, HOWLER_THRESHOLD } from '../lib/carnac/howler.js';
import { initKeypair } from '../lib/spectral.js';
import { CASES } from './fixtures/carnac_cases.js';

const NO_SEM = { useSemantic: false };

initKeypair();

beforeEach(() => {
  _resetEngine();
  _resetControls();
  _resetLedger();
  _resetPolicy();
  delete process.env.CARNAC_POLICY_ATTESTORS;
});

// ── Deterministic classification ──────────────────────────────────────────────

for (const c of CASES) {
  test(`classify: ${c.name} reaches level ${c.level}`, () => {
    const r = classifyDeterministic(c.text);
    assert.equal(r.level, c.level, `${c.name}: expected ${c.level}, got ${r.level}`);
    const ids = r.categories.map((x) => x.id);
    for (const e of c.expect) assert.ok(ids.includes(e), `${c.name}: missing category ${e} (got ${ids.join(',')})`);
    if (c.big_amount) assert.equal(r.big_amount, true, `${c.name}: big_amount not set`);
    if (c.lang === 'es') assert.ok(r.languages.includes('es'), `${c.name}: es not detected`);
  });
}

test('blank input is level 0 and marked blank', () => {
  const r = classifyDeterministic('   ');
  assert.equal(r.blank, true);
  assert.equal(r.level, 0);
  assert.equal(r.categories.length, 0);
});

test('feature_digest is stable and content-free (same features -> same digest)', () => {
  const a = classifyDeterministic('wire transfer $500 to vendor');
  const b = classifyDeterministic('please wire transfer $500 to vendor now');
  // Different length bucket may diverge; identical short texts must match.
  const c = classifyDeterministic('wire transfer $500 to vendor');
  assert.equal(a.feature_digest, c.feature_digest);
  assert.equal(typeof a.feature_digest, 'string');
  assert.equal(a.feature_digest.length, 64);
  assert.ok(!a.feature_digest.includes('vendor'));
  // Sanity: b is still a valid digest.
  assert.equal(b.feature_digest.length, 64);
});

test('composed classify degrades to deterministic when semantic disabled', async () => {
  const r = await classify('delete the production database', NO_SEM);
  assert.equal(r.engine, 'deterministic');
  assert.equal(r.semantic_used, false);
  assert.equal(r.level, 3);
});

// ── Routing & disposition ─────────────────────────────────────────────────────

test('all seven responses are reachable across levels', () => {
  const seen = new Set();
  for (const level of [0, 1, 2, 3]) {
    for (const r of composeRoute(level, 'formation').responses) seen.add(r.id);
  }
  for (const id of Object.keys(RESPONSES)) {
    assert.ok(seen.has(id), `response ${id} never reachable`);
  }
});

test('level maps to primary route and disposition', () => {
  assert.equal(composeRoute(0, 'formation').primary_route, 'let_it_run');
  assert.equal(composeRoute(0, 'formation').disposition.state, 'allow');
  assert.equal(composeRoute(1, 'formation').disposition.state, 'allow_with_receipt');
  assert.equal(composeRoute(2, 'formation').disposition.state, 'hold_for_confirmation');
  assert.equal(composeRoute(3, 'formation').primary_route, 'howler');
  assert.equal(composeRoute(3, 'formation').disposition.state, 'hold_and_escalate');
});

test('disposition never commits an effect; pre-effect phases flag prevention', () => {
  assert.equal(composeRoute(3, 'effect').disposition.effect_committed, false);
  assert.equal(composeRoute(3, 'effect').disposition.prevention, true);
  assert.equal(composeRoute(2, 'formation').disposition.prevention, false);
});

// ── Signing & verification ────────────────────────────────────────────────────

test('judge produces a valid ed25519-signed envelope', async () => {
  const r = await judge({ request: 'wire transfer $9000 to vendor', ...NO_SEM }, { sandbox: true });
  assert.equal(r.ok, true);
  assert.equal(verifyJudgment(r.envelope).valid, true);
});

test('tampering with a signed judgment fails verification', async () => {
  const r = await judge({ request: 'send an email to the list', ...NO_SEM }, { sandbox: true });
  const tampered = { ...r.envelope, effective_level: 3 };
  assert.equal(verifyJudgment(tampered).valid, false);
});

// ── Howler ────────────────────────────────────────────────────────────────────

test('Howler minted at threshold on a real judgment, null below', async () => {
  const high = await judge({ request: 'delete production permanently', ...NO_SEM }, { sandbox: false });
  assert.ok(high.howler, 'expected a howler at level 3');
  assert.equal(high.howler.severity, HOWLER_THRESHOLD);
  assert.equal(verifyJudgment(high.howler).valid, true);

  const low = await judge({ request: 'what time is it', ...NO_SEM }, { sandbox: false });
  assert.equal(low.howler, null);
});

test('sandbox never mints a Howler even at level 3', async () => {
  const r = await judge({ request: 'delete production permanently', ...NO_SEM }, { sandbox: true });
  assert.equal(r.envelope.effective_level, 3);
  assert.equal(r.howler, null);
  assert.equal(r.ledger.durable, false);
});

test('buildHowler uses honest instrumented-path language, no "the system knew"', () => {
  const h = buildHowler({ effective_level: 3, judgment_id: 'x', categories: [{ id: 'health', label: 'Health or safety', sev: 3 }] });
  assert.ok(/instrumented path/i.test(h.reason));
  assert.ok(!/knew|understood|intended/i.test(h.reason));
});

// ── Idempotency / replay / order ──────────────────────────────────────────────

test('idempotency: same key returns the same judgment id', async () => {
  const a = await judge({ request: 'wire $500', idempotency_key: 'k1', ...NO_SEM }, { sandbox: false });
  const b = await judge({ request: 'totally different text', idempotency_key: 'k1', ...NO_SEM }, { sandbox: false });
  assert.equal(b.idempotent_replay, true);
  assert.equal(b.envelope.judgment_id, a.envelope.judgment_id);
});

test('replay: a nonce is single-use', async () => {
  const a = await judge({ request: 'wire $500', nonce: 'once', ...NO_SEM }, { sandbox: false });
  assert.equal(a.ok, true);
  const b = await judge({ request: 'wire $500', nonce: 'once', ...NO_SEM }, { sandbox: false });
  assert.equal(b.ok, false);
  assert.equal(b.code, 'replay_detected');
  assert.equal(b.status, 409);
});

test('order: reads within a trajectory must not regress', async () => {
  const t = 'traj-1';
  assert.equal((await judge({ request: 'a', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM })).ok, true);
  assert.equal((await judge({ request: 'b', output: 'o', trajectory_id: t, phase: 'output', seq: 2, ...NO_SEM })).ok, true);
  const regress = await judge({ request: 'c', trajectory_id: t, phase: 'formation', seq: 3, ...NO_SEM });
  assert.equal(regress.ok, false);
  assert.equal(regress.code, 'out_of_order');
});

test('order: seq must strictly increase within a trajectory', async () => {
  const t = 'traj-2';
  await judge({ request: 'a', trajectory_id: t, phase: 'invocation', seq: 5, ...NO_SEM });
  const stale = await judge({ request: 'b', trajectory_id: t, phase: 'output', output: 'o', seq: 5, ...NO_SEM });
  assert.equal(stale.ok, false);
  assert.equal(stale.code, 'out_of_order');
});

test('output phase requires an output field', async () => {
  const r = await judge({ request: 'x', phase: 'output', ...NO_SEM });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'missing_output');
});

test('invalid phase is rejected', async () => {
  const r = await judge({ request: 'x', phase: 'nonsense', ...NO_SEM });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'invalid_phase');
});

test('oversized input is rejected', async () => {
  const r = await judge({ request: 'x'.repeat(9000), ...NO_SEM });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'input_too_large');
});

// ── Ledger ────────────────────────────────────────────────────────────────────

test('ledger records every judgment; trajectory index resolves', async () => {
  const t = 'traj-led';
  await judge({ request: 'a', trajectory_id: t, phase: 'formation', seq: 1, ...NO_SEM }, { sandbox: false });
  await judge({ request: 'b', trajectory_id: t, phase: 'invocation', seq: 2, ...NO_SEM }, { sandbox: false });
  const list = listByTrajectory(t);
  assert.equal(list.length, 2);
  for (const e of list) assert.equal(verifyJudgment(e).valid, true);
});

test('below-threshold judgments are still ledgered (absence of Howler is provable)', async () => {
  const t = 'traj-below';
  const r = await judge({ request: 'what time is it', trajectory_id: t, phase: 'formation', ...NO_SEM }, { sandbox: false });
  assert.equal(r.howler, null);
  assert.equal(listByTrajectory(t).length, 1);
});

// ── Governed policy floor ─────────────────────────────────────────────────────

test('runtime override may raise but never lower below the floor', () => {
  const classification = { level: 1, categories: [{ id: 'financial', sev: 2 }] };
  // Floor for financial is 2; requesting 1 must be clamped.
  const clamp = applyFloor(classification, { financial: 1 });
  assert.equal(clamp.effective_level, 2);
  assert.equal(clamp.runtime_clamp_attempted, true);
  assert.equal(clamp.raised_by_runtime, false);
  // Requesting 3 must raise.
  const raise = applyFloor(classification, { financial: 3 });
  assert.equal(raise.effective_level, 3);
  assert.equal(raise.raised_by_runtime, true);
});

test('category floor forces a minimum level regardless of engine level', () => {
  // health floor is 3 even if a caller-supplied classification says level 1.
  const r = applyFloor({ level: 1, categories: [{ id: 'health', sev: 1 }] }, {});
  assert.equal(r.effective_level, 3);
});

function makeAttestor() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64');
  return { pubB64, privateKey };
}

function signAmendment(amendment, attestor) {
  const digest = amendmentDigest(amendment);
  const signature = crypto.sign(null, Buffer.from(digest, 'hex'), attestor.privateKey).toString('base64');
  return { public_key: attestor.pubB64, signature };
}

test('amendment: raising the floor requires one attestor signature', () => {
  const a = makeAttestor();
  process.env.CARNAC_POLICY_ATTESTORS = a.pubB64;
  const amendment = { direction: 'raise', new_version: 'floor-raise-1', category_floor: { outbound: 2 } };
  const res = amendPolicy(amendment, [signAmendment(amendment, a)]);
  assert.equal(res.ok, true);
  assert.equal(res.direction, 'raise');
  assert.equal(currentPolicy().category_floor.outbound, 2);
});

test('amendment: lowering the floor requires a quorum of distinct attestors', () => {
  const a = makeAttestor();
  const b = makeAttestor();
  process.env.CARNAC_POLICY_ATTESTORS = `${a.pubB64},${b.pubB64}`;
  const amendment = { direction: 'lower', new_version: 'floor-lower-1', category_floor: { health: 1 } };

  // One signature is insufficient for a lowering.
  const one = amendPolicy(amendment, [signAmendment(amendment, a)]);
  assert.equal(one.ok, false);
  assert.equal(one.status, 403);
  assert.equal(currentPolicy().category_floor.health, 3);

  // Two distinct valid signatures pass.
  const two = amendPolicy(amendment, [signAmendment(amendment, a), signAmendment(amendment, b)]);
  assert.equal(two.ok, true);
  assert.equal(currentPolicy().category_floor.health, 1);
});

test('amendment: duplicate signature from one attestor does not satisfy quorum', () => {
  const a = makeAttestor();
  const b = makeAttestor();
  process.env.CARNAC_POLICY_ATTESTORS = `${a.pubB64},${b.pubB64}`;
  const amendment = { direction: 'lower', new_version: 'floor-lower-dup', category_floor: { health: 2 } };
  const sig = signAmendment(amendment, a);
  const res = amendPolicy(amendment, [sig, sig]);
  assert.equal(res.ok, false);
  assert.equal(res.status, 403);
});

test('amendment: with no attestors configured, lowering is impossible', () => {
  const amendment = { direction: 'lower', new_version: 'floor-nope', category_floor: { health: 1 } };
  const res = amendPolicy(amendment, []);
  assert.equal(res.ok, false);
  assert.equal(res.status, 403);
});

// ── Compute response validation ───────────────────────────────────────────────

test('validateComputeResponse accepts a well-formed classification', () => {
  const v = validateComputeResponse({ level: 3, categories: [{ id: 'health', sev: 3 }] });
  assert.equal(v.ok, true);
  assert.equal(v.classification.level, 3);
});

test('validateComputeResponse rejects malformed shapes', () => {
  assert.equal(validateComputeResponse(null).ok, false);
  assert.equal(validateComputeResponse({ level: 9, categories: [] }).ok, false);
  assert.equal(validateComputeResponse({ level: 2, categories: 'x' }).ok, false);
  assert.equal(validateComputeResponse({ level: 2, categories: [{ id: 'bogus', sev: 2 }] }).ok, false);
});

test('validateComputeResponse clamps level up to the strongest category severity', () => {
  const v = validateComputeResponse({ level: 1, categories: [{ id: 'health', sev: 3 }] });
  assert.equal(v.ok, true);
  assert.equal(v.classification.level, 3);
});
