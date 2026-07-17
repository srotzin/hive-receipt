/**
 * Sandbox Canon dispatch trace — public-safe and truthful.
 *
 * The sandbox response exposes a `dispatch` array derived from the composed
 * routes. Only the Spectral ed25519 receipt runs for real (succeeded); the
 * durable ledger and Howler are selected but never written; external Canon
 * primitives are pending_external and never claimed to have run. Each entry
 * exposes only target_primitive, status, route, reason, and an optional channel.
 * No raw prompt is leaked. AFiR is absent because the engine never selects
 * fragmented inference.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { judge, _resetEngine } from '../lib/carnac/engine.js';
import { _resetControls } from '../lib/carnac/idempotency.js';
import { _resetLedger } from '../lib/carnac/ledger.js';
import { _resetPolicy } from '../lib/carnac/policy.js';
import { sandboxDispatchTrace } from '../lib/carnac/dispatch.js';
import { initKeypair } from '../lib/spectral.js';

initKeypair();

const NO_SEM = { useSemantic: false };
const ALLOWED_STATUS = new Set([
  'selected', 'invoked', 'succeeded', 'failed', 'unavailable', 'pending_external',
]);
const ALLOWED_KEYS = new Set(['target_primitive', 'status', 'route', 'reason', 'channel']);

beforeEach(() => {
  _resetEngine();
  _resetControls();
  _resetLedger();
  _resetPolicy();
});

test('financial Level 2 hold prompt yields an honest sandbox dispatch trace', async () => {
  const r = await judge({ request: 'wire $5,000 to a new vendor account', ...NO_SEM }, { sandbox: true });
  assert.equal(r.ok, true);
  assert.equal(r.envelope.effective_level, 2);
  assert.equal(r.envelope.primary_route, 'hold');

  const trace = sandboxDispatchTrace(r.envelope);
  // Level 2 composes receipt, enrich, verify, hold.
  assert.deepEqual(trace.map((e) => e.route), ['receipt', 'enrich', 'verify', 'hold']);

  const byRoute = Object.fromEntries(trace.map((e) => [e.route, e]));

  // The receipt genuinely ran (ed25519 signature over the judgment).
  assert.equal(byRoute.receipt.status, 'succeeded');
  assert.equal(byRoute.receipt.target_primitive, 'spectral_receipt');
  assert.equal(byRoute.receipt.channel, 'receipt');

  // External Canon primitives are pending_external; never claimed invoked.
  assert.equal(byRoute.enrich.status, 'pending_external');
  assert.equal(byRoute.enrich.target_primitive, 'canon_provenance');
  assert.equal(byRoute.verify.status, 'pending_external');
  assert.equal(byRoute.verify.target_primitive, 'canon_verification');
  assert.equal(byRoute.hold.status, 'pending_external');
  assert.equal(byRoute.hold.target_primitive, 'canon_imprimatur');

  // No entry may falsely claim external invocation.
  for (const e of trace) {
    if (e.status === 'invoked' || e.status === 'succeeded') {
      assert.equal(e.target_primitive, 'spectral_receipt',
        `only the in-repo receipt may report as run, not ${e.target_primitive}`);
    }
  }
});

test('every dispatch entry uses only the allowed shape and truthful statuses', async () => {
  const r = await judge({ request: 'wire $5,000 to a new vendor account', ...NO_SEM }, { sandbox: true });
  const trace = sandboxDispatchTrace(r.envelope);
  assert.ok(trace.length > 0);
  for (const e of trace) {
    for (const k of Object.keys(e)) {
      assert.ok(ALLOWED_KEYS.has(k), `unexpected field "${k}" in dispatch entry`);
    }
    assert.equal(typeof e.target_primitive, 'string');
    assert.equal(typeof e.route, 'string');
    assert.equal(typeof e.reason, 'string');
    assert.ok(ALLOWED_STATUS.has(e.status), `status "${e.status}" is not in the allowed set`);
  }
});

test('a non-fragmented prompt proves AFiR is absent from the dispatch trace', async () => {
  const r = await judge({ request: 'send a status email to the team', ...NO_SEM }, { sandbox: true });
  const trace = sandboxDispatchTrace(r.envelope);
  for (const e of trace) {
    assert.ok(!/afir/i.test(e.target_primitive), `AFiR must not appear: ${e.target_primitive}`);
    assert.ok(!/afir/i.test(e.route), `AFiR must not appear in route: ${e.route}`);
  }
});

test('the dispatch trace exposes no raw prompt text', async () => {
  const secret = 'topsecret-wire-passphrase-xyzzy';
  const r = await judge({ request: `wire $5,000 ${secret}`, ...NO_SEM }, { sandbox: true });
  const trace = sandboxDispatchTrace(r.envelope);
  const blob = JSON.stringify(trace);
  assert.ok(!blob.includes(secret), 'dispatch trace must not contain raw prompt text');
});

test('a Level 0 prompt selects only the ledger entry, not run in the sandbox', async () => {
  const r = await judge({ request: 'what time is it', ...NO_SEM }, { sandbox: true });
  assert.equal(r.envelope.effective_level, 0);
  const trace = sandboxDispatchTrace(r.envelope);
  assert.deepEqual(trace.map((e) => e.route), ['let_it_run']);
  assert.equal(trace[0].status, 'selected');
  assert.equal(trace[0].target_primitive, 'ledger_entry');
  assert.equal(trace[0].channel, 'ledger');
});

test('a Level 3 prompt selects the Howler but never mints it in the sandbox', async () => {
  const r = await judge({ request: 'delete production permanently', ...NO_SEM }, { sandbox: true });
  assert.equal(r.envelope.effective_level, 3);
  assert.equal(r.howler, null);
  const trace = sandboxDispatchTrace(r.envelope);
  const howler = trace.find((e) => e.route === 'howler');
  assert.ok(howler, 'level 3 includes a howler route');
  assert.equal(howler.status, 'selected');
  assert.equal(howler.target_primitive, 'howler');
  assert.equal(howler.channel, 'escalation');
});
