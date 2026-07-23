/**
 * Primitive catalog, InkFrame engine, and public smoke tests.
 *
 * These run offline with no network and no server. They assert that the catalog
 * is truthful (its runnable entries actually execute), that the InkFrame v1
 * substrate signs and verifies end to end, that disclosure-free replay refuses
 * raw text, that the arrival countersignature detects a delivered mismatch, and
 * that the in-process smoke runner passes every credential-free primitive.
 *
 * Content rules honored here: no em dashes; Carnac reads consequence. It does
 * not judge.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PRIMITIVES, catalog, SAMPLES } from '../lib/primitives.js';
import { runSmoke } from '../lib/primitives_smoke.js';
import { generateKeypair } from '../lib/inkframe/engine/crypto.mjs';
import {
  inputRoot, anchorSet, cueGraphRoot, proofDemandRoot, evidenceRoot,
  actionEnvelopeRoot, lineage, buildFrame, signFrame, verifyFrame,
  arrivalCountersign, verifyArrivalCountersign,
} from '../lib/inkframe/engine/inkframe.mjs';
import { buildReplayManifest, verifyReplayManifest } from '../lib/inkframe/engine/replay.mjs';
import { initKeypair } from '../lib/spectral.js';

initKeypair();

const SEED = new Uint8Array(32).map((_, i) => (i + 1) & 0xff);

function sampleFrame(keys) {
  const s = SAMPLES.frame;
  const frame = buildFrame({
    input_root: inputRoot(s.input_text),
    anchor_set: anchorSet(s.input_text, s.anchors),
    cue_graph_root: cueGraphRoot(s.edges),
    proof_demand_root: proofDemandRoot(s.demands),
    evidence_root: evidenceRoot(s.bindings),
    action_envelope_root: actionEnvelopeRoot(s.action),
    lineage: lineage({}),
  });
  return signFrame(frame, keys);
}

// ── Catalog shape and truthfulness ────────────────────────────────────────────

test('catalog exposes a stable, well-formed shape', () => {
  const c = catalog('https://example.test');
  assert.equal(c.service, 'hive-receipt');
  assert.ok(c.primitives.length >= 15);
  assert.equal(c.smoke_endpoint, '/v1/primitives/smoke');
  for (const p of c.primitives) {
    assert.ok(p.id && p.family && p.label && p.method && p.endpoint, `entry ${p.id} complete`);
    assert.ok(['runnable', 'gated', 'protected', 'catalog'].includes(p.status), `valid status ${p.id}`);
    if (p.status === 'runnable') {
      assert.equal(p.auth, 'none', `runnable ${p.id} needs no auth`);
      assert.ok(p.sample_curl && p.sample_curl.includes('https://example.test'), `runnable ${p.id} has curl`);
    }
  }
});

test('counts add up to the primitive total', () => {
  const c = catalog();
  const summed = Object.values(c.counts).reduce((a, b) => a + b, 0);
  assert.equal(summed, c.primitives.length);
});

test('no user-facing string uses an em dash or a forbidden ruling word', () => {
  // The only permitted use of the ruling verb is the exact phrase below.
  const ALLOWED = 'It does not judge.';
  const forbidden = /judg|verdict/i;
  const strings = [];
  for (const p of PRIMITIVES) strings.push(p.label, p.description, p.family);
  for (const s of strings) {
    assert.ok(!s.includes('—'), `no em dash in: ${s}`);
    const stripped = s.split(ALLOWED).join('');
    assert.ok(!forbidden.test(stripped), `no forbidden ruling word in: ${s}`);
  }
});

test('runnable statuses match reality: the catalog does not overclaim', async () => {
  // Every id the smoke runner exercises must be marked runnable in the catalog.
  const report = await runSmoke();
  const runnableIds = new Set(PRIMITIVES.filter((p) => p.status === 'runnable').map((p) => p.id));
  for (const check of report.checks) {
    assert.ok(runnableIds.has(check.id), `${check.id} exercised but not marked runnable`);
  }
});

// ── InkFrame v1 substrate ─────────────────────────────────────────────────────

test('InkFrame frame signs and self-verifies', () => {
  const keys = generateKeypair(SEED);
  const signed = sampleFrame(keys);
  const v = verifyFrame(signed);
  assert.ok(v.ok, v.reason);
  assert.equal(v.frame_id, signed.frame_id);
});

test('InkFrame non-mutation: a one-byte change breaks the frame', () => {
  const keys = generateKeypair(SEED);
  const signed = sampleFrame(keys);
  signed.frame_body.action_envelope_root.target = 'tampered';
  const v = verifyFrame(signed);
  assert.equal(v.ok, false);
});

test('cue graph rejects an invalid relation', () => {
  assert.throws(() => cueGraphRoot([{ src: 'a', tgt: 'b', rel: 'nonsense' }]));
});

test('disclosure-free replay verifies and reconstruction stays fingerprint-only', () => {
  const keys = generateKeypair(SEED);
  const signed = sampleFrame(keys);
  const manifest = buildReplayManifest(signed, [], keys);
  const v = verifyReplayManifest(manifest, signed);
  assert.ok(v.ok, v.reason);
  // The manifest carries no raw-text fields.
  const flat = JSON.stringify(manifest);
  assert.ok(!/"(raw_text|span_text|prompt)"\s*:/.test(flat), 'manifest is disclosure-free');
});

test('arrival countersignature matches on an approved delivery and refuses a mismatch', () => {
  const keys = generateKeypair(SEED);
  const signed = sampleFrame(keys);
  const match = arrivalCountersign(signed, SAMPLES.deliveredAction, keys);
  assert.ok(verifyArrivalCountersign(match).ok);
  assert.equal(match.countersign_body.matches, true);

  const mismatch = arrivalCountersign(signed, { action_type: 'ship', target: 'elsewhere' }, keys);
  assert.ok(verifyArrivalCountersign(mismatch).ok, 'refusal is still a valid signature');
  assert.equal(mismatch.countersign_body.matches, false);
});

// ── Public smoke ──────────────────────────────────────────────────────────────

test('public smoke passes every credential-free primitive', async () => {
  const report = await runSmoke();
  assert.equal(report.ok, true, JSON.stringify(report.checks.filter((c) => !c.ok)));
  assert.equal(report.failed, 0);
  assert.ok(report.passed >= 9);
  for (const c of report.checks) assert.ok(c.ok, `${c.id}: ${c.error || ''}`);
});
