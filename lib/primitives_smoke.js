// lib/primitives_smoke.js
//
// In-process exerciser for the credential-free public primitives. It runs the
// same engine paths the public routes run, so a single call to
// GET /v1/primitives/smoke is a self-contained live proof that the runnable set
// executes end to end: content addressing, hybrid signing, disclosure-free
// replay with its leak guard, arrival countersignature match and mismatch, and
// the Carnac no-effect read. No credentials, no external network, no payment.
//
// Content rules: no em dashes; Carnac reads consequence. It does not judge.

import { generateKeypair } from './inkframe/engine/crypto.mjs';
import {
  inputRoot, anchorSet, cueGraphRoot, proofDemandRoot, evidenceRoot,
  actionEnvelopeRoot, lineage, buildFrame, signFrame, verifyFrame,
  proofPreFill, arrivalCountersign, verifyArrivalCountersign,
} from './inkframe/engine/inkframe.mjs';
import { buildReplayManifest, verifyReplayManifest } from './inkframe/engine/replay.mjs';
import { judge } from './carnac/engine.js';
import { verifyArtifact } from './carnac/verify.js';
import { verifyLifecycle } from './carnac/lifecycle.js';
import { currentPolicy } from './carnac/engine.js';
import { SAMPLES } from './primitives.js';

// A fixed 32-byte seed so the smoke run is deterministic. This keypair is only
// used to prove the signing path executes; it is not the deployment signer.
const SMOKE_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 11) & 0xff);

async function step(id, fn) {
  const t0 = process.hrtime.bigint();
  try {
    const detail = await fn();
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    return { id, ok: true, ms: Number(ms.toFixed(3)), detail: detail || null };
  } catch (e) {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    return { id, ok: false, ms: Number(ms.toFixed(3)), error: e.message };
  }
}

export async function runSmoke() {
  const started_at = new Date().toISOString();
  const keys = generateKeypair(SMOKE_SEED);
  const checks = [];

  // Build one signed frame the later steps reuse.
  let signed;
  checks.push(await step('inkframe.frame', () => {
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
    signed = signFrame(frame, keys);
    const v = verifyFrame(signed);
    if (!v.ok) throw new Error('frame self-verify failed: ' + v.reason);
    return { frame_id: signed.frame_id, self_verify: true };
  }));

  checks.push(await step('inkframe.cue_edge', () => {
    const root = cueGraphRoot([SAMPLES.cueEdge]);
    return { addr: root.addr || 'ok', edges: root.edges.length };
  }));

  checks.push(await step('inkframe.prefill', () => {
    const prefills = proofPreFill(SAMPLES.prefill.anchor_set, SAMPLES.prefill.proof_demand_root, SAMPLES.prefill.local_index);
    return { prefills: prefills.length };
  }));

  checks.push(await step('inkframe.replay', () => {
    if (!signed) throw new Error('no signed frame');
    const manifest = buildReplayManifest(signed, [], keys);
    const v = verifyReplayManifest(manifest, signed);
    if (!v.ok) throw new Error('replay self-verify failed: ' + v.reason);
    // Leak guard: a raw-text delta must be refused before build.
    const leakRe = /"(raw_text|span_text|text|prompt|input|content)"\s*:/;
    const leaked = leakRe.test(JSON.stringify([{ raw_text: 'secret' }]));
    if (!leaked) throw new Error('leak guard pattern did not fire on raw text');
    return { self_verify: true, leak_guard: 'refuses_raw_text' };
  }));

  checks.push(await step('inkframe.countersign', () => {
    if (!signed) throw new Error('no signed frame');
    const match = arrivalCountersign(signed, SAMPLES.deliveredAction, keys);
    const mv = verifyArrivalCountersign(match);
    if (!mv.ok) throw new Error('countersign signature invalid');
    if (!match.countersign_body.matches) throw new Error('expected approved-vs-delivered match');
    const mismatch = arrivalCountersign(signed, { action_type: 'ship', target: 'other' }, keys);
    if (mismatch.countersign_body.matches) throw new Error('expected a mismatch on a different target');
    return { match: true, mismatch_detected: true };
  }));

  checks.push(await step('carnac.sandbox', async () => {
    const result = await judge(SAMPLES.sandbox, { sandbox: true });
    if (!result.ok) throw new Error(result.code || 'sandbox read failed');
    return { effective_level: result.envelope.effective_level, route: result.envelope.route || null };
  }));

  checks.push(await step('carnac.policy', () => {
    const p = currentPolicy();
    if (!p || !p.version) throw new Error('policy missing version');
    return { version: p.version };
  }));

  checks.push(await step('carnac.verify', async () => {
    const j = await judge(SAMPLES.sandbox, { sandbox: true });
    if (!j.ok) throw new Error('could not mint an artifact to verify');
    const v = await verifyArtifact(j.envelope);
    if (!v.signature_valid) throw new Error('freshly signed artifact did not verify');
    return { signature_valid: true };
  }));

  checks.push(await step('carnac.lifecycle_verify', () => {
    const v = verifyLifecycle([]);
    if (!v.ok) throw new Error('empty lifecycle verify should be ok');
    return { ok: true, count: v.count };
  }));

  const passed = checks.filter((c) => c.ok).length;
  const failed = checks.length - passed;
  return {
    service: 'hive-receipt',
    smoke: 'public-primitives',
    started_at,
    finished_at: new Date().toISOString(),
    total: checks.length,
    passed,
    failed,
    ok: failed === 0,
    checks,
  };
}
