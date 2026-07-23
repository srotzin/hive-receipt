// lib/inkframe/routes.js
//
// InkFrame v1 endpoints for hive-receipt.
//
//   POST /v1/inkframe/frame        build + sign a full frame from a body
//   POST /v1/inkframe/prefill      resolve demands against a local index (fingerprint-only)
//   POST /v1/inkframe/cue-edge     validate a single typed edge {src, tgt, rel}
//   POST /v1/inkframe/replay       build + verify a replay manifest
//   POST /v1/inkframe/countersign  arrival countersignature (approved vs delivered)
//
//   GET  /v1/inkframe/health       liveness + version + fingerprints
//
// The engine is content-addressed and signature-verified end to end.
// Ed25519 + ML-DSA-65 hybrid. RFC 8785 JCS + SHA-256.
//
// Keys: the process signer uses a deterministic keypair derived from
// INKFRAME_SEED_B64 in the environment. If unset, a fresh keypair is
// generated at boot and its public keys are logged.

import { Router } from 'express';
import {
  generateKeypair, hybridVerify
} from './engine/crypto.mjs';
import {
  INKFRAME_VERSION,
  inputRoot, anchorSet, cueGraphRoot, proofDemandRoot, evidenceRoot,
  actionEnvelopeRoot, lineage, buildFrame, signFrame, verifyFrame,
  proofPreFill, arrivalCountersign, verifyArrivalCountersign
} from './engine/inkframe.mjs';
import {
  buildReplayManifest, verifyReplayManifest, reconstructStory
} from './engine/replay.mjs';

// ---------- key material ----------

let _keys = null;
let _gatewayKeys = null;
let _bootedAt = null;

function loadKeys() {
  const seedB64 = process.env.INKFRAME_SEED_B64;
  const gwSeedB64 = process.env.INKFRAME_GATEWAY_SEED_B64;
  let seed, gwSeed;
  if (seedB64) {
    seed = new Uint8Array(Buffer.from(seedB64, 'base64'));
    if (seed.length !== 32) throw new Error('INKFRAME_SEED_B64 must decode to 32 bytes');
  } else {
    seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
  }
  if (gwSeedB64) {
    gwSeed = new Uint8Array(Buffer.from(gwSeedB64, 'base64'));
    if (gwSeed.length !== 32) throw new Error('INKFRAME_GATEWAY_SEED_B64 must decode to 32 bytes');
  } else {
    gwSeed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(gwSeed);
  }
  _keys = generateKeypair(seed);
  _gatewayKeys = generateKeypair(gwSeed);
  _bootedAt = new Date().toISOString();
  if (!seedB64) {
    console.log('[inkframe] fresh signer keypair (ephemeral)');
    console.log('  ed25519_public:', _keys.ed25519.publicKey.slice(0, 32) + '...');
    console.log('  mldsa_public:',   _keys.mldsa65.publicKey.slice(0, 32) + '...');
  } else {
    console.log('[inkframe] signer keypair loaded from env');
  }
  return { _keys, _gatewayKeys };
}

// ---------- helpers ----------

function bad(res, status, code, msg, extra = {}) {
  return res.status(status).json({ ok: false, error: code, message: msg, ...extra });
}

// ---------- router ----------

export function makeInkframeRouter() {
  loadKeys();
  const r = Router();

  // health
  r.get('/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'inkframe',
      version: INKFRAME_VERSION,
      booted_at: _bootedAt,
      standards: {
        canon: 'rfc8785+sha256',
        signature: 'ed25519+ml-dsa-65',
        mldsa: 'nist-fips-204'
      },
      public_keys: {
        signer_ed25519: _keys.ed25519.publicKey,
        signer_mldsa65: _keys.mldsa65.publicKey,
        gateway_ed25519: _gatewayKeys.ed25519.publicKey,
        gateway_mldsa65: _gatewayKeys.mldsa65.publicKey
      }
    });
  });

  // POST /frame
  // Build a full signed frame from a body containing:
  //   input_text, anchors, edges, demands, bindings, action, lineage?
  r.post('/frame', (req, res) => {
    try {
      const b = req.body || {};
      if (typeof b.input_text !== 'string') return bad(res, 400, 'bad_request', 'input_text is required');
      if (!Array.isArray(b.anchors)) return bad(res, 400, 'bad_request', 'anchors must be an array');
      if (!Array.isArray(b.edges))   return bad(res, 400, 'bad_request', 'edges must be an array');
      if (!Array.isArray(b.demands)) return bad(res, 400, 'bad_request', 'demands must be an array');
      if (!Array.isArray(b.bindings))return bad(res, 400, 'bad_request', 'bindings must be an array');
      if (!b.action || typeof b.action !== 'object') return bad(res, 400, 'bad_request', 'action is required');

      const frame = buildFrame({
        input_root:           inputRoot(b.input_text),
        anchor_set:           anchorSet(b.input_text, b.anchors),
        cue_graph_root:       cueGraphRoot(b.edges),
        proof_demand_root:    proofDemandRoot(b.demands),
        evidence_root:        evidenceRoot(b.bindings),
        action_envelope_root: actionEnvelopeRoot(b.action),
        lineage:              lineage(b.lineage || {})
      });
      const signed = signFrame(frame, _keys);
      const v = verifyFrame(signed);
      if (!v.ok) return bad(res, 500, 'internal', 'signed frame failed self-verify: ' + v.reason);
      res.json({ ok: true, signed_frame: signed, self_verify: v });
    } catch (e) {
      return bad(res, 400, 'build_failed', e.message);
    }
  });

  // POST /prefill
  // Given anchor_set + proof_demand_root + a local index, resolve demands
  // by fingerprint only and return pre-fills ready to bind BEFORE the action fires.
  r.post('/prefill', (req, res) => {
    try {
      const b = req.body || {};
      if (!b.anchor_set || !b.proof_demand_root) {
        return bad(res, 400, 'bad_request', 'anchor_set and proof_demand_root are required');
      }
      const localIndex = b.local_index || {};
      const prefills = proofPreFill(b.anchor_set, b.proof_demand_root, localIndex);
      res.json({ ok: true, prefills, resolved_at: new Date().toISOString() });
    } catch (e) {
      return bad(res, 400, 'prefill_failed', e.message);
    }
  });

  // POST /cue-edge
  // Validate one typed edge {src, tgt, rel}. Relations must be one of
  // supports/contradicts/supersedes/enables. No scoring.
  r.post('/cue-edge', (req, res) => {
    try {
      const b = req.body || {};
      if (!b.src || !b.tgt || !b.rel) return bad(res, 400, 'bad_request', 'src, tgt, rel all required');
      // cueGraphRoot enforces relation validation
      const root = cueGraphRoot([{ src: b.src, tgt: b.tgt, rel: b.rel }]);
      res.json({ ok: true, edge: { src: b.src, tgt: b.tgt, rel: b.rel }, addr: root.addr });
    } catch (e) {
      return bad(res, 400, 'invalid_edge', e.message);
    }
  });

  // POST /replay
  // Build + verify a replay manifest from a signed frame + cue deltas.
  // Deltas MUST NOT carry raw text. Leaks fail closed.
  r.post('/replay', (req, res) => {
    try {
      const b = req.body || {};
      if (!b.signed_frame || !Array.isArray(b.deltas)) {
        return bad(res, 400, 'bad_request', 'signed_frame and deltas are required');
      }
      // Guard against raw-text leaks BEFORE building.
      const flat = JSON.stringify(b.deltas);
      const leakRe = /"(raw_text|span_text|text|prompt|input|content)"\s*:/;
      if (leakRe.test(flat)) {
        return bad(res, 400, 'leak', 'deltas contain a raw-text field (disclosure-free replay refuses)');
      }
      const manifest = buildReplayManifest(b.signed_frame, b.deltas, _keys);
      const v = verifyReplayManifest(manifest, b.signed_frame);
      if (!v.ok) return bad(res, 500, 'internal', 'replay self-verify failed: ' + v.reason);
      const story = b.reconstruct === true ? reconstructStory(manifest, b.signed_frame) : undefined;
      res.json({ ok: true, manifest, self_verify: v, story });
    } catch (e) {
      return bad(res, 400, 'replay_failed', e.message);
    }
  });

  // POST /countersign
  // Given a signed frame + a delivered action tuple, gateway countersigns
  // if approved-vs-delivered match. Otherwise signs a refusal.
  r.post('/countersign', (req, res) => {
    try {
      const b = req.body || {};
      if (!b.signed_frame || !b.delivered_action) {
        return bad(res, 400, 'bad_request', 'signed_frame and delivered_action are required');
      }
      const v = verifyFrame(b.signed_frame);
      if (!v.ok) return bad(res, 400, 'frame_invalid', 'signed_frame did not verify: ' + v.reason);
      const cs = arrivalCountersign(b.signed_frame, b.delivered_action, _gatewayKeys);
      const cv = verifyArrivalCountersign(cs);
      res.json({ ok: true, countersignature: cs, self_verify: cv });
    } catch (e) {
      return bad(res, 400, 'countersign_failed', e.message);
    }
  });

  // Utility: verify anything the caller sends back
  r.post('/verify-frame', (req, res) => {
    const v = verifyFrame(req.body?.signed_frame);
    res.json(v);
  });
  r.post('/verify-replay', (req, res) => {
    const v = verifyReplayManifest(req.body?.manifest, req.body?.signed_frame);
    res.json(v);
  });
  r.post('/verify-countersign', (req, res) => {
    const v = verifyArrivalCountersign(req.body?.countersignature);
    res.json(v);
  });

  return r;
}
