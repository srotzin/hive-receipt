// engine/inkframe.mjs
// InkFrame v1 substrate. Non-mutating, content-addressed envelope for
// Carnac Live Ink™ proof-completion frames.
//
// Eight roots (all content-addressed sha256):
//   input_root            — the raw prompt/input text (never rewritten)
//   anchor_set            — anchors: byte-range references into input
//   cue_graph_root        — typed edges {src, tgt, rel} between anchors
//   proof_demand_root     — demands: {anchor_id, level, enabled_by, policy_id}
//   evidence_root         — bindings: {anchor_id, binding_type, artifact_sha256}
//   action_envelope_root  — approved action tuple: {action_type, target}
//   lineage               — {previous_frame_id?, tool, agent, timestamps}
//   signature_set         — hybrid Ed25519 + ML-DSA-65 over canonical frame
//
// Non-mutation guarantee: change one byte in any layer, the address of that
// layer changes, the frame_id changes, the signature breaks. Verifiable by
// recomputation, not by policy.
//
// This file is public-safe. Span-detection, proof-sizing, and routing math
// are NOT here.

import { jcs, sha256hex, contentAddress, hybridSign, hybridVerify } from './crypto.mjs';

export const INKFRAME_VERSION = 'inkframe-v1';

// ---------- root builders ----------

// input_root: the raw input text is committed by hash. The bytes stay wherever
// the tenant already stores them (or nowhere, if disclosure-free). Only the
// hash and a length live in the frame.
export function inputRoot(inputText) {
  const bytes = new TextEncoder().encode(inputText);
  return {
    kind: 'input_root',
    input_sha256: sha256hex(bytes),
    input_bytes: bytes.length,
    encoding: 'utf-8'
  };
}

// anchor_set: byte-range references into the input. NEVER carries raw text.
// Each anchor is {anchor_id, start, end, span_sha256} where span_sha256 is
// the hash of the referenced byte range. This is what makes fingerprint-only
// evidence binding possible.
export function anchorSet(inputText, anchors) {
  const bytes = new TextEncoder().encode(inputText);
  const set = anchors.map((a, i) => {
    if (a.start < 0 || a.end > bytes.length || a.start >= a.end) {
      throw new Error(`anchor ${i}: invalid range [${a.start},${a.end})`);
    }
    const span = bytes.slice(a.start, a.end);
    return {
      anchor_id: a.anchor_id || `a${i}`,
      start: a.start,
      end: a.end,
      span_sha256: sha256hex(span)
    };
  });
  return { kind: 'anchor_set', anchors: set };
}

// cue_graph_root: typed edges between anchors. Relations: supports,
// contradicts, supersedes, enables. No scoring, no severity math.
const VALID_REL = new Set(['supports', 'contradicts', 'supersedes', 'enables']);
export function cueGraphRoot(edges) {
  const clean = edges.map((e, i) => {
    if (!VALID_REL.has(e.rel)) throw new Error(`edge ${i}: invalid rel "${e.rel}"`);
    if (!e.src || !e.tgt) throw new Error(`edge ${i}: missing src or tgt`);
    return { src: e.src, tgt: e.tgt, rel: e.rel };
  });
  return { kind: 'cue_graph_root', edges: clean };
}

// proof_demand_root: at each anchor, what proof level does policy demand.
const VALID_LEVEL = new Set(['none', 'attest', 'evidence', 'authority']);
export function proofDemandRoot(demands) {
  const clean = demands.map((d, i) => {
    if (!VALID_LEVEL.has(d.level)) throw new Error(`demand ${i}: invalid level "${d.level}"`);
    if (!d.anchor_id) throw new Error(`demand ${i}: missing anchor_id`);
    return {
      anchor_id: d.anchor_id,
      level: d.level,
      enabled_by: d.enabled_by || null,
      policy_id: d.policy_id || null
    };
  });
  return { kind: 'proof_demand_root', demands: clean };
}

// evidence_root: what was bound to satisfy each demand. binding_type is
// 'authority' (a policy artifact) or 'evidence' (a data artifact). Only
// the sha256 of the artifact is stored. Raw artifact never touches the frame.
const VALID_BINDING = new Set(['authority', 'evidence']);
export function evidenceRoot(bindings) {
  const clean = bindings.map((b, i) => {
    if (!VALID_BINDING.has(b.binding_type)) throw new Error(`binding ${i}: invalid binding_type`);
    if (!b.anchor_id) throw new Error(`binding ${i}: missing anchor_id`);
    if (!b.artifact_sha256) throw new Error(`binding ${i}: missing artifact_sha256`);
    return {
      anchor_id: b.anchor_id,
      binding_type: b.binding_type,
      artifact_sha256: b.artifact_sha256,
      bound_at: b.bound_at || new Date().toISOString()
    };
  });
  return { kind: 'evidence_root', bindings: clean };
}

// action_envelope_root: the tuple that describes what action the receipt is
// authorizing. This is what Arrival Countersignature compares against.
export function actionEnvelopeRoot(action) {
  if (!action.action_type) throw new Error('action_envelope: missing action_type');
  if (!action.target) throw new Error('action_envelope: missing target');
  return {
    kind: 'action_envelope_root',
    action_type: action.action_type,
    target: action.target,
    params: action.params || {}
  };
}

// lineage: tool, agent, timestamps, optional previous_frame_id for chains.
export function lineage(meta) {
  return {
    kind: 'lineage',
    tool: meta.tool || 'unknown',
    agent: meta.agent || 'unknown',
    tenant: meta.tenant || null,
    previous_frame_id: meta.previous_frame_id || null,
    created_at: meta.created_at || new Date().toISOString()
  };
}

// ---------- assemble & sign ----------

export function buildFrame({ input_root, anchor_set, cue_graph_root, proof_demand_root, evidence_root, action_envelope_root, lineage: lin }) {
  const frame_body = {
    version: INKFRAME_VERSION,
    input_root: { ...input_root, addr: contentAddress(input_root) },
    anchor_set: { ...anchor_set, addr: contentAddress(anchor_set) },
    cue_graph_root: { ...cue_graph_root, addr: contentAddress(cue_graph_root) },
    proof_demand_root: { ...proof_demand_root, addr: contentAddress(proof_demand_root) },
    evidence_root: { ...evidence_root, addr: contentAddress(evidence_root) },
    action_envelope_root: { ...action_envelope_root, addr: contentAddress(action_envelope_root) },
    lineage: { ...lin, addr: contentAddress(lin) }
  };
  const frame_id = contentAddress(frame_body);
  return { frame_id, frame_body };
}

export function signFrame(frame, keys) {
  const signature_set = hybridSign(frame.frame_body, keys);
  return {
    ...frame,
    signature_set
  };
}

// ---------- verify ----------

// Recompute every address and verify the hybrid signature.
export function verifyFrame(signed_frame) {
  const body = signed_frame.frame_body;
  const checks = [];

  // Recompute each layer's address (strip the .addr field first).
  const layers = ['input_root', 'anchor_set', 'cue_graph_root', 'proof_demand_root', 'evidence_root', 'action_envelope_root', 'lineage'];
  for (const layer of layers) {
    const stored = body[layer].addr;
    const { addr, ...withoutAddr } = body[layer];
    const recomputed = contentAddress(withoutAddr);
    checks.push({ layer, ok: stored === recomputed, stored, recomputed });
    if (stored !== recomputed) {
      return { ok: false, reason: `layer "${layer}" address mismatch`, checks };
    }
  }

  // Recompute frame_id.
  const recomputed_frame_id = contentAddress(body);
  if (recomputed_frame_id !== signed_frame.frame_id) {
    return { ok: false, reason: 'frame_id mismatch', checks };
  }

  // Verify hybrid signature.
  const sigResult = hybridVerify(body, signed_frame.signature_set);
  if (!sigResult.ok) {
    return { ok: false, reason: 'signature: ' + sigResult.reason, checks };
  }

  return { ok: true, frame_id: signed_frame.frame_id, checks, signature: sigResult };
}

// ---------- Proof Pre-Fill primitive ----------
// At the instant a demand fires, resolve evidence/authority against a local
// index by span_sha256 fingerprint. NEVER transmit or store the raw span text.
// Returns bindings that can be handed to evidenceRoot() before submit.
export function proofPreFill(anchor_set, proof_demand_root, localIndex) {
  // localIndex maps span_sha256 → {artifact_sha256, binding_type}
  const bindings = [];
  for (const demand of proof_demand_root.demands) {
    if (demand.level === 'none') continue;
    const anchor = anchor_set.anchors.find(a => a.anchor_id === demand.anchor_id);
    if (!anchor) continue;
    const hit = localIndex[anchor.span_sha256];
    if (hit) {
      bindings.push({
        anchor_id: demand.anchor_id,
        binding_type: hit.binding_type,
        artifact_sha256: hit.artifact_sha256
      });
    }
  }
  return bindings;
}

// ---------- Arrival Countersignature primitive ----------
// Compare the approved action tuple (from the signed frame) against the
// action tuple actually delivered at the gateway. If they match, gateway
// counter-signs. If not, gateway records the delta and refuses.
export function arrivalCountersign(signed_frame, delivered_action, gatewayKeys) {
  const approved = signed_frame.frame_body.action_envelope_root;
  const approved_tuple = {
    action_type: approved.action_type,
    target: approved.target,
    params: approved.params
  };
  const delivered_tuple = {
    action_type: delivered_action.action_type,
    target: delivered_action.target,
    params: delivered_action.params || {}
  };
  const approved_hash = sha256hex(jcs(approved_tuple));
  const delivered_hash = sha256hex(jcs(delivered_tuple));
  const matches = approved_hash === delivered_hash;

  const countersign_body = {
    kind: 'arrival_countersignature',
    frame_id: signed_frame.frame_id,
    approved_tuple_sha256: approved_hash,
    delivered_tuple_sha256: delivered_hash,
    matches,
    arrived_at: new Date().toISOString()
  };
  const signature = hybridSign(countersign_body, gatewayKeys);
  return { countersign_body, signature };
}

export function verifyArrivalCountersign(cs) {
  return hybridVerify(cs.countersign_body, cs.signature);
}
