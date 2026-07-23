// engine/replay.mjs
// Disclosure-Free Replay for InkFrame v1.
//
// Given a signed frame + a cue-delta manifest (the ordered sequence of
// annotations that led to the final frame), reconstruct WHICH spans triggered
// WHICH demands at submit-time WITHOUT ever seeing the raw prompt text.
//
// The replay walks the cue graph and the demand set using anchor_ids and
// span_sha256 fingerprints only. An auditor sees the shape of the reasoning,
// not the words.

import { contentAddress, hybridSign, hybridVerify, sha256hex, jcs } from './crypto.mjs';

// A cue-delta is one step in the annotation session:
//   {step, at, action, anchor_id?, edge?, demand?, binding?}
// action ∈ {add_anchor, add_edge, add_demand, add_binding, snapshot}
// Each delta references anchor_ids and hashes. It never contains raw text.

export function buildReplayManifest(signed_frame, cue_deltas, keys) {
  // Validate: every anchor_id referenced in a delta MUST appear in the frame.
  const frame_anchor_ids = new Set(signed_frame.frame_body.anchor_set.anchors.map(a => a.anchor_id));
  for (let i = 0; i < cue_deltas.length; i++) {
    const d = cue_deltas[i];
    if (d.anchor_id && !frame_anchor_ids.has(d.anchor_id)) {
      throw new Error(`delta ${i}: anchor_id "${d.anchor_id}" not in frame`);
    }
  }

  const manifest_body = {
    kind: 'replay_manifest',
    frame_id: signed_frame.frame_id,
    delta_count: cue_deltas.length,
    deltas: cue_deltas,
    manifest_sha256: sha256hex(jcs(cue_deltas))
  };
  const signature = hybridSign(manifest_body, keys);
  return { manifest_body, signature };
}

// Verify the manifest signature AND that no delta references the raw text.
// Any delta that carries a `raw_text` or `span_text` field is a leak.
const LEAK_KEYS = ['raw_text', 'span_text', 'text', 'prompt', 'input', 'content'];

export function verifyReplayManifest(manifest, signed_frame) {
  // 1. Signature.
  const sig = hybridVerify(manifest.manifest_body, manifest.signature);
  if (!sig.ok) return { ok: false, reason: 'manifest signature: ' + sig.reason };

  // 2. Manifest ties to the frame.
  if (manifest.manifest_body.frame_id !== signed_frame.frame_id) {
    return { ok: false, reason: 'manifest frame_id does not match signed_frame' };
  }

  // 3. Disclosure-free check: no delta carries raw text.
  for (let i = 0; i < manifest.manifest_body.deltas.length; i++) {
    const d = manifest.manifest_body.deltas[i];
    for (const bad of LEAK_KEYS) {
      if (bad in d) {
        return { ok: false, reason: `delta ${i} leaks raw text via "${bad}"` };
      }
    }
  }

  // 4. Every anchor referenced in a delta must exist in the frame.
  const frame_anchor_ids = new Set(signed_frame.frame_body.anchor_set.anchors.map(a => a.anchor_id));
  for (let i = 0; i < manifest.manifest_body.deltas.length; i++) {
    const d = manifest.manifest_body.deltas[i];
    if (d.anchor_id && !frame_anchor_ids.has(d.anchor_id)) {
      return { ok: false, reason: `delta ${i}: unknown anchor_id` };
    }
  }

  return { ok: true, delta_count: manifest.manifest_body.delta_count };
}

// Given the verified manifest, reconstruct the "story" — which spans (by hash
// only) triggered which demands (by level) at what step, and the edges of
// the cue graph as they came into being. Output is disclosure-free by
// construction: it walks anchor_ids and hashes, never text.
export function reconstructStory(manifest, signed_frame) {
  const anchors = new Map(signed_frame.frame_body.anchor_set.anchors.map(a => [a.anchor_id, a]));
  const events = [];
  for (const d of manifest.manifest_body.deltas) {
    const evt = { step: d.step, at: d.at, action: d.action };
    if (d.anchor_id) {
      const a = anchors.get(d.anchor_id);
      evt.anchor = { anchor_id: d.anchor_id, span_sha256: a?.span_sha256, byte_range: [a?.start, a?.end] };
    }
    if (d.edge) evt.edge = d.edge;
    if (d.demand) evt.demand = { anchor_id: d.demand.anchor_id, level: d.demand.level };
    if (d.binding) evt.binding = { anchor_id: d.binding.anchor_id, binding_type: d.binding.binding_type, artifact_sha256: d.binding.artifact_sha256 };
    events.push(evt);
  }
  return { frame_id: signed_frame.frame_id, event_count: events.length, events };
}
