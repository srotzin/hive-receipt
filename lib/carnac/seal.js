/**
 * Continuity sealing — an append-only chain digest across a tenant/trajectory.
 *
 * Each judgment carries previous_digest + chain_digest (computed in the engine):
 *   chain_digest = sha256(previous_digest || '' + '|' + judgment_id + '|' +
 *                         feature_digest + '|' + effective_level + '|' + seq)
 *
 * A seal is a signed checkpoint over the ordered chain for a (tenant,
 * trajectory): it records the head chain_digest, the count, and the seq range,
 * and verifies that the chain is unbroken and in order. Missing or out-of-order
 * links fail verification. Seals reuse the Hive ed25519 signer.
 */

import crypto from 'crypto';
import { signPayload } from '../spectral.js';
import { supaInsert } from './supabase.js';
import { listByTrajectoryDurable } from './ledger.js';

const TABLE = () => process.env.CARNAC_SEAL_TABLE || 'carnac_seals';

const memory = new Map(); // seal_id -> record

export function _resetSeals() {
  memory.clear();
}

/** The link digest for a judgment envelope, given the prior chain digest. */
export function linkDigest(previous_digest, envelope) {
  const material = [
    previous_digest || '',
    envelope.judgment_id,
    envelope.feature_digest,
    envelope.effective_level,
    envelope.seq ?? '',
  ].join('|');
  return crypto.createHash('sha256').update(material).digest('hex');
}

/**
 * Verify the continuity chain of an ordered judgment list. Recomputes each link
 * from the previous digest and checks seq strictly increases (when present).
 * @returns {{ok:boolean, count:number, head:string|null, breaks:object[]}}
 */
export function verifyChain(judgments) {
  const breaks = [];
  let prev = null;
  let lastSeq = null;
  let head = null;
  for (let i = 0; i < judgments.length; i++) {
    const j = judgments[i];
    const expected = linkDigest(prev, j);
    if (j.chain_digest && j.chain_digest !== expected) {
      breaks.push({ index: i, judgment_id: j.judgment_id, reason: 'chain_digest mismatch' });
    }
    if (j.previous_digest && j.previous_digest !== (prev || null)) {
      breaks.push({ index: i, judgment_id: j.judgment_id, reason: 'previous_digest mismatch' });
    }
    if (typeof j.seq === 'number') {
      if (lastSeq !== null && j.seq <= lastSeq) {
        breaks.push({ index: i, judgment_id: j.judgment_id, reason: 'seq out of order' });
      }
      lastSeq = j.seq;
    }
    prev = j.chain_digest || expected;
    head = prev;
  }
  return { ok: breaks.length === 0, count: judgments.length, head, breaks };
}

/**
 * Seal a tenant/trajectory: read the durable ordered chain, verify it, and
 * persist a signed checkpoint. Never throws.
 * @returns {Promise<{ok:true, seal:object, verification:object, source:string, ledger:object}
 *          | {ok:false, status:number, code:string, message:string}>}
 */
export async function sealTrajectory({ tenant_id, trajectory_id } = {}) {
  if (!tenant_id || !trajectory_id) {
    return { ok: false, status: 400, code: 'invalid_input', message: 'tenant_id and trajectory_id required' };
  }
  const { judgments, source } = await listByTrajectoryDurable(tenant_id, trajectory_id);
  const verification = verifyChain(judgments);
  const seqs = judgments.map((j) => j.seq).filter((s) => typeof s === 'number');
  const payload = {
    seal_id: crypto.randomBytes(12).toString('hex'),
    tenant_id,
    trajectory_id,
    count: judgments.length,
    seq_min: seqs.length ? Math.min(...seqs) : null,
    seq_max: seqs.length ? Math.max(...seqs) : null,
    head_chain_digest: verification.head,
    chain_intact: verification.ok,
    breaks: verification.breaks,
    source,
    sealed_at: new Date().toISOString(),
  };
  const seal = { ...payload, ...signPayload(payload) };
  memory.set(seal.seal_id, seal);

  const row = {
    seal_id: seal.seal_id,
    tenant_id,
    trajectory_id,
    count: seal.count,
    head_chain_digest: seal.head_chain_digest,
    chain_intact: seal.chain_intact,
    envelope: seal,
    created_at: seal.sealed_at,
  };
  const ledger = await supaInsert(TABLE(), row);
  return { ok: true, seal, verification, source, ledger };
}
