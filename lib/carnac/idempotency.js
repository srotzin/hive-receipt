/**
 * Idempotency, replay, and order controls for the judgment plane.
 *
 *  - Idempotency: the same idempotency key returns the same judgment id, so a
 *    retried call never produces a second, divergent judgment.
 *  - Replay: a nonce may be used once. A replayed nonce is rejected, so a
 *    captured request cannot be re-submitted to manufacture a duplicate ruling.
 *  - Order: reads within a trajectory must not regress. An effect read cannot
 *    arrive before the output read it depends on; a stale phase is rejected.
 *
 * State is in-memory per process with bounded TTL. This is deliberately the same
 * posture as the MPP payment cache already in this service; a durable store can
 * back it later without changing the contract.
 */

import { PHASE_RANK } from './routes.js';

const TTL_MS = 24 * 60 * 60 * 1000;

const idempotencyStore = new Map(); // key -> { judgment_id, at }
const nonceStore = new Map();       // nonce -> { at }
const trajectoryStore = new Map();  // trajectory_id -> { lastRank, lastSeq, at }

function sweep(store) {
  const now = Date.now();
  for (const [k, v] of store) if (now - v.at > TTL_MS) store.delete(k);
}

export function _resetControls() {
  idempotencyStore.clear();
  nonceStore.clear();
  trajectoryStore.clear();
}

/**
 * @returns {{hit:true, judgment_id:string} | {hit:false}}
 */
export function checkIdempotency(key) {
  if (!key) return { hit: false };
  sweep(idempotencyStore);
  const found = idempotencyStore.get(key);
  return found ? { hit: true, judgment_id: found.judgment_id } : { hit: false };
}

export function recordIdempotency(key, judgment_id) {
  if (!key) return;
  idempotencyStore.set(key, { judgment_id, at: Date.now() });
}

/**
 * @returns {{ok:true} | {ok:false, code:string, message:string}}
 */
export function checkReplay(nonce) {
  if (!nonce) return { ok: true };
  sweep(nonceStore);
  if (nonceStore.has(nonce)) {
    return { ok: false, code: 'replay_detected', message: 'nonce already used' };
  }
  return { ok: true };
}

export function recordNonce(nonce) {
  if (!nonce) return;
  nonceStore.set(nonce, { at: Date.now() });
}

/**
 * Enforce non-decreasing phase order within a trajectory. A monotonic sequence
 * number, when supplied, must also strictly increase.
 * @returns {{ok:true, rank:number} | {ok:false, code:string, message:string}}
 */
export function checkOrder(trajectory_id, phase, seq) {
  const rank = PHASE_RANK[phase];
  if (rank === undefined) {
    return { ok: false, code: 'invalid_phase', message: `unknown phase: ${phase}` };
  }
  if (!trajectory_id) return { ok: true, rank };
  sweep(trajectoryStore);
  const prev = trajectoryStore.get(trajectory_id);
  if (prev) {
    if (rank < prev.lastRank) {
      return { ok: false, code: 'out_of_order', message: `phase ${phase} regresses below last phase in trajectory` };
    }
    if (typeof seq === 'number' && typeof prev.lastSeq === 'number' && seq <= prev.lastSeq) {
      return { ok: false, code: 'out_of_order', message: `seq ${seq} not greater than last seq ${prev.lastSeq}` };
    }
  }
  return { ok: true, rank };
}

export function recordPhase(trajectory_id, phase, seq) {
  if (!trajectory_id) return;
  const rank = PHASE_RANK[phase] ?? 0;
  const prev = trajectoryStore.get(trajectory_id);
  trajectoryStore.set(trajectory_id, {
    lastRank: rank,
    lastSeq: typeof seq === 'number' ? seq : (prev?.lastSeq ?? null),
    at: Date.now(),
  });
}
