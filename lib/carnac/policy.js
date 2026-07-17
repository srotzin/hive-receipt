/**
 * Governed policy floor.
 *
 * The floor is Carnac's own judgment. Ordinary runtime configuration can only
 * raise proof, never lower it: a runtime override that tries to route a matched
 * category below its floor severity is clamped and the attempt is recorded.
 *
 * The floor itself can be revised, but only through a governed PolicyAmendment:
 * a raise requires one attestor signature, a lowering requires a multi-party
 * quorum of distinct attestor signatures over the canonical amendment payload.
 * Attestor public keys are configured via CARNAC_POLICY_ATTESTORS (comma-
 * separated base64 SPKI ed25519 keys). With no attestors configured, lowering is
 * impossible and the default floor stands.
 */

import crypto from 'crypto';

const DEFAULT_CATEGORY_FLOOR = Object.freeze({
  health: 3,
  pii: 3,
  override: 3,
  cyber: 3,
  irrev: 3,
  financial: 2,
  legal: 2,
  outbound: 1,
  datawrite: 1,
});

const QUORUM_DOWNWARD = 2;

let _policy = freshDefault();

function freshDefault() {
  return {
    version: 'floor-2026-07-17-a',
    category_floor: { ...DEFAULT_CATEGORY_FLOOR },
    min_level: 0,
    amended_at: null,
    amendment_history: [],
  };
}

/** Reset to the shipped default floor (used by tests). */
export function _resetPolicy() {
  _policy = freshDefault();
}

/** Public, read-only view of the current governed floor. */
export function currentPolicy() {
  return {
    version: _policy.version,
    category_floor: { ..._policy.category_floor },
    min_level: _policy.min_level,
    amended_at: _policy.amended_at,
    quorum_downward: QUORUM_DOWNWARD,
    attestors_configured: getAttestors().length,
    amendment_count: _policy.amendment_history.length,
  };
}

function getAttestors() {
  const raw = process.env.CARNAC_POLICY_ATTESTORS || '';
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * Apply the governed floor and any runtime overrides to a classification.
 * Runtime overrides may only raise. Returns the effective level plus provenance.
 * @param {{level:number, categories:{id:string,sev:number}[]}} classification
 * @param {Object<string,number>} [runtimeOverrides] category id -> requested min level
 */
export function applyFloor(classification, runtimeOverrides = {}) {
  const floor = _policy.category_floor;
  let effective = Math.max(classification.level || 0, _policy.min_level || 0);
  let raisedByRuntime = false;
  let clampAttempted = false;

  for (const c of classification.categories || []) {
    const floorSev = floor[c.id] ?? c.sev;
    // The category can never route below its floor.
    effective = Math.max(effective, floorSev);

    if (Object.prototype.hasOwnProperty.call(runtimeOverrides, c.id)) {
      const requested = Number(runtimeOverrides[c.id]);
      if (Number.isFinite(requested)) {
        if (requested > effective) { effective = requested; raisedByRuntime = true; }
        else if (requested < floorSev) { clampAttempted = true; }
      }
    }
  }

  effective = Math.max(0, Math.min(3, effective));
  return {
    effective_level: effective,
    floor_version: _policy.version,
    raised_by_runtime: raisedByRuntime,
    runtime_clamp_attempted: clampAttempted,
  };
}

/** Canonical bytes an attestor signs when proposing an amendment. */
export function amendmentDigest(amendment) {
  const canonical = {
    direction: amendment.direction,
    category_floor: amendment.category_floor || null,
    min_level: amendment.min_level ?? null,
    reason: amendment.reason || '',
    new_version: amendment.new_version,
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function verifyAttestorSignature(digestHex, signatureB64, pubKeyB64) {
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(pubKeyB64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(digestHex, 'hex'), pub, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Determine whether an amendment lowers any part of the floor.
 */
function isLowering(amendment) {
  if (typeof amendment.min_level === 'number' && amendment.min_level < _policy.min_level) return true;
  const cf = amendment.category_floor || {};
  for (const [id, sev] of Object.entries(cf)) {
    const current = _policy.category_floor[id] ?? 0;
    if (Number(sev) < current) return true;
  }
  return false;
}

/**
 * Apply a governed PolicyAmendment. Signatures is an array of
 * { public_key, signature } over amendmentDigest(amendment).
 * @returns {{ok:true, policy:object, direction:string} | {ok:false, status:number, code:string, message:string}}
 */
export function amendPolicy(amendment, signatures = []) {
  if (!amendment || typeof amendment !== 'object') {
    return { ok: false, status: 400, code: 'invalid_amendment', message: 'amendment object required' };
  }
  if (amendment.direction !== 'raise' && amendment.direction !== 'lower') {
    return { ok: false, status: 400, code: 'invalid_direction', message: 'direction must be raise or lower' };
  }
  if (!amendment.new_version || typeof amendment.new_version !== 'string') {
    return { ok: false, status: 400, code: 'invalid_version', message: 'new_version string required' };
  }

  const attestors = new Set(getAttestors());
  const digest = amendmentDigest(amendment);

  // Count distinct valid attestor signatures.
  const seen = new Set();
  for (const s of Array.isArray(signatures) ? signatures : []) {
    if (!s || !attestors.has(s.public_key) || seen.has(s.public_key)) continue;
    if (verifyAttestorSignature(digest, s.signature, s.public_key)) seen.add(s.public_key);
  }
  const validSigs = seen.size;

  const lowering = amendment.direction === 'lower' || isLowering(amendment);
  const required = lowering ? QUORUM_DOWNWARD : 1;

  if (validSigs < required) {
    return {
      ok: false,
      status: 403,
      code: 'insufficient_authorization',
      message: `${lowering ? 'lowering' : 'raising'} the floor requires ${required} distinct attestor signature(s); ${validSigs} valid provided`,
    };
  }

  // Apply.
  const next = {
    version: amendment.new_version,
    category_floor: { ..._policy.category_floor, ...(amendment.category_floor || {}) },
    min_level: typeof amendment.min_level === 'number' ? amendment.min_level : _policy.min_level,
    amended_at: new Date().toISOString(),
    amendment_history: [
      ..._policy.amendment_history,
      {
        version: amendment.new_version,
        direction: lowering ? 'lower' : 'raise',
        reason: amendment.reason || '',
        digest,
        signatures: validSigs,
        at: new Date().toISOString(),
      },
    ],
  };
  _policy = next;
  return { ok: true, policy: currentPolicy(), direction: lowering ? 'lower' : 'raise' };
}
