/**
 * Merkle micro-batching for lifecycle stage finalization.
 *
 * The asynchronous finalizer groups signed stages into a batch and commits one
 * Merkle root. Each stage keeps an O(log n) inclusion path so a single stage
 * still verifies on its own, offline, against the batch root. This is the
 * amortization the Evidence Plane describes: per-stage marginal proof cost falls
 * to one hash insert while every stage remains independently checkable.
 *
 * Domain separation: leaves and internal nodes use different tags so a leaf
 * digest can never be reinterpreted as an internal node (a second-preimage
 * defense). Odd nodes are promoted (duplicated) at each level.
 */

import crypto from 'crypto';

const LEAF = 'carnac.merkle.leaf.v1';
const NODE = 'carnac.merkle.node.v1';

function h(tag, ...parts) {
  return crypto.createHash('sha256').update(`${tag}\n${parts.join('|')}`).digest('hex');
}

/** Hash a leaf value (a stage digest hex) into a Merkle leaf. */
export function leafHash(valueHex) {
  return h(LEAF, valueHex);
}

/**
 * Build a Merkle tree over leaf values (hex strings, e.g. stage digests).
 * @param {string[]} values
 * @returns {{root:string|null, leaves:string[], proofs:string[][], size:number}}
 *   proofs[i] is the ordered sibling path for values[i]; each entry is
 *   `${position}:${hash}` where position is 'L' or 'R' (sibling side).
 */
export function buildMerkle(values) {
  const size = values.length;
  if (size === 0) return { root: null, leaves: [], proofs: [], size: 0 };
  const leaves = values.map(leafHash);
  const proofs = leaves.map(() => []);
  // indices maps each original leaf to its position on the current level.
  let level = leaves.slice();
  let positions = leaves.map((_, i) => i);
  while (level.length > 1) {
    const next = [];
    const nextPositions = new Array(level.length);
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // promote odd
      const parent = h(NODE, left, right);
      const parentIndex = next.length;
      next.push(parent);
      // Record sibling for every original leaf that sits under i or i+1.
      for (let p = 0; p < positions.length; p++) {
        if (positions[p] === i) { proofs[p].push(`R:${right}`); nextPositions[p] = parentIndex; }
        else if (positions[p] === i + 1) { proofs[p].push(`L:${left}`); nextPositions[p] = parentIndex; }
      }
    }
    level = next;
    positions = nextPositions;
  }
  return { root: level[0], leaves, proofs, size };
}

/**
 * Verify that a leaf value is included under root using an inclusion path.
 * @param {string} valueHex the original leaf value (stage digest)
 * @param {string[]} proof ordered `${side}:${hash}` siblings from leaf to root
 * @param {string} root expected Merkle root
 * @returns {boolean}
 */
export function verifyInclusion(valueHex, proof, root) {
  if (!root || !Array.isArray(proof)) return false;
  let acc = leafHash(valueHex);
  for (const step of proof) {
    const sep = step.indexOf(':');
    if (sep < 0) return false;
    const side = step.slice(0, sep);
    const sib = step.slice(sep + 1);
    if (side === 'L') acc = h(NODE, sib, acc);
    else if (side === 'R') acc = h(NODE, acc, sib);
    else return false;
  }
  return acc === root;
}
