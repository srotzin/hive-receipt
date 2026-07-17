/**
 * Howler — the severity-bound escalation artifact.
 *
 * A Howler is produced only when a judgment reaches the escalation threshold
 * (effective level 3). It is the disposition workflow's escalation receipt: it
 * names why the judgment escalated, what confirmation is required, and carries
 * the feature digest and route so a human or upstream system can act. The engine
 * signs it with the same Hive ed25519 key used for judgments.
 */

import crypto from 'crypto';

export const HOWLER_THRESHOLD = 3;

/**
 * Build an unsigned Howler body. Returns null when below threshold.
 * @param {object} judgment the judgment payload (pre-signature)
 * @returns {object|null}
 */
export function buildHowler(judgment) {
  if (!judgment || (judgment.effective_level ?? 0) < HOWLER_THRESHOLD) return null;
  return {
    howler_id: crypto.randomBytes(12).toString('hex'),
    judgment_id: judgment.judgment_id,
    trajectory_id: judgment.trajectory_id,
    phase: judgment.phase,
    severity: judgment.effective_level,
    categories: (judgment.categories || []).map((c) => ({ id: c.id, label: c.label, sev: c.sev })),
    feature_digest: judgment.feature_digest,
    reason: escalationReason(judgment),
    required_disposition: 'human_confirmation',
    primary_route: judgment.primary_route,
    policy_version: judgment.policy_version,
    raised_at: new Date().toISOString(),
  };
}

function escalationReason(judgment) {
  const cats = (judgment.categories || []).filter((c) => c.sev >= HOWLER_THRESHOLD).map((c) => c.label);
  if (cats.length) {
    return `The classifier produced and signed a high-consequence state from the features observed on the instrumented path: ${cats.join(', ')}.`;
  }
  return 'The classifier produced and signed a high-consequence state from the features observed on the instrumented path.';
}
