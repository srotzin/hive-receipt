/**
 * Composed classifier: deterministic floor + optional semantic reader.
 *
 * The deterministic engine always runs and defines a lower bound on
 * consequence. When the approved Hive compute endpoint is configured and returns
 * a structurally valid classification, its signal is merged upward — the higher
 * level wins and categories are unioned. The semantic reader can never pull a
 * judgment below the deterministic floor, so an unreachable or misbehaving
 * endpoint degrades to the deterministic result rather than weakening it.
 */

import { classifyDeterministic, featureDigest } from './rules.js';
import { classifySemantic } from './compute.js';

const LABELS = {
  health: 'Health or safety',
  pii: 'Privacy or PII exfiltration',
  override: 'Policy or safety override',
  cyber: 'Cybersecurity or credential action',
  irrev: 'Irreversible action',
  financial: 'Financial action',
  legal: 'Legal or regulatory consequence',
  outbound: 'Outbound communication',
  datawrite: 'Data modification',
};

/**
 * @param {string} text
 * @param {{phase?:string, useSemantic?:boolean, timeoutMs?:number}} [opts]
 * @returns {Promise<object>} classification result
 */
export async function classify(text, { phase = 'formation', useSemantic = true, timeoutMs = 6000 } = {}) {
  const base = classifyDeterministic(text);
  const result = {
    ...base,
    engine: 'deterministic',
    semantic_used: false,
    semantic_error: null,
    reference_only: false,
  };

  if (!useSemantic) return result;

  const sem = await classifySemantic(text, { phase, timeoutMs });
  if (!sem.ok) {
    // Not an error condition: the deterministic floor stands. Record why the
    // semantic reader did not contribute so callers can tell the truth.
    result.semantic_error = sem.error;
    return result;
  }

  // Merge upward. Union categories by id, keeping the higher severity.
  const byId = new Map();
  for (const c of base.categories) byId.set(c.id, c);
  for (const c of sem.classification.categories) {
    const existing = byId.get(c.id);
    const label = LABELS[c.id] || c.label || c.id;
    if (!existing || c.sev > existing.sev) byId.set(c.id, { id: c.id, label, sev: c.sev });
  }
  const merged = [...byId.values()].sort((a, b) => (b.sev - a.sev) || a.id.localeCompare(b.id));
  const level = Math.max(base.level, sem.classification.level, merged.reduce((m, c) => Math.max(m, c.sev), 0));

  return {
    ...result,
    level,
    categories: merged,
    engine: 'semantic+deterministic',
    semantic_used: true,
    semantic_latency_ms: sem.latency_ms,
    // Recompute the digest over the merged feature set.
    feature_digest: featureDigest(merged, base.big_amount, base.languages, (text || '').trim().length),
  };
}
