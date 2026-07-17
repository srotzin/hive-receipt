/**
 * Carnac deterministic classification rules.
 *
 * This is the guaranteed floor of the judgment plane: a pure, offline,
 * deterministic reader of consequence. It never calls a model. The semantic
 * classifier in compute.js may raise a level, but this module is what runs when
 * the compute endpoint is unconfigured, unreachable, or returns an invalid
 * shape. It is intentionally conservative and will miss cleverly paraphrased
 * consequence by design; the composed engine treats it as a lower bound.
 *
 * Categories carry a severity that maps directly to the routing level:
 *   3 = high consequence (hold / escalate)
 *   2 = consequential    (hold for confirmation, carry proof)
 *   1 = notable          (attach a receipt, enrich)
 *   0 = ordinary         (let it run, on the ledger)
 *
 * Multiple signals compose upward: the highest matched severity sets the level.
 * A lower rule never lowers a higher one.
 */

import crypto from 'crypto';

/**
 * @typedef {Object} Category
 * @property {string} id
 * @property {string} label
 * @property {number} sev
 */

/** @type {Array<{id:string,label:string,sev:number,re:RegExp}>} */
export const RULES = [
  {
    id: 'health', label: 'Health or safety', sev: 3,
    re: /\b(patient|insulin|dose|dosage|medication|prescription|diagnos\w*|clinical|blood pressure|mg\b|units of|ventilator|defibrillat\w*)\b|\b(insulina|dosis|paciente|medicamento|receta)\b/i,
  },
  {
    id: 'pii', label: 'Privacy or PII exfiltration', sev: 3,
    re: /\b(ssn|social security|passport number|credit card|national id|date of birth|dob)\b|\b(exfiltrat\w*)\b|\b(dump|export|leak)\b[^.]{0,40}\b(users?|customers?|records?|accounts?|personal data|pii)\b|\bpayroll\b[^.]{0,30}\b(ssn|social)\b/i,
  },
  {
    id: 'override', label: 'Policy or safety override', sev: 3,
    re: /\bignore\b[^.]{0,40}\b(rule|rules|policy|policies|safety|instruction|instructions|guardrail|guardrails)\b|\boverride\b|\bbypass\b|\bjailbreak\b|\bdisable\b[^.]{0,30}\b(safety|guard|guardrail|filter|policy|check)\b|\bwithout (approval|authorization|authorisation|consent|sign.?off)\b|\bpretend you (are|have)\b|\bact as (an?|the) (admin|root|system)\b/i,
  },
  {
    id: 'cyber', label: 'Cybersecurity or credential action', sev: 3,
    re: /\b(password|credential|credentials|api key|apikey|secret key|access token|ssh key|private key|encryption key)\b|\brm\s+-rf\b|\bdrop\s+table\b|\bsudo\b|\bdisable\b[^.]{0,20}\bfirewall\b|\bgrant\b[^.]{0,25}\b(access|admin|root|privilege)\b|\bescalat\w*\b[^.]{0,15}\bprivilege\b/i,
  },
  {
    id: 'irrev', label: 'Irreversible action', sev: 3,
    re: /\b(delete|erase|permanent\w*|wipe|destroy|purge|terminate|shred)\b|\bdrop\s+database\b|\bforce\s+push\b|\bdeploy\b[^.]{0,20}\bproduction\b|\bformat\b[^.]{0,15}\b(disk|drive|volume)\b|\b(eliminar|borrar|permanente\w*|destruir|purgar)\b/i,
  },
  {
    id: 'financial', label: 'Financial action', sev: 2,
    re: /\b(transfer|wire|payment|pay|payout|payroll|invoice|refund|withdraw|withdrawal|deposit|loan|remit|disburse)\b|\b(transferir|transferencia|pagar|pago|factura|reembolso)\b/i,
  },
  {
    id: 'legal', label: 'Legal or regulatory consequence', sev: 2,
    re: /\b(patent|infring\w*|lawsuit|litigation|liabilit\w*|regulator\w*|compliance|subpoena|nda|non.?disclosure|gdpr|hipaa|contract breach|indemnif\w*)\b/i,
  },
  {
    id: 'outbound', label: 'Outbound communication', sev: 1,
    re: /\b(send|email|e-mail|message|post to|publish|broadcast|notify)\b[^.]{0,30}\b(email|message|customer|client|user|list|channel|slack|twitter|x\.com)\b|\bsend an? (email|message|dm)\b/i,
  },
  {
    id: 'datawrite', label: 'Data modification', sev: 1,
    re: /\b(update|modify|edit|create|insert|write|append|set)\b[^.]{0,25}\b(record|records|row|rows|entry|entries|field|table|document|profile)\b/i,
  },
];

export const AMOUNT_RE = /\$\s?\d|\b\d{3,}\b|\b(thousand|hundred|million|billion|mil|millones?)\b/i;

const SPANISH_RE = /\b(eliminar|borrar|permanente\w*|transferir|transferencia|pagar|pago|insulina|dosis|paciente|medicamento|receta|destruir|purgar|factura)\b/i;

/**
 * Run the deterministic classifier over a piece of text.
 * @param {string} text
 * @returns {{blank:boolean, level:number, categories:Category[], big_amount:boolean, languages:string[], feature_digest:string}}
 */
export function classifyDeterministic(text) {
  const t = typeof text === 'string' ? text : '';
  const trimmed = t.trim();
  if (!trimmed) {
    return {
      blank: true,
      level: 0,
      categories: [],
      big_amount: false,
      languages: ['en'],
      feature_digest: featureDigest([], false, ['en'], 0),
    };
  }

  const matched = [];
  for (const rule of RULES) {
    if (rule.re.test(t)) matched.push({ id: rule.id, label: rule.label, sev: rule.sev });
  }

  const hasFinancial = matched.some((c) => c.id === 'financial');
  const big_amount = hasFinancial && AMOUNT_RE.test(t);

  const languages = ['en'];
  if (SPANISH_RE.test(t)) languages.push('es');

  // Compose upward: highest matched severity is the level.
  const level = matched.reduce((max, c) => Math.max(max, c.sev), 0);

  // Stable ordering: severity desc, then id asc.
  matched.sort((a, b) => (b.sev - a.sev) || a.id.localeCompare(b.id));

  return {
    blank: false,
    level,
    categories: matched,
    big_amount,
    languages,
    feature_digest: featureDigest(matched, big_amount, languages, trimmed.length),
  };
}

/**
 * Privacy-preserving digest of the observed features. This is the only
 * classification artifact derived from content that is safe to let leave the
 * buyer boundary: it contains category ids, the big-amount flag, detected
 * languages and a coarse length bucket, never the raw text.
 */
export function featureDigest(categories, bigAmount, languages, length) {
  const material = {
    ids: categories.map((c) => c.id).sort(),
    big_amount: Boolean(bigAmount),
    languages: [...languages].sort(),
    len_bucket: Math.floor((length || 0) / 100),
  };
  return crypto.createHash('sha256').update(JSON.stringify(material)).digest('hex');
}
