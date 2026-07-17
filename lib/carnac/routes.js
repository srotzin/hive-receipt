/**
 * Carnac routing — the seven response decisions and disposition.
 *
 * Consequence is proven in proportion to the stakes. A level maps to a composed
 * set of responses; signals compose upward so the strongest category sets the
 * route and a lower rule never wins. Disposition is the final effect decision and
 * sits outside the read count.
 */

/** The seven canonical responses, each backed by an existing Hive artifact. */
export const RESPONSES = Object.freeze({
  let_it_run: { id: 'let_it_run', artifact: 'ledger_entry', label: 'Let it run, on the ledger' },
  receipt: { id: 'receipt', artifact: 'SiGR/AFiR/S2S', label: 'Attach a signed receipt' },
  enrich: { id: 'enrich', artifact: 'PPR/MoR/MoRSo', label: 'Enrich with provenance' },
  verify: { id: 'verify', artifact: 'verification_receipt', label: 'Verify against the source' },
  hold: { id: 'hold', artifact: 'Imprimatur', label: 'Hold for a confirmation' },
  ask_human: { id: 'ask_human', artifact: 'confirmation_request', label: 'Ask a human to confirm' },
  howler: { id: 'howler', artifact: 'Howler', label: 'Escalate with a Howler' },
});

/** Phase rank for trajectory ordering. Disposition is outside the read count. */
export const PHASE_RANK = Object.freeze({
  formation: 0,
  invocation: 1,
  output: 2,
  effect: 3,
  disposition: 4,
});

export const PHASES = Object.freeze(Object.keys(PHASE_RANK));

/**
 * Compose the response set for a given effective level and lifecycle phase.
 * @param {number} level 0..3
 * @param {string} phase formation|invocation|output|effect
 * @returns {{level:number, phase:string, responses:object[], primary_route:string, disposition:object}}
 */
export function composeRoute(level, phase = 'formation') {
  let ids;
  switch (level) {
    case 0: ids = ['let_it_run']; break;
    case 1: ids = ['receipt', 'enrich']; break;
    case 2: ids = ['receipt', 'enrich', 'verify', 'hold']; break;
    default: ids = ['receipt', 'enrich', 'verify', 'hold', 'ask_human', 'howler']; break;
  }
  const responses = ids.map((id) => RESPONSES[id]);
  const primary_route = ids[ids.length - 1];

  const disposition = decideDisposition(level, phase);
  return { level, phase, responses, primary_route, disposition };
}

/**
 * The disposition is the effect decision. Carnac never commits the effect here;
 * it decides whether the effect may proceed, must wait for confirmation, or is
 * withheld and escalated. Inference return is kept separate from effect
 * commitment so an outage cannot imply a universal denial of service.
 */
export function decideDisposition(level, phase) {
  const preEffect = phase === 'effect' || phase === 'output';
  if (level <= 0) {
    return { state: 'allow', requires_confirmation: false, escalated: false, effect_committed: false };
  }
  if (level === 1) {
    return { state: 'allow_with_receipt', requires_confirmation: false, escalated: false, effect_committed: false };
  }
  if (level === 2) {
    return {
      state: 'hold_for_confirmation',
      requires_confirmation: true,
      escalated: false,
      effect_committed: false,
      prevention: preEffect,
    };
  }
  return {
    state: 'hold_and_escalate',
    requires_confirmation: true,
    escalated: true,
    effect_committed: false,
    prevention: preEffect,
  };
}
