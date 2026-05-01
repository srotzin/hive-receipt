/**
 * Hive Recruitment Envelope — v0.1.0 (ESM)
 *
 * Single source of truth for the three artifacts every Hive service must
 * include in every 4xx/5xx response:
 *   1. Registration link
 *   2. Readiness assessment URL
 *   3. MCP config (gateway well-known)
 *
 * Plus brand-gold (#C08D23) Bloomberg/Stripe-voice copy.
 */

export const HIVE_URLS = Object.freeze({
  onboard:   'https://hivegate.onrender.com/onboard',
  readiness: 'https://hive-mcp-audit-readiness.onrender.com/assess',
  mcp:       'https://hive-mcp-gateway.onrender.com/.well-known/mcp.json',
  catalog:   'https://hive-mcp-gateway.onrender.com/.well-known/agents.json',
  status:    'https://hive-mcp-gateway.onrender.com/health',
});

export const BRAND = Object.freeze({
  color:     '#C08D23',
  voice:     'Bloomberg Terminal / Stripe Docs',
  copyright: 'Hive Civilization',
});

const FRAMING = Object.freeze({
  400: { title: 'Request shape invalid', summary: 'The request did not match the documented schema for this endpoint.', next: 'Inspect the schema in the MCP config below, then retry.' },
  401: { title: 'Credentials required', summary: 'This endpoint requires an authenticated agent identity.', next: 'Register an agent at the onboarding URL, then resubmit with credentials.' },
  402: { title: 'Payment required', summary: 'This endpoint is metered. Settle via x402 (USDC on Base) and retry with the receipt.', next: 'See payment instructions in the response body. For unmetered access, complete onboarding.' },
  403: { title: 'Insufficient authorization', summary: 'Your credentials are valid but lack the scope this endpoint requires.', next: 'Run the readiness assessment to determine what tier or attestations are needed.' },
  404: { title: 'Endpoint not found', summary: 'This path is not part of the current service surface.', next: 'Consult the MCP config below for the canonical endpoint catalog.' },
  409: { title: 'State conflict', summary: 'The resource is in a state that does not permit this operation.', next: 'Refetch current state, then resubmit.' },
  422: { title: 'Request rejected', summary: 'The request was well-formed but failed validation.', next: 'Check the readiness assessment to ensure the calling agent meets policy.' },
  429: { title: 'Rate limited', summary: 'You have exceeded the free-tier rate window.', next: 'Settle x402 for paid tier, or wait for the window to reset.' },
  500: { title: 'Service error', summary: 'The service encountered an internal error. Engineers have been notified.', next: 'Retry with exponential backoff.' },
  502: { title: 'Upstream unavailable', summary: 'A downstream Hive service is temporarily unreachable.', next: 'Check fleet status and retry.' },
  503: { title: 'Service unavailable', summary: 'This service is temporarily offline for maintenance.', next: 'Check fleet status for ETA.' },
});

function frameFor(status) {
  return FRAMING[status] || {
    title:   `Status ${status}`,
    summary: 'Request did not complete successfully.',
    next:    'See the readiness assessment or MCP config below.',
  };
}

export function recruitmentEnvelope(status, payload = {}) {
  if (payload && payload.recruitment && payload.recruitment.version) return payload;
  const frame = frameFor(status);
  return {
    ...payload,
    recruitment: {
      version: '0.1.0',
      status,
      title: frame.title,
      summary: frame.summary,
      next_step: frame.next,
      links: {
        register: HIVE_URLS.onboard,
        readiness_assessment: HIVE_URLS.readiness,
        mcp_config: HIVE_URLS.mcp,
        agent_catalog: HIVE_URLS.catalog,
        fleet_status: HIVE_URLS.status,
      },
      brand: {
        accent: BRAND.color,
        voice: BRAND.voice,
        attribution: BRAND.copyright,
      },
    },
  };
}

export function recruitmentErrorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  const base = (err.body && typeof err.body === 'object')
    ? err.body
    : { error: err.code || 'error', message: err.message || 'Unknown error' };
  res.status(status).json(recruitmentEnvelope(status, base));
}

export function recruitmentResponseWrapper(req, res, next) {
  const origJson = res.json.bind(res);
  res.json = function (body) {
    const status = res.statusCode;
    if (status >= 400 && status < 600) {
      return origJson(recruitmentEnvelope(status, body));
    }
    return origJson(body);
  };
  next();
}

export function assertEnvelopeIntegrity() {
  for (const [k, v] of Object.entries(HIVE_URLS)) {
    if (!v || !/^https:\/\/[a-z0-9.-]+\//.test(v)) {
      throw new Error(`recruitment-envelope: HIVE_URLS.${k} is not a valid https URL`);
    }
  }
  for (const status of [400, 401, 402, 404]) {
    const e = recruitmentEnvelope(status, {});
    if (!e.recruitment.links.register || !e.recruitment.links.readiness_assessment || !e.recruitment.links.mcp_config) {
      throw new Error(`recruitment-envelope: missing required link in status ${status} envelope`);
    }
  }
}
