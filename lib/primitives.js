// lib/primitives.js
//
// Single source of truth for the public primitive catalog surfaced at
// GET /v1/primitives and exercised by GET /v1/primitives/smoke and
// scripts/smoke.mjs.
//
// The catalog is truthful by construction. Each entry declares a status:
//
//   runnable   public, credential-free, executes fully in one call
//   gated      public, but completion requires an x402 payment header
//   protected  requires a tenant-scoped bearer credential
//   catalog    declared surface whose live path needs external configuration
//              (for example the external Hive typed signer) and therefore is
//              not exercisable on the public deployment today
//
// Only entries marked "runnable" are claimed as a self-contained public demo.
// Nothing here asserts that a protected or catalog entry is live.
//
// Content rules for every string in this file: no em dashes; the product marks
// Carnac Live Ink is written with its mark; the words that describe a ruling are
// avoided in prose. Carnac reads consequence and composes a signed disposition.
// It does not judge.

export const PRIMITIVES_VERSION = 'primitives-v1';

// A curl sample is a function of the deployment base URL so the catalog stays
// correct whether it is read locally or against the live host.
function curl(method, path, body) {
  return (base) => {
    const url = `${base}${path}`;
    if (method === 'GET') return `curl -s ${url}`;
    const json = body ? ` -d '${JSON.stringify(body)}'` : '';
    return `curl -s -X ${method} ${url} -H 'content-type: application/json'${json}`;
  };
}

// Small, valid sample bodies reused by the smoke runner so the documented curl
// and the live self-check exercise the same shapes.
export const SAMPLES = {
  frame: {
    input_text: 'Ship 5 units to Acme by Friday.',
    anchors: [{ anchor_id: 'a0', start: 0, end: 11 }],
    edges: [{ src: 'a0', tgt: 'a0', rel: 'supports' }],
    demands: [{ anchor_id: 'a0', level: 'attest' }],
    bindings: [],
    action: { action_type: 'ship', target: 'acme' },
  },
  cueEdge: { src: 'a0', tgt: 'a1', rel: 'supports' },
  prefill: { anchor_set: { anchors: [] }, proof_demand_root: { demands: [] }, local_index: {} },
  sandbox: { request: 'delete all production data', phase: 'formation' },
  deliveredAction: { action_type: 'ship', target: 'acme' },
};

export const PRIMITIVES = [
  // ── Carnac Live Ink™ / InkFrame v1 substrate (public, credential-free) ──────
  {
    id: 'inkframe.frame',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'Build and sign a content-addressed frame',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/inkframe/frame',
    auth: 'none',
    description: 'Commits input, anchors, typed cue graph, proof demands, evidence, an action envelope, and lineage into one hybrid-signed frame (Ed25519 plus ML-DSA-65, RFC 8785 JCS over SHA-256). Self-verifies before returning.',
    sample_curl: curl('POST', '/v1/inkframe/frame', SAMPLES.frame),
  },
  {
    id: 'inkframe.cue_edge',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'Validate a single typed cue edge',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/inkframe/cue-edge',
    auth: 'none',
    description: 'Validates one typed edge {src, tgt, rel} against the allowed relation set (supports, contradicts, supersedes, enables) and returns its content address. No scoring.',
    sample_curl: curl('POST', '/v1/inkframe/cue-edge', SAMPLES.cueEdge),
  },
  {
    id: 'inkframe.prefill',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'Proof Pre-Fill by fingerprint',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/inkframe/prefill',
    auth: 'none',
    description: 'Resolves proof demands against a local index by span fingerprint only, returning bindings ready to attach before an action fires. Raw span text never transits.',
    sample_curl: curl('POST', '/v1/inkframe/prefill', SAMPLES.prefill),
  },
  {
    id: 'inkframe.replay',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'Disclosure-free replay manifest',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/inkframe/replay',
    auth: 'none',
    description: 'Builds and verifies a replay manifest from a signed frame plus cue deltas. Deltas carrying raw text are refused before the manifest is built, so replay stays disclosure-free.',
    sample_curl: curl('POST', '/v1/inkframe/replay', { signed_frame: '<signed_frame from /frame>', deltas: [] }),
  },
  {
    id: 'inkframe.countersign',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'Arrival countersignature',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/inkframe/countersign',
    auth: 'none',
    description: 'Compares the approved action tuple inside a signed frame against the action actually delivered. On a match the gateway countersigns; on a mismatch it records the delta and signs a refusal.',
    sample_curl: curl('POST', '/v1/inkframe/countersign', { signed_frame: '<signed_frame from /frame>', delivered_action: SAMPLES.deliveredAction }),
  },
  {
    id: 'inkframe.health',
    family: 'Carnac Live Ink™ (InkFrame v1)',
    label: 'InkFrame liveness and signer public keys',
    status: 'runnable',
    method: 'GET',
    endpoint: '/v1/inkframe/health',
    auth: 'none',
    description: 'Reports version, standards, and the signer and gateway public keys (Ed25519 and ML-DSA-65) so any party can verify frames offline.',
    sample_curl: curl('GET', '/v1/inkframe/health'),
  },

  // ── Carnac™ reading plane (public, credential-free) ─────────────────────────
  {
    id: 'carnac.sandbox',
    family: 'Carnac™',
    label: 'No-effect consequence read (sandbox)',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/carnac/sandbox',
    auth: 'none',
    description: 'Reads consequence across a request lifecycle, applies the governed floor, composes a route and a signed disposition, and returns it. Never durable, never commits an effect. It does not judge.',
    sample_curl: curl('POST', '/v1/carnac/sandbox', SAMPLES.sandbox),
  },
  {
    id: 'carnac.policy',
    family: 'Carnac™',
    label: 'Current governed floor',
    status: 'runnable',
    method: 'GET',
    endpoint: '/v1/carnac/policy',
    auth: 'none',
    description: 'Returns the public-safe fields of the current governed floor: version, per-category floor levels, and bounds.',
    sample_curl: curl('GET', '/v1/carnac/policy'),
  },
  {
    id: 'carnac.verify',
    family: 'Carnac™',
    label: 'Verify a signed artifact by value',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/carnac/verify',
    auth: 'none',
    description: 'Re-checks the Ed25519 signature (and any bound ML-DSA-65 sibling) of a complete artifact submitted by value. Returns cryptographic validity only.',
    sample_curl: curl('POST', '/v1/carnac/verify', { artifact: '<signed artifact>' }),
  },
  {
    id: 'carnac.lifecycle_verify',
    family: 'Carnac™',
    label: 'Verify a lifecycle chain by value',
    status: 'runnable',
    method: 'POST',
    endpoint: '/v1/carnac/lifecycle/verify',
    auth: 'none',
    description: 'Recomputes every stage digest and chain head, verifies each finalized signature over the canonical core, and checks Merkle inclusion. No credentials and no plaintext required.',
    sample_curl: curl('POST', '/v1/carnac/lifecycle/verify', { stages: [] }),
  },
  {
    id: 'carnac.health',
    family: 'Carnac™',
    label: 'Carnac compute, ledger, signer, and readiness',
    status: 'runnable',
    method: 'GET',
    endpoint: '/v1/carnac/health',
    auth: 'none',
    description: 'Reports compute, durable ledger, post-quantum signer, governed floor, and readiness flags. Distinguishes the always-available public sandbox from protected routes that need durable and post-quantum configuration.',
    sample_curl: curl('GET', '/v1/carnac/health'),
  },

  // Receipt / SiGR (public read; signing is x402 gated)
  {
    id: 'receipt.verify',
    family: 'SiGR receipts',
    label: 'Verify a signed receipt by id',
    status: 'runnable',
    method: 'GET',
    endpoint: '/v1/receipt/verify/:receipt_id',
    auth: 'none',
    description: 'Re-verifies the Ed25519 signature of a stored receipt envelope against its embedded public key. Free. Returns 404 for an unknown id.',
    sample_curl: curl('GET', '/v1/receipt/verify/UNKNOWN_ID'),
  },
  {
    id: 'receipt.list',
    family: 'SiGR receipts',
    label: 'List receipts for a payer',
    status: 'runnable',
    method: 'GET',
    endpoint: '/v1/receipt/list/:payer_did',
    auth: 'none',
    description: 'Returns the receipts recorded for a payer DID. Free public read.',
    sample_curl: curl('GET', '/v1/receipt/list/did:hive:demo'),
  },
  {
    id: 'receipt.sign',
    family: 'SiGR receipts',
    label: 'Sign a payment receipt',
    status: 'gated',
    method: 'POST',
    endpoint: '/v1/receipt/sign',
    auth: 'x402',
    description: 'Issues a Spectral Ed25519-signed receipt after best-effort on-chain verification. Without an X-PAYMENT header the endpoint returns a well-formed x402 challenge, which is itself demonstrable without credentials.',
    sample_curl: curl('POST', '/v1/receipt/sign', { tx_hash: '0x1', network: 'base' }),
  },

  // ── MCP (public) ────────────────────────────────────────────────────────────
  {
    id: 'mcp.tools',
    family: 'MCP',
    label: 'MCP JSON-RPC tool surface',
    status: 'runnable',
    method: 'POST',
    endpoint: '/mcp',
    auth: 'none',
    description: 'JSON-RPC 2.0 endpoint exposing tools/list and tools/call. The carnac_verify and sandbox reader tools run credential-free; sign_receipt returns its x402 challenge.',
    sample_curl: curl('POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  },

  // ── Protected Carnac™ routes (require a tenant-scoped bearer) ────────────────
  // The durable tenant-scoped read exists for compatibility but is intentionally
  // omitted from this public catalog: its legacy route identifier is not surfaced
  // in discovery. The durable path is reached through the protected surface, not
  // through public discovery.
  {
    id: 'carnac.export',
    family: 'Carnac™',
    label: 'Tenant-scoped audit export',
    status: 'protected',
    method: 'GET',
    endpoint: '/v1/carnac/export',
    auth: 'bearer+tenant',
    description: 'Tenant-scoped audit export as JSON or CSV. Requires a bearer credential.',
    sample_curl: null,
  },
  {
    id: 'carnac.seal',
    family: 'Carnac™',
    label: 'Continuity seal over a trajectory',
    status: 'protected',
    method: 'POST',
    endpoint: '/v1/carnac/seal',
    auth: 'bearer+tenant',
    description: 'Signs a continuity checkpoint over a tenant trajectory. Requires a bearer credential.',
    sample_curl: null,
  },
  {
    id: 'carnac.lifecycle',
    family: 'Carnac™',
    label: 'Lifecycle open, append, and finalize',
    status: 'protected',
    method: 'POST',
    endpoint: '/v1/carnac/lifecycle/open',
    auth: 'bearer+tenant',
    description: 'Opens a signed lifecycle chain and appends typed stages for one inference from prompt boundary through downstream effect. Public verification of the resulting chain is credential-free at /v1/carnac/lifecycle/verify.',
    sample_curl: null,
  },

  // ── External typed signer (declared; live path needs configuration) ──────────
  {
    id: 'carnac.typed_signer',
    family: 'Carnac™',
    label: 'ML-DSA-65 typed signer',
    status: 'catalog',
    method: 'GET',
    endpoint: '/v1/carnac/health',
    auth: 'external',
    description: 'Post-quantum ML-DSA-65 signing is provided by the external Hive typed signer. Its live availability is reported by the pq block of Carnac health; when unconfigured it reports available:false and protected routes stay closed rather than signing without it.',
    sample_curl: curl('GET', '/v1/carnac/health'),
  },
];

// Public projection: resolve each curl sample against a base URL and drop the
// function. Safe to serialize.
export function catalog(base = '') {
  const primitives = PRIMITIVES.map((p) => ({
    id: p.id,
    family: p.family,
    label: p.label,
    status: p.status,
    method: p.method,
    endpoint: p.endpoint,
    auth: p.auth,
    description: p.description,
    sample_curl: typeof p.sample_curl === 'function' ? p.sample_curl(base) : null,
  }));
  const counts = primitives.reduce((acc, p) => {
    acc[p.status] = (acc[p.status] || 0) + 1;
    return acc;
  }, {});
  return {
    service: 'hive-receipt',
    catalog_version: PRIMITIVES_VERSION,
    base_url: base || null,
    counts,
    note: 'status runnable means public, credential-free, and exercisable in one call. Exercise the runnable set live at GET /v1/primitives/smoke.',
    smoke_endpoint: '/v1/primitives/smoke',
    primitives,
  };
}
