import express from 'express';
import crypto from 'crypto';
import { initKeypair, getPublicKeyB64, signPayload, verifyEnvelope } from './lib/spectral.js';
import { verifyOnChain } from './lib/onchain.js';
import mppMiddleware from './middleware/mpp.js';
import {
  recruitmentEnvelope,
  recruitmentResponseWrapper,
  recruitmentErrorHandler,
  assertEnvelopeIntegrity,
} from './middleware/recruitment.js';
import { buildIntelligence } from './lib/intelligence.js';
import { fetchEvents, insertHit } from './lib/site_store.js';
import { checkOwnerAuth, getConfiguredToken } from './lib/owner_auth.js';
import { judge, verifyJudgment, currentPolicy } from './lib/carnac/engine.js';
import { amendPolicy } from './lib/carnac/policy.js';
import { fetchJudgment, listByTrajectoryDurable, ledgerHealth } from './lib/carnac/ledger.js';
import { computeHealth } from './lib/carnac/compute.js';
import { authenticateCarnac, tenantScopeAllows, carnacAuthConfigured, SANDBOX_TENANT } from './lib/carnac/auth.js';
import { pqHealth } from './lib/carnac/pqsign.js';
import { recordDisposition, listDispositions } from './lib/carnac/dispositions.js';
import { fetchHowler, verifyHowler } from './lib/carnac/howler_store.js';
import { verifyArtifact, verifyById } from './lib/carnac/verify.js';
import { buildExport, exportToCsv } from './lib/carnac/export.js';
import { sealTrajectory } from './lib/carnac/seal.js';
import { sandboxDispatchTrace } from './lib/carnac/dispatch.js';
import {
  openLifecycle,
  appendStage,
  getLifecycle,
  verifyLifecycle,
  drainFinalize,
  startFinalizer,
} from './lib/carnac/lifecycle.js';
import { makeInkframeRouter } from './lib/inkframe/routes.js';
assertEnvelopeIntegrity();

const app = express();
app.use(express.json());
app.use(recruitmentResponseWrapper);

// ─── CORS middleware ──────────────────────────────────────────────────────────
// Carnac routes use route-specific, allowlisted CORS (NEVER wildcard) so a
// protected route can never be invoked cross-origin from an arbitrary site. The
// public sandbox remains callable from the marketing site and local dev. The
// rest of the service keeps its existing wildcard posture, unchanged.
const CARNAC_PUBLIC_ORIGINS = () => {
  const base = [
    'https://thehiveryiq.com',
    'https://www.thehiveryiq.com',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
  ];
  const extra = (process.env.CARNAC_PUBLIC_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return new Set([...base, ...extra]);
};

app.use('/v1/carnac', (req, res, next) => {
  const origin = req.headers.origin;
  const allowed = CARNAC_PUBLIC_ORIGINS();
  if (origin && allowed.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Carnac-Tenant');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(origin && allowed.has(origin) ? 204 : 403);
  next();
});

app.use((req, res, next) => {
  // Carnac handles its own (non-wildcard) CORS above.
  if (req.path.startsWith('/v1/carnac')) return next();
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Payment, X-Did, X-Signature');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});


const PORT = process.env.PORT || 3000;
const MONROE = '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK = 'base';
const CHAIN_ID = 8453;

// Pricing (USDC 6-decimal atomic)
const PRICE_STANDARD = 1000;   // $0.001
const PRICE_AUDIT    = 100000; // $0.10

// In-memory receipt store (Phase 1)
const receiptStore = new Map();  // receipt_id -> envelope
const payerIndex   = new Map();  // payer_did -> receipt_id[]

// Init ed25519 keypair
initKeypair();

// ── helpers ──────────────────────────────────────────────────────────────────

function make402Challenge(tier, resource) {
  const amount = tier === 'audit' ? PRICE_AUDIT : PRICE_STANDARD;
  const desc   = tier === 'audit'
    ? 'Hive universal receipt — audit grade with 7-year retention guarantee.'
    : 'Hive universal receipt signature — $0.001 per receipt.';
  return {
    scheme: 'exact',
    network: NETWORK,
    chainId: CHAIN_ID,
    asset: 'USDC',
    contract: USDC_BASE,
    maxAmountRequired: String(amount),
    payTo: MONROE,
    resource,
    description: desc,
    mimeType: 'application/json'
  };
}

function generateReceiptId() {
  return crypto.randomBytes(16).toString('hex');
}

// ── routes ───────────────────────────────────────────────────────────────────


// ─── MPP OpenAPI Discovery (public) ──────────────────────────────────────────
// Required for MPPScan auto-discovery and mppx compatibility
app.get('/openapi.json', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({
    openapi: '3.0.3',
    info: {
      title: 'Hive Receipt — Spectral-Signed Payment Receipt Service',
      version: '1.0.0',
      description: 'Stream B/E receipt attestation service. Ed25519 Spectral-signed receipts, on-chain verification. USDC on Tempo/Base. Accepts x402 and MPP rails.',
      contact: { name: 'Hive Civilization', url: 'https://thehiveryiq.com', email: 'steve@thehiveryiq.com' },
    },
    servers: [{ url: 'https://hive-receipt.onrender.com' }],
    'x-mpp': {
      realm: 'hive-receipt.onrender.com',
      payment: { method: 'tempo', currency: '0x20c000000000000000000000b9537d11c60e8b50', decimals: 6, recipient: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E' },
      rails: ['x402', 'mpp'],
      categories: ['receipts', 'attestation'],
      integration: 'first-party',
      tags: ['receipt', 'attestation', 'spectral', 'payment', 'stream-b', 'stream-e'],
      treasury: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
    },
    paths: {
      '/v1/receipt/sign': {
        post: {
          summary: 'Sign a receipt',
          description: 'Issue a Spectral-signed payment receipt. $0.05 USDC.',
          'x-mpp-charge': { amount: '50000', intent: 'charge' },
          responses: { '200': { description: 'Signed receipt' }, '402': { description: 'Payment required — x402 or MPP' } },
        },
      },
      '/v1/receipt/batch': {
        post: {
          summary: 'Batch receipt signing',
          description: 'Sign a batch of receipts. $0.50 USDC per batch.',
          'x-mpp-charge': { amount: '500000', intent: 'charge' },
          responses: { '200': { description: 'Batch signed' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/receipt/audit': {
        post: {
          summary: 'Audit-grade receipt',
          description: 'Issue a receipt with 7-year retention. $0.10 USDC.',
          'x-mpp-charge': { amount: '100000', intent: 'charge' },
          responses: { '200': { description: 'Audit receipt issued' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/receipt/attest': {
        post: {
          summary: 'Attestation',
          description: 'Attest a payment event. $0.10 USDC.',
          'x-mpp-charge': { amount: '100000', intent: 'charge' },
          responses: { '200': { description: 'Attestation issued' }, '402': { description: 'Payment required' } },
        },
      },
      '/v1/receipt/verify/:receipt_id': {
        get: {
          summary: 'Verify receipt',
          description: 'Verify a receipt by ID. Free.',
          responses: { '200': { description: 'Verification result' } },
        },
      },
    },
  });
});

// MPP rail — runs after x402, grants access via MPP Payment header
// Payment: scheme="mpp", tx_hash="0x...", rail="tempo", amount="0.05"
// IETF draft-ryan-httpauth-payment compliant. Tempo + Base mainnet only.
app.use('/v1', mppMiddleware);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'hive-receipt', version: '1.0.0', ts: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.json({
    service: 'hive-receipt',
    description: 'Universal Spectral-signed payment receipts. x402 gated. Real on-chain verification.',
    spectral_pubkey: getPublicKeyB64(),
    monroe: MONROE,
    pricing: {
      standard_atomic: PRICE_STANDARD,
      standard_usd: '$0.001',
      audit_atomic: PRICE_AUDIT,
      audit_usd: '$0.10 — 7-year retention guarantee'
    },
    carnac: {
      description: 'Judgment & routing plane. Reads consequence across a request lifecycle, composes a signed disposition, never commits the effect itself.',
      sandbox: '/v1/carnac/sandbox',
      judge: '/v1/carnac/judge',
      health: '/v1/carnac/health',
      policy: '/v1/carnac/policy',
    },
    docs: 'https://github.com/srotzin/hive-receipt'
  });
});

app.get('/.well-known/agent.json', (_req, res) => {
  res.json({
    name: 'hive-receipt',
    version: '1.0.0',
    description: 'Universal Spectral-signed payment receipts. On-chain verification for Base, Ethereum, Solana. Offline-verifiable via ed25519 pubkey.',
    brand_color: '#C08D23',
    payment: {
      protocol: 'x402',
      network: NETWORK,
      chain_id: CHAIN_ID,
      asset: 'USDC',
      contract: USDC_BASE,
      payTo: MONROE,
      standard_amount_atomic: PRICE_STANDARD,
      audit_amount_atomic: PRICE_AUDIT
    },
    spectral: {
      public_key: getPublicKeyB64(),
      signature_algo: 'ed25519',
      verify_endpoint: '/v1/receipt/verify/:receipt_id'
    },
    mcp_endpoint: '/mcp',
    tools: ['sign_receipt', 'verify_receipt', 'list_my_receipts', 'carnac_judge', 'carnac_verify']
  });
});

// MCP JSON-RPC
app.post('/mcp', async (req, res) => {
  const { jsonrpc, id, method, params } = req.body || {};
  if (jsonrpc !== '2.0') {
    return res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
  }

  if (method === 'tools/list') {
    return res.json({
      jsonrpc: '2.0', id,
      result: {
        tools: [
          {
            name: 'sign_receipt',
            description: 'Sign a payment receipt. Verifies the tx on-chain (best-effort) and returns a Spectral ed25519-signed envelope. Requires x402 payment — use POST /v1/receipt/sign with X-PAYMENT header.',
            inputSchema: {
              type: 'object',
              required: ['tx_hash', 'network', 'expected_recipient', 'expected_amount_atomic', 'expected_asset'],
              properties: {
                tx_hash: { type: 'string', description: 'On-chain transaction hash or signature.' },
                network: { type: 'string', enum: ['base', 'ethereum', 'solana'], description: 'Network where the tx occurred.' },
                expected_recipient: { type: 'string', description: 'Expected recipient address or pubkey.' },
                expected_amount_atomic: { type: 'integer', description: 'Expected amount in atomic units.' },
                expected_asset: { type: 'string', description: 'Asset symbol (USDC, USDT, SOL, etc.).' },
                payer_did: { type: 'string', description: 'DID of the payer.' },
                payee_did: { type: 'string', description: 'DID of the payee.' }
              }
            }
          },
          {
            name: 'verify_receipt',
            description: 'Verify a Spectral-signed receipt envelope by receipt_id. Re-verifies the ed25519 signature against the embedded pubkey.',
            inputSchema: {
              type: 'object',
              required: ['receipt_id'],
              properties: {
                receipt_id: { type: 'string' }
              }
            }
          },
          {
            name: 'list_my_receipts',
            description: 'List all receipts for a given payer DID.',
            inputSchema: {
              type: 'object',
              required: ['payer_did'],
              properties: {
                payer_did: { type: 'string' }
              }
            }
          },
          {
            name: 'carnac_judge',
            description: 'Read consequence on a request in the Carnac judgment plane (public no-effect sandbox). Classifies the text, applies the governed floor, composes a route and disposition, and returns a signed judgment envelope. Never commits any effect. For a durable ruling use POST /v1/carnac/judge.',
            inputSchema: {
              type: 'object',
              required: ['request'],
              properties: {
                request: { type: 'string', description: 'The forming request text to read.' },
                output: { type: 'string', description: 'Produced output text (output/effect phases).' },
                phase: { type: 'string', enum: ['formation', 'invocation', 'output', 'effect'], description: 'Lifecycle phase of the read.' },
                trajectory_id: { type: 'string', description: 'Bind the read to a trajectory to enforce lifecycle order.' },
                seq: { type: 'integer', description: 'Monotonic read sequence within the trajectory.' }
              }
            }
          },
          {
            name: 'carnac_verify',
            description: 'Verify a Carnac judgment (or Howler) envelope by re-checking its ed25519 signature against the embedded public key.',
            inputSchema: {
              type: 'object',
              required: ['judgment_id'],
              properties: {
                judgment_id: { type: 'string' }
              }
            }
          }
        ]
      }
    });
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};

    if (toolName === 'sign_receipt') {
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              note: 'sign_receipt requires x402 payment. Use POST /v1/receipt/sign with X-PAYMENT header.',
              x402_challenge: make402Challenge('standard', '/v1/receipt/sign')
            })
          }]
        }
      });
    }

    if (toolName === 'verify_receipt') {
      const { receipt_id } = toolArgs;
      const envelope = receiptStore.get(receipt_id);
      if (!envelope) {
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ error: 'receipt not found' }) }] } });
      }
      const verification = verifyEnvelope(envelope);
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ ...envelope, signature_valid: verification.valid }) }] } });
    }

    if (toolName === 'list_my_receipts') {
      const { payer_did } = toolArgs;
      const ids = payerIndex.get(payer_did) || [];
      const receipts = ids.map(id => receiptStore.get(id)).filter(Boolean).map(e => ({
        receipt_id: e.receipt_id, tx_hash: e.tx_hash, network: e.network,
        verified: e.verified, generated_at: e.generated_at
      }));
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ payer_did, count: receipts.length, receipts }) }] } });
    }

    if (toolName === 'carnac_judge') {
      const result = await judge({
        request: toolArgs.request,
        output: toolArgs.output,
        phase: toolArgs.phase,
        trajectory_id: toolArgs.trajectory_id,
        seq: toolArgs.seq,
      }, { sandbox: true });
      if (!result.ok) {
        return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ error: result.code, message: result.message }) }] } });
      }
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ sandbox: true, judgment: result.envelope, howler: result.howler }) }] } });
    }

    if (toolName === 'carnac_verify') {
      // Public-safe: return only cryptographic validity + a non-sensitive
      // projection. Never leak tenant identity or unrelated ledger fields.
      const result = await verifyById(toolArgs.judgment_id, { client: 'mcp' });
      const body = result.ok
        ? { found: result.found, signature_valid: result.signature_valid, pq: result.pq, artifact: result.artifact || null }
        : { error: result.code, message: result.message };
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(body) }] } });
    }

    return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
  }

  return res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
});

// ── REST endpoints ────────────────────────────────────────────────────────────

// POST /v1/receipt/sign — gated by x402
app.post('/v1/receipt/sign', async (req, res) => {
  const xPayment = req.headers['x-payment'];
  const tier = req.query.tier === 'audit' ? 'audit' : 'standard';
  const requiredAmount = tier === 'audit' ? PRICE_AUDIT : PRICE_STANDARD;

  // x402 gate
  if (!xPayment) {
    res.status(402).set({ 'X-Payment-Required': 'true', 'Content-Type': 'application/json' });
    return res.json({
      x402_version: '0.2.0',
      error: 'Payment Required',
      accepts: [make402Challenge(tier, `/v1/receipt/sign${tier === 'audit' ? '?tier=audit' : ''}`)]
    });
  }

  const {
    tx_hash, network, expected_recipient,
    expected_amount_atomic, expected_asset,
    payer_did, payee_did
  } = req.body || {};

  if (!tx_hash || !network) {
    return res.status(400).json({ error: 'tx_hash and network required' });
  }

  // On-chain verification (best-effort)
  const onchain = await verifyOnChain({
    tx_hash, network, expected_recipient,
    expected_amount_atomic, expected_asset
  });

  const receipt_id = generateReceiptId();
  const generated_at = new Date().toISOString();

  // Build payload for signing
  const payload = {
    receipt_id,
    tx_hash,
    network,
    expected_recipient: expected_recipient || null,
    expected_amount_atomic: expected_amount_atomic || null,
    expected_asset: expected_asset || null,
    payer_did: payer_did || null,
    payee_did: payee_did || null,
    verified: onchain.verified,
    verification_attempted: onchain.verification_attempted,
    verification_status: onchain.verification_status,
    tier,
    generated_at
  };

  const sigData = signPayload(payload);

  const envelope = {
    ...payload,
    ...sigData
  };

  // Store
  receiptStore.set(receipt_id, envelope);
  if (payer_did) {
    if (!payerIndex.has(payer_did)) payerIndex.set(payer_did, []);
    payerIndex.get(payer_did).push(receipt_id);
  }

  res.json(envelope);
});

// GET /v1/receipt/verify/:receipt_id
app.get('/v1/receipt/verify/:receipt_id', (req, res) => {
  const envelope = receiptStore.get(req.params.receipt_id);
  if (!envelope) return res.status(404).json({ error: 'receipt not found' });
  const verification = verifyEnvelope(envelope);
  res.json({ ...envelope, signature_valid: verification.valid, signature_error: verification.error || null });
});

// GET /v1/receipt/list/:payer_did
app.get('/v1/receipt/list/:payer_did', (req, res) => {
  const payer_did = req.params.payer_did;
  const ids = payerIndex.get(payer_did) || [];
  const receipts = ids.map(id => receiptStore.get(id)).filter(Boolean);
  res.json({ payer_did, count: receipts.length, receipts });
});

// ── Carnac judgment & routing plane ───────────────────────────────────────────
// The judgment plane reads consequence across a request's lifecycle and composes
// a signed disposition. It never commits the effect itself. See docs/carnac.md.
//
// Public (no auth):
//   POST /v1/carnac/sandbox        no-effect read (never durable, fixed sandbox tenant)
//   GET  /v1/carnac/policy         current governed floor (public-safe fields)
//   POST /v1/carnac/verify         verify a complete signed artifact by value
//   GET  /v1/carnac/verify/:id     verify a stored judgment by id (rate-limited)
//   GET  /v1/carnac/health         compute + durable ledger + PQ signer + policy + readiness
// Protected (constant-time bearer; tenant-scoped, existence never leaked):
//   POST /v1/carnac/judge          real read (durable ledger, PQ-signed, may mint a Howler)
//   GET  /v1/carnac/judgment/:id   fetch + re-verify a prior judgment
//   GET  /v1/carnac/trajectory/:id durable, tenant-scoped, ordered trajectory listing
//   POST /v1/carnac/policy/amend   governed PolicyAmendment (attestor-signed)
//   POST /v1/carnac/disposition    append-only human/actor disposition
//   GET  /v1/carnac/howler/:id     fetch + verify a Howler and its judgment binding
//   GET  /v1/carnac/export         tenant-scoped audit export (JSON or CSV)
//   POST /v1/carnac/seal           sign a continuity checkpoint over a trajectory

function carnacBadInput(res, result) {
  return res.status(result.status || 400).json({ error: result.code, message: result.message });
}

// Authenticate a protected Carnac request. On failure it writes the response and
// returns null; callers must stop. Existence is never leaked because auth is
// resolved before any record lookup.
function requireCarnacAuth(req, res, { requireTenant = false } = {}) {
  const auth = authenticateCarnac(req, { requireTenant });
  if (!auth.ok) {
    res.status(auth.status).json({ error: auth.code, message: auth.message });
    return null;
  }
  return auth;
}

// Pseudonymous per-client id for verification rate limiting — the raw IP is
// never stored, only a truncated salted hash.
function verifyClientId(req) {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '';
  return crypto.createHash('sha256').update(`carnac-verify|${ip}`).digest('hex').slice(0, 32);
}

app.post('/v1/carnac/sandbox', async (req, res) => {
  try {
    const result = await judge(req.body || {}, { sandbox: true });
    if (!result.ok) return carnacBadInput(res, result);
    res.json({
      sandbox: true,
      judgment: result.envelope,
      howler: result.howler,
      ledger: result.ledger,
      idempotent_replay: Boolean(result.idempotent_replay),
      dispatch: sandboxDispatchTrace(result.envelope),
    });
  } catch (e) {
    res.status(500).json({ error: 'carnac_error', message: e.message });
  }
});

app.post('/v1/carnac/judge', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  try {
    const result = await judge(req.body || {}, {
      sandbox: false,
      tenant_id: auth.tenant_id,
      actor: auth.actor,
      requireTenant: true,
      requirePQ: true,
      enforceContinuity: Boolean(req.body && req.body.trajectory_id),
    });
    if (!result.ok) return carnacBadInput(res, result);
    res.json({
      sandbox: false,
      judgment: result.envelope,
      howler: result.howler,
      ledger: result.ledger,
      idempotent_replay: Boolean(result.idempotent_replay),
    });
  } catch (e) {
    res.status(500).json({ error: 'carnac_error', message: e.message });
  }
});

app.get('/v1/carnac/judgment/:id', async (req, res) => {
  const auth = requireCarnacAuth(req, res);
  if (!auth) return;
  const envelope = await fetchJudgment(req.params.id);
  // A record the caller may not see is indistinguishable from a missing one.
  if (!envelope || !tenantScopeAllows(auth, envelope.tenant_id || null)) {
    return res.status(404).json({ error: 'not_found', message: 'judgment not found' });
  }
  const verification = verifyJudgment(envelope);
  res.json({ judgment: envelope, signature_valid: verification.valid, signature_error: verification.error || null });
});

app.get('/v1/carnac/trajectory/:id', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const { source, judgments } = await listByTrajectoryDurable(auth.tenant_id, req.params.id);
  res.json({ trajectory_id: req.params.id, tenant_id: auth.tenant_id, source, count: judgments.length, judgments });
});

app.get('/v1/carnac/policy', (_req, res) => {
  res.json(currentPolicy());
});

app.post('/v1/carnac/policy/amend', (req, res) => {
  const auth = requireCarnacAuth(req, res);
  if (!auth) return;
  const { amendment, signatures } = req.body || {};
  const result = amendPolicy(amendment, signatures || []);
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  res.json({ ok: true, direction: result.direction, policy: result.policy });
});

app.post('/v1/carnac/disposition', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const body = req.body || {};
  if (!body.judgment_id) return res.status(400).json({ error: 'judgment_required', message: 'judgment_id required' });
  // The judgment must exist and be visible to this caller; the disposition floor
  // is the judgment's own effective level, so an override can never lower it.
  const judgment = await fetchJudgment(body.judgment_id);
  if (!judgment || !tenantScopeAllows(auth, judgment.tenant_id || null)) {
    return res.status(404).json({ error: 'not_found', message: 'judgment not found' });
  }
  const result = await recordDisposition({
    tenant_id: judgment.tenant_id || auth.tenant_id,
    judgment_id: body.judgment_id,
    trajectory_id: body.trajectory_id || judgment.trajectory_id || null,
    howler_id: body.howler_id || judgment.howler_id || null,
    actor: auth.actor,
    action: body.action,
    reason: body.reason || '',
    floor_level: judgment.effective_level,
    override_level: body.override_level,
  });
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  res.json({ ok: true, disposition: result.record, ledger: result.ledger });
});

app.get('/v1/carnac/howler/:id', async (req, res) => {
  const auth = requireCarnacAuth(req, res);
  if (!auth) return;
  const howler = await fetchHowler(req.params.id);
  if (!howler || !tenantScopeAllows(auth, howler.tenant_id || null)) {
    return res.status(404).json({ error: 'not_found', message: 'howler not found' });
  }
  const judgment = await fetchJudgment(howler.judgment_id);
  const verification = verifyHowler(howler, judgment);
  res.json({ howler, verification });
});

app.post('/v1/carnac/verify', async (req, res) => {
  try {
    const artifact = (req.body && req.body.artifact) || req.body || {};
    const result = await verifyArtifact(artifact);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'carnac_error', message: e.message });
  }
});

app.get('/v1/carnac/verify/:id', async (req, res) => {
  const result = await verifyById(req.params.id, { client: verifyClientId(req) });
  if (!result.ok) {
    if (result.retry_after_s) res.setHeader('Retry-After', String(result.retry_after_s));
    return res.status(result.status || 400).json({ error: result.code, message: result.message });
  }
  res.json(result);
});

app.get('/v1/carnac/export', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const result = await buildExport({
    tenant_id: auth.tenant_id,
    trajectory_id: req.query.trajectory_id || undefined,
    from: req.query.from || undefined,
    to: req.query.to || undefined,
    limit: req.query.limit ? Number(req.query.limit) : undefined,
  });
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  if ((req.query.format || '').toLowerCase() === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="carnac-audit-export.csv"');
    return res.send(exportToCsv(result.report));
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json(result.report);
});

app.post('/v1/carnac/seal', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const trajectory_id = (req.body && req.body.trajectory_id) || null;
  const result = await sealTrajectory({ tenant_id: auth.tenant_id, trajectory_id });
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  res.json({ ok: true, seal: result.seal, verification: result.verification, source: result.source, ledger: result.ledger });
});

// ── Lifecycle chain ───────────────────────────────────────────────────────────
// One signed chain for one inference, from the prompt-window boundary through
// execution to downstream effect. The serving path (open/append/seal) is local
// only: bounded validation, canonicalization, domain-separated hashing, and an
// in-memory append + enqueue. No synchronous network call and no synchronous
// public-key signature. Signing, durable persistence, and Merkle batching happen
// asynchronously in the finalizer. Public verification needs no plaintext.

// Open a lifecycle. Tenant is taken from the authenticated caller, never the body,
// so a caller can never open a lifecycle under a tenant it does not control.
app.post('/v1/carnac/lifecycle/open', (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const body = req.body || {};
  const result = openLifecycle({
    tenant_id: auth.tenant_id,
    lifecycle_id: body.lifecycle_id || undefined,
    trajectory_id: body.trajectory_id || undefined,
    parent_lifecycle_id: body.parent_lifecycle_id || undefined,
    policy_version: body.policy_version || undefined,
    replay_class: body.replay_class || undefined,
    prefix_commit: body.prefix_commit || undefined,
    prefix_text: body.prefix_text || undefined,
    seed_receipt_zero: body.seed_receipt_zero || undefined,
  });
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  res.json({ ok: true, lifecycle: result.lifecycle });
});

// Append a typed stage. Raw prompt/context/output text is hashed locally and
// dropped; only commitments are stored. Instruction authority is enforced here.
app.post('/v1/carnac/lifecycle/:id/stage', (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const body = req.body || {};
  const result = appendStage({ ...body, tenant_id: auth.tenant_id, lifecycle_id: req.params.id });
  if (!result.ok) return res.status(result.status || 400).json({ error: result.code, message: result.message });
  res.json({ ok: true, stage: result.stage, idempotent_replay: Boolean(result.idempotent_replay) });
});

// Read a lifecycle's status: ordered stages, head, pending/final counts. Scoped
// to the caller's tenant; another tenant's lifecycle is indistinguishable from
// a missing one.
app.get('/v1/carnac/lifecycle/:id', (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const result = getLifecycle(auth.tenant_id, req.params.id);
  if (!result.ok) return res.status(404).json({ error: 'not_found', message: 'lifecycle not found' });
  res.json({ ok: true, lifecycle: result.lifecycle });
});

// Force-drain the finalizer (ops/testing). Signing and persistence otherwise run
// on the background interval; this makes the pending->final transition observable
// on demand without waiting.
app.post('/v1/carnac/lifecycle/:id/finalize', async (req, res) => {
  const auth = requireCarnacAuth(req, res, { requireTenant: true });
  if (!auth) return;
  const exists = getLifecycle(auth.tenant_id, req.params.id);
  if (!exists.ok) return res.status(404).json({ error: 'not_found', message: 'lifecycle not found' });
  const result = await drainFinalize();
  const after = getLifecycle(auth.tenant_id, req.params.id);
  res.json({ ok: true, drain: result, lifecycle: after.ok ? after.lifecycle : null });
});

// Public verification: recompute every stage digest and chain head, verify each
// finalized signature over the canonical core, and check Merkle inclusion. No
// authentication and no plaintext are required; the caller submits the stages
// (by value) and gets back a full structural verdict.
app.post('/v1/carnac/lifecycle/verify', (req, res) => {
  try {
    const body = req.body || {};
    const stages = Array.isArray(body.stages) ? body.stages : (body.lifecycle && body.lifecycle.stages) || [];
    const result = verifyLifecycle(stages);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'carnac_error', message: e.message });
  }
});

app.get('/v1/carnac/health', async (_req, res) => {
  const [compute, ledger, pq] = await Promise.all([computeHealth(), ledgerHealth(), pqHealth()]);
  const policy = currentPolicy();
  const durableOk = ledger.durable_configured ? Boolean(ledger.durable_reachable) : false;
  const authConfigured = carnacAuthConfigured();
  // Protected production routes are ready only when effects can be recorded
  // durably AND carry a real post-quantum signature AND auth is configured. The
  // public sandbox is always available (in a degraded no-PQ state if needed).
  const protectedReady = Boolean(durableOk && pq.available && authConfigured);
  res.json({
    status: protectedReady ? 'ok' : 'degraded',
    service: 'carnac',
    spectral_pubkey: getPublicKeyB64(),
    compute,
    ledger,
    pq,
    policy,
    continuity: { chain_algo: 'sha256', sealing: 'available' },
    readiness: {
      protected_routes_ready: protectedReady,
      durable_ledger: durableOk,
      pq_signer: pq.available,
      auth_configured: authConfigured,
      sandbox_available: true,
    },
    ts: new Date().toISOString(),
  });
});

// ── InkFrame v1 (Carnac Live Ink substrate) ─────────────────────────────────
// Same CORS posture as Carnac public routes: only the marketing site and
// local dev can call cross-origin.
app.use('/v1/inkframe', (req, res, next) => {
  const origin = req.headers.origin;
  const allow = CARNAC_PUBLIC_ORIGINS();
  if (origin && allow.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
app.use('/v1/inkframe', makeInkframeRouter());

// ── well-known / x402 ─────────────────────────────────────────────────────────

app.get('/.well-known/x402', (_req, res) => {
  res.json({
    x402Version:  2,
    cold_safe:    true,
    service:      'hive-receipt',
    version:      '1.0.0',
    brand_color:  '#C08D23',
    payTo:        '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
    network:      'base',
    chain_id:     8453,
    asset:        'USDC',
    contract:     '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    accepted_assets: [
      {
        symbol:    'USDC',
        contract:  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        network:   'base',
        chain_id:  8453,
        primary:   true
      },
      {
        symbol:    'USDT',
        contract:  '0xfde4C96c8593536E31F229Ea8f37b2ADa2699bb2',
        network:   'base',
        chain_id:  8453,
        primary:   false
      },
      {
        symbol:               'USAd',
        program_id:           'usad_stablecoin.aleo',
        network:              'aleo',
        network_name:         'aleo-mainnet',
        primary:              false,
        issuer:               'Paxos Labs',
        backing:              'Paxos Trust USDG 1:1',
        privacy:              'zk-default',
        docs:                 'https://aleo.org/usad',
        facilitator:          'https://hive-aleo-arc.onrender.com/v1/facilitator',
        facilitator_treasury: 'aleo1cyk7r2jmd7lfcftzyy85z4j5x6rlern598qecx8v2ms738xcvgyq72q6tk',
        added:                '2026-04-29'
      },
      {
        symbol:               'USDCx',
        program_id:           'usdcx_stablecoin.aleo',
        network:              'aleo',
        network_name:         'aleo-mainnet',
        primary:              false,
        issuer:               'Circle xReserve',
        backing:              'USDC 1:1 (Ethereum reserve)',
        privacy:              'zk-default',
        docs:                 'https://aleo.org/usdcx',
        facilitator:          'https://hive-aleo-arc.onrender.com/v1/facilitator',
        facilitator_treasury: 'aleo1cyk7r2jmd7lfcftzyy85z4j5x6rlern598qecx8v2ms738xcvgyq72q6tk',
        added:                '2026-04-29'
      }
    ],
    facilitator: {
      url:                    'https://hive-aleo-arc.onrender.com/v1/facilitator',
      supported_schemes:      ['exact'],
      supported_networks:     ['eip155:8453', 'aleo-mainnet'],
      syncFacilitatorOnStart: false,
      cold_safe:              true,
      aleo_treasury:          'aleo1cyk7r2jmd7lfcftzyy85z4j5x6rlern598qecx8v2ms738xcvgyq72q6tk',
      usad_program_id:        'usad_stablecoin.aleo',
      usdcx_program_id:       'usdcx_stablecoin.aleo',
    },
    resources: [
      {
        path:        '/v1/receipt/sign',
        method:      'POST',
        description: 'Sign a payment receipt. Standard tier: $0.001 USDC. Audit tier: $0.10.',
        'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.',
        },
        'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.',
        }
      },
      {
        path:        '/v1/receipt/verify/:receipt_id',
        method:      'GET',
        description: 'Verify a Spectral-signed receipt. Free.',
        'x-pricing':      { scheme: 'free', note: 'Verification is free. No payment required.' },
        'x-payment-info': { scheme: 'free', note: 'Verification is free. No payment required.' }
      }
    ],
    discovery_companions: {
      agent_card: '/.well-known/agent-card.json',
      ap2:        '/.well-known/ap2.json',
      openapi:    '/.well-known/openapi.json'
    },
    disclaimers: {
      not_a_security: true,
      not_custody:    true,
      not_insurance:  true,
      signal_only:    true
    }
  });
});

// ── well-known / agent-card.json (A2A 0.1) ────────────────────────────────────

app.get('/.well-known/agent-card.json', (req, res) => {
  const pubkey = (typeof getPublicKeyB64 === 'function')
    ? getPublicKeyB64()
    : (typeof spectral !== 'undefined' ? (spectral.publicKeyB64 || null) : null);
  res.json({
    name:        'hive-receipt',
    version:     '1.0.0',
    description: 'Universal Spectral-signed payment receipts. x402 gated. Real on-chain verification.',
    brand_color: '#C08D23',
    did:         `did:web:${req.hostname}`,
    protocol:    'A2A/0.1',
    capabilities: [
      'receipt.sign',
      'receipt.verify',
      'receipt.list',
      'carnac.judge',
      'carnac.verify'
    ],
    spectral: {
      public_key:    pubkey,
      signature_algo: 'ed25519',
      jwks_endpoint: '/.well-known/jwks.json'
    },
    treasury: {
      address:  '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
      network:  'base',
      chain_id: 8453,
      asset:    'USDC'
    },
    payment: {
      protocol: 'x402',
      version:  '2',
      network:  'base',
      chain_id: 8453,
      asset:    'USDC',
      contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo:    '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E'
    },
    mcp_endpoint: '/mcp',
    tools: ['sign_receipt', 'verify_receipt', 'list_my_receipts', 'carnac_judge', 'carnac_verify']
  });
});

// ── well-known / ap2.json (AP2 0.1) ───────────────────────────────────────────

app.get('/.well-known/ap2.json', (_req, res) => {
  res.json({
    ap2_version:   '0.1',
    service:       'hive-receipt',
    accepted_tokens: [
      {
        symbol:   'USDC',
        contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        network:  'base',
        chain_id: 8453,
        decimals: 6
      },
      {
        symbol:   'USDT',
        contract: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2',
        network:  'base',
        chain_id: 8453,
        decimals: 6,
        role:     'alternate'
      }
    ],
    networks:           [{ name: 'base', chain_id: 8453, role: 'primary' }],
    payment_protocols:  ['x402/v2'],
    settlement: {
      finality:  'on-chain',
      network:   'base',
      chain_id:  8453,
      payTo:     '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E'
    },
    paid_endpoints: [
      { path: '/v1/receipt/sign', method: 'POST', description: 'Sign a payment receipt. Standard tier: $0.001 USDC. Audit tier: $0.10.' }
    ],
    free_endpoints: [
      { path: '/v1/receipt/verify/:receipt_id', method: 'GET', description: 'Verify a Spectral-signed receipt. Free.' }
    ],
    brand_color: '#C08D23'
  });
});

// ── well-known / openapi.json (OpenAPI 3.0.3 + x-pricing + x-payment-info) ────

app.get('/.well-known/openapi.json', (_req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title:       'hive-receipt API',
      version:     '1.0.0',
      description: 'Universal Spectral-signed payment receipts. x402 gated. Real on-chain verification.',
      contact:     { name: 'The Hivery', url: 'https://thehiveryiq.com' }
    },
    servers: [{ url: 'https://hive-receipt.onrender.com', description: 'Production (Render)' }],
    paths: {
      '/v1/receipt/sign': {
        post: {
          operationId: 'v1_receipt_sign',
          summary: 'Sign a payment receipt. Standard tier: $0.001 USDC. Audit tier: $0.10.',
          'x-pricing': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.'
          },
          'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.'
          },
          responses: {
            '200': { description: 'Success.' },
            '402': { description: 'Payment Required — x402 challenge.' },
            '400': { description: 'Validation error.' }
          }
        }
      },
      '/v1/receipt/verify/:receipt_id': {
        get: {
          operationId: 'v1_receipt_verify_:receipt_id',
          summary: 'Verify a Spectral-signed receipt. Free.',
          responses: {
            '200': { description: 'Success.' },
            '400': { description: 'Validation error.' }
          }
        }
      }
    }
  });
});


// ─── JWKS ─────────────────────────────────────────────────────────────────────
app.get('/.well-known/jwks.json', (_req, res) => {
  const der = Buffer.from(getPublicKeyB64(), 'base64');
  const x   = der.slice(-32).toString('base64url');
  res.json({
    keys: [{
      kty: 'OKP',
      crv: 'Ed25519',
      use: 'sig',
      alg: 'EdDSA',
      kid: 'hive-receipt-spectral-1',
      x
    }]
  });
});

// ─── DID document ─────────────────────────────────────────────────────────────
app.get('/.well-known/did.json', (_req, res) => {
  const did = 'did:web:hive-receipt.onrender.com';
  const der = Buffer.from(getPublicKeyB64(), 'base64');
  const x   = der.slice(-32).toString('base64url');
  res.json({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1'
    ],
    id: did,
    verificationMethod: [{
      id:         `${did}#spectral`,
      type:       'JsonWebKey2020',
      controller: did,
      publicKeyJwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        use: 'sig',
        alg: 'EdDSA',
        kid: 'hive-receipt-spectral-1',
        x
      }
    }],
    authentication:  [`${did}#spectral`],
    assertionMethod: [`${did}#spectral`],
    service: [
      {
        id:              `${did}#agent-card`,
        type:            'AgentCard',
        serviceEndpoint: 'https://hive-receipt.onrender.com/.well-known/agent.json'
      },
      {
        id:              `${did}#a2a`,
        type:            'A2AService',
        serviceEndpoint: 'https://hive-receipt.onrender.com/v1'
      }
    ]
  });
});

// ── PAGE HIT TRACKER ─────────────────────────────────────────────────────────
// Telemetry source is Supabase table clarity_hits. Access is hardened in
// lib/site_store.js so source failures surface truthfully instead of being
// masked as "no data".
const DISPLAY_TZ = process.env.SITE_TZ || 'America/Los_Angeles';
const SITE_HOST  = process.env.SITE_HOST || 'thehiveryiq.com';
// Stable per-deploy salt for pseudonymous visitor/session ids. Falls back to a
// constant so ids stay stable across restarts even without extra config; set
// SITE_INTEL_SALT to rotate.
const INTEL_SALT = process.env.SITE_INTEL_SALT || 'hive-site-intel-v1';

async function getHitsFromDB(){
  // Backward-compatible helper for the legacy HTML log view (newest first).
  const { events } = await fetchEvents({ sinceIso: null, limit: 5000 });
  return events.slice().reverse();
}

app.get('/ping/clarity', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
  let city = '', org = '', region = '';
  try {
    const geo = await fetch(`http://ip-api.com/json/${ip}?fields=city,regionName,org`).then(r => r.json());
    city   = geo.city       || '';
    region = geo.regionName || '';
    org    = geo.org        || '';
  } catch(e){}
  // Page path + optional client session id, captured for per-visitor journeys.
  const rawPath = req.query.p || req.query.path || '';
  let path = '';
  if (rawPath) { try { path = new URL(rawPath, `https://${SITE_HOST}`).pathname; } catch { path = String(rawPath).slice(0, 512); } }
  const sid = (req.query.sid || req.query.s || '').toString().slice(0, 128) || null;
  const entry = {
    ts:      new Date().toISOString(),
    ip,
    city,
    region,
    country: req.headers['cf-ipcountry'] || '',
    org,
    ua:      req.headers['user-agent'] || '',
    ref:     req.headers['referer'] || '',
    path:    path || null,
    sid,
  };
  const result = await insertHit(entry);
  if (!result.ok) console.error('[CLARITY HIT DB ERROR]', result.error);
  else if (result.degraded) console.warn('[CLARITY HIT] stored without path/sid columns (add them to unlock page analytics)');
  res.json({ ok: true });
});

app.get('/ping/clarity/log', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    const hits = await getHitsFromDB();
    // HTML view
    const rows = hits.map(h => {
      const d = new Date(h.ts);
      const local = d.toLocaleString('en-US', { timeZone:'America/Los_Angeles', hour12:true });
      return `<tr>
        <td>${local}</td>
        <td>${h.city||''}${h.region ? ', '+h.region : ''} ${h.country||''}</td>
        <td>${h.org||''}</td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h.ua||''}</td>
        <td>${h.ref||'direct'}</td>
      </tr>`;
    }).join('');
    res.setHeader('Content-Type','text/html');
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>CLARITY — Hit Log</title>
<style>
body{background:#070B11;color:#fff;font-family:'Inter Tight',sans-serif;padding:24px;}
h2{color:#2F80FF;margin-bottom:16px;font-size:14px;letter-spacing:.1em;text-transform:uppercase;}
table{border-collapse:collapse;width:100%;font-size:11px;}
th{text-align:left;color:rgba(255,255,255,0.4);font-weight:600;letter-spacing:.08em;padding:6px 12px;border-bottom:1px solid rgba(47,128,255,0.15);}
td{padding:7px 12px;border-bottom:1px solid rgba(255,255,255,0.04);color:#fff;vertical-align:top;}
tr:hover td{background:rgba(47,128,255,0.06);}
.count{font-size:28px;font-weight:900;font-family:monospace;color:#34D399;margin-bottom:4px;}
.sub{font-size:10px;color:rgba(255,255,255,0.35);margin-bottom:20px;}
</style></head><body>
<div class="count">${hits.length}</div>
<div class="sub">total hits · /clarity/</div>
<h2>Hit Log — PDT</h2>
<table>
<thead><tr><th>Time (PDT)</th><th>Location</th><th>Org / ISP</th><th>Browser</th><th>Referrer</th></tr></thead>
<tbody>${rows}</tbody>
</table>
</body></html>`);
  } catch(e) {
    res.setHeader('Content-Type','text/html');
    res.send('<html><body style="background:#070B11;color:#fff;font-family:monospace;padding:24px">No hits yet.</body></html>');
  }
});

// ── OWNER SITE INTELLIGENCE ──────────────────────────────────────────────────
// Authenticated, deterministic, explainable analytics over the clarity_hits
// event store. No external LLM. Never fabricates a narrative. See
// docs/site-intelligence.md for the full contract.

const SITE_LOOKBACK_MS = 7 * 86_400_000;

async function gatherIntelligence({ now = new Date() } = {}) {
  const sinceIso = new Date(now.getTime() - SITE_LOOKBACK_MS).toISOString();
  const { events, health } = await fetchEvents({ sinceIso, limit: 10000 });
  return buildIntelligence({
    events,
    now,
    timezone: DISPLAY_TZ,
    salt: INTEL_SALT,
    siteHost: SITE_HOST,
    sourceHealth: health,
    lookbackMs: SITE_LOOKBACK_MS,
  });
}

// Public, PII-free source health probe so the frontend can distinguish
// "backend down" from "no data" without a token. Rail-style health only.
app.get('/v1/site/health', async (_req, res) => {
  try {
    const sinceIso = new Date(Date.now() - 86_400_000).toISOString();
    const { events, health } = await fetchEvents({ sinceIso, limit: 1 });
    res.json({
      status: health.reachable ? 'ok' : 'degraded',
      source: health.source,
      reachable: health.reachable,
      error: health.error,
      last_probe_utc: health.fetched_at,
      latency_ms: health.latency_ms,
      timezone: DISPLAY_TZ,
      intelligence_endpoint: '/v1/site/intelligence',
      owner_auth_configured: Boolean(getConfiguredToken()),
      sampled_rows: events.length,
    });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// Authenticated owner intelligence. GET /v1/site/intelligence
// Auth: Authorization: Bearer <SITE_INTEL_TOKEN>  (or ?token=)
// ?format=csv for a flat CSV export of session journeys.
app.get('/v1/site/intelligence', async (req, res) => {
  const auth = checkOwnerAuth(req);
  if (!auth.ok) {
    return res.status(auth.status).json({ error: auth.code, message: auth.message });
  }
  try {
    const report = await gatherIntelligence({ now: new Date() });
    if ((req.query.format || '').toLowerCase() === 'csv') {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="site-intelligence-journeys.csv"');
      return res.send(journeysToCsv(report));
    }
    res.setHeader('Cache-Control', 'no-store');
    res.json(report);
  } catch (e) {
    console.error('[SITE INTEL ERROR]', e.stack || e.message);
    res.status(500).json({ error: 'intelligence_error', message: e.message });
  }
});

function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function journeysToCsv(report) {
  const header = ['generated_at', 'session_id', 'visitor_id', 'is_crawler', 'entry_page', 'referrer_class', 'page_count', 'exit_page', 'started_at_utc', 'ended_at_utc', 'total_dwell_seconds', 'country', 'device', 'likely_organization'];
  const lines = [header.join(',')];
  for (const j of report.session_journeys) {
    lines.push([
      report.generated_at, j.session_id, j.visitor_id, j.is_crawler, j.entry_page,
      j.referrer_class, j.page_count, j.exit_page, j.started_at_utc, j.ended_at_utc,
      j.total_dwell_seconds, j.country, j.device, j.likely_organization,
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

// Catch-all 404 (replaces stock Express HTML) + envelope error handler.
app.use((req, res) => res.status(404).json({ error: 'not_found', path: req.path }));
app.use(recruitmentErrorHandler);

app.listen(PORT, () => {
  console.log(`hive-receipt listening on :${PORT}`);
  // Background lifecycle finalizer: signs, batches, and persists pending stages
  // off the serving path. Unref'd so it never keeps the process alive on its own.
  startFinalizer();
});
