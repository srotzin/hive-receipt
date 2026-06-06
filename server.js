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
assertEnvelopeIntegrity();

const app = express();
app.use(express.json());
app.use(recruitmentResponseWrapper);

// ─── CORS middleware ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
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
    tools: ['sign_receipt', 'verify_receipt', 'list_my_receipts']
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
      'receipt.list'
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
    tools: ['sign_receipt', 'verify_receipt', 'list_my_receipts']
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
const SUPA_URL = 'https://rdxdcbxeploukweaczrq.supabase.co';
const SUPA_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJkeGRjYnhlcGxvdWt3ZWFjenJxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAwODk5NzcsImV4cCI6MjA5NTY2NTk3N30.5eUIH9xIIzrInHSYz1fuw_niM_qB7L0La79SQJkbjZQ';

async function logHitToDB(entry){
  try {
    await fetch(`${SUPA_URL}/rest/v1/clarity_hits`, {
      method: 'POST',
      headers: {
        'apikey': SUPA_KEY,
        'Authorization': `Bearer ${SUPA_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify(entry)
    });
  } catch(e){ console.error('[CLARITY HIT DB ERROR]', e.message); }
}

async function getHitsFromDB(){
  const r = await fetch(`${SUPA_URL}/rest/v1/clarity_hits?select=*&order=ts.desc`, {
    headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` }
  });
  return r.json();
}

app.get('/ping/clarity', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
  let city = '', org = '', region = '';
  try {
    const geo = await fetch(`https://ipapi.co/${ip}/json/`).then(r => r.json());
    city   = geo.city    || '';
    region = geo.region  || '';
    org    = geo.org     || '';
  } catch(e){}
  const entry = {
    ts:      new Date().toISOString(),
    ip,
    city,
    region,
    country: req.headers['cf-ipcountry'] || '',
    org,
    ua:      req.headers['user-agent'] || '',
    ref:     req.headers['referer'] || '',
  };
  await logHitToDB(entry);
  console.log('[CLARITY HIT]', JSON.stringify(entry));
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

// Catch-all 404 (replaces stock Express HTML) + envelope error handler.
app.use((req, res) => res.status(404).json({ error: 'not_found', path: req.path }));
app.use(recruitmentErrorHandler);

app.listen(PORT, () => {
  console.log(`hive-receipt listening on :${PORT}`);
});
