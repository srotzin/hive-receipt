import express from 'express';
import crypto from 'crypto';
import { initKeypair, getPublicKeyB64, signPayload, verifyEnvelope } from './lib/spectral.js';
import { verifyOnChain } from './lib/onchain.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const MONROE = '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e';
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
    payTo:        '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
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
        symbol:     'USAd',
        program_id: 'PENDING_ALEO_RESOLUTION',
        network:    'aleo',
        primary:    false,
        issuer:     'Paxos Labs',
        backing:    'Paxos Trust USDG 1:1',
        privacy:    'zk-default',
        docs:       'https://aleo.org/usad',
        added:      '2026-04-29'
      },
      {
        symbol:     'USDCx',
        program_id: 'PENDING_ALEO_RESOLUTION',
        network:    'aleo',
        primary:    false,
        issuer:     'Circle xReserve',
        backing:    'USDC 1:1 (Ethereum reserve)',
        privacy:    'zk-default',
        docs:       'https://aleo.org/usdcx',
        added:      '2026-04-29'
      }
    ],
    facilitator: {
      url:                    'https://hivemorph.onrender.com/v1/x402',
      supported_schemes:      ['exact'],
      supported_networks:     ['eip155:8453'],
      syncFacilitatorOnStart: false,
      cold_safe:              true
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
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.',
        },
        'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
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
      address:  '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
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
      payTo:    '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
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
      payTo:     '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e'
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
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
          description: '$0.001 standard / $0.10 audit per receipt. payTo Monroe.'
          },
          'x-payment-info': {
          scheme: 'exact',
          asset: 'USDC',
          standard_atomic: 1000,
          audit_atomic: 100000,
          payTo: '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
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

app.listen(PORT, () => {
  console.log(`hive-receipt listening on :${PORT}`);
});
