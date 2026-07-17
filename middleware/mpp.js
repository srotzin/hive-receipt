/**
 * Hive Receipt — MPP (Machine Payments Protocol) Middleware
 *
 * Runs ALONGSIDE existing x402 middleware. Either rail satisfies payment.
 * Implements IETF draft-ryan-httpauth-payment Payment header scheme.
 * MPP receipts emit Spectral receipts with payment_method: "mpp".
 *
 * Stream B/E — receipt service, attestation
 * Treasury: Monroe Base 0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E
 * Tempo RPC: https://rpc.tempo.xyz
 *
 * References:
 *   https://github.com/wevm/mppx
 *   https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/
 *   https://github.com/tempoxyz/mpp
 */

// ─── Configuration ───────────────────────────────────────────

const PAYMENT_ADDRESS = (
  process.env.HIVE_RECEIPT_PAYMENT_ADDRESS ||
  process.env.HIVE_PAYMENT_ADDRESS ||
  '0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E'
).toLowerCase();

const TEMPO_RPC_URL = process.env.TEMPO_RPC_URL || 'https://rpc.tempo.xyz';
const BASE_RPC_URL  = process.env.BASE_RPC_URL  || 'https://mainnet.base.org';
const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const TEMPO_USDCE   = '0x20c000000000000000000000b9537d11c60e8b50';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
// Self-referential — receipt service emits its own receipts directly to store
const RECEIPT_ENDPOINT = 'https://hive-receipt.onrender.com/v1/receipt/sign';

// In-memory MPP payment cache (TTL 10 min)
const mppPaymentCache = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of mppPaymentCache) {
    if (now - v.timestamp > 600_000) mppPaymentCache.delete(k);
  }
}, 60_000);

// ─── Spectral Receipt (non-blocking) ─────────────────────────

async function emitMppSpectralReceipt({ path, amount, txHash, rail }) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4_000);
    await fetch(RECEIPT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        issuer_did:     'did:hive:hive-receipt',
        event_type:     'api_payment',
        amount_usd:     amount,
        currency:       'USDC',
        network:        rail === 'tempo' ? 'tempo' : 'base',
        pay_to:         PAYMENT_ADDRESS,
        endpoint:       path,
        tx_hash:        txHash,
        payment_method: 'mpp',
        rail:           rail,
        timestamp:      new Date().toISOString(),
      }),
    });
    clearTimeout(timer);
  } catch (_) {
    // Non-blocking — never interrupts the fee path
  }
}

// ─── On-chain USDC verification (Base or Tempo) ──────────────

async function verifyMppOnChain(txHash, expectedAmount, rail) {
  const rpcUrl = rail === 'tempo' ? TEMPO_RPC_URL : BASE_RPC_URL;
  const usdcContract = rail === 'tempo' ? TEMPO_USDCE : USDC_CONTRACT;

  try {
    const rpcRes = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt',
        params: [txHash],
      }),
      signal: AbortSignal.timeout(8_000),
    });
    const { result: receipt } = await rpcRes.json();
    if (!receipt || receipt.status !== '0x1') {
      return { ok: false, reason: 'tx not confirmed or reverted' };
    }
    for (const log of receipt.logs) {
      if (
        log.address?.toLowerCase() === usdcContract &&
        log.topics?.[0] === TRANSFER_TOPIC
      ) {
        const toAddr = '0x' + log.topics[2].slice(26).toLowerCase();
        if (toAddr === PAYMENT_ADDRESS) {
          const transferAmount = parseInt(log.data, 16) / 1e6;
          if (transferAmount >= expectedAmount - 0.001) {
            return { ok: true, transferAmount };
          }
          return { ok: false, reason: `insufficient: got ${transferAmount}, need ${expectedAmount}` };
        }
      }
    }
    return { ok: false, reason: 'no matching USDC Transfer to treasury found' };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ─── MPP Payment Header Parser ───────────────────────────────

function parseMppHeader(req) {
  const paymentHdr = req.headers['payment'] || req.headers['x-payment'] || '';
  if (paymentHdr) {
    const params = {};
    for (const part of paymentHdr.split(',')) {
      const m = part.trim().match(/^([\w-]+)="([^"]*)"$/);
      if (m) params[m[1]] = m[2];
    }
    if (params.scheme === 'mpp' || params.tx_hash) {
      return {
        found:   true,
        txHash:  params.tx_hash || params.credential || '',
        rail:    params.rail || 'tempo',
        amount:  parseFloat(params.amount || '0') || null,
      };
    }
  }

  const credHdr = req.headers['payment-credential'] || '';
  if (credHdr) {
    return {
      found:   true,
      txHash:  credHdr,
      rail:    req.headers['x-mpp-rail'] || 'tempo',
      amount:  parseFloat(req.headers['x-mpp-amount'] || '0') || null,
    };
  }

  return { found: false };
}

// ─── Fee table ───────────────────────────────────────────────
// Stream B/E: receipts, attestation

const DID_CREDENTIAL_PRICING = {
  '/v1/receipt/sign':        0.05,
  '/v1/receipt/batch':       0.50,
  '/v1/receipt/audit':       0.10,
  '/v1/receipt/attest':      0.10,
};

function getMppPrice(path) {
  if (DID_CREDENTIAL_PRICING[path]) return DID_CREDENTIAL_PRICING[path];
  if (path.startsWith('/v1/receipt/batch')) return 0.50;
  if (path.startsWith('/v1/receipt/sign'))  return 0.05;
  if (path.startsWith('/v1/receipt/'))      return 0.05;
  return 0.05;
}

// ─── Free-path list ──────────────────────────────────────────

const FREE_PATHS = new Set([
  '/health', '/', '/openapi.json',
  '/v1/receipt/verify',
]);

function isFreePath(path) {
  if (FREE_PATHS.has(path)) return true;
  if (path.startsWith('/.well-known/')) return true;
  if (path.startsWith('/v1/site/')) return true; // owner analytics, token-gated separately

  // Carnac judgment plane: only the genuinely public routes are free. Protected
  // routes are NOT blanket-bypassed here — they enforce their own bearer auth so
  // an unauthenticated caller cannot slip through the generic free-path list.
  if (path === '/v1/carnac/health') return true;
  if (path === '/v1/carnac/policy') return true;
  if (path === '/v1/carnac/sandbox') return true;
  if (path === '/v1/carnac/verify' || path.startsWith('/v1/carnac/verify/')) return true;

  if (path.startsWith('/v1/receipt/verify/')) return true;
  if (path.startsWith('/v1/receipt/list/'))   return true;
  return false;
}

// ─── Main MPP Middleware ──────────────────────────────────────

async function mppMiddleware(req, res, next) {
  if (isFreePath(req.path)) return next();

  const mpp = parseMppHeader(req);
  if (!mpp.found) return next();

  const { txHash, rail, amount: headerAmount } = mpp;
  const expectedAmount = getMppPrice(req.path);
  const amountToVerify = headerAmount || expectedAmount;

  if (mppPaymentCache.has(txHash)) {
    const cached = mppPaymentCache.get(txHash);
    if (cached.ok) {
      res.set('Payment-Receipt', `mpp:${txHash}:verified`);
      res.set('X-Hive-Payment-Rail', 'mpp');
      res.set('X-Hive-Payment-Method', 'mpp');
      return next();
    }
    return res.status(402).json({
      error: 'MPP payment verification failed (cached)',
      code:  'MPP_PAYMENT_INVALID',
      reason: cached.reason,
    });
  }

  const verification = await verifyMppOnChain(txHash, amountToVerify, rail || 'tempo');
  mppPaymentCache.set(txHash, { ...verification, timestamp: Date.now() });

  if (!verification.ok) {
    return res.status(402).json({
      error:  'MPP payment verification failed',
      code:   'MPP_PAYMENT_INVALID',
      reason: verification.reason,
      hint:   'Provide a confirmed Tempo or Base USDC transaction in the Payment header.',
    });
  }

  emitMppSpectralReceipt({
    path:   req.path,
    amount: amountToVerify,
    txHash,
    rail:   rail || 'tempo',
  }).catch(() => {});

  res.set('Payment-Receipt',        `mpp:${txHash}:${rail || 'tempo'}`);
  res.set('X-Hive-Payment-Rail',   'mpp');
  res.set('X-Hive-Payment-Method', 'mpp');
  return next();
}

export default mppMiddleware;
export { mppPaymentCache };
