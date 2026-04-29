/**
 * Rail 3 — Receipt Gravity / Loyalty Discount Middleware
 * lib/loyalty.js
 *
 * Spectral receipt–backed loyalty discounting for Hive surfaces.
 * Every paid call mints a receipt. Agents presenting prior receipts on
 * subsequent calls receive 5% off per valid receipt, capped at 25% (5 receipts).
 *
 * NEED  : loyalty drives multi-rail consumption
 * YIELD : preserves ≥75% of revenue per call (max 25% discount)
 * CLEAN : no token, no airdrop — self-discounting SaaS only
 *
 * Brand gold: #C08D23
 * Treasury:   0x15184bf50b3d3f52b60434f8942b7d52f2eb436e
 */

import crypto from 'crypto';

// ── config ────────────────────────────────────────────────────────────────────
const HIVE_RECEIPT_VERIFY_BASE = process.env.HIVE_RECEIPT_BASE || 'https://hive-receipt.onrender.com';
const SPECTRAL_PUBKEY_B64 = 'MCowBQYDK2VwAyEAJTHrah3YgnUpAoeVuWla+8vt/VDlkHx0+uXHp1ei6OQ=';
const DISCOUNT_BPS_PER_RECEIPT = 500;   // 5.00% in basis points
const MAX_DISCOUNT_BPS         = 2500;  // 25.00% cap
const CACHE_TTL_MS             = 60_000; // 60s verified-receipt cache
const VERIFY_TIMEOUT_MS        = 5_000;  // individual verify call timeout
const BRAND_GOLD               = '#C08D23';

// ── in-process caches ─────────────────────────────────────────────────────────
// verifiedCache: receipt_id → { valid: bool, envelope: obj|null, cachedAt: ms }
const verifiedCache = new Map();

// replayGuard: `${callerDid}:${endpoint}:${utcDay}:${receiptId}` → true
const replayGuard   = new Set();

// ── helpers ───────────────────────────────────────────────────────────────────

/** UTC day string YYYY-MM-DD for replay-protection keying. */
function utcDay() {
  return new Date().toISOString().slice(0, 10);
}

/** Extract caller DID from request (header or body fallback). */
function callerDid(req) {
  return (
    req.headers['x-hive-did'] ||
    req.headers['x-did']      ||
    req.body?.did              ||
    req.body?.payer_did        ||
    'anonymous'
  );
}

/**
 * Verify a single receipt via hive-receipt's /v1/receipt/verify/:id endpoint.
 * Returns { valid: bool, envelope: obj|null }.
 * Uses 60s in-process cache. Falls back to invalid on timeout/error.
 */
async function verifyReceipt(receiptId) {
  const now = Date.now();

  // Cache hit
  const cached = verifiedCache.get(receiptId);
  if (cached && now - cached.cachedAt < CACHE_TTL_MS) {
    return { valid: cached.valid, envelope: cached.envelope };
  }

  try {
    const url = `${HIVE_RECEIPT_VERIFY_BASE}/v1/receipt/verify/${encodeURIComponent(receiptId)}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), VERIFY_TIMEOUT_MS);

    let resp;
    try {
      resp = await fetch(url, { signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }

    if (!resp.ok) {
      verifiedCache.set(receiptId, { valid: false, envelope: null, cachedAt: now });
      return { valid: false, envelope: null };
    }

    const envelope = await resp.json();

    // signature_valid must be true AND the public key must match our known Spectral key
    const sigValid = envelope.signature_valid === true;
    const pkMatch  = envelope.public_key === SPECTRAL_PUBKEY_B64;
    const valid    = sigValid && pkMatch;

    verifiedCache.set(receiptId, { valid, envelope: valid ? envelope : null, cachedAt: now });
    return { valid, envelope: valid ? envelope : null };

  } catch (_err) {
    // timeout or network error → treat as invalid, do NOT cache (ephemeral failure)
    return { valid: false, envelope: null };
  }
}

/**
 * Parse the X-Hive-Prior-Receipts header.
 * Value: comma-separated receipt IDs (max 10 parsed, excess ignored).
 * Returns string[].
 */
function parsePriorReceiptIds(req) {
  const raw = (req.headers['x-hive-prior-receipts'] || '').trim();
  if (!raw) return [];
  return raw
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .slice(0, 10); // upper bound — only first 5 valid ones count anyway
}

/**
 * Core loyalty discount engine.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {number} basePrice  — base price in atomic units (USDC 6-decimal or any consistent unit)
 * @returns {Promise<{
 *   adjustedPrice: number,
 *   discountAppliedBps: number,
 *   receiptIdsAccepted: string[],
 *   receiptIdsRejected: string[],
 *   receiptIdsReplay:   string[]
 * }>}
 */
export async function applyLoyaltyDiscount(req, res, basePrice) {
  const ids    = parsePriorReceiptIds(req);
  const did    = callerDid(req);
  const day    = utcDay();
  const target = req.originalUrl || req.url || '/';

  const accepted = [];
  const rejected = [];
  const replayed = [];

  if (ids.length > 0) {
    // Verify in parallel for speed
    const results = await Promise.all(ids.map(id => verifyReceipt(id)));

    for (let i = 0; i < ids.length; i++) {
      const id     = ids[i];
      const result = results[i];

      if (!result.valid) {
        rejected.push(id);
        continue;
      }

      // Replay protection: (caller_DID, target_endpoint, day, receipt_id)
      const guardKey = `${did}:${target}:${day}:${id}`;
      if (replayGuard.has(guardKey)) {
        replayed.push(id);
        continue;
      }

      accepted.push(id);

      // Cap at 5 accepted receipts
      if (accepted.length >= 5) break;
    }

    // Register replay guards for accepted receipts AFTER we know the final set
    for (const id of accepted) {
      const guardKey = `${did}:${target}:${day}:${id}`;
      replayGuard.add(guardKey);

      // Auto-expire replay guard entries after midnight UTC (rough TTL via cleanup)
      setTimeout(() => replayGuard.delete(guardKey), 25 * 60 * 60 * 1000); // 25h
    }
  }

  const discountAppliedBps = Math.min(
    accepted.length * DISCOUNT_BPS_PER_RECEIPT,
    MAX_DISCOUNT_BPS
  );

  // Integer floor — always a non-negative amount, never below 75% of base
  const discountAmount = Math.floor(basePrice * discountAppliedBps / 10_000);
  const adjustedPrice  = basePrice - discountAmount;

  // Set response headers
  res.setHeader('X-Hive-Loyalty-Discount-Bps',      String(discountAppliedBps));
  res.setHeader('X-Hive-Receipts-Accepted-Count',    String(accepted.length));
  res.setHeader('X-Hive-Brand-Gold',                 BRAND_GOLD);

  if (accepted.length > 0) {
    res.setHeader('X-Hive-Receipts-Accepted',        accepted.join(','));
  }
  if (rejected.length > 0) {
    res.setHeader('X-Hive-Receipts-Rejected',        rejected.join(','));
  }
  if (replayed.length > 0) {
    res.setHeader('X-Hive-Receipts-Replay-Blocked',  replayed.join(','));
  }

  return {
    adjustedPrice,
    discountAppliedBps,
    receiptIdsAccepted: accepted,
    receiptIdsRejected: rejected,
    receiptIdsReplay:   replayed,
  };
}

/**
 * Convenience: build a standard x402 challenge JSON body with loyalty pricing applied.
 *
 * @param {object} opts
 * @param {number}  opts.adjustedPrice       — atomic USDC price (post-discount)
 * @param {number}  opts.discountAppliedBps  — discount in basis points
 * @param {string}  opts.resource            — endpoint path/URL
 * @param {string}  [opts.description]       — human-readable description
 * @param {string}  [opts.network]           — default 'base'
 * @param {number}  [opts.chainId]           — default 8453
 * @param {string}  [opts.asset]             — default 'USDC'
 * @param {string}  [opts.contract]          — default USDC on Base
 * @param {string}  [opts.payTo]             — default Monroe treasury
 */
export function buildLoyaltyChallenge({
  adjustedPrice,
  discountAppliedBps,
  resource,
  description = 'Hive service — x402 payment required.',
  network   = 'base',
  chainId   = 8453,
  asset     = 'USDC',
  contract  = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  payTo     = '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e',
}) {
  const challenge = {
    scheme:             'exact',
    network,
    chainId,
    asset,
    contract,
    maxAmountRequired:  String(adjustedPrice),
    payTo,
    resource,
    description,
    mimeType:           'application/json',
    x402Version:        1,
    loyalty: {
      discountBps:  discountAppliedBps,
      discountPct:  (discountAppliedBps / 100).toFixed(2) + '%',
      brandGold:    BRAND_GOLD,
      note: discountAppliedBps > 0
        ? `Receipt-gravity discount applied: ${(discountAppliedBps / 100).toFixed(0)}% off via Rail 3.`
        : 'No prior receipts presented. Submit X-Hive-Prior-Receipts for loyalty discount (5% per receipt, max 25%).',
    },
  };
  return challenge;
}

/**
 * Clear the in-process verified-receipt cache (useful in tests).
 */
export function clearLoyaltyCache() {
  verifiedCache.clear();
}

/**
 * Clear replay guards (useful in tests / day-boundary jobs).
 */
export function clearReplayGuard() {
  replayGuard.clear();
}
