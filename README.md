# hive-receipt

**Universal Spectral-signed payment receipts. x402 Base USDC. On-chain verification for Base, Ethereum, and Solana.**

<span style="color:#C08D23">&#9632;</span> Brand: `#C08D23`

---

## Overview

`hive-receipt` issues cryptographically signed receipts for any on-chain payment across Base, Ethereum, and Solana. Every receipt is signed with a Spectral ed25519 keypair — the public key is advertised in the agent card so any party can verify offline without trusting the server.

**Settlement rail:** Base mainnet — USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)  
**Monroe treasury:** `0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E`  
**Signature algo:** ed25519 (Spectral)  
**On-chain verification:** Base, Ethereum, Solana — best-effort via public RPCs  

---

## Pricing

| Tier | Amount (atomic USDC) | USD | Notes |
|---|---|---|---|
| Standard | `1000` | $0.001 | Immediate signed receipt |
| Audit (`?tier=audit`) | `100000` | $0.10 | 7-year retention guarantee |

---

## Tools (MCP)

| Tool | Description |
|---|---|
| `sign_receipt` | Sign a payment receipt. Returns Spectral ed25519 envelope. x402 gated — use `POST /v1/receipt/sign` with `X-PAYMENT`. |
| `verify_receipt` | Verify a receipt by `receipt_id`. Re-verifies ed25519 signature against embedded pubkey. |
| `list_my_receipts` | List all receipts for a `payer_did`. |

MCP endpoint: `POST /mcp` (JSON-RPC 2.0, MCP `2024-11-05`)

---

## REST Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | Health check |
| GET | `/v1/primitives` | none | Truthful catalog of runnable, gated, protected, and catalog-only primitives with method, endpoint, and a copy-paste curl for each runnable one |
| GET | `/v1/primitives/smoke` | none | Exercises the runnable public set in-process and returns a pass/fail line per primitive; ready for live verification |
| GET | `/` | none | Service info + pubkey + pricing |
| GET | `/.well-known/agent.json` | none | Agent card (Monroe + Spectral pubkey advertised) |
| POST | `/mcp` | none | MCP JSON-RPC |
| POST | `/v1/receipt/sign` | **x402** | Sign a receipt; 402 fires without `X-PAYMENT` |
| GET | `/v1/receipt/verify/:receipt_id` | none | Verify receipt signature |
| GET | `/v1/receipt/list/:payer_did` | none | List receipts for payer |
| POST | `/v1/carnac/sandbox` | none | Carnac judgment plane — public no-effect read |
| POST | `/v1/carnac/judge` | none | Carnac durable read; may mint a Howler |
| GET | `/v1/carnac/judgment/:id` | none | Fetch + re-verify a prior judgment |
| GET | `/v1/carnac/policy` | none | Current governed floor |
| GET | `/v1/carnac/health` | none | Compute + ledger + policy health |

---

## Live verification (no credentials)

Every runnable primitive is public and credential-free. Discover them and prove
they execute in two calls:

```bash
# 1. List runnable, gated, protected, and catalog-only primitives with sample curls
curl -s https://inkframe.thehiveryiq.com/v1/primitives

# 2. Exercise the runnable public set server-side and get a pass/fail per primitive
curl -s https://inkframe.thehiveryiq.com/v1/primitives/smoke
```

The runnable set covers the Carnac Live Ink&trade; (InkFrame v1) substrate
(`/v1/inkframe/frame`, `/cue-edge`, `/prefill`, `/replay`, `/countersign`,
`/health`), the Carnac&trade; public reading plane (`/v1/carnac/sandbox`,
`/policy`, `/verify`, `/lifecycle/verify`, `/health`), the free SiGR receipt
reads, and the MCP tool surface. Disclosure-free replay refuses raw-text deltas;
the arrival countersignature detects an approved-vs-delivered mismatch.

A local or live soak run, with `p50`/`p95`/`p99`, is available from the CLI:

```bash
node bench/primitives_smoke.mjs https://inkframe.thehiveryiq.com 200
```

It exits non-zero if any primitive fails, so it drops straight into a health
gate.

---

## Carnac — judgment & routing plane

Carnac reads consequence across a request's lifecycle (formation → invocation →
output → effect) and composes a **signed disposition** using the same Spectral
ed25519 key. It classifies against a deterministic floor (with an optional,
structurally-validated semantic reader that can only *raise* a level), routes to
one of seven responses, enforces idempotency/replay/order, records every judgment
to a ledger (so the absence of a Howler is provable), and mints a **Howler**
escalation receipt at the top severity. **Carnac decides the disposition; it
never commits the effect itself.**

See [`docs/carnac.md`](docs/carnac.md) for the full contract, endpoints, governed
floor amendment rules, and environment variables. MCP tools `carnac_judge`
(sandbox) and `carnac_verify` are exposed on `/mcp`.

---

## x402 Payment Challenge

Standard tier — calling `POST /v1/receipt/sign` without `X-PAYMENT`:

```json
{
  "x402_version": "0.2.0",
  "error": "Payment Required",
  "accepts": [{
    "scheme": "exact",
    "network": "base",
    "chainId": 8453,
    "asset": "USDC",
    "contract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "maxAmountRequired": "1000",
    "payTo": "0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E",
    "resource": "/v1/receipt/sign",
    "description": "Hive universal receipt signature — $0.001 per receipt.",
    "mimeType": "application/json"
  }]
}
```

Audit tier: add `?tier=audit` — `maxAmountRequired` becomes `"100000"`.

---

## Sample Signed Envelope

```json
{
  "receipt_id": "a1b2c3d4e5f6...",
  "tx_hash": "0xabc...",
  "network": "base",
  "expected_recipient": "0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E",
  "expected_amount_atomic": 1000000,
  "expected_asset": "USDC",
  "payer_did": "did:hive:0xpayer...",
  "payee_did": "did:hive:0xpayee...",
  "verified": true,
  "verification_attempted": true,
  "verification_status": "verified",
  "tier": "standard",
  "generated_at": "2025-05-01T12:00:00.000Z",
  "signature": "<base64-ed25519-sig>",
  "public_key": "<base64-spki-pubkey>",
  "signed_payload_sha256": "<sha256-of-payload>",
  "signature_algo": "ed25519"
}
```

### Offline Verification

Anyone can verify a receipt offline:

```javascript
import crypto from 'crypto';

// pubkey from /.well-known/agent.json -> spectral.public_key
const pubKeyDer = Buffer.from(envelope.public_key, 'base64');
const pubKeyObj = crypto.createPublicKey({ key: pubKeyDer, format: 'der', type: 'spki' });

const { signature, public_key, signed_payload_sha256, signature_algo, ...payload } = envelope;
const payloadStr = JSON.stringify(payload);
const valid = crypto.verify(null, Buffer.from(payloadStr), pubKeyObj, Buffer.from(signature, 'base64'));
console.log('valid:', valid); // true
```

---

## On-Chain Verification

| Network | RPC | Verification Method |
|---|---|---|
| Base (8453) | `https://mainnet.base.org` | `eth_getTransactionReceipt` |
| Ethereum | `https://eth.llamarpc.com` | `eth_getTransactionReceipt` |
| Solana | `https://api.mainnet-beta.solana.com` | `getTransaction` |

All verification is best-effort. If the RPC is unreachable, `verification_status` is set to `"unverified"` but the receipt is still signed. The signature proves the server attested to the inputs at a given time.

---

## Supported Rails

| Network | Asset | Address / Mint |
|---|---|---|
| Base 8453 | USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Base 8453 | USDT | `0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2` |
| Solana | USDC | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Solana treasury | — | `B1N61cuL35fhskWz5dw8XqDyP6LWi3ZWmq8CNA9L3FVn` |

---

## Pairs With

- [`hive-checkout`](https://github.com/srotzin/hive-checkout) — bundle multiple tool payments; request a receipt for the settlement.
- [`hive-mcp-evaluator`](https://github.com/srotzin/hive-mcp-evaluator) — sign a receipt after an LLM evaluation job settles.

---

## Connect

**Smithery:** `https://smithery.ai/server/srotzin/hive-receipt`  
**Glama:** `https://glama.ai/mcp/servers/srotzin/hive-receipt`  
**Repo:** `https://github.com/srotzin/hive-receipt`

---

*Built on Base mainnet. Real rails only. Brand gold `#C08D23`. Hivemorph stays private.*


---

## Hive Civilization

Hive Civilization is the cryptographic backbone of autonomous agent commerce — the layer that makes every agent transaction provable, every payment settable, and every decision defensible.

This repository is part of the **PROVABLE** pillar.

- thehiveryiq.com
- hiveagentiq.com
- agent-card: https://hivetrust.onrender.com/.well-known/agent-card.json
