# hive-receipt

**Universal Spectral-signed payment receipts. x402 Base USDC. On-chain verification for Base, Ethereum, and Solana.**

<span style="color:#C08D23">&#9632;</span> Brand: `#C08D23`

---

## Overview

`hive-receipt` issues cryptographically signed receipts for any on-chain payment across Base, Ethereum, and Solana. Every receipt is signed with a Spectral ed25519 keypair — the public key is advertised in the agent card so any party can verify offline without trusting the server.

**Settlement rail:** Base mainnet — USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)  
**Monroe treasury:** `0x15184bf50b3d3f52b60434f8942b7d52f2eb436e`  
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
| GET | `/` | none | Service info + pubkey + pricing |
| GET | `/.well-known/agent.json` | none | Agent card (Monroe + Spectral pubkey advertised) |
| POST | `/mcp` | none | MCP JSON-RPC |
| POST | `/v1/receipt/sign` | **x402** | Sign a receipt; 402 fires without `X-PAYMENT` |
| GET | `/v1/receipt/verify/:receipt_id` | none | Verify receipt signature |
| GET | `/v1/receipt/list/:payer_did` | none | List receipts for payer |

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
    "payTo": "0x15184bf50b3d3f52b60434f8942b7d52f2eb436e",
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
  "expected_recipient": "0x15184bf50b3d3f52b60434f8942b7d52f2eb436e",
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
