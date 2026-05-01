# hive-receipt v1.0.0

**Universal Spectral-signed payment receipts — x402 Base USDC**

---

## What This Server Does

`hive-receipt` issues ed25519-signed receipts for any on-chain payment. The Spectral public key is advertised in the agent card, enabling offline verification by any party. On-chain verification is attempted via public RPCs for Base, Ethereum, and Solana — best-effort, non-blocking.

---

## Tools

| Tool | Description |
|---|---|
| `sign_receipt` | Sign a payment receipt. Verifies tx on-chain (best-effort). Returns Spectral ed25519 envelope. x402 gated. |
| `verify_receipt` | Verify a receipt by `receipt_id`. Re-verifies ed25519 signature offline. |
| `list_my_receipts` | List receipts for a `payer_did`. Public read. |

---

## Backend Endpoint

```
https://hive-receipt.onrender.com
```

x402 challenge pays to Monroe (`0x15184Bf50B3d3F52b60434f8942b7D52F2eB436E`) on Base 8453, USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.

---

## Pricing

| Tier | Atomic (USDC 6-dec) | USD |
|---|---|---|
| Standard | `1000` | $0.001 |
| Audit (`?tier=audit`) | `100000` | $0.10 — 7-year retention guarantee |

---

## Council Provenance

Ad-hoc launch — commodity surface. Passes NEED + YIELD + CLEAN-MONEY gates:

- **NEED:** Every Hive tool settlement needs a portable, verifiable receipt.
- **YIELD:** $0.001 per receipt at scale; $0.10 for audit grade. Fee stacks with checkout volume.
- **CLEAN-MONEY:** Pure USDC on Base mainnet. No derivatives, no energy futures, no external exchange layer.

---

## Spectral Cryptography

- Algorithm: ed25519
- Keypair generated at deploy time; persisted via `SPECTRAL_PRIVKEY_B64` / `SPECTRAL_PUBKEY_B64` env vars
- Public key advertised in `/.well-known/agent.json` — enables offline verification without server trust

---

## On-Chain Verification Networks

- Base 8453 via `eth_getTransactionReceipt`
- Ethereum via public LlamaRPC
- Solana via `getTransaction` on mainnet

Best-effort — if RPC unreachable, `verification_status:"unverified"` is set and receipt is still signed.

---

## Brand

Color: `#C08D23` (Pantone 1245 C — Hive gold)

---

*Real rails only. Base USDC mainnet. Hivemorph stays private.*
