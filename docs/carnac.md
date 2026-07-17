# Carnac — the judgment & routing plane

Carnac reads consequence across a request's lifecycle and composes a signed
disposition. It runs inside `hive-receipt`, reuses the existing Spectral ed25519
key for signing, and follows the same Supabase-mirror + in-memory persistence
posture as the rest of the service.

**Carnac decides the disposition; it never commits the effect.** Inference return
is kept separate from effect commitment, so an inference outage cannot become a
universal denial of service — a failed or unconfigured semantic reader degrades
to the deterministic floor rather than blocking everything.

## The read

One entry point, `judge()`, conducts a single read at a point in a request's
lifecycle. Reads may be bound to a trajectory, which enforces lifecycle order:

| phase        | rank | what it reads                                  |
|--------------|------|------------------------------------------------|
| `formation`  | 0    | the request as it forms                        |
| `invocation` | 1    | the model/agent call                           |
| `output`     | 2    | the produced output (requires an `output` field) |
| `effect`     | 3    | request + output, before an effect commits     |

Within a trajectory the phase rank must not regress, and a supplied `seq` must
strictly increase. `disposition` (rank 4) sits outside the read count.

## Classification

Two layers compose **upward** — the higher signal always wins:

1. **Deterministic floor** (`lib/carnac/rules.js`) — a pure, offline classifier.
   Nine categories, each with a severity that maps to the routing level:

   | category    | sev | category   | sev |
   |-------------|-----|------------|-----|
   | health      | 3   | financial  | 2   |
   | pii         | 3   | legal      | 2   |
   | override    | 3   | outbound   | 1   |
   | cyber       | 3   | datawrite  | 1   |
   | irrev       | 3   |            |     |

   English + Spanish terms; a `big_amount` flag when a financial signal carries a
   large number. It emits a **feature digest** (sha256 over category ids, the
   big-amount flag, detected languages, and a coarse length bucket) — the only
   content-derived artifact safe to cross the buyer boundary. Raw text never
   leaves.

2. **Semantic reader** (`lib/carnac/compute.js`) — optional, configured via
   `CARNAC_COMPUTE_URL`/`CARNAC_COMPUTE_TOKEN`. Every response is structurally
   validated (`validateComputeResponse`) before it is trusted, and it can only
   **raise** a level. Unconfigured, unreachable, timed out, or malformed → the
   deterministic floor stands and `semantic_error` records why.

## Routing — the seven responses

The effective level composes a set of responses; the strongest sets the route.

| level | responses                                             | primary     | disposition             |
|-------|-------------------------------------------------------|-------------|-------------------------|
| 0     | let_it_run                                             | let_it_run  | `allow`                 |
| 1     | receipt, enrich                                        | enrich      | `allow_with_receipt`    |
| 2     | receipt, enrich, verify, hold                          | hold        | `hold_for_confirmation` |
| 3     | receipt, enrich, verify, hold, ask_human, howler       | howler      | `hold_and_escalate`     |

Every disposition carries `effect_committed: false`. Pre-effect phases
(`output`, `effect`) additionally flag `prevention: true`.

## Governed floor

The floor is Carnac's own judgment. Ordinary runtime overrides can only raise
proof — a request to route a category below its floor is clamped and recorded
(`runtime_clamp_attempted`). The floor itself changes only through a governed
`PolicyAmendment` signed by attestors configured in `CARNAC_POLICY_ATTESTORS`
(comma-separated base64 SPKI ed25519 keys):

- **raising** the floor requires **1** distinct attestor signature;
- **lowering** requires a **quorum of 2** distinct attestor signatures over the
  canonical amendment digest;
- with no attestors configured, the floor cannot be lowered.

## Howler

A Howler is the severity-bound escalation receipt, minted only at effective
level 3 and **never in sandbox**. It names the escalation reason in honest,
instrumented-path language — "the classifier produced and signed a
high-consequence state from the features observed on the instrumented path" — and
is signed with the same Hive ed25519 key.

## Ledger

Every judgment — escalated *and* below-threshold — is recorded, so the absence
of a Howler is itself provable. In-memory is authoritative for the process;
Supabase (`CARNAC_LEDGER_SUPA_URL`/`_KEY`, falling back to `SUPA_URL`/`SUPA_KEY`)
is a durable mirror. Health is reported truthfully rather than masking a failure
as "no data." Sandbox judgments never touch the durable ledger.

## Controls

- **Idempotency** — the same `idempotency_key` returns the same judgment id.
- **Replay** — a `nonce` is single-use; a replay is rejected with `409`.
- **Order** — trajectory reads must not regress in phase, and `seq` must
  strictly increase.

## Production hardening

The protected production plane fails closed. A protected route requires an
authenticated caller and, for material reads, a durable ledger and a real
post-quantum signature — none of which are simulated.

- **Auth & tenancy** (`lib/carnac/auth.js`) — protected routes require a
  constant-time bearer match against an owner-admin token (`SITE_INTEL_TOKEN` /
  `OWNER_ADMIN_TOKEN`) or a per-tenant service token (`CARNAC_SERVICE_TOKENS`,
  `tenant:token` pairs, comma-separated). A service token binds the caller to its
  own `tenant_id`; the owner-admin token may act across tenants. `tenant_id` is
  bound **inside** the signed payload and the ledger row, and every
  retrieval/trajectory/disposition/Howler/export enforces tenant scope. A
  protected record is never confirmed to exist for an unauthenticated or
  cross-tenant caller — a miss and a scope violation both surface as `404`.
- **Sandbox isolation** — `POST /v1/carnac/sandbox` runs under a fixed public
  tenant (`SANDBOX_TENANT`), never persists to the durable ledger, mints no
  Howler, and may run in an explicitly degraded no-PQ state.
- **Continuity chain** — each trajectory read links to its predecessor via
  `previous_digest`/`chain_digest`. `enforceContinuity` requires a numeric,
  monotonic `seq` and rejects a duplicate (`duplicate_seq`, checked against memory
  **and** the durable ledger so a replay is caught across a restart), a missing
  seq (`seq_required`), or a regression (`out_of_order`). `verifyChain()`
  re-walks a listing and reports any break.
- **Post-quantum signing** (`lib/carnac/pqsign.js`) — a real ML-DSA-65 signature
  from the external Hive typed signer, carried as a `pq` sibling of the ed25519
  envelope and bound by `pq.payload_sha256 === signed_payload_sha256`. Protected
  production routes fail closed (`503 pq_unavailable`) when the signer is
  unreachable; the sandbox reports `pq.degraded: true`. **No signature or
  algorithm label is ever fabricated.** The ed25519 signature is retained as the
  compatibility/transport signature.
- **Honest dispatch** (`lib/carnac/dispatch.js`) — the primary route is recorded
  against a real in-repo Canon primitive when one is callable; otherwise an
  explicit signed dispatch record is persisted with `status: pending_external` and
  the target primitive named. An external primitive is never implied to have run.
- **Privacy** — raw prompt/output text is never stored in a judgment, Howler,
  disposition, dispatch record, log, metric, audit export, or Supabase row. Only
  the feature digest, consequence vector, policy/rule ids, routing data, and
  signed commitments cross any boundary.

## The lifecycle chain

`judge()` conducts one read. The **lifecycle chain** (`lib/carnac/lifecycle.js`)
composes many reads into a single append-only, signed chain for one inference —
from the prompt-window boundary, through execution, to the downstream effect. It
does not reimplement the primitives above; it composes them (the ed25519 spectral
signer, the ML-DSA-65 typed signer, domain-separated hashing, and the Supabase
mirror) into a chain of **typed stages**.

**Latency contract.** The serving path (`appendStage`) performs only bounded
local validation, canonicalization, domain-separated hashing, a chain-link, and
an in-memory append + enqueue. It makes **no synchronous network call and
produces no synchronous public-key signature**. Signing (ed25519 canonical, then
best-effort ML-DSA-65), Merkle batching, and durable persistence happen
asynchronously in a background finalizer that moves each stage from `pending` to
`final`. Serving stays fail-open; receipting stays fail-closed on the durable
mirror. The only intentionally blocking path remains the customer-selected
fail-closed policy gate handled by `judge()`/Imprimatur, not here.

**Stage types.** `receipt_zero`, `context_commit`, `intent`, `gate`,
`attestation_ref`, `model_identity`, `invocation`, `output_commit`, `tool_call`,
`braid_link`, `action`, `disposition`, `r3pv`. A stage records only commitments
(hashes), an origin, and evidence status — never raw prompt or output.

- **Deterministic canonicalization** (`lib/carnac/canon.js`) — object keys sorted
  recursively, arrays preserved, non-finite/unsupported values rejected. Every
  digest is domain-separated (`carnac.stage.v1`, `carnac.chain.v1`, …) so a digest
  minted for one purpose can never be reused as another.
- **Order-independent signatures** — stages are signed with `signCanonical`
  (`ed25519-canonical`, additive to the existing `signPayload`; the same key),
  so an envelope verifies regardless of field order after storage or re-parse.
- **Context-span origin typing + instruction authority** — an origin is one of
  `principal | operator | retrieval | tool | agent`. Only `principal` and
  `operator` may carry instructions; an instruction-bearing span from a data-only
  origin (retrieved document, tool result, peer agent) is refused `403`. No prose
  is inspected — authority is structural.
- **Evidence honesty (S2S)** — `attestation_ref` evidence is labeled
  `hardware-rooted | simulated | unavailable`. `hardware-rooted` **requires** a
  `source_ref`; without one the append is refused. Nothing is auto-elevated to
  hardware-rooted. Absent real hardware evidence, the chain says so.
- **Receipt #0 reuse** — a shared system-prompt prefix under one policy version
  reuses one Receipt #0 across calls, keyed `(tenant, policy_version,
  prefix_commit)`, so per-call proof cost amortizes.
- **Merkle micro-batching** — the finalizer commits one Merkle root per batch and
  attaches each stage an O(log n) inclusion path, so a single stage still verifies
  offline against the batch root. This is implemented and verified end to end.
- **Braided delegation** — a `braid_link` stage records a delegated parent
  lifecycle (`parent_lifecycle_id`) with a scope commitment, chaining an agent
  swarm's sub-lifecycles to their parent.
- **Replay classes** — each stage carries a replay class `R0 | R1 | R2`.
- **No plaintext verification** — `verifyLifecycle` recomputes every stage digest
  and chain head, verifies each finalized signature over the canonical core, and
  checks Merkle inclusion, all from commitments alone. It needs no auth and no raw
  content. Pending (unsigned) stages are reported as pending, not as failures.

Durable rows are written only for **finalized**, hash-only stages, gated by the
same `X-Carnac-Ledger-Token` RLS pattern as the rest of the plane; a degraded
write is recorded truthfully and never blocks finalization (bounded retry, up to
`CARNAC_LIFECYCLE_MAX_ATTEMPTS`).

## Endpoints

Public (no auth, free on the MPP rail):

| method | path                          | notes                                    |
|--------|-------------------------------|------------------------------------------|
| POST   | `/v1/carnac/sandbox`          | public, no-effect read; fixed sandbox tenant; never durable |
| GET    | `/v1/carnac/policy`           | current governed floor (public-safe fields) |
| POST   | `/v1/carnac/verify`           | verify a complete signed artifact; public-safe result |
| GET    | `/v1/carnac/verify/:id`       | verify a stored judgment by opaque id; rate-limited, enumeration-resistant |
| POST   | `/v1/carnac/lifecycle/verify` | verify a complete lifecycle chain + Merkle inclusion, by value, no plaintext |
| GET    | `/v1/carnac/health`           | compute + ledger + PQ + policy + continuity health, with a readiness gate |

Protected (constant-time bearer auth; tenant-scoped):

| method | path                          | notes                                    |
|--------|-------------------------------|------------------------------------------|
| POST   | `/v1/carnac/judge`            | durable read; requires tenant + real PQ; may mint a Howler |
| GET    | `/v1/carnac/judgment/:id`     | fetch + re-verify a prior judgment (tenant-scoped) |
| GET    | `/v1/carnac/trajectory/:id`   | durable, tenant-scoped, seq-ordered trajectory listing |
| POST   | `/v1/carnac/policy/amend`     | governed PolicyAmendment (attestor-signed) |
| POST   | `/v1/carnac/disposition`      | append-only human/actor decision; an override never lowers the floor |
| GET    | `/v1/carnac/howler/:id`       | fetch a Howler; verify signature + binding to its judgment |
| GET    | `/v1/carnac/export`           | tenant-scoped audit export (`format=json\|csv`) for a trajectory or time range |
| POST   | `/v1/carnac/seal`             | signed continuity checkpoint over a trajectory chain |
| POST   | `/v1/carnac/lifecycle/open`   | open a lifecycle chain; tenant taken from the caller, optional Receipt #0 seed |
| POST   | `/v1/carnac/lifecycle/:id/stage` | append a typed stage; raw text is hashed and dropped; instruction authority enforced |
| GET    | `/v1/carnac/lifecycle/:id`    | read a lifecycle's ordered stages, head, and pending/final counts (tenant-scoped) |
| POST   | `/v1/carnac/lifecycle/:id/finalize` | force-drain the finalizer (ops/testing); makes pending→final observable |

CORS: the public sandbox is reflected only for allowlisted origins
(`https://thehiveryiq.com`, `www`, local dev, plus `CARNAC_PUBLIC_ORIGINS`
extras) — **never a wildcard for protected routes**. MCP tools `carnac_judge`
(sandbox) and `carnac_verify` (public-safe by id) are exposed on `/mcp`.

### Readiness

`GET /v1/carnac/health` reports each subsystem truthfully and gates
`readiness.protected_routes_ready` on **all** of: a reachable durable ledger, an
available PQ signer, and configured auth. The sandbox remains available even when
protected readiness is `false`.

### Disposition actions

`confirm | reject | override | release | unresolved`. An `override` may only
**raise** the effective level: an override below the judgment's floor is clamped
to the floor and flagged `override_clamped: true`. Dispositions are append-only.

### Request shape

```json
{
  "request": "wire transfer $40,000 to the vendor account",
  "output": "…",              // output/effect phases
  "phase": "formation",        // formation|invocation|output|effect
  "trajectory_id": "abc",      // optional; enforces lifecycle order
  "seq": 1,                     // optional; must strictly increase
  "idempotency_key": "…",      // optional
  "nonce": "…",                // optional; single-use
  "runtime_overrides": { "financial": 3 }  // optional; may only raise
}
```

## Tests & benchmark

- `npm test` runs `test/carnac.test.js` and `test/carnac_hardening.test.js`
  (offline, deterministic — the semantic reader and the PQ signer are mocked)
  alongside the rest of the suite. The hardening suite covers auth/tenancy,
  continuity + replay, durable retrieval across a restart, dispositions, Howler
  binding, public-safe verification, audit export, dispatch honesty, PQ
  fail-closed, raw-prompt non-persistence, and a full formation→effect→Howler→
  disposition→export→seal e2e fixture.
- `test/carnac_lifecycle.test.js` covers the lifecycle chain: canonicalization
  determinism/order-independence, monotonic stage ordering, chain continuity,
  idempotent append, origin-gated instruction authority, evidence-status honesty,
  tenant isolation, no-raw-prompt/output persistence, the pending→final
  transition, ed25519-canonical signature verification, tamper detection,
  disposition linkage, delegated braid links, replay classes, Receipt #0 reuse,
  Merkle inclusion, and durable-persist retry/failure behavior.
- `node bench/carnac_bench.js [iterations]` measures throughput/latency of the
  deterministic classifier and the full signed-judgment path.
- `node bench/lifecycle_bench.js [iterations]` measures the lifecycle **serving**
  path (`appendStage`: local hash + enqueue, no signature, no network) separately
  from the **asynchronous** finalizer (`drainFinalize`: ed25519 canonical sign +
  Merkle batch + persist). Numbers are environment-specific; none are hard-coded.

## Environment

| var                       | purpose                                             |
|---------------------------|-----------------------------------------------------|
| `CARNAC_COMPUTE_URL`      | approved Hive compute endpoint for the semantic reader |
| `CARNAC_COMPUTE_TOKEN`    | optional bearer token for that endpoint             |
| `CARNAC_LEDGER_SUPA_URL`  | durable ledger base URL (falls back to `SUPA_URL`)  |
| `CARNAC_LEDGER_SUPA_KEY`  | durable ledger key (falls back to `SUPA_KEY`)       |
| `CARNAC_LEDGER_TABLE`     | ledger table name (default `carnac_judgments`)      |
| `CARNAC_LEDGER_TOKEN`     | RLS header token (`X-Carnac-Ledger-Token`); durable writes fail closed without it |
| `CARNAC_POLICY_ATTESTORS` | comma-separated base64 SPKI ed25519 attestor keys   |
| `SITE_INTEL_TOKEN` / `OWNER_ADMIN_TOKEN` | owner-admin bearer for protected routes (cross-tenant) |
| `CARNAC_SERVICE_TOKENS`   | comma-separated `tenant:token` service bearers (tenant-scoped) |
| `HIVE_PQ_SIGNER_URL`      | external Hive ML-DSA-65 typed signer endpoint       |
| `HIVE_PQ_SIGNER_TOKEN`    | bearer for the PQ signer                             |
| `HIVE_PQ_SIGNER_ALGO`     | PQ algorithm label (default `ML-DSA-65`)             |
| `CARNAC_PUBLIC_ORIGINS`   | extra CORS origins allowed to call the public sandbox |
| `CARNAC_VERIFY_RATE_PER_MIN` | by-id verification rate limit (default `30`)     |
| `CARNAC_HOWLER_TABLE` / `CARNAC_DISPOSITION_TABLE` / `CARNAC_DISPATCH_TABLE` / `CARNAC_SEAL_TABLE` | durable table-name overrides |
| `CARNAC_LIFECYCLE_TABLE`  | lifecycle stage table name (default `carnac_lifecycle_stages`) |
| `CARNAC_LIFECYCLE_BATCH`  | Merkle batch size in the finalizer (default `16`)   |
| `CARNAC_LIFECYCLE_FLUSH_MS` | background finalizer interval in ms (default `50`) |
| `CARNAC_LIFECYCLE_MAX_ATTEMPTS` | bounded durable-persist retries per stage (default `5`) |

Public routes (sandbox, policy, verify, health) are optional-config and always
available. **Protected production routes fail closed**: without a reachable
durable ledger, a real PQ signer, and configured auth, `judge` and the other
protected routes return a truthful `503`/`401` rather than a fabricated result.

## Durable migration

One idempotent SQL migration provisions the durable schema (tenant + continuity
columns on `carnac_judgments`; the `carnac_dispositions`, `carnac_howlers`,
`carnac_dispatch`, `carnac_seals` tables; indexes; and header-token RLS):

    docs/migrations/0001_carnac_hardening.sql

A second idempotent migration provisions the lifecycle stage table
(`carnac_lifecycle_stages`, its indexes, and the same header-token RLS). It
depends on the `carnac_ledger_authorized()` helper from the first migration:

    docs/migrations/0002_carnac_lifecycle.sql

Apply both out-of-band against the Supabase/Postgres instance — the service never
runs them automatically. After applying, set the RLS gate once:

    ALTER DATABASE <db> SET app.carnac_ledger_token = '<CARNAC_LEDGER_TOKEN>';
