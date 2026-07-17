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

## Endpoints

| method | path                          | notes                                    |
|--------|-------------------------------|------------------------------------------|
| POST   | `/v1/carnac/sandbox`          | public, no-effect read; never durable    |
| POST   | `/v1/carnac/judge`            | durable read; may mint a Howler          |
| GET    | `/v1/carnac/judgment/:id`     | fetch + re-verify a prior judgment       |
| GET    | `/v1/carnac/trajectory/:id`   | list judgments bound to a trajectory     |
| GET    | `/v1/carnac/policy`           | current governed floor                   |
| POST   | `/v1/carnac/policy/amend`     | governed PolicyAmendment (attestor-signed) |
| GET    | `/v1/carnac/health`           | compute + ledger + policy health         |

All `/v1/carnac/*` paths are free (never charged by the MPP rail). MCP tools
`carnac_judge` (sandbox) and `carnac_verify` are exposed on `/mcp`.

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

- `npm test` runs `test/carnac.test.js` (offline, deterministic — the semantic
  reader is disabled) alongside the rest of the suite.
- `node bench/carnac_bench.js [iterations]` measures throughput/latency of the
  deterministic classifier and the full signed-judgment path.

## Environment

| var                       | purpose                                             |
|---------------------------|-----------------------------------------------------|
| `CARNAC_COMPUTE_URL`      | approved Hive compute endpoint for the semantic reader |
| `CARNAC_COMPUTE_TOKEN`    | optional bearer token for that endpoint             |
| `CARNAC_LEDGER_SUPA_URL`  | durable ledger base URL (falls back to `SUPA_URL`)  |
| `CARNAC_LEDGER_SUPA_KEY`  | durable ledger key (falls back to `SUPA_KEY`)       |
| `CARNAC_LEDGER_TABLE`     | ledger table name (default `carnac_judgments`)      |
| `CARNAC_POLICY_ATTESTORS` | comma-separated base64 SPKI ed25519 attestor keys   |

All are optional. With none set, the plane runs on the deterministic floor with
an in-memory ledger and an unlowerable default floor.
