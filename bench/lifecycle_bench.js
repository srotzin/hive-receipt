/**
 * Carnac lifecycle-chain benchmark.
 *
 * Measures the two paths separately, because they have very different cost:
 *
 *   1. appendStage — the SERVING path. Bounded local validation, canonicalization,
 *      domain-separated hashing, chain-link, in-memory append + enqueue. No
 *      network, no public-key signature. This is the only cost a request pays.
 *
 *   2. drainFinalize — the ASYNCHRONOUS path that runs off the request. ed25519
 *      canonical signing, best-effort ML-DSA-65 (unavailable/offline here, so its
 *      cost is not counted as if it were free), Merkle batching, and durable
 *      persist (a fail-open no-op when Supabase is unconfigured).
 *
 * Numbers are measured on the machine you run this on. Nothing here is hard-coded
 * as a marketing figure; run it to get real p50/p95/p99 for your environment.
 *
 *   node bench/lifecycle_bench.js [iterations]
 */

import { initKeypair } from '../lib/spectral.js';
import {
  openLifecycle, appendStage, drainFinalize, _resetLifecycle, _setPersistHook,
} from '../lib/carnac/lifecycle.js';

initKeypair();

const iterations = Number(process.argv[2]) || 20000;
const TENANT = 'bench_tenant';

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function report(label, samples, totalMs, count) {
  samples.sort((a, b) => a - b);
  console.log(`\n${label}`);
  console.log(`  operations     ${count}`);
  console.log(`  total          ${totalMs.toFixed(1)} ms`);
  console.log(`  throughput     ${((count / totalMs) * 1000).toFixed(0)} ops/sec`);
  console.log(`  mean           ${(totalMs / count).toFixed(5)} ms`);
  console.log(`  p50            ${percentile(samples, 50).toFixed(5)} ms`);
  console.log(`  p95            ${percentile(samples, 95).toFixed(5)} ms`);
  console.log(`  p99            ${percentile(samples, 99).toFixed(5)} ms`);
}

async function main() {
  console.log(`Carnac lifecycle benchmark — ${iterations} iterations`);
  // Persist is a no-op so the finalize measurement reflects sign+merkle cost, not
  // a network round trip. Supabase timing is a separate, environment-specific I/O
  // concern and is deliberately excluded from the CPU-path numbers.
  _setPersistHook(async () => ({ ok: true, durable: false }));

  // ── SERVING PATH: appendStage only ────────────────────────────────────────
  _resetLifecycle();
  _setPersistHook(async () => ({ ok: true, durable: false }));
  const open = openLifecycle({ tenant_id: TENANT, lifecycle_id: 'bench_lc' });
  if (!open.ok) throw new Error('open failed');
  const text = 'a representative prompt span of moderate length that gets hashed and dropped';

  // Warm up.
  for (let i = 0; i < Math.min(2000, iterations); i++) {
    appendStage({ tenant_id: TENANT, lifecycle_id: 'bench_lc', type: 'context_commit', origin: { class: 'principal' }, text });
  }
  const appendSamples = new Array(iterations);
  const a0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const s = process.hrtime.bigint();
    appendStage({ tenant_id: TENANT, lifecycle_id: 'bench_lc', type: 'context_commit', origin: { class: 'principal' }, text });
    appendSamples[i] = Number(process.hrtime.bigint() - s) / 1e6;
  }
  const appendTotal = Number(process.hrtime.bigint() - a0) / 1e6;
  report('appendStage — SERVING path (local hash + enqueue, no signature, no network)', appendSamples, appendTotal, iterations);

  // ── ASYNC PATH: drainFinalize (sign + merkle + persist no-op) ──────────────
  // Measure per-drain cost by finalizing the queue built above in one pass, then
  // report amortized per-stage cost.
  const queued = iterations + Math.min(2000, iterations);
  const d0 = process.hrtime.bigint();
  const drain = await drainFinalize();
  const drainTotal = Number(process.hrtime.bigint() - d0) / 1e6;
  console.log('\ndrainFinalize — ASYNC path (ed25519 canonical sign + Merkle batch + persist no-op)');
  console.log(`  stages finalized  ${drain.final}`);
  console.log(`  batches           ${drain.batches}`);
  console.log(`  total             ${drainTotal.toFixed(1)} ms`);
  console.log(`  per-stage (amort) ${(drainTotal / Math.max(1, drain.final)).toFixed(5)} ms`);
  console.log(`  throughput        ${((drain.final / drainTotal) * 1000).toFixed(0)} stages/sec`);
  console.log(`  note              ML-DSA-65 signer unconfigured here; PQ cost not included. ed25519 dominates.`);

  console.log('\nInterpretation: the SERVING path is what a request waits on. The ASYNC');
  console.log('path (signing, batching, persistence) runs off the request and never');
  console.log('blocks it. Durable Supabase write latency is separate I/O, excluded above.');
}

main().catch((e) => { console.error(e); process.exit(1); });
