/**
 * Carnac deterministic-path benchmark.
 *
 * Measures throughput and latency of the guaranteed floor: classification plus
 * the full signed judgment (routing, disposition, ed25519 sign). The semantic
 * reader is disabled so this reflects the offline path that always runs, even
 * when the compute endpoint is unconfigured or unreachable.
 *
 *   node bench/carnac_bench.js [iterations]
 */

import { classifyDeterministic } from '../lib/carnac/rules.js';
import { judge, _resetEngine } from '../lib/carnac/engine.js';
import { _resetControls } from '../lib/carnac/idempotency.js';
import { _resetLedger } from '../lib/carnac/ledger.js';
import { initKeypair } from '../lib/spectral.js';
import { CASES } from '../test/fixtures/carnac_cases.js';

initKeypair();

const iterations = Number(process.argv[2]) || 5000;

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function bench(label, fn) {
  // Warm up.
  for (let i = 0; i < Math.min(500, iterations); i++) fn(i);
  const samples = new Array(iterations);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const s = process.hrtime.bigint();
    fn(i);
    samples[i] = Number(process.hrtime.bigint() - s) / 1e6; // ms
  }
  const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
  samples.sort((a, b) => a - b);
  const throughput = (iterations / totalMs) * 1000;
  console.log(`\n${label}`);
  console.log(`  iterations     ${iterations}`);
  console.log(`  total          ${totalMs.toFixed(1)} ms`);
  console.log(`  throughput     ${throughput.toFixed(0)} ops/sec`);
  console.log(`  mean           ${(totalMs / iterations).toFixed(4)} ms`);
  console.log(`  p50            ${percentile(samples, 50).toFixed(4)} ms`);
  console.log(`  p95            ${percentile(samples, 95).toFixed(4)} ms`);
  console.log(`  p99            ${percentile(samples, 99).toFixed(4)} ms`);
}

async function main() {
  console.log(`Carnac deterministic benchmark — ${CASES.length} fixture cases, ${iterations} iterations each stage`);

  // Stage 1: pure deterministic classification.
  bench('classifyDeterministic (pure floor)', (i) => {
    classifyDeterministic(CASES[i % CASES.length].text);
  });

  // Stage 2: full signed judgment (classify + route + disposition + ed25519 sign),
  // sandbox mode so nothing persists durably. Reset control/ledger state
  // periodically so single-use nonces and idempotency don't accumulate.
  let counter = 0;
  const runJudge = async (i) => {
    await judge({ request: CASES[i % CASES.length].text, useSemantic: false }, { sandbox: true });
    if (++counter % 1000 === 0) { _resetControls(); _resetLedger(); _resetEngine(); }
  };

  // hrtime-based async bench.
  for (let i = 0; i < Math.min(500, iterations); i++) await runJudge(i);
  const samples = new Array(iterations);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const s = process.hrtime.bigint();
    await runJudge(i);
    samples[i] = Number(process.hrtime.bigint() - s) / 1e6;
  }
  const totalMs = Number(process.hrtime.bigint() - t0) / 1e6;
  samples.sort((a, b) => a - b);
  console.log('\njudge() full signed judgment (sandbox, offline)');
  console.log(`  iterations     ${iterations}`);
  console.log(`  total          ${totalMs.toFixed(1)} ms`);
  console.log(`  throughput     ${((iterations / totalMs) * 1000).toFixed(0)} ops/sec`);
  console.log(`  mean           ${(totalMs / iterations).toFixed(4)} ms`);
  console.log(`  p50            ${percentile(samples, 50).toFixed(4)} ms`);
  console.log(`  p95            ${percentile(samples, 95).toFixed(4)} ms`);
  console.log(`  p99            ${percentile(samples, 99).toFixed(4)} ms`);
}

main().catch((e) => { console.error(e); process.exit(1); });
