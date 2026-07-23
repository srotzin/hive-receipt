/**
 * Live public-primitive smoke and routine soak for a running deployment.
 *
 * It reads GET /v1/primitives, then exercises every runnable, credential-free
 * primitive over HTTP against the real host and prints a pass/fail line with a
 * measured latency for each. With a soak count it repeats the runnable set and
 * reports p50/p95/p99 so an operator can watch a deployment hold steady. No
 * credentials, no payment, no external state.
 *
 *   node bench/primitives_smoke.mjs [base_url] [soak_iterations]
 *
 *   node bench/primitives_smoke.mjs https://inkframe.thehiveryiq.com
 *   node bench/primitives_smoke.mjs https://inkframe.thehiveryiq.com 200
 *
 * Exit code is 0 when every primitive passed, 1 otherwise, so it drops straight
 * into a health gate.
 *
 * Content rules: no em dashes; Carnac reads consequence. It does not judge.
 */

const BASE = (process.argv[2] || process.env.SMOKE_BASE || 'https://inkframe.thehiveryiq.com').replace(/\/$/, '');
const SOAK = Number(process.argv[3] || 0);

async function call(method, path, body) {
  const t0 = process.hrtime.bigint();
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  let json = null;
  try { json = await res.json(); } catch { /* non-json body */ }
  return { status: res.status, ms, json };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

// Each check returns { ok, note }. They mirror the credential-free routes.
async function buildChecks() {
  // A signed frame the replay and countersign checks reuse.
  const frameBody = {
    input_text: 'Ship 5 units to Acme by Friday.',
    anchors: [{ anchor_id: 'a0', start: 0, end: 11 }],
    edges: [{ src: 'a0', tgt: 'a0', rel: 'supports' }],
    demands: [{ anchor_id: 'a0', level: 'attest' }],
    bindings: [],
    action: { action_type: 'ship', target: 'acme' },
  };
  const frameRes = await call('POST', '/v1/inkframe/frame', frameBody);
  const signed = frameRes.json && frameRes.json.signed_frame;

  return [
    {
      id: 'inkframe.health',
      run: () => call('GET', '/v1/inkframe/health'),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true,
    },
    {
      id: 'inkframe.frame',
      run: () => call('POST', '/v1/inkframe/frame', frameBody),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true && r.json.self_verify && r.json.self_verify.ok,
    },
    {
      id: 'inkframe.cue_edge',
      run: () => call('POST', '/v1/inkframe/cue-edge', { src: 'a0', tgt: 'a1', rel: 'supports' }),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true,
    },
    {
      id: 'inkframe.prefill',
      run: () => call('POST', '/v1/inkframe/prefill', { anchor_set: { anchors: [] }, proof_demand_root: { demands: [] }, local_index: {} }),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true,
    },
    {
      id: 'inkframe.replay',
      run: () => call('POST', '/v1/inkframe/replay', { signed_frame: signed, deltas: [] }),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true && r.json.self_verify && r.json.self_verify.ok,
    },
    {
      id: 'inkframe.replay_leak_guard',
      run: () => call('POST', '/v1/inkframe/replay', { signed_frame: signed, deltas: [{ raw_text: 'secret' }] }),
      ok: (r) => r.status === 400 && r.json && r.json.error === 'leak',
    },
    {
      id: 'inkframe.countersign_match',
      run: () => call('POST', '/v1/inkframe/countersign', { signed_frame: signed, delivered_action: { action_type: 'ship', target: 'acme' } }),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true && r.json.countersignature.countersign_body.matches === true,
    },
    {
      id: 'inkframe.countersign_mismatch',
      run: () => call('POST', '/v1/inkframe/countersign', { signed_frame: signed, delivered_action: { action_type: 'ship', target: 'elsewhere' } }),
      ok: (r) => r.status === 200 && r.json && r.json.countersignature.countersign_body.matches === false,
    },
    {
      id: 'carnac.sandbox',
      run: () => call('POST', '/v1/carnac/sandbox', { request: 'delete all production data', phase: 'formation' }),
      ok: (r) => r.status === 200 && r.json && r.json.sandbox === true && r.json.judgment,
    },
    {
      id: 'carnac.policy',
      run: () => call('GET', '/v1/carnac/policy'),
      ok: (r) => r.status === 200 && r.json && typeof r.json.version === 'string',
    },
    {
      id: 'carnac.lifecycle_verify',
      run: () => call('POST', '/v1/carnac/lifecycle/verify', { stages: [] }),
      ok: (r) => r.status === 200 && r.json && r.json.ok === true,
    },
    {
      id: 'carnac.health',
      run: () => call('GET', '/v1/carnac/health'),
      ok: (r) => r.status === 200 && r.json && r.json.service === 'carnac',
    },
    {
      id: 'receipt.sign_x402_challenge',
      run: () => call('POST', '/v1/receipt/sign', { tx_hash: '0x1', network: 'base' }),
      ok: (r) => r.status === 402 && r.json && Array.isArray(r.json.accepts),
    },
    {
      id: 'receipt.verify_unknown_404',
      run: () => call('GET', '/v1/receipt/verify/UNKNOWN_ID'),
      ok: (r) => r.status === 404,
    },
    {
      id: 'primitives.catalog',
      run: () => call('GET', '/v1/primitives'),
      ok: (r) => r.status === 200 && r.json && Array.isArray(r.json.primitives) && r.json.primitives.length > 0,
    },
    {
      id: 'primitives.smoke',
      run: () => call('GET', '/v1/primitives/smoke'),
      ok: (r) => (r.status === 200 || r.status === 503) && r.json && typeof r.json.ok === 'boolean',
    },
  ];
}

async function main() {
  console.log(`live smoke: ${BASE}`);
  const checks = await buildChecks();

  let allOk = true;
  console.log('\nprimitive                         status  http   ms');
  console.log('------------------------------------------------------');
  for (const c of checks) {
    let r;
    try {
      r = await c.run();
    } catch (e) {
      allOk = false;
      console.log(`${c.id.padEnd(32)}  FAIL    err    ${e.message}`);
      continue;
    }
    const ok = c.ok(r);
    if (!ok) allOk = false;
    console.log(`${c.id.padEnd(32)}  ${ok ? 'PASS' : 'FAIL'}    ${String(r.status).padEnd(4)}  ${r.ms.toFixed(1)}`);
  }

  if (SOAK > 0) {
    console.log(`\nroutine soak: ${SOAK} passes over the runnable set`);
    const samples = [];
    let soakFailures = 0;
    for (let i = 0; i < SOAK; i++) {
      for (const c of checks) {
        try {
          const r = await c.run();
          samples.push(r.ms);
          if (!c.ok(r)) soakFailures++;
        } catch {
          soakFailures++;
        }
      }
    }
    samples.sort((a, b) => a - b);
    const mean = samples.reduce((a, b) => a + b, 0) / (samples.length || 1);
    console.log(`  requests       ${samples.length}`);
    console.log(`  failures       ${soakFailures}`);
    console.log(`  mean           ${mean.toFixed(1)} ms`);
    console.log(`  p50            ${percentile(samples, 50).toFixed(1)} ms`);
    console.log(`  p95            ${percentile(samples, 95).toFixed(1)} ms`);
    console.log(`  p99            ${percentile(samples, 99).toFixed(1)} ms`);
    if (soakFailures > 0) allOk = false;
  }

  console.log(`\nresult: ${allOk ? 'all primitives passed' : 'one or more primitives failed'}`);
  process.exit(allOk ? 0 : 1);
}

main().catch((e) => {
  console.error('smoke error:', e.message);
  process.exit(1);
});
