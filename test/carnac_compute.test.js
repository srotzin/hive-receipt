/**
 * Carnac semantic client — header contract and fallback tests.
 *
 * The approved Hive compute endpoint authenticates the internal call with the
 * dedicated X-Hive-Internal-Token header (never Authorization: Bearer). These
 * tests mock global.fetch so they are offline and deterministic: they assert the
 * exact header is sent, that no Authorization header leaks, that the token never
 * surfaces in results, that the semantic reader can only raise severity above the
 * deterministic floor, and that the engine falls back to deterministic on a 402,
 * a timeout, or a malformed response.
 */

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { classifySemantic } from '../lib/carnac/compute.js';
import { classify } from '../lib/carnac/classify.js';

const URL = 'https://compute.example.test/classify';
const TOKEN = 'hive_internal_llm_' + 'T'.repeat(48);

let realFetch;
let lastCall;

function mockFetchOnce(handler) {
  global.fetch = async (url, init) => {
    lastCall = { url, init };
    return handler(url, init);
  };
}

function jsonResponse(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

beforeEach(() => {
  realFetch = global.fetch;
  lastCall = null;
  process.env.CARNAC_COMPUTE_URL = URL;
  process.env.CARNAC_COMPUTE_TOKEN = TOKEN;
});

afterEach(() => {
  global.fetch = realFetch;
  delete process.env.CARNAC_COMPUTE_URL;
  delete process.env.CARNAC_COMPUTE_TOKEN;
});

test('sends the token as X-Hive-Internal-Token with the exact value', async () => {
  mockFetchOnce(() => jsonResponse({ level: 2, categories: [{ id: 'financial', sev: 2 }] }));
  const r = await classifySemantic('wire $500', { phase: 'formation' });
  assert.equal(r.ok, true);
  const headers = lastCall.init.headers;
  assert.equal(headers['X-Hive-Internal-Token'], TOKEN);
});

test('never sends an Authorization header', async () => {
  mockFetchOnce(() => jsonResponse({ level: 0, categories: [] }));
  await classifySemantic('hello', { phase: 'formation' });
  const headers = lastCall.init.headers;
  const keys = Object.keys(headers).map((k) => k.toLowerCase());
  assert.ok(!keys.includes('authorization'), `Authorization header present: ${keys.join(',')}`);
});

test('omits the auth header entirely when no token is configured', async () => {
  delete process.env.CARNAC_COMPUTE_TOKEN;
  mockFetchOnce(() => jsonResponse({ level: 0, categories: [] }));
  await classifySemantic('hello', { phase: 'formation' });
  const headers = lastCall.init.headers;
  assert.equal(headers['X-Hive-Internal-Token'], undefined);
  assert.ok(!Object.keys(headers).map((k) => k.toLowerCase()).includes('authorization'));
});

test('token never leaks into the result or the request body', async () => {
  mockFetchOnce(() => jsonResponse({ level: 1, categories: [{ id: 'outbound', sev: 1 }] }));
  const r = await classifySemantic('post to the channel', { phase: 'formation' });
  assert.ok(!JSON.stringify(r).includes(TOKEN), 'token leaked into result');
  assert.ok(!String(lastCall.init.body).includes(TOKEN), 'token leaked into request body');
});

test('semantic reader may only RAISE severity above the deterministic floor', async () => {
  // Deterministic floor for this text is 3 (irreversible). A semantic reader that
  // returns a lower level must not pull the composed judgment down.
  mockFetchOnce(() => jsonResponse({ level: 1, categories: [{ id: 'outbound', sev: 1 }] }));
  const low = await classify('delete the production database permanently', { phase: 'formation' });
  assert.equal(low.level, 3, 'semantic must not lower below deterministic floor');
  assert.equal(low.semantic_used, true);

  // A benign text (deterministic 0) with a semantic reader raising to 3 must rise.
  mockFetchOnce(() => jsonResponse({ level: 3, categories: [{ id: 'health', sev: 3 }] }));
  const high = await classify('please help me with a routine question', { phase: 'formation' });
  assert.equal(high.level, 3, 'semantic should raise a benign deterministic result');
  assert.ok(high.categories.some((c) => c.id === 'health'));
});

test('deterministic fallback on a 402 challenge', async () => {
  mockFetchOnce(() => jsonResponse({ error: 'payment required' }, { ok: false, status: 402 }));
  const sem = await classifySemantic('x', { phase: 'formation' });
  assert.equal(sem.ok, false);
  assert.match(sem.error, /402/);

  const r = await classify('wire transfer $9000 to vendor', { phase: 'formation' });
  assert.equal(r.engine, 'deterministic');
  assert.equal(r.semantic_used, false);
  assert.match(r.semantic_error, /402/);
  assert.equal(r.level, 2); // deterministic floor still stands
});

test('deterministic fallback on a timeout', async () => {
  mockFetchOnce(() => { const e = new Error('timed out'); e.name = 'TimeoutError'; throw e; });
  const r = await classify('delete production permanently', { phase: 'formation', timeoutMs: 10 });
  assert.equal(r.engine, 'deterministic');
  assert.equal(r.semantic_used, false);
  assert.match(r.semantic_error, /timeout/);
  assert.equal(r.level, 3);
});

test('deterministic fallback on a malformed response', async () => {
  mockFetchOnce(() => jsonResponse({ level: 'not-a-number', categories: 'nope' }));
  const sem = await classifySemantic('x', { phase: 'formation' });
  assert.equal(sem.ok, false);
  assert.match(sem.error, /invalid_response/);

  const r = await classify('send an email to the customer list', { phase: 'formation' });
  assert.equal(r.engine, 'deterministic');
  assert.equal(r.semantic_used, false);
  assert.equal(r.level, 1);
});
