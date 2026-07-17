/**
 * Carnac ledger — durable Supabase token contract tests.
 *
 * The durable table's RLS policies require the X-Carnac-Ledger-Token header,
 * sourced from CARNAC_LEDGER_TOKEN. These tests mock global.fetch so they are
 * offline and deterministic: they assert the header rides on every REST write,
 * read, and health probe; that durable operations fail closed (degraded, never
 * throwing) when the token is absent while the in-memory store still serves; and
 * that the token never leaks into a returned value or error.
 */

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  persistJudgment,
  fetchJudgment,
  ledgerHealth,
  _resetLedger,
} from '../lib/carnac/ledger.js';

const URL = 'https://ledger.example.test';
const KEY = 'supa_service_key_' + 'K'.repeat(32);
const TOKEN = 'carnac_ledger_' + 'T'.repeat(40);

let realFetch;
let calls;

function mockFetch(handler) {
  global.fetch = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
}

function okJson(body, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => body, text: async () => JSON.stringify(body) };
}

function envelope(id, { trajectory_id = null } = {}) {
  return {
    judgment_id: id,
    trajectory_id,
    phase: 'formation',
    effective_level: 2,
    primary_route: 'confirm',
    disposition: { state: 'confirm', escalated: false },
    feature_digest: 'fd-abc',
    policy_version: 'v1',
    engine: 'deterministic',
    generated_at: '2026-07-17T00:00:00.000Z',
  };
}

beforeEach(() => {
  realFetch = global.fetch;
  calls = [];
  _resetLedger();
  process.env.CARNAC_LEDGER_SUPA_URL = URL;
  process.env.CARNAC_LEDGER_SUPA_KEY = KEY;
  process.env.CARNAC_LEDGER_TOKEN = TOKEN;
});

afterEach(() => {
  global.fetch = realFetch;
  delete process.env.CARNAC_LEDGER_SUPA_URL;
  delete process.env.CARNAC_LEDGER_SUPA_KEY;
  delete process.env.CARNAC_LEDGER_TOKEN;
});

test('insert carries X-Carnac-Ledger-Token', async () => {
  mockFetch(() => okJson(null, { status: 201 }));
  const r = await persistJudgment(envelope('j-insert'));
  assert.equal(r.durable, true);
  assert.equal(r.degraded, false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['X-Carnac-Ledger-Token'], TOKEN);
});

test('select carries X-Carnac-Ledger-Token', async () => {
  mockFetch(() => okJson([{ envelope: envelope('j-read') }]));
  const r = await fetchJudgment('j-read'); // memory empty after reset -> durable path
  assert.ok(r && r.judgment_id === 'j-read');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers['X-Carnac-Ledger-Token'], TOKEN);
});

test('health probe carries X-Carnac-Ledger-Token', async () => {
  mockFetch(() => okJson([{ judgment_id: 'x' }]));
  const h = await ledgerHealth();
  assert.equal(h.durable_reachable, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers['X-Carnac-Ledger-Token'], TOKEN);
});

test('missing token: insert fails closed but in-memory still serves', async () => {
  delete process.env.CARNAC_LEDGER_TOKEN;
  let fetched = false;
  mockFetch(() => { fetched = true; return okJson(null, { status: 201 }); });
  const r = await persistJudgment(envelope('j-nomemory'));
  assert.equal(r.ok, true);
  assert.equal(r.durable, false);
  assert.equal(r.degraded, true, 'degradation reported truthfully');
  assert.equal(fetched, false, 'no durable write attempted without the token');
  // In-memory fallback still authoritative for reads in-process.
  const back = await fetchJudgment('j-nomemory');
  assert.ok(back && back.judgment_id === 'j-nomemory');
});

test('missing token: durable read fails closed (no fetch), memory miss returns null', async () => {
  delete process.env.CARNAC_LEDGER_TOKEN;
  let fetched = false;
  mockFetch(() => { fetched = true; return okJson([{ envelope: envelope('j-x') }]); });
  const r = await fetchJudgment('j-not-in-memory');
  assert.equal(r, null);
  assert.equal(fetched, false, 'no durable read attempted without the token');
});

test('missing token: health reports degraded truthfully without probing', async () => {
  delete process.env.CARNAC_LEDGER_TOKEN;
  let fetched = false;
  mockFetch(() => { fetched = true; return okJson([]); });
  const h = await ledgerHealth();
  assert.equal(h.durable_configured, true);
  assert.equal(h.durable_reachable, false);
  assert.ok(typeof h.error === 'string' && h.error.length > 0, 'truthful error present');
  assert.equal(fetched, false, 'no probe attempted without the token');
});

test('the token never leaks into returned values or errors', async () => {
  // Success path.
  mockFetch(() => okJson(null, { status: 201 }));
  const p = await persistJudgment(envelope('j-leak'));
  assert.ok(!JSON.stringify(p).includes(TOKEN), 'token leaked into persist result');

  const h = await (async () => { mockFetch(() => okJson([{ judgment_id: 'x' }])); return ledgerHealth(); })();
  assert.ok(!JSON.stringify(h).includes(TOKEN), 'token leaked into health');

  // Error path: durable write returns non-ok; the token must not ride in the error.
  mockFetch(() => okJson({ message: 'denied' }, { ok: false, status: 401 }));
  const perr = await persistJudgment(envelope('j-leak-err'));
  assert.equal(perr.degraded, true);
  assert.ok(!JSON.stringify(perr).includes(TOKEN), 'token leaked into error result');
});
