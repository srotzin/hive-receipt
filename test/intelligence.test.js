import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIntelligence, _internal } from '../lib/intelligence.js';
import { checkOwnerAuth, getConfiguredToken } from '../lib/owner_auth.js';

const NOW = new Date('2026-07-15T20:00:00.000Z');
const TZ = 'America/Los_Angeles';

function at(offsetMs, extra = {}) {
  return {
    ts: new Date(NOW.getTime() + offsetMs).toISOString(),
    ip: '203.0.113.7',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120 Safari/537.36',
    country: 'US', region: 'California', city: 'San Francisco', org: 'Comcast Cable',
    ref: '', ...extra,
  };
}
const healthy = { reachable: true, source: 'test', error: null };

test('empty data: no fabricated narrative, honest diagnostics', () => {
  const r = buildIntelligence({ events: [], now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.data_quality.rows_returned, 0);
  assert.equal(r.brief.sufficient_data, false);
  assert.ok(r.brief.note.length > 0);
  assert.equal(r.high_signal_visits.length, 0);
  assert.equal(r.session_journeys.length, 0);
  assert.ok(r.anomalies.some((a) => a.type === 'no_events'));
  assert.equal(r.facts['24h'].current.events_total, 0);
  // Contract keys present even when empty.
  for (const k of ['generated_at', 'timezone', 'source_health', 'facts', 'brief', 'limitations', 'conversions']) {
    assert.ok(k in r, `missing key ${k}`);
  }
});

test('source unreachable: broken_telemetry critical, closed narrative', () => {
  const r = buildIntelligence({ events: [], now: NOW, timezone: TZ, sourceHealth: { reachable: false, error: 'timeout after 8000ms', source: 'supabase' } });
  assert.ok(r.anomalies.some((a) => a.type === 'broken_telemetry' && a.severity === 'critical'));
  assert.equal(r.brief.sufficient_data, false);
  assert.ok(r.brief.recommended_actions.some((a) => /telemetry source/i.test(a.statement)));
});

test('stale data: stale_feed anomaly when last event beyond threshold', () => {
  const events = [at(-2 * 3600_000)]; // 2h ago > 15m threshold
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.source_health.is_stale, true);
  assert.ok(r.source_health.silence_seconds >= 7000);
  assert.ok(r.anomalies.some((a) => a.type === 'stale_feed'));
});

test('one event: counts of 1, no divide-by-zero, no repeat visitor', () => {
  const r = buildIntelligence({ events: [at(-60_000)], now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.facts['1h'].current.events_total, 1);
  assert.equal(r.facts['1h'].current.unique_human_visitors, 1);
  assert.equal(r.aggregations_24h_human.repeat_visitors, 0);
  // previous period is 0 -> change vs empty baseline is null, never NaN/Infinity.
  assert.equal(r.facts['1h'].comparison.human_events_change_pct, null);
});

test('bot-only traffic: excluded from human counts, reported as crawlers', () => {
  const bots = [
    at(-60_000, { ua: 'Googlebot/2.1 (+http://www.google.com/bot.html)' }),
    at(-120_000, { ua: 'GPTBot/1.0', ip: '52.1.1.1', org: 'Amazon AWS' }),
    at(-180_000, { ua: '', ip: '10.0.0.9', org: 'DigitalOcean' }),
  ];
  const r = buildIntelligence({ events: bots, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.facts['24h'].current.human_events, 0);
  assert.equal(r.facts['24h'].current.crawler_events, 3);
  assert.equal(r.high_signal_visits.length, 0, 'crawlers never high signal');
  assert.equal(r.aggregations_24h_human.top_countries.length, 0, 'no human aggregation from bots');
  assert.ok(r.classification.crawler_events_7d >= 3);
});

test('repeated sessions: same visitor across 2 days counts as repeat', () => {
  const events = [
    at(-60_000),
    at(-25 * 3600_000), // ~25h ago, different UTC day -> 2 active days
  ];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.aggregations_24h_human.repeat_visitors, 1);
  assert.equal(r.data_quality.unique_visitors_7d, 1);
});

test('session gap splits journeys; contiguous events stay one session', () => {
  const v = { ip: '198.51.100.5', ua: at(0).ua, org: 'Verizon' };
  const events = [
    at(-40 * 60_000, { ...v, path: '/' }),        // session A start
    at(-39 * 60_000, { ...v, path: '/pricing' }), // same session
    at(-5 * 60_000, { ...v, path: '/contact' }),  // >30m gap -> session B
  ];
  const sessions = _internal.buildSessions(events.map((e) => _internal.normalizeRow(e, 's', 'thehiveryiq.com')));
  assert.equal(sessions.length, 2);
});

test('high signal journey: multi-page with pricing+contact, ordered, dwell valid', () => {
  const v = { ip: '198.51.100.22', ua: at(0).ua, org: 'Verizon Business', country: 'US', ref: 'https://www.google.com/search?q=x' };
  const events = [
    at(-9 * 60_000, { ...v, path: '/' }),
    at(-7 * 60_000, { ...v, path: '/pricing' }),
    at(-5 * 60_000, { ...v, path: '/contact' }),
  ];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.ok(r.high_signal_visits.length >= 1);
  const hs = r.high_signal_visits[0];
  assert.ok(hs.confidence > 0.35);
  assert.ok(hs.evidence.some((e) => e.code === 'high_intent_page'));
  const j = r.session_journeys[0];
  assert.equal(j.entry_page, '/');
  assert.equal(j.exit_page, '/contact');
  assert.equal(j.referrer_class, 'search');
  assert.equal(j.page_count, 3);
  // ordered by ts ascending
  const ts = j.pages.map((p) => p.ts_utc);
  assert.deepEqual(ts, [...ts].sort());
  // last page dwell is null (unbounded), earlier steps valid
  assert.equal(j.pages[2].dwell_valid, false);
  assert.equal(j.pages[0].dwell_valid, true);
});

test('period comparison uses equal length complete windows', () => {
  // 6 events in current hour, 2 in prior hour.
  const events = [];
  for (let i = 0; i < 6; i++) events.push(at(-(i + 1) * 5 * 60_000, { ip: `1.2.3.${i}` }));
  for (let i = 0; i < 2; i++) events.push(at(-(70 + i * 5) * 60_000, { ip: `4.5.6.${i}` }));
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.facts['1h'].current.human_events, 6);
  assert.equal(r.facts['1h'].previous.human_events, 2);
  assert.equal(r.facts['1h'].comparison.human_events_change_pct, 200);
  assert.equal(r.facts['1h'].comparison.basis, 'equal_length_complete_periods');
});

test('traffic spike anomaly fires on 3x prior hour', () => {
  const events = [];
  for (let i = 0; i < 18; i++) events.push(at(-(i + 1) * 2 * 60_000, { ip: `9.9.${i}.1` }));
  for (let i = 0; i < 5; i++) events.push(at(-(65 + i) * 60_000, { ip: `8.8.${i}.1` }));
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.ok(r.anomalies.some((a) => a.type === 'traffic_spike'));
});

test('missing geo/network fields handled without error', () => {
  const events = [
    { ts: at(-60_000).ts, ip: '5.5.5.5', ua: at(0).ua }, // no country/org/city
    { ts: at(-120_000).ts, ua: at(0).ua },                // no ip either
  ];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.ok(r.limitations.some((l) => /geo country/i.test(l)));
  assert.equal(r.facts['24h'].current.events_total, 2);
});

test('invalid timestamps excluded and counted in data_quality', () => {
  const events = [at(-60_000), { ts: 'not-a-date', ip: '1.1.1.1', ua: 'x' }];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.data_quality.rows_returned, 2);
  assert.equal(r.data_quality.rows_valid_ts, 1);
  assert.equal(r.data_quality.rows_invalid_ts, 1);
});

test('conversions only from explicit events, never page views', () => {
  const v = { ip: '198.51.100.9', ua: at(0).ua };
  const events = [
    at(-10 * 60_000, { ...v, path: '/signup' }),               // page view, NOT a conversion
    at(-9 * 60_000, { ...v, path: '/signup', event: 'signup_completed' }), // explicit
  ];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.conversions.total_explicit_events, 1);
  assert.equal(r.conversions.by_event[0].event, 'signup_completed');
  assert.equal(r.conversions.by_event[0].count, 1);
});

test('no raw PII (ip, full UA, email) in serialized payload', () => {
  const events = [at(-60_000, { ip: '203.0.113.77', ua: 'Mozilla/5.0 secret-agent-string', ref: 'mailto:steve@example.com' })];
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  const json = JSON.stringify(r);
  assert.ok(!json.includes('203.0.113.77'), 'raw ip leaked');
  assert.ok(!json.includes('secret-agent-string'), 'raw UA leaked');
  assert.ok(!json.includes('steve@example.com'), 'email leaked');
  // visitor id is a pseudonymous hash
  assert.match(r.classification.sample[0].session_id, /^[sd]_[0-9a-f]{12}$/);
});

test('bot classifier reasons + confidence', () => {
  const bot = _internal.classifyAgent('Googlebot/2.1', 'Google LLC');
  assert.equal(bot.is_bot, true);
  assert.ok(bot.reasons.includes('ua_contains_bot'));
  assert.ok(bot.confidence >= 0.5 && bot.confidence <= 0.99);
  const human = _internal.classifyAgent(at(0).ua, 'Comcast');
  assert.equal(human.is_bot, false);
});

test('referrer classification: direct/search/social/internal', () => {
  assert.equal(_internal.classifyReferrer('', 'thehiveryiq.com').class, 'direct');
  assert.equal(_internal.classifyReferrer('https://www.google.com/search', 'thehiveryiq.com').class, 'search');
  assert.equal(_internal.classifyReferrer('https://x.com/foo', 'thehiveryiq.com').class, 'social');
  assert.equal(_internal.classifyReferrer('https://thehiveryiq.com/a', 'thehiveryiq.com').class, 'internal');
  assert.equal(_internal.classifyReferrer('https://random.dev/a', 'thehiveryiq.com').class, 'external');
});

test('changePct null baseline safety', () => {
  assert.equal(_internal.changePct(5, 0), null);
  assert.equal(_internal.changePct(0, 0), 0);
  assert.equal(_internal.changePct(10, 5), 100);
});

test('timezone: UTC preserved, LA offset label present', () => {
  const r = buildIntelligence({ events: [at(-60_000)], now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.generated_at, NOW.toISOString()); // UTC preserved
  assert.equal(r.timezone, TZ);
  assert.match(r.timezone_offset, /GMT-\d/); // PDT/PST negative offset
});

// ── auth ────────────────────────────────────────────────────────────────────
test('auth: unconfigured -> 503 not_configured (closed, not open)', () => {
  delete process.env.SITE_INTEL_TOKEN;
  delete process.env.OWNER_ADMIN_TOKEN;
  const res = checkOwnerAuth({ headers: {}, query: {} });
  assert.equal(res.ok, false);
  assert.equal(res.status, 503);
  assert.equal(res.code, 'not_configured');
  assert.equal(getConfiguredToken(), null);
});

test('auth: missing token -> 401', () => {
  process.env.SITE_INTEL_TOKEN = 'super-secret-value';
  const res = checkOwnerAuth({ headers: {}, query: {} });
  assert.equal(res.status, 401);
  assert.equal(res.code, 'unauthorized');
  delete process.env.SITE_INTEL_TOKEN;
});

test('auth: wrong token -> 401; correct bearer -> ok; query token -> ok', () => {
  process.env.SITE_INTEL_TOKEN = 'super-secret-value';
  assert.equal(checkOwnerAuth({ headers: { authorization: 'Bearer nope' }, query: {} }).status, 401);
  assert.equal(checkOwnerAuth({ headers: { authorization: 'Bearer super-secret-value' }, query: {} }).ok, true);
  assert.equal(checkOwnerAuth({ headers: {}, query: { token: 'super-secret-value' } }).ok, true);
  delete process.env.SITE_INTEL_TOKEN;
});

test('row count + aggregation grain validation', () => {
  const events = [];
  for (let i = 0; i < 10; i++) events.push(at(-(i + 1) * 60_000, { ip: `7.7.7.${i}` }));
  const r = buildIntelligence({ events, now: NOW, timezone: TZ, sourceHealth: healthy });
  assert.equal(r.data_quality.rows_returned, 10);
  assert.equal(r.data_quality.rows_valid_ts, 10);
  assert.equal(r.data_quality.aggregation_grain, 'per_event');
  // 10 distinct ips -> 10 unique visitors, no double counting
  assert.equal(r.facts['24h'].current.unique_human_visitors, 10);
});
