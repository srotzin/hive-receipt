/**
 * Site Owner Intelligence Engine (the "Yoda layer", internal name only).
 *
 * Pure, deterministic, dependency-free. Given an array of raw telemetry rows
 * plus a reference clock, it produces a stable JSON contract that explains what
 * changed, what matters, and what to do next, with every claim traceable to
 * supporting events.
 *
 * Design rules honored here:
 *   - Real data only. Never fabricate a narrative when data is insufficient.
 *   - Never expose raw IP, email, or full user agent. Visitor and session ids
 *     are stable pseudonymous hashes.
 *   - Company identity is labeled as network / likely organization, never
 *     asserted as authoritative.
 *   - Equal length complete periods for comparisons. No average of averages,
 *     no bot inflation of human counts, no double counting.
 *   - Timestamps preserved in UTC; display timezone applied only for labels.
 */

import crypto from 'crypto';

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const SESSION_GAP_MS = 30 * 60_000; // 30 min inactivity ends a session
const STALE_AFTER_MS = 15 * 60_000; // feed considered stale after 15 min silence

// ── crawler / bot signatures ────────────────────────────────────────────────
// Substring match against a lowercased user agent. Reason strings are surfaced.
const BOT_SIGNATURES = [
  ['bot', 'ua_contains_bot'],
  ['crawl', 'ua_contains_crawl'],
  ['spider', 'ua_contains_spider'],
  ['slurp', 'ua_yahoo_slurp'],
  ['bingpreview', 'ua_bing_preview'],
  ['facebookexternalhit', 'ua_facebook_scraper'],
  ['embedly', 'ua_embedly'],
  ['python-requests', 'ua_python_requests'],
  ['python-httpx', 'ua_python_httpx'],
  ['axios', 'ua_axios_client'],
  ['curl/', 'ua_curl'],
  ['wget', 'ua_wget'],
  ['go-http-client', 'ua_go_http'],
  ['node-fetch', 'ua_node_fetch'],
  ['headless', 'ua_headless_browser'],
  ['lighthouse', 'ua_lighthouse'],
  ['gptbot', 'ua_openai_gptbot'],
  ['claudebot', 'ua_anthropic_claudebot'],
  ['ccbot', 'ua_common_crawl'],
  ['perplexity', 'ua_perplexity'],
  ['ahrefs', 'ua_ahrefs'],
  ['semrush', 'ua_semrush'],
  ['dataforseo', 'ua_dataforseo'],
  ['uptime', 'ua_uptime_monitor'],
  ['pingdom', 'ua_pingdom_monitor'],
];

// Hosting / cloud organizations are a weak automation signal (not definitive).
const HOSTING_ORG_HINTS = [
  'amazon', 'aws', 'google cloud', 'gcp', 'microsoft azure', 'azure',
  'digitalocean', 'ovh', 'hetzner', 'linode', 'contabo', 'oracle cloud',
  'vultr', 'scaleway', 'cloudflare', 'fastly', 'akamai', 'leaseweb',
  'datacamp', 'm247', 'choopa', 'gigenet', 'colocrossing',
];

function sha(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

function pseudoId(prefix, ...parts) {
  return prefix + sha(parts.join('|')).slice(0, 12);
}

function isValidDate(d) {
  return d instanceof Date && !Number.isNaN(d.getTime());
}

// ── referrer classification ───────────────────────────────────────────────
const SEARCH_HOSTS = ['google.', 'bing.', 'duckduckgo.', 'yahoo.', 'baidu.', 'yandex.', 'ecosia.', 'brave.'];
const SOCIAL_HOSTS = ['x.com', 'twitter.', 't.co', 'facebook.', 'fb.', 'linkedin.', 'lnkd.in', 'reddit.', 'instagram.', 'youtube.', 'youtu.be', 't.me', 'telegram.', 'news.ycombinator.', 'mastodon', 'bsky.', 'discord.'];

function classifyReferrer(ref, siteHost) {
  if (!ref || typeof ref !== 'string' || ref.trim() === '') {
    return { class: 'direct', host: null };
  }
  let host = '';
  try {
    host = new URL(ref).hostname.toLowerCase();
  } catch {
    host = ref.toLowerCase();
  }
  if (siteHost && host.includes(siteHost)) return { class: 'internal', host };
  if (SEARCH_HOSTS.some((h) => host.includes(h))) return { class: 'search', host };
  if (SOCIAL_HOSTS.some((h) => host.includes(h))) return { class: 'social', host };
  return { class: 'external', host };
}

// ── page category + intent (only when a path exists) ────────────────────────
function categorizePath(path) {
  if (!path || typeof path !== 'string') return { category: 'unknown', intent: 'unknown', confidence: 0 };
  const p = path.toLowerCase();
  const table = [
    [/(^\/$|\/index|\/home)/, 'home', 'browse', 0.6],
    [/(pricing|plans|cost)/, 'pricing', 'evaluate_purchase', 0.85],
    [/(contact|demo|book|call|schedule)/, 'contact', 'high_intent_contact', 0.9],
    [/(signup|sign-up|register|get-started|start|trial)/, 'signup', 'high_intent_convert', 0.9],
    [/(login|signin|sign-in|account|dashboard|admin)/, 'app', 'returning_user', 0.7],
    [/(docs|documentation|guide|reference|api)/, 'docs', 'research', 0.75],
    [/(blog|article|news|post|\/p\/)/, 'content', 'read', 0.7],
    [/(about|team|company|mission)/, 'about', 'research', 0.6],
    [/(product|feature|solution|platform)/, 'product', 'evaluate', 0.7],
    [/(case-study|customers|testimonial)/, 'social_proof', 'evaluate', 0.7],
  ];
  for (const [re, category, intent, confidence] of table) {
    if (re.test(p)) return { category, intent, confidence };
  }
  return { category: 'other', intent: 'browse', confidence: 0.4 };
}

// ── bot classification for one normalized visitor ───────────────────────────
function classifyAgent(ua, org) {
  const uaLc = (ua || '').toLowerCase();
  const orgLc = (org || '').toLowerCase();
  const reasons = [];
  let botScore = 0;

  for (const [needle, reason] of BOT_SIGNATURES) {
    if (uaLc.includes(needle)) {
      reasons.push(reason);
      botScore += 0.6;
    }
  }
  if (!uaLc || uaLc.trim() === '') {
    reasons.push('empty_user_agent');
    botScore += 0.5;
  }
  const looksBrowser = /mozilla|applewebkit|gecko|chrome|safari|firefox|edg\//.test(uaLc);
  if (uaLc && !looksBrowser && botScore === 0) {
    reasons.push('non_browser_user_agent');
    botScore += 0.4;
  }
  if (HOSTING_ORG_HINTS.some((h) => orgLc.includes(h))) {
    reasons.push('hosting_or_cloud_network');
    botScore += 0.3;
  }

  const isBot = botScore >= 0.5;
  const confidence = Math.min(0.99, Math.max(0.5, isBot ? botScore : 1 - botScore));
  if (!isBot && reasons.length === 0) reasons.push('browser_user_agent_no_bot_signature');
  return { is_bot: isBot, classification: isBot ? 'crawler' : 'human', confidence: round(confidence, 2), reasons };
}

// ── device from user agent (coarse, never the raw UA) ───────────────────────
function deviceFromUa(ua) {
  const u = (ua || '').toLowerCase();
  if (!u) return 'unknown';
  if (/ipad|tablet/.test(u)) return 'tablet';
  if (/mobi|iphone|android/.test(u)) return 'mobile';
  if (/mozilla|chrome|safari|firefox|edg\//.test(u)) return 'desktop';
  return 'other';
}

function round(n, dp = 2) {
  if (n === null || n === undefined || Number.isNaN(n)) return null;
  const f = 10 ** dp;
  return Math.round(n * f) / f;
}

// Percent change between two equal-length period counts.
function changePct(current, previous) {
  if (previous === 0) return current === 0 ? 0 : null; // null == "no prior baseline"
  return round(((current - previous) / previous) * 100, 1);
}

// ── normalization: raw row → pseudonymous event, no raw PII retained ─────────
function normalizeRow(row, salt, siteHost) {
  const tsRaw = row.ts || row.timestamp || row.created_at;
  const ts = tsRaw ? new Date(tsRaw) : null;
  const ip = row.ip || '';
  const ua = row.ua || row.user_agent || '';
  const org = row.org || '';
  const country = (row.country || '').trim();
  const region = (row.region || '').trim();
  const city = (row.city || '').trim();
  const path = row.path || row.p || null;
  const ref = row.ref || row.referrer || null;
  const explicitSid = row.sid || row.session_id || null;
  const explicitEvent = row.event || row.event_type || null;

  const visitor_id = ip || ua ? pseudoId('v_', ip, ua, salt) : pseudoId('v_', 'anon', JSON.stringify(row), salt);
  const agent = classifyAgent(ua, org);
  const referrer = classifyReferrer(ref, siteHost);

  return {
    ts,
    ts_valid: isValidDate(ts),
    visitor_id,
    explicit_session_id: explicitSid ? pseudoId('s_', explicitSid, salt) : null,
    path,
    page: categorizePath(path),
    referrer,
    country: country || null,
    region: region || null,
    city: city || null,
    org: org || null,
    device: deviceFromUa(ua),
    is_bot: agent.is_bot,
    bot: agent,
    event: explicitEvent, // explicit conversion/funnel event name, if telemetry emits one
  };
}

// ── sessionization: group a visitor's events into ordered journeys ──────────
function buildSessions(events) {
  const byVisitor = new Map();
  for (const e of events) {
    if (!e.ts_valid) continue;
    if (!byVisitor.has(e.visitor_id)) byVisitor.set(e.visitor_id, []);
    byVisitor.get(e.visitor_id).push(e);
  }
  const sessions = [];
  for (const [visitor_id, evs] of byVisitor) {
    evs.sort((a, b) => a.ts - b.ts);
    let current = null;
    for (const e of evs) {
      const startNew =
        !current ||
        (e.explicit_session_id && e.explicit_session_id !== current.explicit_session_id) ||
        (!e.explicit_session_id && e.ts - current.last_ts > SESSION_GAP_MS);
      if (startNew) {
        current = {
          session_id: e.explicit_session_id || pseudoId('d_', visitor_id, e.ts.toISOString()),
          explicit_session_id: e.explicit_session_id,
          visitor_id,
          events: [],
          first_ts: e.ts,
          last_ts: e.ts,
          is_bot: e.is_bot,
        };
        sessions.push(current);
      }
      current.events.push(e);
      current.last_ts = e.ts;
      current.is_bot = current.is_bot && e.is_bot ? true : current.is_bot || e.is_bot;
    }
  }
  return sessions;
}

function topN(counter, n, keyName = 'value') {
  return [...counter.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, n)
    .map(([k, count]) => ({ [keyName]: k, count }));
}

function increment(map, key) {
  if (key === null || key === undefined || key === '') return;
  map.set(key, (map.get(key) || 0) + 1);
}

// Facts over a window [start, end). Humans only where it matters, bots reported separately.
function windowFacts(events, start, end) {
  const inWin = events.filter((e) => e.ts_valid && e.ts >= start && e.ts < end);
  const human = inWin.filter((e) => !e.is_bot);
  const bot = inWin.filter((e) => e.is_bot);
  const humanVisitors = new Set(human.map((e) => e.visitor_id));
  const botVisitors = new Set(bot.map((e) => e.visitor_id));
  const allVisitors = new Set(inWin.map((e) => e.visitor_id));
  return {
    window_start_utc: start.toISOString(),
    window_end_utc: end.toISOString(),
    events_total: inWin.length,
    human_events: human.length,
    crawler_events: bot.length,
    unique_visitors: allVisitors.size,
    unique_human_visitors: humanVisitors.size,
    unique_crawler_visitors: botVisitors.size,
  };
}

function periodBlock(events, now, spanMs, label) {
  const currentStart = new Date(now.getTime() - spanMs);
  const priorStart = new Date(now.getTime() - 2 * spanMs);
  const current = windowFacts(events, currentStart, now);
  const previous = windowFacts(events, priorStart, currentStart);
  return {
    label,
    span_ms: spanMs,
    current,
    previous,
    comparison: {
      basis: 'equal_length_complete_periods',
      events_total_change_pct: changePct(current.events_total, previous.events_total),
      human_events_change_pct: changePct(current.human_events, previous.human_events),
      unique_human_visitors_change_pct: changePct(current.unique_human_visitors, previous.unique_human_visitors),
      crawler_events_change_pct: changePct(current.crawler_events, previous.crawler_events),
    },
  };
}

// ── high signal visits: only real evidence, no page-view-as-conversion ──────
function scoreSession(session) {
  const reasons = [];
  let score = 0;
  const humanEvents = session.events.filter((e) => !e.is_bot);
  const pageEvents = session.events.filter((e) => e.path);
  const dwellMs = session.last_ts - session.first_ts;

  if (session.is_bot) return null; // crawlers are never "high signal" owner leads

  if (pageEvents.length >= 3) {
    score += 0.3;
    reasons.push({ code: 'multi_page_session', detail: `${pageEvents.length} pages viewed` });
  }
  const highIntentPages = pageEvents.filter((e) => ['pricing', 'contact', 'signup'].includes(e.page.category));
  for (const e of highIntentPages) {
    score += 0.35;
    reasons.push({ code: 'high_intent_page', detail: `${e.page.category} (${e.path})`, event_ts_utc: e.ts.toISOString() });
  }
  if (dwellMs >= 60_000 && pageEvents.length >= 2) {
    score += 0.2;
    reasons.push({ code: 'sustained_dwell', detail: `${Math.round(dwellMs / 1000)}s across session` });
  }
  const explicitEvents = session.events.filter((e) => e.event);
  for (const e of explicitEvents) {
    score += 0.4;
    reasons.push({ code: 'explicit_event', detail: e.event, event_ts_utc: e.ts.toISOString() });
  }
  const first = session.events[0];
  if (first && ['search', 'social'].includes(first.referrer.class)) {
    score += 0.1;
    reasons.push({ code: 'acquisition_channel', detail: `${first.referrer.class}${first.referrer.host ? ' via ' + first.referrer.host : ''}` });
  }

  if (score < 0.35) return null;
  return {
    session_id: session.session_id,
    visitor_id: session.visitor_id,
    confidence: round(Math.min(0.95, score), 2),
    likely_intent: highIntentPages[0]?.page.intent || pageEvents[0]?.page.intent || 'browse',
    page_category: highIntentPages[0]?.page.category || pageEvents[0]?.page.category || 'unknown',
    started_at_utc: session.first_ts.toISOString(),
    country: first?.country || null,
    likely_organization: first?.org || null,
    evidence: reasons,
  };
}

function buildJourney(session) {
  const evs = session.events;
  const first = evs[0];
  const last = evs[evs.length - 1];
  const dwellMs = last.ts - first.ts;
  const pages = evs.map((e, i) => {
    const next = evs[i + 1];
    // Dwell per step is only valid when a later event exists to bound it.
    const stepDwell = next ? Math.round((next.ts - e.ts) / 1000) : null;
    return {
      path: e.path || null,
      page_category: e.page.category,
      ts_utc: e.ts.toISOString(),
      dwell_seconds: stepDwell,
      dwell_valid: stepDwell !== null,
    };
  });
  return {
    session_id: session.session_id,
    visitor_id: session.visitor_id,
    is_crawler: session.is_bot,
    entry_page: first.path || null,
    referrer_class: first.referrer.class,
    referrer_host: first.referrer.host,
    pages,
    page_count: evs.length,
    exit_page: last.path || null,
    last_page: last.path || null,
    started_at_utc: first.ts.toISOString(),
    ended_at_utc: last.ts.toISOString(),
    total_dwell_seconds: dwellMs > 0 ? Math.round(dwellMs / 1000) : null,
    total_dwell_valid: dwellMs > 0 && evs.length > 1,
    country: first.country,
    device: first.device,
    likely_organization: first.org,
  };
}

// ── anomaly detection over deterministic thresholds ─────────────────────────
function detectAnomalies(events, now, sourceHealth, hourBlock, dayBlock) {
  const anomalies = [];
  const lastEventTs = events.filter((e) => e.ts_valid).reduce((max, e) => (e.ts > max ? e.ts : max), new Date(0));
  const silenceMs = now - lastEventTs;

  if (!sourceHealth.reachable) {
    anomalies.push({
      type: 'broken_telemetry',
      severity: 'critical',
      detail: `Telemetry source unreachable: ${sourceHealth.error || 'unknown error'}`,
      fact_or_inference: 'fact',
      evidence: ['source_health.reachable=false'],
    });
  }
  if (events.length === 0 && sourceHealth.reachable) {
    anomalies.push({
      type: 'no_events',
      severity: 'warning',
      detail: 'Source reachable but returned zero events in the lookback window.',
      fact_or_inference: 'fact',
      evidence: ['events.length=0'],
    });
  }
  if (events.length > 0 && silenceMs > STALE_AFTER_MS) {
    anomalies.push({
      type: 'stale_feed',
      severity: silenceMs > DAY_MS ? 'critical' : 'warning',
      detail: `No events for ${Math.round(silenceMs / 60000)} min. Last event ${lastEventTs.toISOString()}.`,
      fact_or_inference: 'fact',
      evidence: [`last_event_utc=${lastEventTs.toISOString()}`],
    });
  }
  // Traffic spike / silence vs prior equal period (human events).
  const cur = hourBlock.current.human_events;
  const prev = hourBlock.previous.human_events;
  if (prev >= 5 && cur >= prev * 3) {
    anomalies.push({
      type: 'traffic_spike',
      severity: 'info',
      detail: `Human events this hour (${cur}) are ${round(cur / prev, 1)}x the prior hour (${prev}).`,
      fact_or_inference: 'fact',
      evidence: [`1h.current.human_events=${cur}`, `1h.previous.human_events=${prev}`],
    });
  }
  if (prev >= 5 && cur === 0) {
    anomalies.push({
      type: 'sudden_silence',
      severity: 'warning',
      detail: `Zero human events this hour after ${prev} in the prior hour.`,
      fact_or_inference: 'fact',
      evidence: [`1h.current.human_events=0`, `1h.previous.human_events=${prev}`],
    });
  }
  // Crawler surge (24h).
  const cCur = dayBlock.current.crawler_events;
  const cPrev = dayBlock.previous.crawler_events;
  if (cPrev >= 5 && cCur >= cPrev * 3) {
    anomalies.push({
      type: 'crawler_surge',
      severity: 'info',
      detail: `Crawler events in last 24h (${cCur}) are ${round(cCur / cPrev, 1)}x the prior 24h (${cPrev}).`,
      fact_or_inference: 'fact',
      evidence: [`24h.current.crawler_events=${cCur}`, `24h.previous.crawler_events=${cPrev}`],
    });
  }
  return anomalies;
}

// ── the owner brief: what changed / what matters / recommended actions ──────
function buildBrief(ctx) {
  const { hourBlock, dayBlock, highSignal, anomalies, sourceHealth, events } = ctx;
  const what_changed = [];
  const what_matters = [];
  const recommended_actions = [];

  // What changed — only from computed period deltas and anomalies.
  const d = dayBlock.comparison.human_events_change_pct;
  if (d !== null) {
    what_changed.push({
      statement: `Human events over the last 24h changed ${d >= 0 ? '+' : ''}${d}% versus the prior 24h (${dayBlock.current.human_events} vs ${dayBlock.previous.human_events}).`,
      fact_or_inference: 'fact',
      confidence: 1,
      evidence: ['facts.24h.current.human_events', 'facts.24h.previous.human_events'],
    });
  }
  for (const a of anomalies) {
    what_changed.push({
      statement: a.detail,
      fact_or_inference: a.fact_or_inference,
      confidence: a.severity === 'critical' ? 1 : 0.9,
      evidence: a.evidence,
    });
  }

  // What matters.
  if (highSignal.length > 0) {
    what_matters.push({
      statement: `${highSignal.length} high signal human session(s) detected in the lookback window.`,
      fact_or_inference: 'inference',
      confidence: round(highSignal.reduce((s, h) => s + h.confidence, 0) / highSignal.length, 2),
      evidence: highSignal.slice(0, 5).map((h) => `high_signal_visits[session_id=${h.session_id}]`),
    });
  }
  const criticalAnoms = anomalies.filter((a) => a.severity === 'critical');
  for (const a of criticalAnoms) {
    what_matters.push({
      statement: a.detail,
      fact_or_inference: a.fact_or_inference,
      confidence: 1,
      evidence: a.evidence,
    });
  }

  // Recommended actions — grounded, never speculative narrative.
  if (!sourceHealth.reachable) {
    recommended_actions.push({
      statement: 'Restore the telemetry source. The analytics feed cannot be trusted until the source is reachable.',
      fact_or_inference: 'fact',
      confidence: 1,
      evidence: ['source_health.reachable=false'],
    });
  }
  if (anomalies.some((a) => a.type === 'stale_feed')) {
    recommended_actions.push({
      statement: 'Verify the site beacon is firing. Events have gone stale beyond the freshness threshold.',
      fact_or_inference: 'fact',
      confidence: 0.9,
      evidence: ['anomalies[type=stale_feed]'],
    });
  }
  for (const h of highSignal.slice(0, 3)) {
    recommended_actions.push({
      statement: `Review high signal session ${h.session_id} (${h.likely_intent}, ${h.page_category}) and follow up if a contact channel exists.`,
      fact_or_inference: 'inference',
      confidence: h.confidence,
      evidence: [`high_signal_visits[session_id=${h.session_id}]`],
    });
  }

  const insufficient = events.length === 0 || !sourceHealth.reachable;
  return {
    sufficient_data: !insufficient,
    what_changed,
    what_matters,
    recommended_actions,
    note: insufficient
      ? 'Insufficient trustworthy data to produce a narrative. Diagnostics only.'
      : null,
  };
}

// ── timezone helpers ─────────────────────────────────────────────────────────
function tzOffsetLabel(date, timeZone) {
  try {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'shortOffset' }).formatToParts(date);
    const tzn = parts.find((p) => p.type === 'timeZoneName');
    return tzn ? tzn.value : null;
  } catch {
    return null;
  }
}

function localLabel(date, timeZone) {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).format(date);
  } catch {
    return null;
  }
}

/**
 * Build the full intelligence contract.
 *
 * @param {object} opts
 * @param {Array<object>} opts.events            Raw telemetry rows (clarity_hits shape).
 * @param {Date}          [opts.now]             Reference clock (defaults to new Date()).
 * @param {string}        [opts.timezone]        Display tz (default America/Los_Angeles).
 * @param {string}        [opts.salt]            Pseudonymization salt (stable per deploy).
 * @param {string}        [opts.siteHost]        Site hostname for internal-referrer detection.
 * @param {object}        [opts.sourceHealth]    { reachable, error, source, fetched_at, latency_ms }.
 * @param {number}        [opts.lookbackMs]      How far back events were requested (for diagnostics).
 * @param {number}        [opts.rowCountRequested] Raw row count returned by source (validation).
 */
export function buildIntelligence(opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const timezone = opts.timezone || 'America/Los_Angeles';
  const salt = opts.salt || 'hive-site-intel-v1';
  const siteHost = opts.siteHost || 'thehiveryiq.com';
  const lookbackMs = opts.lookbackMs || 7 * DAY_MS;
  const sourceHealth = {
    reachable: true,
    error: null,
    source: 'unknown',
    fetched_at: now.toISOString(),
    latency_ms: null,
    ...(opts.sourceHealth || {}),
  };

  const rawRows = Array.isArray(opts.events) ? opts.events : [];
  const events = rawRows.map((r) => normalizeRow(r, salt, siteHost));
  const validEvents = events.filter((e) => e.ts_valid);
  const invalidTsCount = events.length - validEvents.length;

  const lastEvent = validEvents.reduce((max, e) => (e.ts > max ? e.ts : max), null);
  const firstEvent = validEvents.reduce((min, e) => (min === null || e.ts < min ? e.ts : min), null);
  const silenceMs = lastEvent ? now - lastEvent : null;
  const isStale = silenceMs !== null && silenceMs > STALE_AFTER_MS;

  const sessions = buildSessions(validEvents);
  const humanSessions = sessions.filter((s) => !s.is_bot);

  const hourBlock = periodBlock(validEvents, now, HOUR_MS, '1h');
  const dayBlock = periodBlock(validEvents, now, DAY_MS, '24h');
  const weekBlock = periodBlock(validEvents, now, 7 * DAY_MS, '7d');

  // Current activity: active pseudonymous sessions in the last 30 minutes.
  const activeCutoff = new Date(now.getTime() - SESSION_GAP_MS);
  const activeSessions = sessions.filter((s) => s.last_ts >= activeCutoff);
  const activeHuman = activeSessions.filter((s) => !s.is_bot);

  // Aggregations over the human 24h window (bots excluded to avoid inflation).
  const day = new Date(now.getTime() - DAY_MS);
  const humanDayEvents = validEvents.filter((e) => !e.is_bot && e.ts >= day);
  const pages = new Map(); const countries = new Map(); const orgs = new Map();
  const referrers = new Map(); const devices = new Map();
  for (const e of humanDayEvents) {
    if (e.path) increment(pages, e.path);
    increment(countries, e.country);
    increment(orgs, e.org);
    increment(referrers, e.referrer.class);
    increment(devices, e.device);
  }
  const hasPagePaths = validEvents.some((e) => e.path);

  // Repeat visitors: pseudonymous visitors seen on 2+ distinct calendar-ish days (UTC) in 7d.
  const week = new Date(now.getTime() - 7 * DAY_MS);
  const visitorDays = new Map();
  for (const e of validEvents.filter((ev) => !ev.is_bot && ev.ts >= week)) {
    const dayKey = e.ts.toISOString().slice(0, 10);
    if (!visitorDays.has(e.visitor_id)) visitorDays.set(e.visitor_id, new Set());
    visitorDays.get(e.visitor_id).add(dayKey);
  }
  const repeatVisitors = [...visitorDays.entries()].filter(([, d]) => d.size >= 2);

  // High signal + journeys.
  const highSignal = sessions
    .map((s) => scoreSession(s))
    .filter(Boolean)
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 25);

  const journeys = humanSessions
    .filter((s) => s.events.length >= 1)
    .sort((a, b) => b.last_ts - a.last_ts)
    .slice(0, 25)
    .map((s) => buildJourney(s));

  // Explicit conversion / funnel events only (never inferred from a page view).
  const conversionEvents = validEvents.filter((e) => e.event);
  const conversionCounter = new Map();
  for (const e of conversionEvents) increment(conversionCounter, e.event);

  const anomalies = detectAnomalies(validEvents, now, sourceHealth, hourBlock, dayBlock);

  const brief = buildBrief({ hourBlock, dayBlock, highSignal, anomalies, sourceHealth, events: validEvents });

  const limitations = [];
  if (!hasPagePaths) {
    limitations.push('No page path in telemetry rows. Page level metrics (top_pages, page categories, journey entry/exit pages) are empty until the beacon sends a path field.');
  }
  if (conversionEvents.length === 0) {
    limitations.push('No explicit conversion or funnel events present. Conversions are never inferred from page views, so conversion metrics are empty.');
  }
  if (invalidTsCount > 0) {
    limitations.push(`${invalidTsCount} row(s) had an invalid or missing timestamp and were excluded from time based analysis.`);
  }
  if (!validEvents.some((e) => e.country)) {
    limitations.push('No geo country present on events. Country and network breakdowns may be sparse.');
  }
  limitations.push('Organization values are labeled as likely network or organization from IP geolocation, not authoritative identity.');

  return {
    generated_at: now.toISOString(),
    timezone,
    timezone_offset: tzOffsetLabel(now, timezone),
    generated_at_local: localLabel(now, timezone),
    schema_version: '1.0.0',

    source_health: {
      ...sourceHealth,
      last_event_utc: lastEvent ? lastEvent.toISOString() : null,
      last_event_local: lastEvent ? localLabel(lastEvent, timezone) : null,
      first_event_utc: firstEvent ? firstEvent.toISOString() : null,
      silence_seconds: silenceMs === null ? null : Math.round(silenceMs / 1000),
      is_stale: isStale,
      stale_threshold_seconds: STALE_AFTER_MS / 1000,
      lookback_seconds: Math.round(lookbackMs / 1000),
    },

    data_quality: {
      rows_returned: rawRows.length,
      rows_valid_ts: validEvents.length,
      rows_invalid_ts: invalidTsCount,
      aggregation_grain: 'per_event',
      bot_handling: 'crawler events excluded from human counts and aggregations; reported separately',
      comparison_basis: 'equal_length_complete_periods',
      pseudonymization: 'visitor_id and session_id are sha256 hashes; raw ip, user agent, and email are never returned',
      unique_visitors_7d: visitorDays.size,
    },

    current_activity: {
      active_sessions: activeSessions.length,
      active_human_sessions: activeHuman.length,
      active_crawler_sessions: activeSessions.length - activeHuman.length,
      window_seconds: SESSION_GAP_MS / 1000,
      sessions: activeSessions.slice(0, 25).map((s) => ({
        session_id: s.session_id,
        visitor_id: s.visitor_id,
        is_crawler: s.is_bot,
        events: s.events.length,
        started_at_utc: s.first_ts.toISOString(),
        last_seen_utc: s.last_ts.toISOString(),
        last_page: s.events[s.events.length - 1].path || null,
        country: s.events[0].country,
      })),
    },

    facts: {
      '1h': hourBlock,
      '24h': dayBlock,
      '7d': weekBlock,
    },

    classification: {
      basis: 'user_agent_signatures + hosting_network_hints',
      total_events_7d: validEvents.filter((e) => e.ts >= week).length,
      human_events_7d: validEvents.filter((e) => e.ts >= week && !e.is_bot).length,
      crawler_events_7d: validEvents.filter((e) => e.ts >= week && e.is_bot).length,
      sample: sessions.slice(0, 10).map((s) => ({
        session_id: s.session_id,
        classification: s.is_bot ? 'crawler' : 'human',
        confidence: s.events[0].bot.confidence,
        reasons: s.events[0].bot.reasons,
      })),
    },

    high_signal_visits: highSignal,

    session_journeys: journeys,

    aggregations_24h_human: {
      top_pages: topN(pages, 10, 'path'),
      top_countries: topN(countries, 10, 'country'),
      likely_networks: topN(orgs, 10, 'organization'),
      top_referrer_classes: topN(referrers, 10, 'referrer_class'),
      devices: topN(devices, 10, 'device'),
      repeat_visitors: repeatVisitors.length,
      repeat_visitor_sample: repeatVisitors.slice(0, 10).map(([v, d]) => ({ visitor_id: v, active_days_7d: d.size })),
    },

    conversions: {
      basis: 'explicit_events_only',
      total_explicit_events: conversionEvents.length,
      by_event: topN(conversionCounter, 20, 'event'),
      note: 'A conversion is only counted when telemetry emits an explicit event. Page views are never treated as conversions.',
    },

    anomalies,

    brief,

    limitations,
  };
}

export const _internal = {
  classifyAgent, classifyReferrer, categorizePath, normalizeRow,
  buildSessions, changePct, deviceFromUa, SESSION_GAP_MS, STALE_AFTER_MS,
};
