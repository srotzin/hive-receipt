# Site Owner Intelligence API

Deterministic, explainable owner analytics over the `clarity_hits` telemetry
store. No external LLM. Never fabricates a narrative when data is insufficient.
Every claim is traceable to supporting events.

Base URL (production): `https://hive-receipt.onrender.com`

---

## Endpoints

### `GET /v1/site/health` (public, PII-free)

Lets the frontend distinguish "backend down" from "no data yet" without a token.

```json
{
  "status": "ok",                       // "ok" | "degraded" | "error"
  "source": "supabase:clarity_hits",
  "reachable": true,
  "error": null,
  "last_probe_utc": "2026-07-15T21:00:00.000Z",
  "latency_ms": 84,
  "timezone": "America/Los_Angeles",
  "intelligence_endpoint": "/v1/site/intelligence",
  "owner_auth_configured": true,        // false => SITE_INTEL_TOKEN not set on server
  "sampled_rows": 1
}
```

### `GET /v1/site/intelligence` (authenticated, owner only)

The full contract. Returns `200` with the report, or an error envelope.

**Auth** (either form):
- Header: `Authorization: Bearer <SITE_INTEL_TOKEN>`
- Query:  `?token=<SITE_INTEL_TOKEN>` (convenience for dashboard fetches)

**Auth failure modes:**
| Condition | Status | Body `error` |
|---|---|---|
| `SITE_INTEL_TOKEN` not set on server | `503` | `not_configured` |
| No token presented | `401` | `unauthorized` |
| Wrong token | `401` | `unauthorized` |

Unconfigured deploys are **closed, not open** — the endpoint never defaults to public.

**Query params:**
- `format=csv` — flat CSV export of `session_journeys` (auth still required).

**Response** `Cache-Control: no-store`. Top-level keys:

```
generated_at            ISO8601 UTC (authoritative timestamp)
timezone                "America/Los_Angeles" (display default)
timezone_offset         e.g. "GMT-7"
generated_at_local      display-tz label
schema_version          "1.0.0"

source_health           { reachable, error, source, fetched_at, latency_ms,
                          last_event_utc, last_event_local, first_event_utc,
                          silence_seconds, is_stale, stale_threshold_seconds,
                          lookback_seconds, total_rows, row_cap, row_cap_hit }

data_quality            { rows_returned, rows_valid_ts, rows_invalid_ts,
                          aggregation_grain:"per_event", bot_handling,
                          comparison_basis, pseudonymization, unique_visitors_7d }

current_activity        { active_sessions, active_human_sessions,
                          active_crawler_sessions, window_seconds, sessions:[
                            { session_id, visitor_id, is_crawler, events,
                              started_at_utc, last_seen_utc, last_page, country } ] }

facts                   { "1h": <block>, "24h": <block>, "7d": <block> }
                        <block> = { label, span_ms,
                          current:  { window_start_utc, window_end_utc,
                                      events_total, human_events, crawler_events,
                                      unique_visitors, unique_human_visitors,
                                      unique_crawler_visitors },
                          previous: { ...same shape, immediately prior equal window },
                          comparison: { basis:"equal_length_complete_periods",
                                        events_total_change_pct,
                                        human_events_change_pct,
                                        unique_human_visitors_change_pct,
                                        crawler_events_change_pct } }
                        change_pct is null when there is no prior baseline (never NaN/Infinity).

classification          { basis, total_events_7d, human_events_7d,
                          crawler_events_7d, sample:[ { session_id,
                          classification:"human"|"crawler", confidence, reasons:[...] } ] }

high_signal_visits      [ { session_id, visitor_id, confidence, likely_intent,
                            page_category, started_at_utc, country,
                            likely_organization, evidence:[
                              { code, detail, event_ts_utc? } ] } ]

session_journeys        [ { session_id, visitor_id, is_crawler, entry_page,
                            referrer_class, referrer_host, pages:[
                              { path, page_category, ts_utc, dwell_seconds,
                                dwell_valid } ],
                            page_count, exit_page, last_page, started_at_utc,
                            ended_at_utc, total_dwell_seconds, total_dwell_valid,
                            country, device, likely_organization } ]

aggregations_24h_human  { top_pages:[{path,count}], top_countries:[{country,count}],
                          likely_networks:[{organization,count}],
                          top_referrer_classes:[{referrer_class,count}],
                          devices:[{device,count}], repeat_visitors,
                          repeat_visitor_sample:[{visitor_id,active_days_7d}] }

conversions             { basis:"explicit_events_only", total_explicit_events,
                          by_event:[{event,count}], note }
                        A conversion is only counted from an explicit event.
                        Page views are NEVER treated as conversions.

anomalies               [ { type, severity, detail, fact_or_inference, evidence:[...] } ]
                        types: broken_telemetry | no_events | stale_feed |
                               traffic_spike | sudden_silence | crawler_surge

brief                   { sufficient_data, note,
                          what_changed:        [ item ],
                          what_matters:        [ item ],
                          recommended_actions: [ item ] }
                        item = { statement, fact_or_inference:"fact"|"inference",
                                 confidence, evidence:[ "<path.into.report>" ] }

limitations             [ string ]   // honest caveats about what could not be computed
```

---

## Privacy model

- Raw IP, full user agent, and email are **never** returned.
- `visitor_id` = `v_` + first 12 hex of `sha256(ip | user_agent | salt)`.
- `session_id` = `s_` (client-supplied session) or `d_` (derived) + hash.
- Organization is labeled **likely network / organization** from IP geolocation,
  not authoritative identity.

## Timezone

UTC is authoritative on every timestamp field (`*_utc`, `generated_at`). The
display timezone (default `America/Los_Angeles`) is applied only to `*_local`
label fields and offset strings.

## Comparison methodology

Each period compares the current complete window against the immediately prior
window of **equal length** (1h vs prior 1h, 24h vs prior 24h, 7d vs prior 7d).
Crawler events are excluded from human counts and human aggregations to avoid
bot inflation. Each event is counted once (grain = `per_event`); no average of
averages.

## CORS

`Access-Control-Allow-Origin: *`, methods `GET, POST, OPTIONS`, headers
`Content-Type, Authorization, X-Payment, X-Did, X-Signature`. `OPTIONS`
preflight returns `204`. A browser dashboard on any origin can call these
endpoints; send the token via the `Authorization` header or `?token=`.

---

## Telemetry collection (beacon)

`GET /ping/clarity` records one hit. Backward compatible; now also accepts:
- `?p=<path>`  — page path (relative or absolute; only pathname is stored)
- `?sid=<id>`  — optional client session id (e.g. a `sessionStorage` UUID)

Example beacon:
```html
<script>
  navigator.sendBeacon(
    'https://hive-receipt.onrender.com/ping/clarity?p=' +
    encodeURIComponent(location.pathname) +
    '&sid=' + (sessionStorage.hiveSid ||= crypto.randomUUID())
  );
</script>
```

### Unlocking page-level analytics

`top_pages`, page categories, and journey entry/exit pages require a `path`
value on stored rows. The collector writes `path` and `sid` when the
`clarity_hits` table has those columns; if not, it transparently falls back to
the legacy columns so nothing breaks. To enable page analytics, add two nullable
text columns to `clarity_hits`:

```sql
alter table clarity_hits add column if not exists path text;
alter table clarity_hits add column if not exists sid  text;
```

Until then, page-level fields return empty with a matching entry in
`limitations`.

---

## Required environment variables (server)

| Var | Required | Purpose |
|---|---|---|
| `SITE_INTEL_TOKEN` | **yes, for `/v1/site/intelligence`** | Owner bearer token. If unset, the endpoint returns `503 not_configured` (closed). Alias: `OWNER_ADMIN_TOKEN`. |
| `SITE_INTEL_SALT` | no | Rotates pseudonymous id salt. Defaults to a stable constant. |
| `SITE_TZ` | no | Display timezone. Default `America/Los_Angeles`. |
| `SITE_HOST` | no | Site hostname for internal-referrer detection. Default `thehiveryiq.com`. |
| `SUPA_URL` / `SUPA_KEY` | no | Override the telemetry Supabase project/key. Defaults to the existing project. |

Set `SITE_INTEL_TOKEN` in the Render dashboard (Environment tab). Do not commit
the value.
