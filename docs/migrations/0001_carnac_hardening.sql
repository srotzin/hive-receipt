-- ============================================================================
-- Carnac production hardening — durable schema.
--
-- Idempotent. Safe to run more than once. DO NOT run automatically from the
-- service; apply out-of-band against the Supabase/Postgres instance that backs
-- the Carnac durable plane.
--
-- What this does:
--   1. Extends the existing public.carnac_judgments table with the tenant +
--      continuity columns the hardened engine now writes.
--   2. Creates the durable dispositions, howlers, dispatch, and seals tables.
--   3. Adds tenant/trajectory/time indexes for the durable listings.
--   4. Enables RLS on every table, gated by the same X-Carnac-Ledger-Token
--      request-header pattern already used for public.carnac_judgments, so the
--      service (which sends that header) can read/write and anonymous PostgREST
--      callers cannot.
--
-- RLS token model:
--   PostgREST surfaces request headers via current_setting('request.headers').
--   The server sends header  X-Carnac-Ledger-Token: <CARNAC_LEDGER_TOKEN>.
--   The database compares that header to a server-side GUC that you set once:
--
--       ALTER DATABASE <db> SET app.carnac_ledger_token = '<CARNAC_LEDGER_TOKEN>';
--
--   (or set app.carnac_ledger_token at the role level). The helper below returns
--   true only when the presented header equals that configured secret.
-- ============================================================================

BEGIN;

-- ── 0. Ledger-token gate ────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.carnac_ledger_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    coalesce(
      nullif(current_setting('app.carnac_ledger_token', true), ''), '__unset__'
    )
    =
    coalesce(
      (current_setting('request.headers', true)::json ->> 'x-carnac-ledger-token'),
      '__absent__'
    );
$$;

-- ── 1. carnac_judgments — add tenant + continuity columns ───────────────────
ALTER TABLE public.carnac_judgments ADD COLUMN IF NOT EXISTS tenant_id       text;
ALTER TABLE public.carnac_judgments ADD COLUMN IF NOT EXISTS seq             bigint;
ALTER TABLE public.carnac_judgments ADD COLUMN IF NOT EXISTS previous_digest text;
ALTER TABLE public.carnac_judgments ADD COLUMN IF NOT EXISTS chain_digest    text;
ALTER TABLE public.carnac_judgments ADD COLUMN IF NOT EXISTS howler_id       text;

CREATE INDEX IF NOT EXISTS carnac_judgments_tenant_traj_idx
  ON public.carnac_judgments (tenant_id, trajectory_id, seq);
CREATE INDEX IF NOT EXISTS carnac_judgments_tenant_created_idx
  ON public.carnac_judgments (tenant_id, created_at);
-- A (tenant, trajectory, seq) is unique when a seq is present: rejects a
-- durable duplicate/replay even across a restart.
CREATE UNIQUE INDEX IF NOT EXISTS carnac_judgments_tenant_traj_seq_uk
  ON public.carnac_judgments (tenant_id, trajectory_id, seq)
  WHERE seq IS NOT NULL;

-- ── 2. carnac_dispositions — append-only human/actor decisions ──────────────
CREATE TABLE IF NOT EXISTS public.carnac_dispositions (
  disposition_id  text PRIMARY KEY,
  tenant_id       text,
  judgment_id     text,
  trajectory_id   text,
  howler_id       text,
  actor           text,
  action          text,
  effective_after integer,
  envelope        jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS carnac_dispositions_tenant_judgment_idx
  ON public.carnac_dispositions (tenant_id, judgment_id, created_at);
CREATE INDEX IF NOT EXISTS carnac_dispositions_tenant_traj_idx
  ON public.carnac_dispositions (tenant_id, trajectory_id, created_at);

-- ── 3. carnac_howlers — durable escalation receipts ─────────────────────────
CREATE TABLE IF NOT EXISTS public.carnac_howlers (
  howler_id      text PRIMARY KEY,
  tenant_id      text,
  judgment_id    text,
  trajectory_id  text,
  severity       integer,
  feature_digest text,
  policy_version text,
  envelope       jsonb NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS carnac_howlers_tenant_idx
  ON public.carnac_howlers (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS carnac_howlers_judgment_idx
  ON public.carnac_howlers (tenant_id, judgment_id);

-- ── 4. carnac_dispatch — honest Canon dispatch records ──────────────────────
CREATE TABLE IF NOT EXISTS public.carnac_dispatch (
  dispatch_id      text PRIMARY KEY,
  tenant_id        text,
  judgment_id      text,
  trajectory_id    text,
  route            text,
  target_primitive text,
  status           text,
  envelope         jsonb NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS carnac_dispatch_tenant_judgment_idx
  ON public.carnac_dispatch (tenant_id, judgment_id, created_at);

-- ── 5. carnac_seals — signed continuity checkpoints ─────────────────────────
CREATE TABLE IF NOT EXISTS public.carnac_seals (
  seal_id           text PRIMARY KEY,
  tenant_id         text,
  trajectory_id     text,
  count             integer,
  head_chain_digest text,
  chain_intact      boolean,
  envelope          jsonb NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS carnac_seals_tenant_traj_idx
  ON public.carnac_seals (tenant_id, trajectory_id, created_at);

-- ── 6. Row-level security — one policy per table, header-token gated ─────────
DO $$
DECLARE
  t text;
  tables text[] := ARRAY[
    'carnac_judgments',
    'carnac_dispositions',
    'carnac_howlers',
    'carnac_dispatch',
    'carnac_seals'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', t || '_ledger_token', t);
    EXECUTE format(
      'CREATE POLICY %I ON public.%I FOR ALL
         USING (public.carnac_ledger_authorized())
         WITH CHECK (public.carnac_ledger_authorized());',
      t || '_ledger_token', t
    );
  END LOOP;
END $$;

COMMIT;
