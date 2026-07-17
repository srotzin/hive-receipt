-- ============================================================================
-- Carnac lifecycle chain — durable schema.
--
-- Idempotent. Safe to run more than once. DO NOT run automatically from the
-- service; apply out-of-band against the same Supabase/Postgres instance that
-- backs the Carnac durable plane (see 0001_carnac_hardening.sql).
--
-- What this does:
--   1. Creates public.carnac_lifecycle_stages: one row per finalized lifecycle
--      stage. Only hash-only, public-safe fields are stored; the full signed
--      stage envelope (also hash-only, no raw prompt/output) lives in `envelope`.
--   2. Adds lifecycle/tenant/batch indexes for status reads and verification.
--   3. Enables RLS gated by the SAME X-Carnac-Ledger-Token header helper defined
--      in 0001 (public.carnac_ledger_authorized()), so the service can read/write
--      and anonymous PostgREST callers cannot.
--
-- Table name is overridable by CARNAC_LIFECYCLE_TABLE (default below). If you
-- change it, change it in both places.
-- ============================================================================

BEGIN;

-- Depends on public.carnac_ledger_authorized() from 0001_carnac_hardening.sql.

CREATE TABLE IF NOT EXISTS public.carnac_lifecycle_stages (
  stage_id      text PRIMARY KEY,
  lifecycle_id  text NOT NULL,
  tenant_id     text,
  type          text,
  seq           bigint,
  chain_head    text,
  batch_root    text,
  envelope      jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Ordered read of one lifecycle for a tenant (status + verification).
CREATE INDEX IF NOT EXISTS carnac_lifecycle_tenant_lc_seq_idx
  ON public.carnac_lifecycle_stages (tenant_id, lifecycle_id, seq);
-- Batch lookups (a Merkle root maps to its member stages).
CREATE INDEX IF NOT EXISTS carnac_lifecycle_batch_idx
  ON public.carnac_lifecycle_stages (batch_root);
-- A (tenant, lifecycle, seq) is unique: rejects a durable duplicate/replay even
-- across a restart.
CREATE UNIQUE INDEX IF NOT EXISTS carnac_lifecycle_tenant_lc_seq_uk
  ON public.carnac_lifecycle_stages (tenant_id, lifecycle_id, seq)
  WHERE seq IS NOT NULL;

ALTER TABLE public.carnac_lifecycle_stages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS carnac_lifecycle_stages_ledger_token ON public.carnac_lifecycle_stages;
CREATE POLICY carnac_lifecycle_stages_ledger_token ON public.carnac_lifecycle_stages
  FOR ALL
  USING (public.carnac_ledger_authorized())
  WITH CHECK (public.carnac_ledger_authorized());

COMMIT;
