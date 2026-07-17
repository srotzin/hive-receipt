-- ============================================================================
-- Carnac RLS gate — consolidate onto the v3 PRIVATE ledger-token helper.
--
-- Idempotent. Safe to run more than once. DO NOT run automatically from the
-- service; apply out-of-band against the Supabase/Postgres instance that backs
-- the Carnac durable plane, AFTER 0001_carnac_hardening.sql and
-- 0002_carnac_lifecycle.sql.
--
-- Why this exists:
--   0001/0002 gated every durable table with public.carnac_ledger_authorized(),
--   a helper that PUBLIC/anon/authenticated could EXECUTE directly. Production
--   was subsequently hardened (two corrective migrations after commit ae41afa)
--   onto a single canonical helper in the PRIVATE schema,
--   private.carnac_ledger_authorized(), so the gate function is not directly
--   callable by untrusted roles. This migration records that final intended
--   state so fresh environments and disaster recovery match production exactly.
--
-- Final intended state after this migration:
--   * private.carnac_ledger_authorized() is the ONE canonical gate, executable
--     by anon (RLS policy expressions are evaluated as the querying role; the
--     service role bypasses RLS entirely).
--   * public.carnac_ledger_authorized() no longer exists and is not granted to
--     PUBLIC/anon/authenticated.
--   * public.carnac_judgments is gated by split, role-anon policies
--     carnac_server_insert (INSERT) and carnac_server_select (SELECT); the old
--     overlapping FOR ALL policy carnac_judgments_ledger_token is gone.
--   * carnac_dispatch, carnac_dispositions, carnac_howlers,
--     carnac_lifecycle_stages, carnac_seals keep their *_ledger_token policy,
--     now scoped TO anon and using private.carnac_ledger_authorized() for both
--     USING and WITH CHECK.
--
-- The RLS token model is unchanged (header X-Carnac-Ledger-Token compared to the
-- app.carnac_ledger_token GUC); only the helper's schema, execute grants, and the
-- carnac_judgments policy shape change. Application behavior is preserved.
--
-- Assumes the Supabase roles anon and authenticated exist (they always do on a
-- Supabase project). Existence checks guard every object that may already be in
-- its final state, so re-running is a no-op.
-- ============================================================================

BEGIN;

-- ── 0. Canonical PRIVATE helper (create only if missing; never overwrite prod) ──
-- Same gate logic as the original public helper: the presented request header
-- must equal the server-side app.carnac_ledger_token GUC. Created only when
-- absent so a production definition is never silently replaced.
CREATE SCHEMA IF NOT EXISTS private;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'private' AND p.proname = 'carnac_ledger_authorized'
  ) THEN
    EXECUTE $fn$
      CREATE FUNCTION private.carnac_ledger_authorized()
      RETURNS boolean
      LANGUAGE sql
      STABLE
      AS $body$
        SELECT
          coalesce(
            nullif(current_setting('app.carnac_ledger_token', true), ''), '__unset__'
          )
          =
          coalesce(
            (current_setting('request.headers', true)::json ->> 'x-carnac-ledger-token'),
            '__absent__'
          );
      $body$;
    $fn$;
  END IF;
END $$;

-- anon evaluates the gate inside RLS policies; the service role bypasses RLS.
-- GRANTs are idempotent. USAGE on the schema is required to resolve the function.
GRANT USAGE ON SCHEMA private TO anon;
REVOKE ALL ON FUNCTION private.carnac_ledger_authorized() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.carnac_ledger_authorized() TO anon;

-- ── 1. Remove direct EXECUTE on the OLD public helper (if it still exists) ──────
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'carnac_ledger_authorized'
  ) THEN
    REVOKE EXECUTE ON FUNCTION public.carnac_ledger_authorized() FROM PUBLIC;
    REVOKE EXECUTE ON FUNCTION public.carnac_ledger_authorized() FROM anon;
    REVOKE EXECUTE ON FUNCTION public.carnac_ledger_authorized() FROM authenticated;
  END IF;
END $$;

-- ── 2. carnac_judgments: drop the old overlapping FOR ALL policy, ensure the ────
--        split role-anon server policies (private helper) exist.
DO $$
BEGIN
  IF to_regclass('public.carnac_judgments') IS NOT NULL THEN
    DROP POLICY IF EXISTS carnac_judgments_ledger_token ON public.carnac_judgments;

    DROP POLICY IF EXISTS carnac_server_insert ON public.carnac_judgments;
    CREATE POLICY carnac_server_insert ON public.carnac_judgments
      FOR INSERT TO anon
      WITH CHECK (private.carnac_ledger_authorized());

    DROP POLICY IF EXISTS carnac_server_select ON public.carnac_judgments;
    CREATE POLICY carnac_server_select ON public.carnac_judgments
      FOR SELECT TO anon
      USING (private.carnac_ledger_authorized());
  END IF;
END $$;

-- ── 3. Repoint the remaining table policies to role anon + private helper ───────
DO $$
DECLARE
  t text;
  pol text;
  tables text[] := ARRAY[
    'carnac_dispatch',
    'carnac_dispositions',
    'carnac_howlers',
    'carnac_lifecycle_stages',
    'carnac_seals'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    IF to_regclass('public.' || t) IS NOT NULL THEN
      pol := t || '_ledger_token';
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I;', pol, t);
      EXECUTE format(
        'CREATE POLICY %I ON public.%I FOR ALL TO anon
           USING (private.carnac_ledger_authorized())
           WITH CHECK (private.carnac_ledger_authorized());',
        pol, t
      );
    END IF;
  END LOOP;
END $$;

-- ── 4. Drop the obsolete public helper (no policy references it anymore) ────────
DROP FUNCTION IF EXISTS public.carnac_ledger_authorized();

COMMIT;
