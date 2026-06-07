-- #1470: add a distinct terminal status for "scanner does not apply to this
-- artifact format" so those scans stop rendering as `failed`.
--
-- Migration 022 created scan_results with
--   CHECK (status IN ('pending','running','completed','failed'))
-- and scanner_service::scan_artifact_inner routed the is_applicable()==false
-- branch through fail_scan(...), persisting `status = 'failed'` with an
-- error_message containing "does not apply". Promotion gating (#1648) had to
-- key the "not applicable" distinction off that error_message substring, and
-- the web UI rendered the row with the same red ❌ used for genuine scanner
-- crashes (a wall of red on artifacts with several inapplicable scanners).
--
-- This relaxes the CHECK to add a fifth terminal value, `not_applicable`, so
-- the inapplicable-scanner path can persist a benign terminal status that is
-- neither a pass-with-findings nor a failure. `failed` stays reserved for
-- "scanner started running and crashed / timed out / errored".
--
-- Safe on existing data: no rows currently carry `not_applicable`, so widening
-- the allowed set never violates the constraint. Historical
-- `status='failed' + error_message LIKE '%does not apply%'` rows are left as-is
-- (the substring-based is_not_applicable() classifier keeps recognizing them);
-- this migration deliberately does NOT backfill them.
--
-- Drop and re-add the constraint with the full status set. We prefer the
-- Postgres default name (scan_results_status_check) which is stable across
-- versions; only when that exact name is absent do we fall back to a
-- definition-match search constrained to constraint definitions that reference
-- the `status` column specifically. The rewrite is skipped entirely when the
-- existing constraint already permits `'not_applicable'` so reruns and
-- pre-patched databases don't take an ACCESS EXCLUSIVE lock for nothing.

DO $$
DECLARE
    chk_name text;
    chk_def  text;
BEGIN
    -- Pass 1: exact default name.
    SELECT con.conname, pg_get_constraintdef(con.oid)
      INTO chk_name, chk_def
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE rel.relname = 'scan_results'
      AND con.contype = 'c'
      AND con.conname = 'scan_results_status_check'
    LIMIT 1;

    -- Pass 2: any CHECK constraint on scan_results whose definition references
    -- the `status` column. ORDER BY + LIMIT 1 makes the choice deterministic
    -- if multiple candidates exist.
    IF chk_name IS NULL THEN
        SELECT con.conname, pg_get_constraintdef(con.oid)
          INTO chk_name, chk_def
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'scan_results'
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ~* '\mstatus\M'
        ORDER BY con.conname
        LIMIT 1;
    END IF;

    -- Skip the rewrite when the existing constraint already permits the five
    -- states we want. Avoids needless ACCESS EXCLUSIVE locking when migration
    -- 124 is replayed against an already-patched database.
    IF chk_name IS NOT NULL
       AND chk_def ILIKE '%pending%'
       AND chk_def ILIKE '%running%'
       AND chk_def ILIKE '%completed%'
       AND chk_def ILIKE '%failed%'
       AND chk_def ILIKE '%not_applicable%' THEN
        RETURN;
    END IF;

    IF chk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE scan_results DROP CONSTRAINT %I', chk_name);
    END IF;

    ALTER TABLE scan_results
        ADD CONSTRAINT scan_results_status_check
        CHECK (status IN ('pending','running','completed','failed','not_applicable'));
END $$;
