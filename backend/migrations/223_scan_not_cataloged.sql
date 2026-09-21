-- #4036: fail closed when a hosted package archive catalogs NOTHING.
--
-- `parse_cyclonedx_catalog` (grype_scanner.rs) deliberately distinguishes
-- `None` ("this scanner reports no catalog") from `Some(vec![])` ("the
-- engine ran and cataloged nothing"). The hosted scan path discarded that
-- signal, so a package archive grype cannot read at all (e.g. a conda
-- `.tar.bz2`) completed with zero findings and was graded 100 / A although
-- its contents were never cataloged.
--
-- Three changes:
--
-- 1. Widen `scan_results.scan_completeness` to a third value,
--    `not_cataloged`, so the orchestrator can persist "the engine ran and
--    cataloged no components from an artifact whose format expects a
--    catalog". `partial` stays reserved for #1153 (lockfile present but
--    unparseable) and #3604 (pin could not be trusted) — both still get
--    graded, while `not_cataloged` floors the repo grade to F. No grade
--    CHECK relaxation is needed: 'F' was always a legal grade.
--
-- 2. `scan_results.scan_completeness_reason TEXT NULL` carries the
--    human-readable why (which scanner cataloged nothing) for operators and
--    audit trails.
--
-- 3. `repo_security_scores.has_uncataloged_scan` mirrors migration 143's
--    `has_failed_scan` (#2167): a persisted fail-closed flag so the
--    dashboard and release-gate treat "contents never cataloged" as NOT
--    clean. Defaults FALSE; cleared automatically once a newer completed
--    scan supersedes the not-cataloged row.
--
-- Safe on existing data: no rows carry `not_cataloged` yet, so widening the
-- allowed set never violates the constraint.

-- 1. Drop and re-add the scan_completeness CHECK with the widened set.
--    Idempotent DO-block pattern copied from
--    124_scan_results_status_not_applicable.sql: prefer the Postgres default
--    name; fall back to a definition-match search referencing the
--    `scan_completeness` column; skip the rewrite entirely when the
--    existing constraint already permits 'not_cataloged'.
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
      AND con.conname = 'scan_results_scan_completeness_check'
    LIMIT 1;

    -- Pass 2: any CHECK constraint on scan_results whose definition
    -- references the `scan_completeness` column. ORDER BY + LIMIT 1 makes
    -- the choice deterministic if multiple candidates exist.
    IF chk_name IS NULL THEN
        SELECT con.conname, pg_get_constraintdef(con.oid)
          INTO chk_name, chk_def
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'scan_results'
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ~* '\mscan_completeness\M'
        ORDER BY con.conname
        LIMIT 1;
    END IF;

    -- Skip the rewrite when the existing constraint already permits the
    -- three states we want. Avoids needless ACCESS EXCLUSIVE locking when
    -- migration 223 is replayed against an already-patched database.
    IF chk_name IS NOT NULL
       AND chk_def ILIKE '%complete%'
       AND chk_def ILIKE '%partial%'
       AND chk_def ILIKE '%not_cataloged%' THEN
        RETURN;
    END IF;

    IF chk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE scan_results DROP CONSTRAINT %I', chk_name);
    END IF;

    -- Online shape per docs/operations/online-migrations.md (PF-008 gate):
    -- NOT VALID skips the whole-table validation scan under ACCESS
    -- EXCLUSIVE; the constraint still ENFORCES for new rows immediately,
    -- which is all 'not_cataloged' needs. The widening is a superset of the
    -- old set, so the follow-up VALIDATE (SHARE UPDATE EXCLUSIVE — no write
    -- block) cannot fail on existing rows.
    ALTER TABLE scan_results
        ADD CONSTRAINT scan_results_scan_completeness_check
        CHECK (scan_completeness IN ('complete', 'partial', 'not_cataloged'))
        NOT VALID;

    ALTER TABLE scan_results
        VALIDATE CONSTRAINT scan_results_scan_completeness_check;
END $$;

-- 2. The why behind a non-'complete' scan_completeness value.
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS scan_completeness_reason TEXT;

-- 3. Fail-closed scoring flag (mirror of 143_repo_scan_failed_flag.sql, with
--    IF NOT EXISTS so the file as a whole stays replay-safe like the DO
--    block above).
ALTER TABLE repo_security_scores
    ADD COLUMN IF NOT EXISTS has_uncataloged_scan BOOLEAN NOT NULL DEFAULT FALSE;
