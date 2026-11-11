-- #5534: a scanner's free-text finding fields are stored as `TEXT`.
--
-- `scan_findings` (022) bounded every scanner-supplied string with a
-- `VARCHAR(n)` the scanners never agreed to: `affected_version`,
-- `fixed_version` and `source` at 100, `affected_component` at 255, `title`
-- at 500, `source_url` at 512. Findings are written by one batched
-- `INSERT ... SELECT FROM UNNEST(...)`, so ONE value over its limit (an
-- advisory listing several fixed versions in one string was the observed
-- case) rejected the whole statement with `value too long for type character
-- varying(100)`: the scan failed and every other finding it reported was
-- dropped with it. `proxy_scan_findings` (202) already stores the same
-- fields as `TEXT`.
--
-- Left as they are:
-- * `severity` holds one of five normalized tokens (CHECK constraint).
-- * `cve_id VARCHAR(30)`: `idx_scan_findings_cve` is a PARTIAL index on it,
--   and PostgreSQL rebuilds a partial index on any type change of its column,
--   even a pure widening, under this ALTER's ACCESS EXCLUSIVE lock. Advisory
--   ids fit in 30; a longer one is refused by the write path with a message
--   naming the finding instead of a bare database error.
--
-- Cost: `VARCHAR(n)` -> `TEXT` is binary coercible, so on PostgreSQL 16/18 the
-- ALTER is a catalogue update. The heap, its TOAST table and every index of
-- `scan_findings` keep their relfilenode (no rewrite, no index rebuild);
-- verified against postgres:16. The lock is still ACCESS EXCLUSIVE for that
-- moment, so each attempt waits at most 5s for it and backs off, rather than
-- queueing every reader behind it for the session's 5-minute lock_timeout.
--
-- The read view `scan_findings_effective` (316) selects these columns, and
-- PostgreSQL refuses to change the type of a column a view uses. It is dropped
-- and recreated from its own stored definition, in the same transaction. It
-- is looked up rather than named because this migration is also shipped on
-- 1.11.x under the same number, where 316 and its view do not exist; there the
-- view is created later, by 316, over the already-widened columns.
--
-- Re-runnable: once no listed column is `character varying` it does nothing.
DO $$
DECLARE
    effective_def TEXT;
    attempt INT := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'scan_findings'
          AND column_name IN ('title', 'affected_component', 'affected_version',
                              'fixed_version', 'source', 'source_url')
          AND data_type = 'character varying'
    ) THEN
        RETURN;
    END IF;

    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            LOCK TABLE scan_findings IN ACCESS EXCLUSIVE MODE;

            effective_def := NULL;
            IF to_regclass('scan_findings_effective') IS NOT NULL THEN
                effective_def := pg_get_viewdef('scan_findings_effective'::regclass);
                DROP VIEW scan_findings_effective;
            END IF;

            ALTER TABLE scan_findings
                ALTER COLUMN title TYPE TEXT,
                ALTER COLUMN affected_component TYPE TEXT,
                ALTER COLUMN affected_version TYPE TEXT,
                ALTER COLUMN fixed_version TYPE TEXT,
                ALTER COLUMN source TYPE TEXT,
                ALTER COLUMN source_url TYPE TEXT;

            IF effective_def IS NOT NULL THEN
                EXECUTE 'CREATE VIEW scan_findings_effective AS ' || effective_def;
            END IF;
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN
                RAISE;
            END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
END $$;
