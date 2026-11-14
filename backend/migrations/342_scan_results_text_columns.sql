-- #5564: a scanner's provenance strings are stored as `TEXT`.
--
-- `scan_results.scanner_version` (022) was `VARCHAR(50)` and
-- `vuln_db_version` (259) was `VARCHAR(100)`. Both are scanner-supplied, and a
-- value past its limit made `complete_scan` fail: the scan stayed `running`
-- until the stuck-scan janitor failed it, which also skipped every scanner
-- after it in the set. That is the same failure shape #5534 fixed for the
-- batched `scan_findings` insert, so the columns get the same treatment.
--
-- Cost: `VARCHAR(n)` -> `TEXT` is binary coercible, so on PostgreSQL 16/18 the
-- ALTER is a catalogue update. Neither column carries an index, so there is no
-- index to rebuild, and the heap/TOAST relfilenodes are unchanged; verified
-- against postgres:16. The lock is still ACCESS EXCLUSIVE for that moment, so
-- each attempt waits at most 5s for it and backs off, rather than queueing
-- every reader behind it for the session's 5-minute lock_timeout.
--
-- Re-runnable: once neither column is `character varying` it does nothing.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'scan_results'
          AND column_name IN ('scanner_version', 'vuln_db_version')
          AND data_type = 'character varying'
    ) THEN
        RETURN;
    END IF;

    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            LOCK TABLE scan_results IN ACCESS EXCLUSIVE MODE;

            ALTER TABLE scan_results
                ALTER COLUMN scanner_version TYPE TEXT,
                ALTER COLUMN vuln_db_version TYPE TEXT;
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
