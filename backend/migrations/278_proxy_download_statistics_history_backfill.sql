-- no-transaction
-- 278_proxy_download_statistics_history_backfill.sql
-- #3844 / #4539: key every existing proxy download row on the
-- `(repository_id, path)` of the catalog row it references (277 added the
-- columns). Every row has a catalog row: until 279 the foreign key still
-- cascades, so a row whose cache entry was evicted is already gone.
--
-- Batched by primary key (keyset, 5000 rows, docs/operations/online-
-- migrations.md "Backfill"): each batch commits on its own, bounds its row
-- locks with lock_timeout and retries a batch that cannot get them or that
-- deadlocks with a cascade DELETE from a pod still on the previous release.
-- No table lock.
--
-- Time bound: the whole DO block is ONE statement, so the migration session's
-- 30-minute statement_timeout (main.rs) is its only ceiling. Measured at
-- about 8 us per row plus the 50 ms pause between batches that changed rows
-- (500k rows: 9 s), so it fits well inside 30 minutes up to tens of millions
-- of rows. The table is small in practice before this upgrade: eviction used
-- to delete a cache entry's rows with it, so it holds history for the live
-- cache only. Re-runnable: a keyed row is skipped and a batch that changed
-- nothing does not pause, so an interrupted run re-walks the keys quickly.
DO $$
DECLARE
    last_id uuid := '00000000-0000-0000-0000-000000000000';
    touched bigint;
    attempt integer;
BEGIN
    LOOP
        attempt := 0;
        LOOP
            BEGIN
                SET LOCAL lock_timeout = '5s';
                WITH batch AS (
                    SELECT d.id
                      FROM proxy_download_statistics d
                     WHERE d.id > last_id
                     ORDER BY d.id
                     LIMIT 5000
                ), filled AS (
                    UPDATE proxy_download_statistics d
                       SET repository_id = c.repository_id,
                           path = c.path
                      FROM batch b, proxy_cache_artifacts c
                     WHERE d.id = b.id
                       AND d.repository_id IS NULL
                       AND c.id = d.proxy_cache_id
                    RETURNING d.id
                )
                SELECT (SELECT b.id FROM batch b ORDER BY b.id DESC LIMIT 1),
                       (SELECT COUNT(*) FROM filled)
                  INTO last_id, touched;
                EXIT;
            EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
                attempt := attempt + 1;
                IF attempt >= 5 THEN
                    RAISE;
                END IF;
                PERFORM pg_sleep(attempt);
            END;
        END LOOP;
        EXIT WHEN last_id IS NULL;
        COMMIT;
        IF touched > 0 THEN
            PERFORM pg_sleep(0.05);
        END IF;
    END LOOP;
END $$;
