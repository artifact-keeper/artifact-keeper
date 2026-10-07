-- no-transaction
-- 278_proxy_download_statistics_history_backfill.sql
-- #3844 / #4539: key every existing proxy download row on the
-- `(repository_id, path)` of the catalog row it references (277 added the
-- columns). Every row has a catalog row: until 279 the foreign key still
-- cascades, so a row whose cache entry was evicted is already gone.
--
-- Batched by primary key (keyset, 5000 rows, docs/operations/online-
-- migrations.md "Backfill"): each batch commits on its own, bounds its row
-- locks with lock_timeout and retries a batch that cannot get them. On a
-- million rows: 200 short transactions, no table lock. Re-runnable: a filled
-- row is skipped, so an interrupted run resumes by re-walking the keys.
DO $$
DECLARE
    last_id uuid := '00000000-0000-0000-0000-000000000000';
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
                SELECT (SELECT b.id FROM batch b ORDER BY b.id DESC LIMIT 1)
                  INTO last_id;
                EXIT;
            EXCEPTION WHEN lock_not_available THEN
                attempt := attempt + 1;
                IF attempt >= 5 THEN
                    RAISE;
                END IF;
                PERFORM pg_sleep(attempt);
            END;
        END LOOP;
        EXIT WHEN last_id IS NULL;
        COMMIT;
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
