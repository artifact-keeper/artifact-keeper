-- no-transaction
-- #4050: backfill artifacts.origin for rows that predate migration 227,
-- deriving from what is still knowable — the owning repository row: a
-- local repo's artifacts are recorded as uploads ("hosted"), a remote
-- repo's as proxied fetches naming the repository's CURRENT upstream_url.
-- The upstream facet is necessarily the repo's present-day upstream: the
-- historical upstream at fetch time was never recorded anywhere, and
-- inventing one would be worse than recording the best available fact.
-- This is the same derivation the fill trigger applies to new rows, so a
-- backfilled row and a freshly ingested one are indistinguishable.
--
-- Batched by primary key with COMMIT between batches (needs the
-- -- no-transaction header and a single-statement file, per
-- docs/operations/online-migrations.md): on a million-row table a single
-- UPDATE would hold row locks on every row and land one WAL burst. The
-- predicate IS the fix (`origin IS NULL`), so an interrupted run resumes
-- where it stopped. Per-batch cost: 5000-row PK lookup + PK-targeted
-- updates; the whole run doubles only the touched rows' heap, in slices.
DO $$
DECLARE
    touched integer;
BEGIN
    LOOP
        WITH batch AS (
            SELECT id FROM artifacts
             WHERE origin IS NULL
             ORDER BY id
             LIMIT 5000
        )
        UPDATE artifacts a
           SET origin = ak_artifact_origin_for_repo(a.repository_id)
          FROM batch b
         WHERE a.id = b.id;
        GET DIAGNOSTICS touched = ROW_COUNT;
        EXIT WHEN touched = 0;
        COMMIT;
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
