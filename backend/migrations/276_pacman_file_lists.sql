-- no-transaction
-- #4424: move hosted pacman file lists out of artifact_metadata.
--
-- Migration 262's pacman handler kept each package's file list (up to
-- 500,000 names) inside its artifact_metadata document. Rendering `{repo}.db`
-- stripped it with `metadata - 'files'`, but only after PostgreSQL had
-- detoasted the whole document, so every `pacman -Sy` (anonymous on a public
-- repository) read every file list in the repository. The lists now live in
-- pacman_file_lists, one row per artifact, read only for the `.files`
-- database; artifact_metadata keeps the small desc fields.
--
-- One statement (a DO block), so the -- no-transaction header lets it COMMIT
-- between batches (docs/operations/online-migrations.md, section 4):
--   * CREATE TABLE IF NOT EXISTS is a new, empty table. Its foreign key takes
--     a brief SHARE ROW EXCLUSIVE lock on artifacts (catalogue only, no scan);
--     SET LOCAL lock_timeout = '5s' makes the upgrade fail fast instead of
--     queueing uploads behind a long transaction.
--   * The backfill moves 100 pacman rows per batch: copy the list, strip it
--     from the document, COMMIT. Every batch runs under SET LOCAL
--     lock_timeout = '5s' (COMMIT ends it, so it is set per batch), and a
--     batch that times out on a row lock is retried up to five times with a
--     growing back-off before the migration gives up. The predicate is the
--     fix itself (`format = 'pacman' AND metadata ? 'files'`), so an
--     interrupted run resumes where it stopped and a re-run is a no-op.
--   * Cost: there is no index on `format`, and `metadata ? 'files'` (which
--     idx_artifact_metadata_gin can answer) also matches every Maven row that
--     records `files` (migration 179), so each batch reads all of those rows
--     before the format filter, then sorts the pacman ones. Pacman was
--     unreleased before this migration, so a real deployment runs zero to a
--     few batches. Only pacman rows are ever written. A batch is bounded in
--     rows (100), not bytes.
--   * List entries that are not JSON strings (a `null` would only come from
--     hand-edited data) are skipped, since `files` is a text array; how many
--     is reported once with RAISE NOTICE.
--   * Re-runnable by hand: `psql -f` on this file moves any list written into
--     artifact_metadata after it ran (by a replica still on older code during
--     a rolling upgrade), see docs/pacman.md.
DO $$
DECLARE
    touched integer;
    attempt integer;
    skipped bigint;
BEGIN
    SET LOCAL lock_timeout = '5s';
    CREATE TABLE IF NOT EXISTS pacman_file_lists (
        artifact_id UUID PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
        files TEXT[] NOT NULL
    );
    COMMENT ON TABLE pacman_file_lists IS
        'Per-package file lists for the pacman .files database (#4424); kept out of artifact_metadata so .db renders never read them.';
    COMMIT;

    SELECT count(*)
      INTO skipped
      FROM artifact_metadata am,
           jsonb_array_elements(
               CASE WHEN jsonb_typeof(am.metadata -> 'files') = 'array'
                    THEN am.metadata -> 'files' END) AS e(entry)
     WHERE am.format = 'pacman'
       AND am.metadata ? 'files'
       AND jsonb_typeof(e.entry) <> 'string';
    IF skipped > 0 THEN
        RAISE NOTICE 'migration 276 (#4424): skipping % pacman file-list entries that are not strings', skipped;
    END IF;

    LOOP
        attempt := 0;
        LOOP
            BEGIN
                SET LOCAL lock_timeout = '5s';
                WITH batch AS (
                    SELECT artifact_id, metadata -> 'files' AS files
                      FROM artifact_metadata
                     WHERE format = 'pacman'
                       AND metadata ? 'files'
                     ORDER BY artifact_id
                     LIMIT 100
                ), moved AS (
                    INSERT INTO pacman_file_lists (artifact_id, files)
                    SELECT b.artifact_id,
                           ARRAY(SELECT e.entry #>> '{}'
                                   FROM jsonb_array_elements(b.files) AS e(entry)
                                  WHERE jsonb_typeof(e.entry) = 'string')
                      FROM batch b
                     WHERE jsonb_typeof(b.files) = 'array'
                    ON CONFLICT (artifact_id) DO NOTHING
                )
                UPDATE artifact_metadata am
                   SET metadata = am.metadata - 'files'
                  FROM batch b
                 WHERE am.artifact_id = b.artifact_id;
                GET DIAGNOSTICS touched = ROW_COUNT;
                EXIT;
            EXCEPTION WHEN lock_not_available THEN
                attempt := attempt + 1;
                IF attempt >= 5 THEN
                    RAISE;
                END IF;
                PERFORM pg_sleep(attempt);
            END;
        END LOOP;
        COMMIT;
        EXIT WHEN touched = 0;
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
