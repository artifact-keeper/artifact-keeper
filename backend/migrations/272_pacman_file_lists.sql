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
--     lock_timeout = 5s makes the upgrade fail fast and retry instead of
--     queueing uploads behind a long transaction.
--   * The backfill moves 100 pacman rows per batch: copy the list, strip it
--     from the document, COMMIT. The predicate is the fix itself
--     (`metadata ? 'files'`, served by idx_artifact_metadata_gin), so an
--     interrupted run resumes where it stopped and a re-run is a no-op.
--     Cost at a million artifacts: only pacman rows that still carry a list
--     are touched; every other format's rows are never written.
DO $$
DECLARE
    touched integer;
BEGIN
    PERFORM set_config('lock_timeout', '5s', true);
    CREATE TABLE IF NOT EXISTS pacman_file_lists (
        artifact_id UUID PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
        files TEXT[] NOT NULL
    );
    COMMENT ON TABLE pacman_file_lists IS
        'Per-package file lists for the pacman .files database (#4424); kept out of artifact_metadata so .db renders never read them.';
    COMMIT;

    LOOP
        PERFORM set_config('lock_timeout', '5s', true);
        WITH batch AS (
            SELECT artifact_id, metadata -> 'files' AS files
              FROM artifact_metadata
             WHERE format = 'pacman'
               AND metadata ? 'files'
             ORDER BY artifact_id
             LIMIT 100
        ), moved AS (
            INSERT INTO pacman_file_lists (artifact_id, files)
            SELECT b.artifact_id, ARRAY(SELECT jsonb_array_elements_text(b.files))
              FROM batch b
             WHERE jsonb_typeof(b.files) = 'array'
            ON CONFLICT (artifact_id) DO NOTHING
        )
        UPDATE artifact_metadata am
           SET metadata = am.metadata - 'files'
          FROM batch b
         WHERE am.artifact_id = b.artifact_id;
        GET DIAGNOSTICS touched = ROW_COUNT;
        EXIT WHEN touched = 0;
        COMMIT;
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
