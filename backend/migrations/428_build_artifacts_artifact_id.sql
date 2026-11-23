-- artifact-keeper-web#618: a build artifact can point at a stored artifact
-- instead of only naming a free-form path. The link goes NULL when the
-- artifact row is purged, the entry keeps its name, path and checksum.
--
-- The new column is nullable with no default, so no rewrite. Its foreign key
-- is declared on the column it adds, so it is an expand (no earlier release
-- writes artifact_id), and Postgres doesn't validate it since every row
-- starts NULL. Adding it still takes SHARE ROW EXCLUSIVE on `artifacts`, so
-- each attempt waits at most 5s for the locks and backs off, up to five
-- attempts, like 340.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            ALTER TABLE build_artifacts
                ADD COLUMN IF NOT EXISTS artifact_id UUID
                    REFERENCES artifacts(id) ON DELETE SET NULL;
            EXIT;
        EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN
                RAISE;
            END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_build_artifacts_artifact_id
    ON build_artifacts (artifact_id) WHERE artifact_id IS NOT NULL;
