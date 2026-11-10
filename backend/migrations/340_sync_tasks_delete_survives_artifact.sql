-- #5624: a peer delete outlives the artifact row it deletes.
--
-- `sync_tasks.artifact_id` referenced `artifacts(id) ON DELETE CASCADE`
-- (008), so hard-deleting an artifact (trash purge, `?permanent=true`, a
-- repository delete, GC of an expired trash row) also deleted the delete
-- tasks still queued for its peers, and those peers kept serving it.
--
-- A delete task now carries what the worker needs to address the peer copy
-- without the row: the repository id and key and the artifact path (plus the
-- SHA-256 it had), written when the task is queued. The foreign key becomes
-- `ON DELETE SET NULL`, so the task stays queued with `artifact_id` NULL and
-- the worker sends `DELETE /api/v1/repositories/{key}/artifacts/{path}` from
-- the stored address. Push tasks of a removed artifact are left with a NULL
-- `artifact_id` as well; the worker never claims them and sweeps them.
--
-- Cost: catalog-only. The new columns are nullable with no default, DROP NOT
-- NULL does not scan, and the foreign key is re-added NOT VALID (every
-- existing row already satisfies it; new rows are checked and the ON DELETE
-- action applies either way), so nothing is rewritten or validated. The
-- backfill touches only the not-yet-finished delete tasks (a queue, not the
-- history). Dropping a foreign key takes ACCESS EXCLUSIVE on both tables
-- (verified against postgres:16), so `artifacts` is locked last, after the
-- backfill, and held only for the catalog swap and the commit; each attempt
-- waits at most 5s for its locks and backs off instead of queueing every
-- request behind it for the session's 5-minute lock_timeout.
--
-- Re-runnable: the columns use IF NOT EXISTS, the backfill only fills NULLs,
-- and the constraint is dropped and re-added by name.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            LOCK TABLE sync_tasks IN ACCESS EXCLUSIVE MODE;

            ALTER TABLE sync_tasks
                ADD COLUMN IF NOT EXISTS target_repository_id UUID,
                ADD COLUMN IF NOT EXISTS target_repository_key TEXT,
                ADD COLUMN IF NOT EXISTS target_path TEXT,
                ADD COLUMN IF NOT EXISTS target_checksum_sha256 TEXT,
                ALTER COLUMN artifact_id DROP NOT NULL;

            UPDATE sync_tasks st
            SET target_repository_id = r.id,
                target_repository_key = r.key,
                target_path = a.path,
                target_checksum_sha256 = a.checksum_sha256
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.id = st.artifact_id
              AND st.task_type = 'delete'
              AND st.status IN ('pending', 'in_progress', 'failed')
              AND st.target_path IS NULL;

            LOCK TABLE artifacts IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE sync_tasks DROP CONSTRAINT IF EXISTS sync_tasks_artifact_id_fkey;
            ALTER TABLE sync_tasks ADD CONSTRAINT sync_tasks_artifact_id_fkey
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
                NOT VALID;
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

COMMENT ON COLUMN sync_tasks.target_path IS
    'Artifact path a delete task removes on the peer; kept when the artifact row is gone (#5624).';
