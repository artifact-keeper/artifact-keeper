-- #5624: a peer delete outlives the artifact row it deletes.
--
-- `sync_tasks.artifact_id` referenced `artifacts(id) ON DELETE CASCADE`
-- (008), so hard-deleting an artifact (trash purge, `?permanent=true`, a
-- repository delete, GC of an expired trash row) also deleted the delete
-- tasks still queued for its peers, and those peers kept serving it.
--
-- A delete task now carries what the worker needs to address the peer copy
-- without the row: the repository key and the artifact path (and the
-- repository id), written when the task is queued. The foreign key becomes
-- `ON DELETE SET NULL`, so the task stays queued with `artifact_id` NULL and
-- the worker sends `DELETE /api/v1/repositories/{key}/artifacts/{path}` from
-- the stored address. Push tasks of a removed artifact are left with a NULL
-- `artifact_id` as well; the worker never claims them and sweeps them.
--
-- Cost: no rewrite and no validation scan. The new columns are nullable with
-- no default, DROP NOT NULL does not scan, and the foreign key is re-added NOT
-- VALID (every existing row already satisfies it; new rows are checked and
-- the ON DELETE action applies either way). The backfill touches only the
-- unfinished delete tasks (a queue, not the history), about 15 us per row.
--
-- Locks: dropping a foreign key takes ACCESS EXCLUSIVE on both tables
-- (verified against postgres:16). Both are taken up front in ONE statement,
-- `artifacts` first: the order every application transaction uses (it locks
-- an artifact row, then writes `sync_tasks`), so the migration does not take
-- one table and wait on the other. Both stay held through the backfill and
-- the catalog swap until commit, so reads and writes on both tables wait for
-- that window. Each attempt waits at most 5s for the locks and backs off; a
-- lock timeout or a deadlock (should one still occur) is retried, up to five
-- attempts (about 35s in all). If every attempt fails the migration raises,
-- nothing of it is applied (it is one transaction), the server exits, and the
-- next start retries it.
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
            LOCK TABLE artifacts, sync_tasks IN ACCESS EXCLUSIVE MODE;

            ALTER TABLE sync_tasks
                ADD COLUMN IF NOT EXISTS target_repository_id UUID,
                ADD COLUMN IF NOT EXISTS target_repository_key TEXT,
                ADD COLUMN IF NOT EXISTS target_path TEXT,
                ALTER COLUMN artifact_id DROP NOT NULL;

            UPDATE sync_tasks st
            SET target_repository_id = r.id,
                target_repository_key = r.key,
                target_path = a.path
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.id = st.artifact_id
              AND st.task_type = 'delete'
              AND st.status IN ('pending', 'in_progress', 'failed')
              AND st.target_path IS NULL;

            ALTER TABLE sync_tasks DROP CONSTRAINT IF EXISTS sync_tasks_artifact_id_fkey;
            ALTER TABLE sync_tasks ADD CONSTRAINT sync_tasks_artifact_id_fkey
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE SET NULL
                NOT VALID;
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

COMMENT ON COLUMN sync_tasks.target_path IS
    'Artifact path a delete task removes on the peer; kept when the artifact row is gone (#5624).';
