-- Conda shard dirty marks: fire only for rows a conda shard can contain.
--
-- Migration 298 put `conda_artifacts_mark_dirty_t` on every insert and update
-- of `artifacts`, and `conda_artifact_metadata_mark_dirty_t` on every change of
-- `artifact_metadata`, with no guard. The function checks the repository's
-- format itself, so a row in any other format paid a PL/pgSQL call and a
-- `repositories` lookup (two lookups for a metadata row) on every upload, in
-- every format.
--
-- Every conda output reads package rows only: shards
-- (`group_artifacts_by_name`), repodata records and the `removed` array
-- (`list_removed_artifacts_at`) all keep a row only when its file name ends in
-- `.conda` or `.tar.bz2` (`is_conda_package` in handlers/conda.rs). A mark for
-- any other row changes nothing a client receives. So:
--
-- * the `artifacts` triggers get a WHEN on the path, old or new, in the same
--   shape as the RPM (`%.rpm`, migration 308) and MCP triggers. Postgres allows
--   OLD in WHEN only for UPDATE and DELETE, so the INSERT-or-UPDATE trigger is
--   split in two. A path ends in `.conda` exactly when its last segment does,
--   so the WHEN keeps the rows `is_conda_package` keeps;
-- * the `artifact_metadata` function, which cannot see the path in WHEN,
--   returns right after its existing artifact lookup when the path is not a
--   package, before the `repositories` and metadata lookups.
--
-- The one observable difference: a subdir's revision no longer moves when only
-- a non-package row in a conda repository changes, because nothing it serves
-- changed.

CREATE OR REPLACE FUNCTION conda_artifact_metadata_mark_dirty() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_artifact RECORD;
    v_old_subdir TEXT;
    v_old_name TEXT;
BEGIN
    SELECT a.id, a.repository_id, a.path, a.name INTO v_artifact
      FROM artifacts a
     WHERE a.id = COALESCE(NEW.artifact_id, OLD.artifact_id);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    -- Only package rows reach a shard, repodata or `removed` (#6090).
    IF v_artifact.path NOT LIKE '%.conda' AND v_artifact.path NOT LIKE '%.tar.bz2' THEN
        RETURN NULL;
    END IF;
    -- The key the row had under its previous metadata (a rename or subdir
    -- edit moves the record out of that shard).
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        v_old_subdir := COALESCE(OLD.metadata ->> 'subdir',
            CASE WHEN position('/' IN v_artifact.path) > 0
                 THEN split_part(v_artifact.path, '/', 1) END, '');
        v_old_name := COALESCE(OLD.metadata ->> 'name', v_artifact.name);
        IF v_old_subdir IS NOT NULL AND v_old_name IS NOT NULL
           AND EXISTS (SELECT 1 FROM repositories r
                        WHERE r.id = v_artifact.repository_id
                          AND r.format::text IN ('conda', 'conda_native')
                          AND r.repo_type::text IN ('local', 'staging')) THEN
            PERFORM conda_append_shard_dirty(
                v_artifact.repository_id, v_old_subdir, v_old_name);
        END IF;
    END IF;
    PERFORM conda_mark_artifact_dirty(
        v_artifact.repository_id, v_artifact.id, v_artifact.path, v_artifact.name);
    RETURN NULL;
END;
$$;

-- CREATE TRIGGER takes SHARE ROW EXCLUSIVE on `artifacts`, which queues behind
-- any open transaction and holds every write behind it while it waits (#4153):
-- as in 298, each attempt waits at most 5 s and a lock timeout is retried.
SET LOCAL lock_timeout = '5s';
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            DROP TRIGGER IF EXISTS conda_artifacts_mark_dirty_t ON artifacts;
            CREATE TRIGGER conda_artifacts_mark_dirty_t
                AFTER INSERT ON artifacts
                FOR EACH ROW
                WHEN (NEW.path LIKE '%.conda' OR NEW.path LIKE '%.tar.bz2')
                EXECUTE FUNCTION conda_artifacts_mark_dirty();

            DROP TRIGGER IF EXISTS conda_artifacts_mark_dirty_upd_t ON artifacts;
            CREATE TRIGGER conda_artifacts_mark_dirty_upd_t
                AFTER UPDATE OF repository_id, path, name, version, size_bytes,
                    checksum_sha256, is_deleted, quarantine_status, quarantine_until, created_at
                ON artifacts
                FOR EACH ROW
                WHEN (OLD.path LIKE '%.conda' OR OLD.path LIKE '%.tar.bz2'
                      OR NEW.path LIKE '%.conda' OR NEW.path LIKE '%.tar.bz2')
                EXECUTE FUNCTION conda_artifacts_mark_dirty();

            DROP TRIGGER IF EXISTS conda_artifacts_mark_dirty_del_t ON artifacts;
            CREATE TRIGGER conda_artifacts_mark_dirty_del_t
                BEFORE DELETE ON artifacts
                FOR EACH ROW
                WHEN (OLD.path LIKE '%.conda' OR OLD.path LIKE '%.tar.bz2')
                EXECUTE FUNCTION conda_artifacts_mark_dirty();
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN
                RAISE;
            END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
END
$$;
