-- #4978 items 1 and 2: the conda dirty-mark triggers no longer lock shared
-- keys, and a row with no subdir gets a mark of its own.
--
-- Migration 298 kept one `conda_shard_dirty` row per (repository, subdir,
-- package name) and every mark was an `INSERT ... ON CONFLICT DO UPDATE` of
-- that row, which holds the row lock until the writer commits. Two writers
-- that mark the same names in different orders (two multi-package writes,
-- an upload against a bulk quarantine or delete, two uploads whose path and
-- metadata keys cross) waited on each other and Postgres aborted one with
-- `40P01 deadlock detected` (answered as a retryable 503 since #5184).
--
-- Marks are now append-only: every mark is a new row keyed by its own
-- sequence value, so writers never wait on each other's marks, and the
-- rebuild still deletes exactly the marks it read (a mark committed after
-- that read survives and is rebuilt by the next reader). Within one
-- transaction a key is marked once, so a bulk write adds one row per key.
--
-- Lock window: the primary key swap takes ACCESS EXCLUSIVE on
-- `conda_shard_dirty` only (a transient table, empty or nearly so between
-- reads), never on `artifacts` or `artifact_metadata`. Each attempt waits
-- at most 5 s for the lock and a lock timeout is retried (5 attempts,
-- backing off), as in migration 298. The functions are replaced with
-- CREATE OR REPLACE, which takes no table lock; the triggers are unchanged.
--
-- Rolling upgrade: 1.11.x replicas never read this table; their writes fire
-- the new functions as soon as this migration commits. Readers built before
-- this migration also work against the new layout: they delete marks by
-- their exact (subdir, name, mark) and rebuild a key listed twice once.
--
-- Rows with no subdir (no metadata `subdir` and no `/` in the path) used to
-- get no mark at all, so a write to one moved no revision. They now mark the
-- key `('', name)`: no document serves that subdir, but its rebuild bumps the
-- repository's revision sum, which is what the virtual dependency-confusion
-- guard caches its owned-name set on (#4978 item 1).
--
-- Idempotent: the functions are CREATE OR REPLACE and the key swap is
-- skipped when the new primary key is already in place.
--
-- Rollback (after draining the table by reading every conda channel, or
-- deleting its rows and resetting `conda_channel_state.backfill_done_at`):
--   ALTER TABLE conda_shard_dirty DROP CONSTRAINT conda_shard_dirty_pkey;
--   ALTER TABLE conda_shard_dirty ADD PRIMARY KEY (repository_id, subdir, package_name);
--   and re-run the function bodies of migration 298.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Add one mark for a key unless this transaction already added one: the
-- earlier mark becomes visible at the same commit as everything after it,
-- so a rebuild that reads it also reads every change it covers. A mark
-- added in a savepoint carries the savepoint's transaction id and is not
-- matched, which only costs a redundant row.
CREATE OR REPLACE FUNCTION conda_append_shard_dirty(
    p_repository_id UUID,
    p_subdir TEXT,
    p_package_name TEXT
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM conda_shard_dirty d
         WHERE d.repository_id = p_repository_id
           AND d.subdir = p_subdir
           AND d.package_name = p_package_name
           AND d.xmin::text = (txid_current() % 4294967296)::text
    ) THEN
        INSERT INTO conda_shard_dirty (repository_id, subdir, package_name, mark)
        VALUES (p_repository_id, p_subdir, p_package_name,
                nextval('conda_shard_dirty_mark_seq'));
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION conda_mark_artifact_dirty(
    p_repository_id UUID,
    p_artifact_id UUID,
    p_path TEXT,
    p_name TEXT
) RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_hosted_conda BOOLEAN;
    v_meta JSONB;
    v_path_subdir TEXT;
    v_meta_subdir TEXT;
    v_meta_name TEXT;
BEGIN
    SELECT r.format::text IN ('conda', 'conda_native')
           AND r.repo_type::text IN ('local', 'staging')
      INTO v_hosted_conda
      FROM repositories r
     WHERE r.id = p_repository_id;
    IF v_hosted_conda IS NOT TRUE THEN
        RETURN;
    END IF;

    IF position('/' IN p_path) > 0 THEN
        v_path_subdir := split_part(p_path, '/', 1);
    END IF;
    SELECT am.metadata INTO v_meta
      FROM artifact_metadata am
     WHERE am.artifact_id = p_artifact_id;
    -- '' stands for "no subdir" (#4978 item 1).
    v_meta_subdir := COALESCE(v_meta ->> 'subdir', v_path_subdir, '');
    v_meta_name := COALESCE(v_meta ->> 'name', p_name);

    IF v_path_subdir IS NOT NULL AND p_name IS NOT NULL THEN
        PERFORM conda_append_shard_dirty(p_repository_id, v_path_subdir, p_name);
    END IF;
    IF v_meta_subdir IS NOT NULL AND v_meta_name IS NOT NULL
       AND (v_meta_subdir IS DISTINCT FROM v_path_subdir OR v_meta_name IS DISTINCT FROM p_name) THEN
        PERFORM conda_append_shard_dirty(p_repository_id, v_meta_subdir, v_meta_name);
    END IF;
END;
$$;

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

-- One row per mark: the primary key moves from the key to (key, mark).
-- Existing rows already have distinct keys, so the new key is unique.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
         WHERE c.conrelid = 'conda_shard_dirty'::regclass
           AND c.contype = 'p'
           AND a.attname = 'mark'
    ) THEN
        RETURN;
    END IF;
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            ALTER TABLE conda_shard_dirty DROP CONSTRAINT IF EXISTS conda_shard_dirty_pkey;
            ALTER TABLE conda_shard_dirty
                ADD CONSTRAINT conda_shard_dirty_pkey
                PRIMARY KEY (repository_id, subdir, package_name, mark);
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
