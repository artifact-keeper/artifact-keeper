-- #4544 follow-up: writers no longer lock `rpm_repodata_roots` rows.
--
-- Migration 308 marked a clean root dirty with INSERT ... ON CONFLICT DO
-- UPDATE, which holds the root's row lock until the writer commits. Two
-- transactions dirtying two clean roots in opposite order (a cross-repository
-- move, a multi-root import at positive depth, any two multi-statement
-- writers) could deadlock, and Postgres aborted one upload. Writers now only
-- append to `rpm_repodata_dirty`, which has no unique key, so their inserts
-- never wait on each other. The builder folds the entries into
-- `rpm_repodata_roots` (serialized, in key order) and consumes them when it
-- claims a root, under the same fence as before.
SET LOCAL lock_timeout = '5s';

CREATE TABLE rpm_repodata_dirty (
    repository_id uuid NOT NULL,
    root text NOT NULL,
    marked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX rpm_repodata_dirty_root_idx ON rpm_repodata_dirty (repository_id, root);

CREATE OR REPLACE FUNCTION ak_rpm_repodata_mark_dirty(repo_id uuid, path text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    r text;
BEGIN
    IF path IS NULL OR path NOT LIKE '%.rpm' THEN RETURN; END IF;
    IF NOT EXISTS (SELECT 1 FROM repositories
                   WHERE id = repo_id AND format = 'rpm' AND repo_type = 'local') THEN
        RETURN;
    END IF;
    r := ak_rpm_repodata_root(repo_id, path);
    -- Held until commit: the builder's claim waits for this transaction, so
    -- a write that skips below because the root is already dirty is
    -- committed before the builder's snapshot is taken.
    PERFORM pg_advisory_xact_lock_shared(ak_rpm_repodata_fence(repo_id, r));
    IF EXISTS (SELECT 1 FROM rpm_repodata_roots
               WHERE repository_id = repo_id AND root = r AND dirty_since IS NOT NULL)
       OR EXISTS (SELECT 1 FROM rpm_repodata_dirty
                  WHERE repository_id = repo_id AND root = r) THEN
        RETURN;
    END IF;
    INSERT INTO rpm_repodata_dirty (repository_id, root) VALUES (repo_id, r);
END
$$;
