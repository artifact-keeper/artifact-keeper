-- #6469: make a lifecycle sweep's derived-state step recoverable.
--
-- A sweep soft-deletes in bulk, commits, and then runs the per-artifact
-- delete's remaining steps for the rows it swept: peer delete tasks, the
-- ARTIFACT_DELETED audit rows, `artifact.deleted` events, search deletes and
-- the Maven and Cargo caches. Those steps run after the commit, so a restart
-- in between (or a failed page) used to lose them for good: nothing recorded
-- that the work was owed, and a rerun of the policy removes nothing.
--
-- The sweep's own transaction now inserts one row here, keyed on the
-- repository and the transaction's `deleted_at` stamp (the stamp migration
-- 261's trigger puts on every row the sweep soft-deletes). Each page of the
-- step then runs in one transaction that locks this row, writes the peer
-- tasks and audit rows, and advances `done_through` to the page's last
-- artifact id. When every page is done the row is deleted. A row left behind
-- by a restart or a failure is picked up by the next lifecycle tick, which
-- resumes after `done_through`, so no page is written twice and none is lost.
--
-- New table only: no lock on an existing table. A replica on the previous
-- release never reads or writes it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS lifecycle_sweep_fanouts (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    deleted_at TIMESTAMPTZ NOT NULL,
    done_through UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, deleted_at)
);

COMMENT ON TABLE lifecycle_sweep_fanouts IS
    'Lifecycle sweeps whose per-artifact derived-state step (peer tasks, audit, events, search, caches) is not finished yet (#6469). done_through is the last artifact id handled; the row is deleted when the step completes.';
