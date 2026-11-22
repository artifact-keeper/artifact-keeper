-- #6429: where a long background walk resumes, shared by every replica.
--
-- The proxy-cache re-catalog sweep walks each Remote's cache tree in bounded
-- chunks. Its position (the Remote it stopped in and that Remote's listing
-- cursor) used to live in the memory of the replica that ran the chunk, so a
-- restart or a lease handover started over from the first Remote and the tail
-- of a large cache was never reached. One row per job, written under the
-- job's scheduler lease.
--
-- A new, empty table: no lock on any existing table, nothing rewritten. A
-- replica on the previous release never reads or writes it.
CREATE TABLE IF NOT EXISTS scheduler_job_cursors (
    job_name      TEXT PRIMARY KEY,
    repository_id UUID,
    cursor        TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE scheduler_job_cursors IS
    'Resume position of a chunked background walk (#6429), one row per scheduler job; NULL repository_id means start from the beginning';
