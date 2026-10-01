-- #3910: storage scrub. Records content-addressed objects whose stored bytes
-- failed re-verification against their recorded SHA-256, so operators get a
-- durable report instead of a log line, plus the walk cursor that lets the
-- bounded (per-run object/byte budget) scrub resume where it stopped.
--
-- A finding never mutates the referencing row: the download path already
-- refuses to complete a corrupt body (#3919), and a repair only happens from
-- a verified good copy, after which the finding is marked 'repaired'. A later
-- pass that finds the object intact deletes the finding.

CREATE TABLE storage_scrub_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_kind TEXT NOT NULL CHECK (object_kind IN ('artifact', 'oci_blob')),
    object_id UUID NOT NULL,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    expected_sha256 TEXT NOT NULL,
    actual_sha256 TEXT,
    expected_size BIGINT,
    actual_size BIGINT,
    status TEXT NOT NULL CHECK (status IN ('corrupt', 'missing', 'repaired')),
    detail TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (object_kind, object_id)
);

CREATE INDEX idx_storage_scrub_findings_status
    ON storage_scrub_findings (status, updated_at DESC);
CREATE INDEX idx_storage_scrub_findings_repository
    ON storage_scrub_findings (repository_id);

-- Walk cursors (keyset on the row UUIDs), one row per scope: 'instance' for
-- the instance-wide walk, or a repository id for a repository-scoped run.
-- Written after every object so a run that is cut short (request timeout,
-- restart) resumes instead of repeating the same work.
CREATE TABLE storage_scrub_state (
    scope TEXT PRIMARY KEY,
    artifact_cursor UUID,
    oci_blob_cursor UUID,
    last_run_at TIMESTAMPTZ,
    last_cycle_completed_at TIMESTAMPTZ
);
