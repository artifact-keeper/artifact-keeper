-- #2464 (Export/Import P1, PR1): bookkeeping for content bundle export and
-- import jobs, a separate home for imported scan evidence, and a provenance
-- column on scan_results so hash-based scan dedup can never reuse a verdict
-- that did not come from this instance's own scanner.

-- One export or import of a bundle. The P2 sequence (stream_id,
-- sequence_number) and the media volume-set columns are reserved now so the
-- table does not change shape when those phases land.
CREATE TABLE bundle_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    direction TEXT NOT NULL CHECK (direction IN ('export', 'import')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'verifying', 'committing',
        'completed', 'failed', 'cancelled'
    )),
    -- Identity of the bundle (manifest bundle_id) and the exact manifest
    -- bytes (SHA-256) the job produced or consumed.
    bundle_id UUID,
    manifest_schema_version INTEGER,
    manifest_sha256 TEXT CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    bundle_kind TEXT NOT NULL DEFAULT 'full'
        CHECK (bundle_kind IN ('full', 'baseline', 'cumulative')),
    stream_id UUID,
    sequence_number BIGINT CHECK (sequence_number >= 1),
    media_profile TEXT,
    volume_count INTEGER CHECK (volume_count >= 1),
    media_control_number TEXT,
    repository_keys TEXT[] NOT NULL DEFAULT '{}',
    -- Storage key of the produced (export) or uploaded (import) bundle.
    storage_key TEXT,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    total_items INTEGER NOT NULL DEFAULT 0,
    completed_items INTEGER NOT NULL DEFAULT 0,
    failed_items INTEGER NOT NULL DEFAULT 0,
    skipped_items INTEGER NOT NULL DEFAULT 0,
    total_bytes BIGINT NOT NULL DEFAULT 0,
    transferred_bytes BIGINT NOT NULL DEFAULT 0,
    error_summary TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX idx_bundle_jobs_created_at ON bundle_jobs (created_at DESC);
CREATE INDEX idx_bundle_jobs_direction_status ON bundle_jobs (direction, status);

-- One artifact record of a job, keyed like the manifest record it mirrors.
-- An import journals each item here (verified -> committed), which is what
-- makes a re-run idempotent and a partly-failed import resumable.
CREATE TABLE bundle_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES bundle_jobs(id) ON DELETE CASCADE,
    repository_key TEXT NOT NULL,
    logical_path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    blob_path TEXT NOT NULL,
    volume INTEGER NOT NULL DEFAULT 1 CHECK (volume >= 1),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'verified', 'committed', 'skipped', 'conflict', 'failed'
    )),
    artifact_id UUID REFERENCES artifacts(id) ON DELETE SET NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (job_id, repository_key, logical_path)
);

CREATE INDEX idx_bundle_items_job_status ON bundle_items (job_id, status);
-- Serves the ON DELETE SET NULL from artifacts: without it every hard delete
-- of an artifact would scan bundle_items (up to millions of journal rows).
CREATE INDEX idx_bundle_items_artifact_id ON bundle_items (artifact_id)
    WHERE artifact_id IS NOT NULL;

-- Low-side scan evidence carried in a bundle (adversarial review on #2464,
-- constraint 1). It is evidence for a human reviewer and at most a reason to
-- reprioritise a local rescan. It is NEVER written to scan_results: a row
-- there with status 'completed' and a checksum would be picked up by
-- find_reusable_scan and silently exempt every future upload of the same
-- bytes, through any channel and into any repository, from a real scan.
-- Rows reference the job, the bundle and the manifest entry they came from,
-- and the signer once bundles are signed (#2466).
CREATE TABLE bundle_scan_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES bundle_jobs(id) ON DELETE CASCADE,
    bundle_id UUID NOT NULL,
    manifest_entry_index INTEGER NOT NULL CHECK (manifest_entry_index >= 0),
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    scanner TEXT NOT NULL,
    scanner_version TEXT,
    vulnerability_db_version TEXT,
    scanned_at TIMESTAMPTZ NOT NULL,
    signer_key_id TEXT,
    signer_fingerprint TEXT,
    verdict JSONB NOT NULL,
    evidence_path TEXT,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (job_id, manifest_entry_index)
);

CREATE INDEX idx_bundle_scan_evidence_sha ON bundle_scan_evidence (artifact_sha256);

-- Provenance on scan_results (constraint 1, defence 2). Every existing and
-- future row written by this instance's scanners is 'local_scan'. Every
-- scan_results read that treats a completed row as "already scanned"
-- (find_reusable_scan, find_existing_scan_for_artifact and the
-- prepare_scan_placeholder short-circuit) only accepts 'local_scan' rows, so
-- even a later change that routes imported data into this table cannot
-- make it stand in for a local scan.
--
-- Online shape on a hot table: a constant default is catalog-only (PG 11+)
-- and the NOT VALID constraint is a catalog update that checks every new
-- write. There is deliberately NO `VALIDATE CONSTRAINT` here: in the same
-- transaction it would run its full scan while still holding the ACCESS
-- EXCLUSIVE lock the two ALTERs took, blocking every read and write of
-- scan_results (docs/operations/online-migrations.md, section 2). Every
-- existing row satisfies the check by construction (it gets the constant
-- default), so validation would prove nothing.
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'local_scan';
ALTER TABLE scan_results ADD CONSTRAINT scan_results_origin_check
    CHECK (origin IN ('local_scan', 'imported')) NOT VALID;
