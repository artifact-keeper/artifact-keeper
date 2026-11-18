-- Durable scan queue, so grype runs on a worker instead of in the request.
-- RowClaimedQueue pattern (services/cluster_work.rs), claim columns and indexes
-- follow migration 148.
CREATE TABLE IF NOT EXISTS scan_queue (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind             TEXT NOT NULL
        CHECK (kind IN ('proxy_file', 'hosted_artifact')),
    state            TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'running', 'failed')),
    -- Fail-closed 100 (a client is parked on it), fail-open 50, hosted 10.
    priority         SMALLINT NOT NULL DEFAULT 50,

    -- Jobs carry a storage reference, never the bytes.
    repository_id    UUID REFERENCES repositories(id) ON DELETE CASCADE,
    cache_path       TEXT,
    digest           TEXT,
    content_type     TEXT,
    size_bytes       BIGINT,

    -- Identity the request asserted (#3003). Unpinned, `clean` means nothing was graded.
    expected_ecosystem TEXT,
    expected_name      TEXT,
    expected_version   TEXT,

    -- Placeholder scan_results ids the API already returned to its caller.
    artifact_id      UUID REFERENCES artifacts(id) ON DELETE CASCADE,
    prepared         JSONB,
    -- The caller's #1469 dedup bypass, which the worker passes on to the scan.
    bypass_dedup     BOOLEAN NOT NULL DEFAULT false,

    attempts         INT NOT NULL DEFAULT 0,
    max_attempts     INT NOT NULL DEFAULT 3,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error       TEXT,

    claimed_by       TEXT,
    claim_token      UUID,
    claim_expires_at TIMESTAMPTZ,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- All three or none: a half-populated pin grades the wrong thing.
    CONSTRAINT ck_scan_queue_expected_complete CHECK (
        (expected_ecosystem IS NULL AND expected_name IS NULL AND expected_version IS NULL)
        OR (expected_ecosystem IS NOT NULL AND expected_name IS NOT NULL
            AND expected_version IS NOT NULL)
    ),

    -- Each kind must carry what its worker branch reads.
    CONSTRAINT ck_scan_queue_payload CHECK (
        (kind = 'proxy_file'
            AND repository_id IS NOT NULL AND cache_path IS NOT NULL
            AND digest IS NOT NULL AND artifact_id IS NULL)
        OR (kind = 'hosted_artifact'
            AND artifact_id IS NOT NULL AND prepared IS NOT NULL)
    )
);

COMMENT ON COLUMN scan_queue.claimed_by IS
    'Diagnostic worker identity, not the correctness guard';
COMMENT ON COLUMN scan_queue.claim_token IS
    'Random per-claim token, finalizers must match it';
COMMENT ON COLUMN scan_queue.claim_expires_at IS
    'Claim lease, heartbeaten while the scan runs. Expired means due again';

CREATE INDEX IF NOT EXISTS idx_scan_queue_pending_claim
    ON scan_queue (priority DESC, created_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_scan_queue_claim_expiry
    ON scan_queue (claim_expires_at)
    WHERE state = 'running';

-- Dedup: a burst on one digest queues one job. Excludes 'failed' so a later
-- pull can queue afresh.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_queue_digest_active
    ON scan_queue (kind, digest)
    WHERE state IN ('pending', 'running') AND digest IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_queue_artifact_active
    ON scan_queue (kind, artifact_id)
    WHERE state IN ('pending', 'running') AND artifact_id IS NOT NULL;

-- Foreign-key lookups. Deleting an artifact or a repository checks this table
-- for rows in every state, terminal ones included, which the partial unique
-- indexes above cannot answer, so without these each delete scans the table.
CREATE INDEX IF NOT EXISTS idx_scan_queue_artifact_id
    ON scan_queue (artifact_id)
    WHERE artifact_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_queue_repository_id
    ON scan_queue (repository_id)
    WHERE repository_id IS NOT NULL;
