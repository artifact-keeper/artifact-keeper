-- #5947: rescan stored artifacts after a vulnerability-database update.
--
-- Additive. `rescan` is a new scan_queue kind (one job per content digest,
-- through uq_scan_queue_digest_active), and two new tables. Nothing runs
-- unless SCAN_RESCAN_MAX_PER_DAY is above 0 (default 0) and the durable scan
-- queue is on.

ALTER TABLE scan_queue DROP CONSTRAINT IF EXISTS scan_queue_kind_check;
ALTER TABLE scan_queue ADD CONSTRAINT scan_queue_kind_check
    CHECK (kind IN ('proxy_file', 'hosted_artifact', 'hosted_upload', 'hosted_image', 'rescan'));

ALTER TABLE scan_queue DROP CONSTRAINT IF EXISTS ck_scan_queue_payload;
ALTER TABLE scan_queue ADD CONSTRAINT ck_scan_queue_payload CHECK (
    (kind = 'proxy_file'
        AND repository_id IS NOT NULL AND cache_path IS NOT NULL
        AND digest IS NOT NULL AND artifact_id IS NULL)
    OR (kind = 'hosted_artifact'
        AND artifact_id IS NOT NULL AND prepared IS NOT NULL)
    OR (kind = 'hosted_upload'
        AND artifact_id IS NOT NULL AND prepared IS NULL)
    OR (kind = 'hosted_image'
        AND repository_id IS NOT NULL AND digest IS NOT NULL
        AND artifact_id IS NULL AND prepared IS NULL)
    OR (kind = 'rescan'
        AND digest IS NOT NULL AND artifact_id IS NULL AND prepared IS NULL)
);

-- One row per digest queued for one set of database builds, so a digest is
-- rescanned once per update (a failing rescan does not loop) and the daily
-- cap counts what was queued in the last 24 hours, completed jobs included.
CREATE TABLE IF NOT EXISTS scan_rescan_ledger (
    digest      TEXT NOT NULL,
    builds_key  TEXT NOT NULL,
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (digest, builds_key)
);

CREATE INDEX IF NOT EXISTS idx_scan_rescan_ledger_enqueued_at
    ON scan_rescan_ledger (enqueued_at);

-- The builds key whose selection last came back short, so an instance with
-- nothing stale does not re-run it until a database updates. One row.
CREATE TABLE IF NOT EXISTS scan_rescan_state (
    id             BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    exhausted_key  TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
