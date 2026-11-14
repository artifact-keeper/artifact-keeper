-- #5946: hosted uploads and pushed OCI images as scan_queue jobs.
--
-- `hosted_upload`: a scan_on_upload for one artifact row, run exactly as the
-- in-process trigger runs it (no pre-allocated placeholders). One job per
-- artifact, through uq_scan_queue_artifact_active.
--
-- `hosted_image`: a pushed OCI manifest, keyed by repository and manifest
-- digest (the artifacts.checksum_sha256 hex). One job per (repository, digest);
-- the worker scans every manifest row in that repository with that digest.
--
-- `requeue`: set when an enqueue lands on a RUNNING job of these kinds. The
-- worker already read what it scans, so instead of being dropped the request
-- sends the job back to `pending` when it completes.

ALTER TABLE scan_queue DROP CONSTRAINT IF EXISTS scan_queue_kind_check;
ALTER TABLE scan_queue ADD CONSTRAINT scan_queue_kind_check
    CHECK (kind IN ('proxy_file', 'hosted_artifact', 'hosted_upload', 'hosted_image'));

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
);

ALTER TABLE scan_queue ADD COLUMN IF NOT EXISTS requeue BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN scan_queue.requeue IS
    'An enqueue arrived while the job was running; completing it returns it to pending';

-- The digest dedup is fleet-wide per kind. A pushed image is per repository,
-- so `hosted_image` leaves this index for its own below.
DROP INDEX IF EXISTS uq_scan_queue_digest_active;
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_queue_digest_active
    ON scan_queue (kind, digest)
    WHERE state IN ('pending', 'running') AND digest IS NOT NULL
      AND kind <> 'hosted_image';

CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_queue_hosted_image_active
    ON scan_queue (repository_id, digest)
    WHERE kind = 'hosted_image' AND state IN ('pending', 'running');
