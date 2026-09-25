-- Deterministic UI listing id for proxy-cache rows (same algorithm as
-- `scan_eligibility::proxy_cache_listing_id`: first 16 bytes of
-- SHA-256("proxy-cache/<repo_key>/<path>") interpreted as a UUID).
-- Enables O(1) Scan/SBOM materialize without a full-catalog scan.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE proxy_cache_artifacts
    ADD COLUMN IF NOT EXISTS listing_id UUID;

-- Backfill existing rows from repository key + path.
UPDATE proxy_cache_artifacts pca
SET listing_id = (
    SELECT (
        substr(h, 1, 8) || '-' ||
        substr(h, 9, 4) || '-' ||
        substr(h, 13, 4) || '-' ||
        substr(h, 17, 4) || '-' ||
        substr(h, 21, 12)
    )::uuid
    FROM repositories r,
    LATERAL (
        SELECT encode(
            substring(digest('proxy-cache/' || r.key || '/' || pca.path, 'sha256') FROM 1 FOR 16),
            'hex'
        ) AS h
    ) d
    WHERE r.id = pca.repository_id
)
WHERE pca.listing_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_cache_artifacts_listing_id
    ON proxy_cache_artifacts (listing_id)
    WHERE listing_id IS NOT NULL;
