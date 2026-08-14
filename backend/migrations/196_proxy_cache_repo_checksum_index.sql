-- 196_proxy_cache_repo_checksum_index.sql
-- Proxy scan visibility (#3348): GET /api/v1/repositories/:key/security/proxy-scans
-- resolves a repository's cached paths and joins each `checksum_sha256` to
-- `proxy_scan_results` to report a verdict. The summary aggregate scans every
-- catalog row for the repository (`WHERE repository_id = $1 AND
-- checksum_sha256 IS NOT NULL`) and needs the checksum for the join key.
-- `idx_proxy_cache_repo` (repository_id only) does not cover checksum, so the
-- planner falls back to a heap fetch per row. This composite index lets the
-- summary aggregate run as an index-only scan.
CREATE INDEX idx_proxy_cache_repo_checksum
    ON proxy_cache_artifacts (repository_id, checksum_sha256);
