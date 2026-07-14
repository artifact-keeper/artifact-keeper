-- 159_proxy_cache_catalog.sql
-- Persisted catalog of proxy-cached objects (#2218 accounting, #2270 visibility).
--
-- SEPARATE table from `artifacts` on purpose: the format-handler serve path
-- never reads it, so this cannot re-open the #1278/#1280 doubled-prefix 500
-- (a proxy `artifacts` row carried a `proxy-cache/<repo>/<path>/__content__`
-- storage_key that the per-repo backend re-prefixed on every cache hit). One
-- row per logical cached object; upserted at sidecar-commit time inside
-- `CachePersister::{tee_stream,write_buffered}` with the TRUE written byte
-- count + checksum, and deleted on invalidate.
CREATE TABLE proxy_cache_artifacts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id    UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path             TEXT NOT NULL,               -- logical path, e.g. simple/click/click-8.0.0-py3-none-any.whl
    storage_key      TEXT NOT NULL,               -- proxy-cache/<repo>/<path>/__content__
    metadata_key     TEXT NOT NULL,               -- proxy-cache/<repo>/<path>/__cache_meta__.json
    size_bytes       BIGINT NOT NULL,
    checksum_sha256  TEXT,                         -- NULL only for a transient row awaiting refresh
    content_type     TEXT,
    upstream_url     TEXT,                         -- URL fetched from upstream (nullable; not always known)
    cached_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_accessed_at TIMESTAMPTZ,                  -- bumped by lazy-backfill / serve (PF-002 lifecycle seam)
    CONSTRAINT uq_proxy_cache_repo_path UNIQUE (repository_id, path)
);

-- Accounting SUM (#2218): GROUP BY repository_id.
CREATE INDEX idx_proxy_cache_repo ON proxy_cache_artifacts (repository_id);

-- Deletes on invalidate resolve by the physical content storage key.
CREATE INDEX idx_proxy_cache_storage_key ON proxy_cache_artifacts (storage_key);
