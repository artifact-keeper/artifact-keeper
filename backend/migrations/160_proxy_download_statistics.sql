-- 160_proxy_download_statistics.sql
-- Sibling of `download_statistics` for proxy-served downloads (#2270 / #2260).
--
-- Kept SEPARATE so the hot `download_statistics` INSERT + its NOT NULL
-- `artifact_id` FK stay untouched (#2505 "exactly one download_statistics
-- INSERT for a hosted serve" invariant preserved). Proxy-cache serves have no
-- `artifacts` row, so they were previously gated out of counting; the new
-- `proxy_cache_artifacts` catalog supplies a stable id to key against here.
CREATE TABLE proxy_download_statistics (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_cache_id UUID NOT NULL REFERENCES proxy_cache_artifacts(id) ON DELETE CASCADE,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address     TEXT,
    user_agent     TEXT,
    downloaded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_proxy_dl_stats_cache ON proxy_download_statistics (proxy_cache_id, downloaded_at);
CREATE INDEX idx_proxy_dl_stats_user  ON proxy_download_statistics (user_id, downloaded_at);
