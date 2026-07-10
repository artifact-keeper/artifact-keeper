-- #2365: per-download IP + user telemetry.
-- Downloads are now attributed to the real client IP (trusted-proxy-aware)
-- instead of the historical '0.0.0.0' sentinel. Index the IP dimension so the
-- admin reporting endpoints (downloads by IP / network-topology views) don't
-- sequential-scan download_statistics.
CREATE INDEX idx_download_stats_ip ON download_statistics(ip_address, downloaded_at);
