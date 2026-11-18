-- Monthly download transfer counter for the instance transfer quota
-- (`TRANSFER_QUOTA_BYTES`).
--
-- One row per calendar month (UTC), keyed by the first day of the month.
-- Every replica counts the artifact download bytes it sends in memory and
-- adds them here every few seconds with an upsert that returns the month's
-- total, so all replicas and restarts share one counter.
CREATE TABLE IF NOT EXISTS transfer_quota_usage (
    period_start DATE PRIMARY KEY,
    bytes BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
