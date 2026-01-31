-- Network-aware sync scheduling profiles for edge nodes
-- Part of Borg Replication: Network-Aware Sync Scheduling

ALTER TABLE edge_nodes
    ADD COLUMN IF NOT EXISTS max_bandwidth_bps BIGINT,
    ADD COLUMN IF NOT EXISTS sync_window_start TIME,
    ADD COLUMN IF NOT EXISTS sync_window_end TIME,
    ADD COLUMN IF NOT EXISTS sync_window_timezone VARCHAR(50) DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS concurrent_transfers_limit INTEGER DEFAULT 4,
    ADD COLUMN IF NOT EXISTS active_transfers INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS backoff_until TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS bytes_transferred_total BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS transfer_failures_total INTEGER NOT NULL DEFAULT 0;

-- Index for scheduler: find nodes within their sync window and under transfer limit
CREATE INDEX IF NOT EXISTS idx_edge_nodes_schedulable
    ON edge_nodes (status, active_transfers, concurrent_transfers_limit)
    WHERE status IN ('online', 'syncing');
