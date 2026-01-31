-- Network-aware sync scheduling profiles for edge nodes
-- Part of Borg Replication: Network-Aware Sync Scheduling

ALTER TABLE edge_nodes
    ADD COLUMN max_bandwidth_bps BIGINT,                -- throttle transfers (NULL = unlimited)
    ADD COLUMN sync_window_start TIME,                  -- daily sync window start (NULL = anytime)
    ADD COLUMN sync_window_end TIME,                    -- daily sync window end
    ADD COLUMN sync_window_timezone VARCHAR(50) DEFAULT 'UTC',
    ADD COLUMN concurrent_transfers_limit INTEGER DEFAULT 4,
    ADD COLUMN active_transfers INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN backoff_until TIMESTAMP WITH TIME ZONE,  -- exponential backoff after failures
    ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN bytes_transferred_total BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN transfer_failures_total INTEGER NOT NULL DEFAULT 0;

-- Index for scheduler: find nodes within their sync window and under transfer limit
CREATE INDEX idx_edge_nodes_schedulable
    ON edge_nodes (status, active_transfers, concurrent_transfers_limit)
    WHERE status IN ('online', 'syncing');
