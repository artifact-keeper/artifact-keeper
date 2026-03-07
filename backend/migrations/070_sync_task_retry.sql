-- Add retry support to sync_tasks.
-- Failed tasks with retry_count < max_retries are automatically reset to
-- 'pending' when the target peer comes back online (backoff expires).

ALTER TABLE sync_tasks
    ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3;

-- Index for finding retriable failed tasks per peer.
CREATE INDEX idx_sync_tasks_retriable
    ON sync_tasks (peer_instance_id, status)
    WHERE status = 'failed';
