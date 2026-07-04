-- Atomic multi-replica claims for sync_tasks (RowClaimedQueue pattern).
--
-- The sync worker used to SELECT pending tasks and only afterwards mark them
-- in_progress with an unconditional UPDATE, so two replicas ticking in the
-- same window could both execute the same peer push/delete. Tasks are now
-- claimed with a FOR UPDATE SKIP LOCKED CTE that flips pending->in_progress
-- and stamps these columns in the same statement; success/failure updates
-- must present the claim_token.
ALTER TABLE sync_tasks
    ADD COLUMN claimed_by TEXT,
    ADD COLUMN claim_token UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ;

COMMENT ON COLUMN sync_tasks.claimed_by IS
    'Diagnostic worker identity that claimed the task; not the correctness guard';
COMMENT ON COLUMN sync_tasks.claim_token IS
    'Random per-claim token; finalizers must match it';
COMMENT ON COLUMN sync_tasks.claim_expires_at IS
    'Claim lease deadline; expired in_progress tasks are reset to pending';

-- Existing in_progress rows were started by pre-claim code and cannot present a
-- token-fenced finalizer. Mark them as expired claims so the recovery sweep can
-- reset them instead of letting them count as live peer capacity forever.
UPDATE sync_tasks
SET claimed_by = COALESCE(claimed_by, 'migration-144-legacy-in-progress'),
    claim_token = COALESCE(claim_token, gen_random_uuid()),
    claim_expires_at = COALESCE(claim_expires_at, NOW() - INTERVAL '1 second')
WHERE status = 'in_progress'
  AND (claimed_by IS NULL OR claim_token IS NULL OR claim_expires_at IS NULL);

-- Claim selection: due pending tasks per peer in priority order.
CREATE INDEX idx_sync_tasks_pending_claim
    ON sync_tasks (peer_instance_id, priority DESC, created_at)
    WHERE status = 'pending';

-- Expired-claim recovery sweep over in-flight tasks.
CREATE INDEX idx_sync_tasks_claim_expiry
    ON sync_tasks (claim_expires_at)
    WHERE status = 'in_progress';
