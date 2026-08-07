-- Completion lease for generic chunked upload sessions (StateMachineLease).
--
-- complete_session used to flip the session straight to 'completed' before
-- the handler streamed the temp file to final storage and upserted the
-- artifact, so duplicate complete requests (possibly routed to different
-- replicas) could both checksum/copy/upsert — and a failed storage copy left
-- the session marked 'completed' with no artifact and no way to retry.
--
-- Port the OCI completion-lease shape: complete atomically transitions
-- pending/in_progress -> 'committing' with a fresh state_token; checksum,
-- storage copy, and artifact upsert run only under that lease; the terminal
-- 'completed'/'failed' transition requires the token. A committing lease
-- older than committing_expires_at (6h, matching OCI's staleness window) is
-- reclaimable, so a crashed commit does not wedge the session.
ALTER TABLE upload_sessions
    ADD COLUMN state_token UUID,
    ADD COLUMN committing_expires_at TIMESTAMPTZ;

ALTER TABLE upload_sessions
    DROP CONSTRAINT IF EXISTS upload_sessions_status_check;
ALTER TABLE upload_sessions
    ADD CONSTRAINT upload_sessions_status_check
    CHECK (status IN ('pending', 'in_progress', 'committing', 'completed', 'failed', 'cancelled'));

COMMENT ON COLUMN upload_sessions.state_token IS
    'Random completion-lease token; terminal status transitions must match it';
COMMENT ON COLUMN upload_sessions.committing_expires_at IS
    'Committing-lease deadline; an expired lease is reclaimable by a new complete request';
