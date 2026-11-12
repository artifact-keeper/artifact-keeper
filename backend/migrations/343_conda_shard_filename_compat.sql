-- Re-encode existing shards without the redundant `fn` record field.
-- Reset only the per-channel cursors; the existing background backfill
-- rebuilds package names in bounded batches. Readers use the compatible
-- per-request path until that backfill completes. Keep old addressed bodies.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

UPDATE conda_channel_state
SET backfill_cursor = NULL, backfill_done_at = NULL, updated_at = NOW()
WHERE backfill_cursor IS NOT NULL OR backfill_done_at IS NOT NULL;

-- An unchanged upstream checksum must not keep old synthesized wire records.
UPDATE conda_synthesized_subdirs
SET stale_since = COALESCE(stale_since, NOW())
WHERE built_at IS NOT NULL;
