-- #5432: re-encode existing CEP-16 shards without the redundant `fn` record
-- field. Data only; no schema change.
--
-- Hosted channels: reset the per-channel backfill cursors so the existing
-- background backfill rebuilds every package name in bounded batches. Until
-- it finishes, a channel's shard endpoints use the per-request path, which
-- already writes the new records. Old addressed bodies are kept, so a client
-- holding an old shard address still gets a body that hashes to it.
--
-- Synthesised remote channels: mark every built subdir stale, so the next
-- request rebuilds it even when the upstream document has not changed.
--
-- On a database upgraded from 1.11.x both tables are empty (they first ship
-- in 1.12.0) and both statements update nothing.
--
-- Rollback: none needed; the rebuilt shards are what this release writes.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

UPDATE conda_channel_state
SET backfill_cursor = NULL, backfill_done_at = NULL, updated_at = NOW()
WHERE backfill_cursor IS NOT NULL OR backfill_done_at IS NOT NULL;

-- An unchanged upstream checksum must not keep old synthesized wire records.
UPDATE conda_synthesized_subdirs
SET stale_since = COALESCE(stale_since, NOW())
WHERE built_at IS NOT NULL;
