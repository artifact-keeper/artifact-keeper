-- Durable curation-sync bookkeeping.
--
-- The curation scheduler re-fetched upstream metadata for every enabled
-- staging repo on every 5-minute tick, on every replica: the configured
-- curation_sync_interval_secs was read but never honored, and there was no
-- record of when a repo last synced. Together with the existing curation_sync
-- scheduler lease, this column makes the sync respect the configured
-- interval and stop multiplying upstream fetches by replica count.
ALTER TABLE repositories
    ADD COLUMN curation_last_synced_at TIMESTAMPTZ;

COMMENT ON COLUMN repositories.curation_last_synced_at IS
    'When curation upstream metadata last synced successfully; NULL = never';
