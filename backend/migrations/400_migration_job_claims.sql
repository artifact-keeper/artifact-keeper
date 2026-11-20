-- Migration job worker claims (#6253).
--
-- A migration job runs in a task on the replica that took `/start` or
-- `/resume`. When that replica died, the row stayed `running` with no worker
-- and `/resume` refused it. The worker now holds a claim on its row and renews
-- it while it runs, and a janitor pauses `running` rows whose claim lapsed, so
-- `/resume` picks them up again. Same shape as `repository_delete_jobs`.
ALTER TABLE migration_jobs
    ADD COLUMN IF NOT EXISTS claimed_by TEXT,
    ADD COLUMN IF NOT EXISTS claim_token UUID,
    ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;

-- Rows already `running` have no claim. A worker from before this migration
-- cannot renew one, so let the janitor pause them on its first pass.
UPDATE migration_jobs SET claim_expires_at = NOW() WHERE status = 'running';
