-- Drop the deprecated notification_subscriptions table (artifact-keeper#920).
--
-- This table backed "System B", the original notification subscriptions
-- introduced in migration 078. The v1.1.9 release shipped the dedicated
-- webhook system (System A, the `webhooks` + `webhook_deliveries` tables),
-- migrated webhook-channel rows over via migration 081, and seeded the
-- dedicated email_subscriptions table from email-channel rows via
-- migration 082. The notifications API and the notification_dispatcher
-- service stayed live through v1.1.x with RFC 8594 deprecation headers
-- and a fixed 2026-08-01 sunset date so customers had a full release cycle
-- to migrate.
--
-- v1.2.0 closes the deprecation window. The Rust code that reads from this
-- table is removed in the same commit; once both land, this DROP is safe.
--
-- Idempotency: DROP TABLE IF EXISTS, and the UPDATE below is gated on the
-- table's existence, so re-running on a fresh DB is a no-op.

-- ---------------------------------------------------------------------------
-- Pre-DROP secret wipe (#920 security review H1)
-- ---------------------------------------------------------------------------
-- The `config` JSONB column historically stored plaintext webhook secrets
-- under `config.secret` for channel='webhook' rows. Migration 081 already
-- copied these into the encrypted `webhooks.secret_ciphertext` column, so
-- the plaintext copy is redundant by the time this migration runs.
--
-- A bare DROP TABLE only deallocates pages; the secret bytes remain on
-- disk in dead tuples and any base backups taken before this migration.
-- We overwrite every row's `config` with an empty JSON object before the
-- DROP so the live row no longer carries plaintext when the DROP happens.
--
-- This UPDATE is transaction-safe and runs inside the migration's wrapping
-- BEGIN/COMMIT. To complete the wipe (so dead tuples are reclaimed and the
-- table file shrinks), operators MUST run `VACUUM FULL notification_subscriptions`
-- after the UPDATE and BEFORE the DROP in the same maintenance window.
-- VACUUM FULL cannot run inside a transaction, so it cannot be folded
-- into this file; the v1.2.0 release notes / upgrade runbook document the
-- VACUUM step.
--
-- Operators with PCI-DSS / HIPAA requirements should additionally rotate
-- every webhook secret that ever lived in this table, since base backups
-- and WAL archives taken before this migration may still contain the
-- plaintext bytes.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_tables
        WHERE schemaname = current_schema()
          AND tablename = 'notification_subscriptions'
    ) THEN
        EXECUTE 'UPDATE notification_subscriptions SET config = ''{}''::jsonb WHERE config IS DISTINCT FROM ''{}''::jsonb';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- DROP
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS notification_subscriptions;
