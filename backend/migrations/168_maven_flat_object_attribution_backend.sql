-- Qualify Maven flat-key attribution by storage backend (#2671).
--
-- Migration 163 keyed `maven_flat_object_owner` on `storage_key` alone. That is
-- correct only for a single-backend deployment. In a MIXED-backend deployment
-- (e.g. repo A on `s3`, repo B on `gcs`) the same Maven GAV maps to the same
-- flat `maven/{path}` storage-key *string* but to two PHYSICALLY DISTINCT
-- objects living in two different clouds. Under a `storage_key`-only primary key
-- both owners collide onto a single row, so the attribution resolver sees
-- COUNT(DISTINCT repository_id) = 2, treats the key as ambiguous, and leaves it
-- UNATTRIBUTED -- which fails closed for BOTH tenants: each gets 404 reading its
-- own object and 403 writing it. This is an availability bug (no cross-tenant
-- data exposure), but it takes both tenants' legitimate objects offline.
--
-- The physical object identity is (storage_backend, storage_key), so the
-- attribution must be qualified by backend too. This migration adds a
-- `storage_backend` column and moves the primary key to
-- (storage_backend, storage_key). Objects on different backends no longer
-- collide, while two repositories that genuinely share one physical namespace
-- (same backend, same key) remain ambiguous and fail-closed as before.
--
-- Additive + replay-safe:
--   * ADD COLUMN IF NOT EXISTS, so re-running is a no-op.
--   * Existing rows are backfilled with their owning repository's *actual*
--     backend, read from `repositories.storage_backend` via the row's
--     repository_id FK (every row references a live repository -- the FK is
--     ON DELETE CASCADE -- so the value is always available and exact). Any
--     residual NULL (defensive; should not occur under the FK) defaults to
--     'filesystem', which matches the historical single-filesystem default and
--     keeps existing single-backend deployments serving their attributed keys.
--   * The primary-key swap is wrapped in an idempotent DO block guarded on
--     pg_constraint, so a replay neither errors nor drops the new PK.

-- 1) Add the backend column (nullable first so the backfill can populate it).
ALTER TABLE maven_flat_object_owner
    ADD COLUMN IF NOT EXISTS storage_backend TEXT;

-- 2) Backfill each row with its owning repository's real backend.
UPDATE maven_flat_object_owner o
SET storage_backend = r.storage_backend
FROM repositories r
WHERE r.id = o.repository_id
  AND o.storage_backend IS NULL;

-- 3) Defensive default for any row we could not attribute a backend to.
UPDATE maven_flat_object_owner
SET storage_backend = 'filesystem'
WHERE storage_backend IS NULL;

-- 4) Enforce NOT NULL now that every row carries a backend.
ALTER TABLE maven_flat_object_owner
    ALTER COLUMN storage_backend SET NOT NULL;

-- 5) Move the primary key from (storage_key) to (storage_backend, storage_key),
--    idempotently and replay-safe.
DO $$
DECLARE
    existing_pk text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'maven_flat_object_owner'::regclass
          AND contype = 'p'
          AND conname = 'maven_flat_object_owner_backend_key_pkey'
    ) THEN
        SELECT conname INTO existing_pk
        FROM pg_constraint
        WHERE conrelid = 'maven_flat_object_owner'::regclass
          AND contype = 'p';
        IF existing_pk IS NOT NULL THEN
            EXECUTE format(
                'ALTER TABLE maven_flat_object_owner DROP CONSTRAINT %I',
                existing_pk
            );
        END IF;
        ALTER TABLE maven_flat_object_owner
            ADD CONSTRAINT maven_flat_object_owner_backend_key_pkey
            PRIMARY KEY (storage_backend, storage_key);
    END IF;
END $$;
