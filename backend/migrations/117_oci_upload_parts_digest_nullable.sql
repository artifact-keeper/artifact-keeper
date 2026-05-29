-- Allow oci_upload_parts.digest_sha256 to be NULL.
--
-- Migration 115 created this column as TEXT NOT NULL. The legacy-backfill first
-- part is synthesized for sessions created before per-part rows existed, and it
-- has no honest per-part digest to record. It was previously inserted with an
-- empty-string '' sentinel, which is a dishonest invariant: '' is not a real
-- SHA-256. Dropping NOT NULL lets the backfill part store NULL instead.
--
-- This lives in a SEPARATE migration (not an edit to 115) on purpose. Migrations
-- run via sqlx::migrate!("./migrations").run(), which enforces per-migration
-- checksums. 114/115/116/117/118 ship together in this change, but once applied to
-- any dev/CI/prod database they become append-only: editing 115 in place
-- afterward would change its checksum and break startup with a checksum mismatch
-- on every database that already ran it. A new migration sidesteps that.
-- (migration_repair.rs only repairs the legacy slots 73-75, not these.)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = 'oci_upload_parts'::regclass
          AND attname = 'digest_sha256'
          AND attnotnull
    ) THEN
        ALTER TABLE oci_upload_parts
            ALTER COLUMN digest_sha256 DROP NOT NULL;
    END IF;
END $$;

-- Backfill: convert any pre-existing '' sentinel digests to honest NULLs so the
-- column's invariant holds for old rows too (new code already writes NULL). A
-- no-op on a fresh database where no '' rows exist.
UPDATE oci_upload_parts SET digest_sha256 = NULL WHERE digest_sha256 = '';
