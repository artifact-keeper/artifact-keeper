-- Relax the upload_chunks.status CHECK to include 'uploading'.
--
-- Migration 072 created the table with
--   CHECK (status IN ('pending','completed','failed'))
-- but the chunked-upload service path in services/upload_service.rs
-- atomically transitions chunks from 'pending' -> 'uploading' as a claim
-- before writing data, then sets 'completed' or 'failed' after the write.
-- The 'uploading' value was never in the CHECK list, so the first PATCH
-- against a chunk would always abort with
--   ERROR: new row for relation "upload_chunks" violates check constraint
-- and the browser would surface this as "Upload big file failed because
-- of database table error" (issue #1168).
--
-- Drop and re-add the constraint with the full status set. The constraint
-- name (upload_chunks_status_check) is the Postgres default and stable
-- across versions, but we look it up via pg_constraint just in case a
-- prior fix migrated it under a different name.

DO $$
DECLARE
    chk_name text;
BEGIN
    SELECT con.conname INTO chk_name
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE rel.relname = 'upload_chunks'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%status%';

    IF chk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE upload_chunks DROP CONSTRAINT %I', chk_name);
    END IF;
END $$;

ALTER TABLE upload_chunks
    ADD CONSTRAINT upload_chunks_status_check
    CHECK (status IN ('pending','uploading','completed','failed'));
