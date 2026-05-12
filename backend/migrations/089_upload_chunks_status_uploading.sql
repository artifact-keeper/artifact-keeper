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
-- Drop and re-add the constraint with the full status set. We prefer the
-- Postgres default name (upload_chunks_status_check) which is stable across
-- versions; only when that exact name is absent do we fall back to a
-- definition-match search, and that search is constrained to constraint
-- definitions that reference the `status` column specifically (not just any
-- text containing "status") to avoid matching unrelated future constraints.
-- Also skip the work entirely when the existing constraint already accepts
-- `'uploading'` so reruns and pre-patched databases don't take an
-- ACCESS EXCLUSIVE lock for nothing.

DO $$
DECLARE
    chk_name text;
    chk_def  text;
BEGIN
    -- Pass 1: exact default name.
    SELECT con.conname, pg_get_constraintdef(con.oid)
      INTO chk_name, chk_def
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE rel.relname = 'upload_chunks'
      AND con.contype = 'c'
      AND con.conname = 'upload_chunks_status_check'
    LIMIT 1;

    -- Pass 2: any CHECK constraint on upload_chunks whose definition
    -- references the `status` column. LIMIT 1 + ORDER BY conname makes
    -- the choice deterministic if multiple candidates exist.
    IF chk_name IS NULL THEN
        SELECT con.conname, pg_get_constraintdef(con.oid)
          INTO chk_name, chk_def
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'upload_chunks'
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ~* '\mstatus\M'
        ORDER BY con.conname
        LIMIT 1;
    END IF;

    -- Skip the rewrite when the existing constraint already permits the
    -- four states we want. Avoids needless ACCESS EXCLUSIVE locking on
    -- hot upload_chunks tables when migration 089 is replayed.
    IF chk_name IS NOT NULL
       AND chk_def ILIKE '%pending%'
       AND chk_def ILIKE '%uploading%'
       AND chk_def ILIKE '%completed%'
       AND chk_def ILIKE '%failed%' THEN
        RETURN;
    END IF;

    IF chk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE upload_chunks DROP CONSTRAINT %I', chk_name);
    END IF;

    ALTER TABLE upload_chunks
        ADD CONSTRAINT upload_chunks_status_check
        CHECK (status IN ('pending','uploading','completed','failed'));
END $$;
