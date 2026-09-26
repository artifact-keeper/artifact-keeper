-- Scope the OCI upload cleanup journal to (repository, storage key) (#3851).
--
-- Migration 116 made `oci_upload_cleanup_keys.storage_key` UNIQUE across the
-- whole database. Final blob keys (`oci-blobs/<digest>`) are content
-- addressed, so two concurrent pushes of one digest to DIFFERENT repositories
-- registered the same journal row. The first to commit deleted it inside its
-- `oci_blobs` transaction; the other then found its row gone and had to prove
-- a peer push won by finding the winner's `oci_blobs` row. If the winner's
-- repository was deleted in that window the proof was gone too, and a valid
-- `docker push` got `503 BLOB_UPLOAD_INVALID`. The row also recorded only the
-- first registrant's repository, so the "was my repository deleted?" check
-- tested the wrong repository.
--
-- Rows are now unique per (repository_id, storage_key): a push can only have
-- its row removed by a push to the SAME repository (whose proof row lives in
-- that same repository), by a cleanup sweep, or by its own repository's
-- deletion. The number of rows stays bounded by concurrent/abandoned pushes
-- per repository, and every row is still reaped by the existing sweeps.
--
-- Where repositories share one physical object namespace (cloud backends),
-- several rows can now name one object. The sweep side refuses to delete an
-- object while another repository holds a fresh, non-tombstoned row for it,
-- and registration and the sweep's tombstone serialize per key on a
-- transaction-scoped advisory lock (see `storage_gc_service`).
-- Drop the single-column UNIQUE(storage_key) whatever it is named (the
-- Postgres default is `oci_upload_cleanup_keys_storage_key_key`).
DO $$
DECLARE
    con RECORD;
BEGIN
    FOR con IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class rel ON rel.oid = c.conrelid
        JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum = ANY (c.conkey)
        WHERE rel.relname = 'oci_upload_cleanup_keys'
          AND c.contype = 'u'
          AND array_length(c.conkey, 1) = 1
          AND a.attname = 'storage_key'
    LOOP
        EXECUTE format('ALTER TABLE oci_upload_cleanup_keys DROP CONSTRAINT %I', con.conname);
    END LOOP;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_oci_upload_cleanup_keys_repo_key
    ON oci_upload_cleanup_keys (repository_id, storage_key);

-- The dropped constraint's index served every `WHERE storage_key = $1`
-- lookup (liveness checks, sibling checks); keep one.
CREATE INDEX IF NOT EXISTS idx_oci_upload_cleanup_keys_storage_key
    ON oci_upload_cleanup_keys (storage_key);
