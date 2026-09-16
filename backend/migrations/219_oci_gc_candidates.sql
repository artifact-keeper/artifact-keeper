-- Durable GC-candidate set for committed OCI objects (#3733).
--
-- Deleting a repository intentionally leaves `oci-manifests/<digest>` and
-- `oci-blobs/<digest>` objects on the backend: they are content-addressed and
-- can be shared cross-repo through `oci_tags` / `oci_manifest_refs` /
-- `oci_blobs` / `manifest_blob_refs`, so the artifacts-only exclusivity guard
-- in the delete purge cannot prove any of them unreferenced (#1598). The
-- delete then CASCADEs away exactly the rows Storage GC and Blob GC start
-- their candidate scans from -- `artifacts` for manifests, `oci_blobs` for
-- blobs -- so an object that WAS this repository's alone becomes undiscoverable
-- and leaks forever.
--
-- This table is the missing hand-off. The delete path records the repository's
-- committed OCI object keys here BEFORE the cascade, and the storage-GC sweep
-- (`cleanup_oci_gc_candidates`) later re-tests each recorded key against every
-- surviving repository's reference tables: still referenced => the row is
-- simply dropped and the object left alone; referenced by nothing => the object
-- is deleted and the row dropped. Either way the row does not survive its
-- sweep, so the set stays small and the sweep is idempotent.
--
-- `storage_path` is the location scope, and is only meaningful on
-- `filesystem`, where every repository roots its own tree and the same key is a
-- DISTINCT file per repository. Cloud backends (S3/GCS/Azure) share one flat
-- keyspace, so their rows store '' and the sweep's predicate matches on
-- `storage_backend` alone -- the same cloud/filesystem split the GC's
-- `ORPHAN_PREDICATE_SQL` and `BLOB_PROTECTED_BY_REFS_SQL` already apply.
--
-- `source_repository_id` is diagnostics only and carries NO foreign key: the
-- repository it names is deleted moments after the row is written, which is the
-- entire point of the row existing.
--
-- `IF NOT EXISTS` throughout so the migration is idempotent on a database that
-- already carries the table from an out-of-tree build.

CREATE TABLE IF NOT EXISTS oci_gc_candidates (
    id                   BIGSERIAL PRIMARY KEY,
    storage_key          TEXT NOT NULL,
    storage_backend      TEXT NOT NULL,
    storage_path         TEXT NOT NULL DEFAULT '',
    source_repository_id UUID,
    recorded_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The recording INSERT upserts on this key, so a repeated delete of the same
-- object (two repositories sharing a digest, or a retried delete) adds no
-- duplicate work. It leads with the location scope because that is what the
-- sweep's per-object lookup binds.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oci_gc_candidates_object
    ON oci_gc_candidates (storage_backend, storage_path, storage_key);

-- The sweep scans oldest-first past a grace window, so it reads this column
-- before it reads anything else.
CREATE INDEX IF NOT EXISTS idx_oci_gc_candidates_recorded_at
    ON oci_gc_candidates (recorded_at);

COMMENT ON TABLE oci_gc_candidates IS
    'Committed OCI object keys recorded at repository-delete time so storage GC can still discover them after the reference rows CASCADE away (#3733). Rows are consumed by the sweep, not retained.';
COMMENT ON COLUMN oci_gc_candidates.storage_path IS
    'Location scope; only meaningful on filesystem (per-repository trees). Cloud backends share one keyspace and store ''''.';
COMMENT ON COLUMN oci_gc_candidates.source_repository_id IS
    'Diagnostics only; intentionally no FK -- the repository is deleted immediately after the row is written.';
