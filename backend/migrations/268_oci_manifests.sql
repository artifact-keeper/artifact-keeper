-- First-class OCI manifest existence registry, first slice of #1683 (#4433).
--
-- Until now the registry had no record of a manifest as such: existence and
-- media type were derived from `oci_tags` (plus the `oci_manifest_refs`
-- children of a tagged index), so a manifest whose last tag was gone became
-- invisible even though its bytes were still in storage (#1681, #1642).
--
-- One row per (repository, manifest digest), independent of any tag:
--   content_type        the stored media type (content-classified at PUT,
--                       the same value written to `oci_tags`)
--   size_bytes          length of the manifest body
--   subject_digest      the manifest's OCI 1.1 `subject.digest`, if any
--   created_at          when the registry first committed the manifest
--   last_referenced_at  refreshed whenever a push/cache commits it again
--
-- This slice is write-only. `persist_tag_and_refs_in_tx` upserts the row in
-- the same transaction as the `oci_tags` row (push, proxy cache, migration
-- import), a delete by digest removes it once no tag and no parent index edge
-- still holds the manifest, and a background startup backfill
-- (`services::oci_manifests`) fills rows for manifests committed before this
-- migration. Nothing reads the table yet; switching GET/HEAD/
-- DELETE, referrers and the storage-GC orphan predicate to it is a later
-- slice, as are FKs from `oci_tags` / `oci_manifest_refs` /
-- `manifest_blob_refs`.
--
-- Online shape: purely additive. The table is new and empty, so its primary
-- key and index cost nothing to build (migration_safety skips tables created
-- in the same file). The only lock on an existing table is the brief
-- SHARE ROW EXCLUSIVE the foreign key takes on `repositories` (a
-- configuration-sized table) to install its trigger; the lock timeout makes a
-- rolling upgrade fail fast and retry on the next start instead of queueing
-- behind an old replica's open transaction. The backfill is application-side,
-- not here, so the migration does no data movement.

SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS oci_manifests (
    repository_id      UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    digest             TEXT        NOT NULL,
    content_type       TEXT        NOT NULL,
    size_bytes         BIGINT      NOT NULL CHECK (size_bytes >= 0),
    subject_digest     TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, digest)
);

-- Referrers lookup ("every manifest in <repo> whose subject is <digest>") for
-- the slice that moves the Referrers API onto this table. Partial: most
-- manifests carry no subject.
CREATE INDEX IF NOT EXISTS idx_oci_manifests_subject
    ON oci_manifests (repository_id, subject_digest)
    WHERE subject_digest IS NOT NULL;
