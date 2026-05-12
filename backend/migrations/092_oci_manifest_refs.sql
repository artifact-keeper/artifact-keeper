-- OCI multi-arch image-index child reference tracking (artifact-keeper#1179).
--
-- An OCI image index (content-type
-- `application/vnd.oci.image.index.v1+json` or the Docker equivalent
-- `application/vnd.docker.distribution.manifest.list.v2+json`) is a
-- manifest that points at one per-architecture child manifest per
-- supported platform. Only the index digest is recorded in `oci_tags`;
-- the children are stored as their own `oci-manifests/<digest>` storage
-- keys with their own (typically soft-deleted) `artifacts` rows.
--
-- Migration 086 (and earlier review work on #1144) added orphan-protection
-- NOT EXISTS guards to the storage GC against `oci_tags` and `oci_blobs`,
-- but those guards only protect digests that appear directly in `oci_tags`.
-- The per-architecture child digests inside an image index do not appear
-- in `oci_tags`, so the GC was free to delete them while the parent index
-- was still in use. Pulling the multi-arch image by digest after such a GC
-- pass returned `MANIFEST_UNKNOWN` for the platform-specific layers.
--
-- This table records, for each multi-arch image index that has been pushed
-- through this registry, the (parent_digest -> child_digest) edges. The
-- storage GC adds a fourth NOT EXISTS clause joining
-- `oci_manifest_refs` -> `oci_tags` so that a child manifest digest is
-- protected as long as its parent index is still tagged in the same repo.
--
-- When the parent's tag is overwritten or deleted, the join finds no row
-- and the children become eligible for collection in the normal flow.
--
-- The rows are written at manifest-PUT time by the OCI v2 handler. A
-- one-shot startup backfill walks existing index-typed `oci_tags` rows
-- that lack any `oci_manifest_refs` entries, loads each manifest from
-- storage, parses the JSON, and inserts the edges. Both writers use
-- `ON CONFLICT DO NOTHING` so the table is safe to populate from either
-- source repeatedly.

CREATE TABLE oci_manifest_refs (
    parent_digest TEXT NOT NULL,
    child_digest TEXT NOT NULL,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (parent_digest, child_digest, repository_id)
);

-- The GC NOT EXISTS clause keys lookups by child_digest; that path needs
-- its own index because the primary key leads with parent_digest.
CREATE INDEX idx_oci_manifest_refs_child ON oci_manifest_refs(child_digest);

-- Reverse-direction lookups (e.g. "given an index digest, list its
-- children") use the leading column of the PK directly, so no extra
-- index is required.
