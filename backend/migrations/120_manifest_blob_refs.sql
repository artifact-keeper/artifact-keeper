-- OCI manifest -> blob reference tracking (artifact-keeper#1635).
--
-- GC prerequisite for #1408 / #1610. Today there is no manifest->blob
-- reference table, so nothing can safely judge an `oci_blobs` row
-- orphaned: a prior per-`(repo,digest)` heuristic already broke 57
-- production blobs. Blob deletion MUST NOT ship until these edges exist.
--
-- A regular OCI/Docker *image* manifest (content-type
-- `application/vnd.oci.image.manifest.v1+json` or the Docker equivalent
-- `application/vnd.docker.distribution.manifest.v2+json`) references the
-- blobs that make up the image: a single `config` blob plus one
-- `layers[]` blob per layer. Those layer/config digests live in
-- `oci_blobs` (storage key `oci-blobs/<digest>`) but nothing currently
-- records *which* manifest pulled them in, so the storage GC has no safe
-- reverse lookup from a blob digest back to the manifests that need it.
--
-- This table records, for every image manifest pushed through (or
-- backfilled into) this registry, the (manifest_digest -> blob_digest)
-- edges, scoped per repository. `kind` distinguishes the config blob
-- ('config') from layer blobs ('layer') for diagnostics; it is not part
-- of the primary key because a blob digest can only play one role within
-- a given manifest.
--
-- Image *index* manifests (a.k.a. manifest lists,
-- `application/vnd.oci.image.index.v1+json` /
-- `application/vnd.docker.distribution.manifest.list.v2+json`) carry no
-- blobs of their own -- they reference per-architecture child manifests,
-- which are tracked separately in `oci_manifest_refs` (#1179). No rows
-- are written here for index manifests.
--
-- Rows are written at manifest-PUT time by the OCI v2 handler. A
-- one-shot startup backfill walks image manifests reachable via
-- `oci_tags` / `oci_manifest_refs.child_digest` that have zero rows
-- here, loads each manifest body from storage, parses it, and inserts the
-- edges. Both writers use `ON CONFLICT DO NOTHING` so the table is safe
-- to populate from either source repeatedly.
--
-- ADDITIVE ONLY: this migration and its writers make blob references
-- KNOWABLE. No deletion logic of any kind is added by #1635.

CREATE TABLE manifest_blob_refs (
    manifest_digest TEXT NOT NULL,
    blob_digest TEXT NOT NULL,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (manifest_digest, blob_digest, repository_id)
);

-- The GC reverse-lookup hot path keys on blob_digest ("given a blob, is
-- any manifest still referencing it?"). The primary key leads with
-- manifest_digest, so that lookup needs its own index.
CREATE INDEX idx_manifest_blob_refs_blob ON manifest_blob_refs(blob_digest);
