-- Per-image OCI content links (#5793).
--
-- In the OCI Distribution Spec `<name>` is `<repository key>/<image>`, and a
-- manifest or blob digest resolves only under the `<name>` that holds it.
-- Until now a hosted repository resolved a digest repository-wide: every
-- per-digest table (`oci_manifests`, `oci_blobs`, `manifest_blob_refs`, the
-- index edges) has no image column, so a digest answered under any image name
-- in the repository, including one that was never pushed. These tables record
-- which image names hold which digests:
--
--   oci_image_manifests   a manifest committed under an image (a tag or a
--                         by-digest push, the children of an index pushed
--                         under it, a promotion, a migration import). It
--                         survives a tag overwrite, so the old digest of an
--                         overwritten tag stays pullable under its own image
--                         (#1681). `image = ''` is the legacy marker the
--                         one-time backfill writes for a manifest it cannot
--                         attribute to any image (an overwrite from before
--                         this migration); nothing else writes it.
--   oci_image_blobs       a blob uploaded or mounted under an image. A blob
--                         referenced by a manifest the image holds resolves
--                         without a row, so replication, promotion and
--                         migration need not write one.
--   oci_image_scope_backfill
--                         repositories whose existing content the backfill
--                         has attributed. Until a repository has a row the
--                         reads keep the old repository-wide rule, so the
--                         upgrade never answers 404 for content that has not
--                         been backfilled yet.
--
-- The links reference the repository-wide rows with ON DELETE CASCADE, so a
-- manifest forgotten by a delete or the reconcile, and a blob reaped by the
-- storage GC or a repository delete, take their links with them.
--
-- Online shape: purely additive and DDL only. The tables are new and empty,
-- so their keys and indexes cost nothing to build. The foreign keys take a
-- brief SHARE ROW EXCLUSIVE lock on `repositories`, `oci_manifests` and
-- `oci_blobs` to install their triggers; the lock timeout makes a rolling
-- upgrade fail fast and retry on the next start rather than queue behind an
-- old replica's open transaction. The backfill is application-side
-- (`services::oci_image_scope`, run by the `oci_manifests` maintenance job).
-- `manifest_blob_refs` already has `idx_manifest_blob_refs_blob
-- (blob_digest)`, which the blob read's derived lookup uses.

SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS oci_image_manifests (
    repository_id UUID        NOT NULL,
    image         TEXT        NOT NULL,
    digest        TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, image, digest),
    FOREIGN KEY (repository_id, digest)
        REFERENCES oci_manifests (repository_id, digest) ON DELETE CASCADE
);

-- The cascade from `oci_manifests` and the legacy-marker lookup key on the
-- digest, not the image.
CREATE INDEX IF NOT EXISTS idx_oci_image_manifests_digest
    ON oci_image_manifests (repository_id, digest);

CREATE TABLE IF NOT EXISTS oci_image_blobs (
    repository_id UUID        NOT NULL,
    image         TEXT        NOT NULL,
    digest        TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, image, digest),
    FOREIGN KEY (repository_id, digest)
        REFERENCES oci_blobs (repository_id, digest) ON DELETE CASCADE
);

-- The cascade from `oci_blobs` keys on the digest.
CREATE INDEX IF NOT EXISTS idx_oci_image_blobs_digest
    ON oci_image_blobs (repository_id, digest);

-- completed_at: when the first backfill attributed the repository's content
-- (or its first push found nothing to attribute). last_scanned_at: when the
-- latest pass started; the next pass re-reads rows written since shortly
-- before it.
CREATE TABLE IF NOT EXISTS oci_image_scope_backfill (
    repository_id   UUID        PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    completed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
