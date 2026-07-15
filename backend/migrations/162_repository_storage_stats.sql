-- Epic #2056 (P1): materialized deduplicated storage accounting per repository.
--
-- These tables are a PARALLEL, READ-ONLY cache of the true physical footprint.
-- They are ADDITIVE: quota enforcement continues to read the live logical
-- SUM in repository_service.rs / repositories.rs and is NOT repointed here
-- (see FixSpec #2056 §7). Nothing in the quota path reads these rows.
--
-- Rows are refreshed by the background storage-stats refresher (scheduler) and
-- the post-GC trigger; the API reads them by primary key for O(1) responses.

CREATE TABLE repository_storage_stats (
    repository_id  UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    -- Sum over every reference (per-row); OCI layer bytes now included.
    logical_bytes  BIGINT NOT NULL DEFAULT 0,
    -- Deduplicated footprint: each distinct physical object counted once
    -- within the dedup scope for this repository.
    physical_bytes BIGINT NOT NULL DEFAULT 0,
    -- Physical bytes of objects referenced ONLY by this repository.
    unique_bytes   BIGINT NOT NULL DEFAULT 0,
    -- physical_bytes - unique_bytes: objects also referenced by another repo.
    -- Always 0 on filesystem backends (a shared digest is two files).
    shared_bytes   BIGINT NOT NULL DEFAULT 0,
    -- Distinct dedup keys referenced by this repository.
    blob_count     BIGINT NOT NULL DEFAULT 0,
    -- 'per_repo' (filesystem) | 'instance' (cloud) — backend at compute time.
    dedup_scope    TEXT   NOT NULL,
    computed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-row instance-level singleton: the true globally-distinct footprint.
-- On cloud backends the sum of per-repo physical_bytes over-counts shared
-- objects (attributed to each sharer), so the instance total is persisted
-- separately and surfaced with a caveat.
CREATE TABLE instance_storage_stats (
    id            BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),  -- single-row guard
    unique_bytes  BIGINT NOT NULL DEFAULT 0,   -- globally distinct footprint (true disk)
    dedup_scope   TEXT   NOT NULL,
    computed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cloud global-digest grouping (GROUP BY digest with a leading-digest scan).
-- Today only the composite (repository_id, digest) index exists.
CREATE INDEX idx_oci_blobs_digest ON oci_blobs(digest);
