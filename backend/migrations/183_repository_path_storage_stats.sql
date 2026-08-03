-- Epic #2056 (P2, #2601): materialized per-path-prefix (folder tree) storage
-- rollup per repository.
--
-- A second, finer-grained materialization next to `repository_storage_stats`
-- (migration 162): one row per (repository, path prefix), where a prefix is a
-- directory-level ancestor of an artifact's logical `path` ('' = repo root).
-- The `/repositories/{key}/storage/tree` endpoint reads these rows only, so a
-- tree/prefix query is an index lookup — never an O(all-artifact-rows) scan —
-- which is the #2516 million-artifact readiness requirement for this feature.
--
-- Like the P1 tables this is a PARALLEL, READ-ONLY accounting cache: rows are
-- refreshed by the storage-stats refresher (scheduler cadence + post-GC) and
-- nothing in the quota path reads them.
--
-- Dedup semantics (per node): `physical_bytes` counts each distinct dedup key
-- under the prefix once, `logical_bytes` sums every reference. A key shared by
-- two sibling subtrees is counted once in EACH subtree node but once at their
-- common ancestor, so the sum of children's `physical_bytes` may exceed the
-- parent's — that difference is the cross-subtree dedup saving. All figures
-- are within-repository only (no cross-tenant sharing data, cf. the #2560
-- restriction on the repo-level endpoint).

CREATE TABLE repository_path_storage_stats (
    repository_id  UUID   NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    -- Directory prefix of artifact logical paths, '/'-separated, no leading or
    -- trailing slash. '' is the repository root node.
    prefix         TEXT   NOT NULL,
    -- Number of path segments in `prefix` (0 for the root row). Materialized
    -- so "one tree level" queries are range scans, not string arithmetic.
    depth          INT    NOT NULL,
    -- Sum over every reference (artifact/proxy-cache row) under the prefix.
    logical_bytes  BIGINT NOT NULL DEFAULT 0,
    -- Deduplicated: each distinct dedup key under the prefix counted once.
    physical_bytes BIGINT NOT NULL DEFAULT 0,
    -- References (rows) under the prefix.
    file_count     BIGINT NOT NULL DEFAULT 0,
    -- Distinct dedup keys under the prefix.
    blob_count     BIGINT NOT NULL DEFAULT 0,
    -- Bytes referenced by this repository that carry no logical path and so
    -- cannot be placed in the tree (today: OCI layer blobs, which are only
    -- linked to image names through manifest content, not the catalog).
    -- Populated on the root row ('') only; 0 elsewhere. Root logical_bytes +
    -- unattributed_bytes == the repo-level logical total.
    unattributed_bytes BIGINT NOT NULL DEFAULT 0,
    computed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, prefix)
);

-- "Children of a prefix at depth d" queries filter on (repository_id, depth)
-- then narrow by prefix LIKE; the composite index keeps that a range scan.
CREATE INDEX idx_repo_path_stats_repo_depth
    ON repository_path_storage_stats(repository_id, depth);
