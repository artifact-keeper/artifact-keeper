-- Index backing the cross-repository overwrite guard (#2504).
--
-- Hosted flat-key writes now consult `artifacts` for a row that references the
-- same `storage_key` in a *different* repository before writing, to prevent one
-- repository from clobbering another's object on shared cloud namespaces
-- (S3/GCS/Azure), where the per-repo storage_path is not applied to the key.
--
-- The guard query filters on `storage_key` alone (it must catch BOTH live and
-- soft-deleted foreign rows: the physical object persists past a soft-delete, so
-- a tombstoned foreign row still owns the key). That column was previously
-- unindexed; without this index every hosted upload would trigger a sequential
-- scan of `artifacts`. A plain (non-unique) b-tree over ALL rows keeps keys flat
-- -- distinct repositories legitimately share a coordinate key today, and
-- content-addressed formats legitimately share sha-based keys -- so this is
-- purely a lookup accelerator, not a uniqueness constraint. Idempotent so it is
-- safe to (re)apply and to cherry-pick onto release branches.
CREATE INDEX IF NOT EXISTS idx_artifacts_storage_key
    ON artifacts (storage_key);
