-- Index backing the cross-repository overwrite guard (#2504).
--
-- Hosted flat-key writes now consult `artifacts` for a live row that references
-- the same `storage_key` in a *different* repository before writing, to prevent
-- one repository from clobbering another's object on shared cloud namespaces
-- (S3/GCS/Azure), where the per-repo storage_path is not applied to the key.
--
-- The guard query filters on `storage_key` (and `is_deleted`), which was
-- previously unindexed; without this index every hosted upload would trigger a
-- sequential scan of `artifacts`. A plain (non-unique) b-tree keeps keys flat —
-- distinct repositories legitimately share a coordinate key today — so this is
-- purely a lookup accelerator, not a uniqueness constraint. Idempotent so it is
-- safe to (re)apply and to cherry-pick onto release branches.
CREATE INDEX IF NOT EXISTS idx_artifacts_storage_key_live
    ON artifacts (storage_key)
    WHERE is_deleted = false;
