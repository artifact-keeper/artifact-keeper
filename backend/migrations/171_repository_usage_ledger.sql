-- PF-007 (#2523): per-repository storage-usage ledger for quota admission.
--
-- Before this table, every quota-enabled upload computed a 3-way UNION
-- aggregate (artifacts + proxy_cache_artifacts + oci_blobs) to answer
-- `check_quota`, and re-ran the same aggregate at finalize for the 80 %
-- warning log -- two full scans per upload. Worse, the admission read was
-- NOT atomic: two concurrent near-limit uploads both read the pre-upload
-- sum, both passed, and both were admitted beyond the quota (the
-- over-admission race, #2523).
--
-- The ledger holds the three usage components per repository. Its immediate
-- role is to serialize quota admission: the upload transaction INSERTs (if
-- absent) and `SELECT ... FOR UPDATE`s this row, so concurrent uploads into
-- the same repository serialize and the second sees the first's committed
-- bytes (closing the race). The stored component bytes are kept true by the
-- background reconciler (`reconcile_all_usage_ledgers`), which recomputes them
-- from the authoritative source tables and repairs any drift -- the mandatory
-- safety net for a write path that does not maintain the ledger. Repointing
-- the quota read itself at these O(1) columns (removing the last aggregate
-- from the upload path) is the follow-up once every mutation site applies an
-- in-transaction delta.
CREATE TABLE repository_usage_ledger (
    repository_id UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    -- artifacts rows that count toward quota (non proxy-cache storage keys).
    hosted_bytes  BIGINT NOT NULL DEFAULT 0,
    -- proxy_cache_artifacts (remote repos have no `artifacts` rows).
    proxy_bytes   BIGINT NOT NULL DEFAULT 0,
    -- oci_blobs (layer/config blobs; only manifests land in `artifacts`).
    oci_bytes     BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill from the authoritative live sums -- the exact components the quota
-- aggregate summed. One row per existing repository. Each per-repo sum is
-- served by the repository_id indexes on the three source tables; on very
-- large installs treat this as a minutes-scale migration (release notes).
INSERT INTO repository_usage_ledger (repository_id, hosted_bytes, proxy_bytes, oci_bytes)
SELECT
    r.id,
    COALESCE((SELECT SUM(a.size_bytes) FROM artifacts a
               WHERE a.repository_id = r.id
                 AND a.is_deleted = false
                 AND a.storage_key NOT LIKE 'proxy-cache/%'), 0),
    COALESCE((SELECT SUM(p.size_bytes) FROM proxy_cache_artifacts p
               WHERE p.repository_id = r.id), 0),
    COALESCE((SELECT SUM(o.size_bytes) FROM oci_blobs o
               WHERE o.repository_id = r.id), 0)
FROM repositories r
ON CONFLICT (repository_id) DO NOTHING;
