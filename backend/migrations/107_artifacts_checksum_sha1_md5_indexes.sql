-- Migration: add B-tree indexes on artifacts.checksum_sha1 and
-- artifacts.checksum_md5 so the checksum-search endpoint can locate
-- artifacts by SHA-1 / MD5 in O(log n) instead of falling back to a
-- sequential scan over the entire artifacts table.
--
-- Context: a release-gate regression (#1247, ak-search-fix) found that
-- /api/v1/search/checksum?checksum=...&algorithm=sha1 returned no
-- artifacts. The proximate cause was that artifact_service::upload
-- only persisted checksum_sha256; checksum_sha1 and checksum_md5
-- were left NULL on every upload. That fix (computing and persisting
-- all three at upload time) lands in the same change set as this
-- migration.
--
-- With those columns now populated for every new artifact, the
-- search query
--
--     SELECT ... FROM artifacts a WHERE a.checksum_sha1 = $1
--
-- becomes a hot path for clients that resolve artifacts by SHA-1
-- (Maven .sha1 sidecars, Debian apt-cache, git-lfs pointer files).
-- Migration 004_artifacts.sql created idx_artifacts_checksum on
-- checksum_sha256 but left sha1/md5 unindexed because nothing was
-- writing to them. Now that we are, we need parity.
--
-- Partial-index predicate `WHERE checksum_sha1 IS NOT NULL` keeps the
-- index small: artifacts that pre-date this change still have NULL
-- sha1/md5 (we cannot recompute them in SQL because we don't have the
-- blob contents), so excluding them from the index avoids bloating it
-- with dead entries. A separate one-shot backfill job (described in
-- the PR description) re-hashes legacy artifacts from object storage.
--
-- CREATE INDEX (non-CONCURRENTLY) is intentional: sqlx::migrate wraps
-- each file in a transaction and CONCURRENTLY is rejected inside a
-- txn block. The non-concurrent build takes ACCESS EXCLUSIVE on
-- `artifacts` for the duration of the build, so new artifact uploads
-- will block until it finishes. Operators with large artifact tables
-- (>10M rows) who cannot accept the lock window can apply the
-- equivalent CONCURRENTLY out of band before running migrations:
--
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_checksum_sha1
--     ON artifacts (checksum_sha1) WHERE checksum_sha1 IS NOT NULL;
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_checksum_md5
--     ON artifacts (checksum_md5)  WHERE checksum_md5  IS NOT NULL;
--
-- IF NOT EXISTS makes this migration idempotent so operators who
-- created the indexes out of band before applying the migration get
-- a clean no-op.

CREATE INDEX IF NOT EXISTS idx_artifacts_checksum_sha1
  ON artifacts (checksum_sha1)
  WHERE checksum_sha1 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_artifacts_checksum_md5
  ON artifacts (checksum_md5)
  WHERE checksum_md5 IS NOT NULL;
