-- Trigram expression indexes matching the catalog-search predicates
-- (PF-001 / #2518).
--
-- The flat catalog listing implements substring search as
--
--   LOWER(name) LIKE '%q%' OR LOWER(path) LIKE '%q%'
--
-- (see ArtifactService::list_page / count). Neither existing index is
-- usable for that shape:
--
--   * `idx_artifacts_name_gin` (migration 004) is a trigram index on the
--     RAW `name` column; the predicate is a function of the column
--     (`LOWER(name)`), so the planner cannot apply it.
--   * `idx_artifacts_repo_lower_name` (migration 106) matches the
--     expression but is a btree intended for `LOWER(name) = $x` equality;
--     a leading-wildcard LIKE cannot use a btree at all.
--   * There is no `LOWER(path)` index of any kind, and the OR arm makes
--     the whole predicate unindexable unless BOTH sides are indexable.
--
-- The result is a scan of the repository's full row range per search
-- request — twice when the exact count runs too — which grows linearly
-- with catalog size (the project has measured multi-second scans at 1M
-- rows for exactly this kind of plan mismatch; see migrations 108/110).
--
-- These two GIN `gin_trgm_ops` expression indexes exactly match the two OR
-- arms, so the planner can BitmapOr them and AND the result with the
-- repository filter: O(matches) instead of O(repository rows). `pg_trgm`
-- has been enabled since migration 004.
--
-- The `WHERE is_deleted = false` partial predicate matches every caller of
-- this query path and keeps tombstoned rows out of the index.
--
-- Write/storage cost: trigram GIN indexes are the heaviest index type this
-- table carries (path is up to 2048 chars). Both are needed because the
-- predicate ORs the two expressions. The raw-`name` trigram index from 004
-- is left in place: dropping indexes is out of scope for a perf fix and
-- other lookups may still use it.
--
-- CREATE INDEX CONCURRENTLY is intentionally not used here: sqlx::migrate
-- runs each migration file inside a transaction, and CONCURRENTLY is
-- rejected inside a transaction block. The non-concurrent build takes
-- ACCESS EXCLUSIVE on `artifacts` for the duration of the build, so new
-- artifact uploads block until it finishes. Operators with very large
-- `artifacts` tables who cannot accept the lock window can create the
-- indexes out of band beforehand:
--
--   CREATE INDEX CONCURRENTLY idx_artifacts_lower_name_trgm
--     ON artifacts USING gin (LOWER(name) gin_trgm_ops)
--     WHERE is_deleted = false;
--   CREATE INDEX CONCURRENTLY idx_artifacts_lower_path_trgm
--     ON artifacts USING gin (LOWER(path) gin_trgm_ops)
--     WHERE is_deleted = false;
--
-- Functionality continues to work without the indexes; they are purely
-- query-plan accelerators. Idempotent via IF NOT EXISTS so re-running on an
-- already-migrated DB (e.g. after an out-of-band CONCURRENTLY build) is a
-- no-op.

CREATE INDEX IF NOT EXISTS idx_artifacts_lower_name_trgm
  ON artifacts USING gin (LOWER(name) gin_trgm_ops)
  WHERE is_deleted = false;

CREATE INDEX IF NOT EXISTS idx_artifacts_lower_path_trgm
  ON artifacts USING gin (LOWER(path) gin_trgm_ops)
  WHERE is_deleted = false;
