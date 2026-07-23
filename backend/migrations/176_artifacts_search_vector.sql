-- GIN-indexed stored tsvector for artifact full-text search
-- (PF / #2871, part of the million-artifact epic #2516).
--
-- SearchService::search (both /search/quick and /search/advanced) matched
-- artifacts with an INLINE functional predicate:
--
--   to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, ''))
--     @@ to_tsquery('english', $1)
--
-- There was no stored/indexed tsvector on the column, so the planner had to
-- recompute to_tsvector() for every candidate row on every search request —
-- a Parallel Seq Scan — and the pagination COUNT ran the same expression in a
-- SECOND full scan. The PTF search-at-scale profile measured p95 of
-- 272ms -> 1.09s -> 3.63s at 10k/100k/500k artifacts, pegging Postgres at
-- ~11-17 cores while the backend itself stayed idle. This is a pure
-- query-plan problem: the predicate is a function of the row, so no index on
-- the base columns can serve it.
--
-- Fix: materialize exactly that tsvector into a stored `search_vector` column,
-- keep it current with a trigger, and add a partial GIN index. The two search
-- queries then match `a.search_vector @@ to_tsquery(...)` — identical
-- semantics, but an index lookup (Bitmap Index Scan) instead of a full scan,
-- and the COUNT becomes index-backed too.
--
-- ---------------------------------------------------------------------------
-- Column: nullable, NO generated/default expression.
-- ---------------------------------------------------------------------------
-- A `GENERATED ALWAYS AS (...) STORED` column would rewrite the whole
-- `artifacts` table under ACCESS EXCLUSIVE at ADD COLUMN time — a multi-minute
-- hard lock at 500k-1M rows during which all uploads block. A plain nullable
-- column with no default is a catalog-only change (instant); it is populated
-- by the trigger below (new/updated rows) and the one-shot backfill (existing
-- rows). Same large-table discipline as migration 173 (#2518).
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- ---------------------------------------------------------------------------
-- Trigger: recompute search_vector whenever a searched column changes.
-- ---------------------------------------------------------------------------
-- The body mirrors the query's expression byte-for-byte so matching is
-- unchanged. `name` and `path` are NOT NULL (migration 004); `version` is
-- nullable, hence COALESCE — matching the inline predicate exactly. Fires
-- only on INSERT or UPDATE OF the three inputs, so unrelated updates (e.g.
-- size_bytes, is_deleted tombstoning) do not pay the recompute.
CREATE OR REPLACE FUNCTION ak_artifacts_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector(
        'english',
        NEW.name || ' ' || NEW.path || ' ' || COALESCE(NEW.version, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_artifacts_search_vector ON artifacts;
CREATE TRIGGER ak_artifacts_search_vector
    BEFORE INSERT OR UPDATE OF name, path, version ON artifacts
    FOR EACH ROW
    EXECUTE FUNCTION ak_artifacts_search_vector_update();

-- ---------------------------------------------------------------------------
-- Backfill: populate existing rows.
-- ---------------------------------------------------------------------------
-- Row-level UPDATE (NOT ACCESS EXCLUSIVE) so search is correct the instant
-- this migration completes — CI/DTF/PTF and normal installs need no extra
-- step. sqlx::migrate runs each file in a single transaction, so this is one
-- statement; a very large table can pre-run an out-of-band keyset-paged
-- backfill in separate commits before deploying, after which this UPDATE
-- matches nothing (WHERE search_vector IS NULL) and is a no-op.
UPDATE artifacts
   SET search_vector = to_tsvector(
       'english',
       name || ' ' || path || ' ' || COALESCE(version, '')
   )
 WHERE search_vector IS NULL;

-- ---------------------------------------------------------------------------
-- Index: partial GIN matching the query predicate.
-- ---------------------------------------------------------------------------
-- `WHERE is_deleted = false` matches every caller of the search path and
-- keeps tombstoned rows out of the index (same partial predicate as migration
-- 173). CREATE INDEX CONCURRENTLY is intentionally not used: sqlx::migrate
-- runs each migration inside a transaction and CONCURRENTLY is rejected there.
-- The non-concurrent build takes ACCESS EXCLUSIVE on `artifacts` for its
-- duration (uploads block until it finishes). Operators with very large tables
-- who cannot accept that window can build it out of band beforehand:
--
--   CREATE INDEX CONCURRENTLY idx_artifacts_search_vector
--     ON artifacts USING gin (search_vector)
--     WHERE is_deleted = false;
--
-- Search continues to work without the index (it is purely a plan
-- accelerator). Idempotent via IF NOT EXISTS, so re-running after an
-- out-of-band CONCURRENTLY build is a no-op.
CREATE INDEX IF NOT EXISTS idx_artifacts_search_vector
    ON artifacts USING gin (search_vector)
    WHERE is_deleted = false;
