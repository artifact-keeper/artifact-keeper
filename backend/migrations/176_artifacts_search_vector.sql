-- Stored, trigger-maintained full-text search vector for artifacts
-- (PF-009 / #2871, part of the million-artifact perf epic #2516).
--
-- SearchService::search (both /search/quick and /search/advanced) filtered on
-- an INLINE functional predicate:
--
--   to_tsvector('english', name || ' ' || path || ' ' || COALESCE(version, ''))
--     @@ to_tsquery('english', $1)
--
-- Nothing on `artifacts` matched that expression, so the planner had no choice
-- but a Parallel Seq Scan that recomputes to_tsvector('english', ...) for every
-- live row on every request -- twice, because the exact-count query for
-- pagination runs the same predicate a second time. EXPLAIN at ~517k rows
-- showed this pegging Postgres at 11-17 cores with p95 climbing 272ms -> 1.09s
-- -> 3.63s at 10k / 100k / 500k artifacts.
--
-- Fix: materialize the exact same tsvector into a stored `search_vector` column
-- maintained by a BEFORE INSERT/UPDATE trigger, and back it with a partial GIN
-- index (WHERE is_deleted = false, matching every caller of this path). The two
-- search queries then filter on `a.search_vector @@ to_tsquery('english', $1)`,
-- which the planner satisfies with a Bitmap Index Scan; the COUNT collapses to
-- the same index-backed bitmap instead of a second full scan. Result semantics
-- and ordering are unchanged: the stored vector is byte-for-byte the vector the
-- inline predicate used to compute per row.
--
-- The column is nullable and carries no default, so `ADD COLUMN` is a
-- catalog-only change (no table rewrite, no long ACCESS EXCLUSIVE hold). The
-- backfill and the (non-concurrent) index build below are the only heavy steps.

-- 1. Catalog-only column add (instant; no rewrite because it is nullable with
--    no default).
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- 2. Trigger function: recompute the stored vector from exactly the same
--    expression the old inline predicate used. Kept in one place so the stored
--    column can never drift from the query semantics.
CREATE OR REPLACE FUNCTION ak_artifacts_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := to_tsvector(
        'english',
        NEW.name || ' ' || NEW.path || ' ' || COALESCE(NEW.version, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Fire only when a component of the vector actually changes (plus every
-- INSERT). Soft-delete (is_deleted) and download/updated_at churn do not touch
-- name/path/version, so they never pay the recompute -- and a soft-deleted row
-- drops out of the partial index regardless.
DROP TRIGGER IF EXISTS ak_artifacts_search_vector_trg ON artifacts;
CREATE TRIGGER ak_artifacts_search_vector_trg
    BEFORE INSERT OR UPDATE OF name, path, version ON artifacts
    FOR EACH ROW
    EXECUTE FUNCTION ak_artifacts_search_vector_update();

-- 3. In-migration backfill of existing rows. Setting search_vector directly
--    does NOT re-fire the trigger above (it only fires on name/path/version),
--    so there is no recursion. This is the one heavy write in this migration;
--    see the online-upgrade note below for large tables.
UPDATE artifacts
   SET search_vector = to_tsvector(
       'english',
       name || ' ' || path || ' ' || COALESCE(version, '')
   )
 WHERE search_vector IS NULL;

-- 4. Partial GIN index matching the search predicate and every caller's
--    `is_deleted = false` filter, so tombstoned rows stay out of the index.
CREATE INDEX IF NOT EXISTS idx_artifacts_search_vector_gin
    ON artifacts USING gin (search_vector)
    WHERE is_deleted = false;

-- ---------------------------------------------------------------------------
-- Online-upgrade path for very large `artifacts` tables (follows the migration
-- 173 precedent; relates to #2524 PF-008).
--
-- sqlx::migrate runs each migration file inside a single transaction, so the
-- backfill above scans/updates every live row under one transaction and the
-- non-concurrent index build takes ACCESS EXCLUSIVE on `artifacts` for its
-- duration -- artifact uploads block until it finishes. On a multi-million-row
-- table an operator who cannot accept that window should perform the heavy
-- steps out of band BEFORE deploying this migration, then let the migration
-- no-op over them (ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS /
-- the WHERE search_vector IS NULL backfill all become empty):
--
--   -- add the column + trigger (cheap) first:
--   ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS search_vector tsvector;
--   -- (create the function + trigger exactly as above)
--
--   -- backfill in bounded batches so no single statement holds a long
--   -- transaction or bloats WAL; run until zero rows are updated:
--   UPDATE artifacts
--      SET search_vector = to_tsvector(
--          'english', name || ' ' || path || ' ' || COALESCE(version, ''))
--    WHERE id IN (
--        SELECT id FROM artifacts WHERE search_vector IS NULL LIMIT 10000
--    );
--
--   -- build the index without blocking writes (cannot run inside the
--   -- migration transaction, hence out of band):
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_search_vector_gin
--     ON artifacts USING gin (search_vector) WHERE is_deleted = false;
--
-- Functionality is correct without the index -- it is purely a query-plan
-- accelerator -- and every statement here is idempotent, so re-running the
-- migration after an out-of-band build is a no-op.
