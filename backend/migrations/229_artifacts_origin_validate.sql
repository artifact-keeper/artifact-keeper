-- #4050: validate the NOT VALID CHECK from migration 227 now that the
-- backfill (227) has run — VALIDATE CONSTRAINT scans under SHARE UPDATE
-- EXCLUSIVE, which blocks neither readers nor writers. Every row now
-- carries an origin: pre-226 rows via the backfill, everything since via
-- the fill trigger.
--
-- Also clear any index left INVALID by an earlier interrupted concurrent
-- build: the next migration is `-- no-transaction`, so a failed build is
-- NOT rolled back and NOT recorded, and `CREATE INDEX CONCURRENTLY IF NOT
-- EXISTS` would happily skip a leftover INVALID index and leave it
-- invalid forever. Drop first, unconditionally.
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_origin_recorded;

DROP INDEX IF EXISTS idx_artifacts_origin_upstream_url;
