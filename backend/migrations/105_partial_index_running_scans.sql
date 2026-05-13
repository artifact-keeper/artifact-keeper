-- Migration: partial index on scan_results(started_at) WHERE status='running' (#1061)
--
-- The stuck-scan janitor (#1015) sweeps `scan_results` every 10 minutes with:
--
--   UPDATE scan_results
--   SET status='failed', ...
--   WHERE status='running'
--     AND started_at IS NOT NULL
--     AND started_at < NOW() - make_interval(secs => $1::double precision)
--
-- The existing `idx_scan_results_repo_status` covers `(repository_id, status)`
-- but the janitor query has no `repository_id` predicate, so on installs with
-- a large `scan_results` table the planner falls back to a wider scan than
-- necessary. A partial index keyed only on `started_at` and constrained to
-- `status='running'` is tiny (only in-flight scans are indexed) and lets the
-- janitor go straight to the candidate rows.
--
-- CREATE INDEX CONCURRENTLY is not used here: sqlx::migrate runs every
-- migration file inside a transaction, and CONCURRENTLY is rejected inside
-- a transaction block. The non-concurrent build takes ACCESS EXCLUSIVE on
-- scan_results for the duration of the build, so inserts to scan_results
-- (i.e. new scans starting) will block until it finishes.
--
-- First-deploy honesty: on installs that pre-date #1015's janitor, the
-- 'running' set on disk is unbounded, it accumulates every historical
-- crashed-mid-scan row. Build time at this migration is proportional to
-- that backlog, NOT to the janitor's steady-state bound (the janitor has
-- not run yet at migration time). Operators with a large pre-existing
-- backlog should size the upgrade window using the SQL count in the
-- CHANGELOG pre-upgrade-check section.
--
-- Idempotent via IF NOT EXISTS so re-running on an already-migrated DB is
-- a no-op.

CREATE INDEX IF NOT EXISTS idx_scan_results_running_started
  ON scan_results (started_at)
  WHERE status = 'running';
