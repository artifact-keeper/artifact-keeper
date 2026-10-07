-- no-transaction
-- #4426: drop the old dedup index (migrations 033/209, predicate
-- `status = 'completed'` only), now superseded by
-- idx_scan_results_dedup_local from migration 274. CONCURRENTLY so the drop
-- waits for in-flight queries without taking ACCESS EXCLUSIVE on
-- scan_results and queueing every reader and writer behind it. Cost is a
-- catalogue change plus file unlink, independent of table size.
-- Re-runnable: IF EXISTS.
DROP INDEX CONCURRENTLY IF EXISTS idx_scan_results_dedup;
