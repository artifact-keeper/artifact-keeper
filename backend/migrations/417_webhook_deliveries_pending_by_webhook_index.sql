-- no-transaction
-- 417_webhook_deliveries_pending_by_webhook_index.sql
-- #5195: the delivery worker claims each webhook's oldest due rows, a few per
-- webhook, instead of ranking every due row in the table. That is one ordered
-- range scan per webhook, stopping after the lane's row cap, on
-- (webhook_id, next_retry_at, id): the claim's equality, range and full
-- ORDER BY. The predicate is the claim's, and 067's, so the planner can prove
-- the index covers the query. Without it the planner walks 067's
-- next_retry_at index and filters by webhook, which reads a whole outage
-- backlog once per webhook (388 ms against 0.4 ms for 50 webhooks with a
-- 50 000-row backlog, scripts/perf/webhook-claim-cost.sh). Pending rows are a
-- small, short-lived fraction of the table, so the partial index stays small.
--
-- Cost: two scans of `webhook_deliveries` under SHARE UPDATE EXCLUSIVE, which
-- blocks no reads or writes; the build first waits for transactions already
-- open on the table. An interrupted build is dropped and retried at the next
-- boot (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down
-- path: drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_webhook_deliveries_pending_by_webhook
    ON webhook_deliveries (webhook_id, next_retry_at, id)
    WHERE success = false AND attempts < max_attempts AND next_retry_at IS NOT NULL;
