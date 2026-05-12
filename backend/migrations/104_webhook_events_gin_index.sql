-- GIN index on webhooks.events for fast ANY(events) filtering.
--
-- The webhook producer (services/webhook_producer.rs::enqueue_for_event) looks
-- up matching webhooks per published domain event with:
--
--   WHERE is_enabled = true
--     AND $1 = ANY(events)
--     AND (repository_id IS NULL OR repository_id = $2)
--
-- The `$1 = ANY(events)` predicate against a text[] column goes sequential
-- without a GIN index. At v1.1.9 fanout (single-digit webhooks per repo) the
-- seq scan is fine, but global webhooks subscribed to every artifact upload
-- pay a full table scan on every event. Issue #949.
--
-- GIN is the right index type for membership queries on array columns; B-tree
-- can't index array elements, and GiST would be slower for the equality
-- semantics we use. The `array_ops` operator class is the default for
-- text[] under GIN and supports the `= ANY(arr)` rewrite the planner uses.
--
-- The index is intentionally NOT partial on `is_enabled = true`. Partial
-- indexes constrain planner choice in ways that hurt after operators bulk-
-- toggle webhooks. The full index pays a small space cost for predictability.

CREATE INDEX IF NOT EXISTS webhooks_events_gin_idx
    ON webhooks USING GIN (events);
