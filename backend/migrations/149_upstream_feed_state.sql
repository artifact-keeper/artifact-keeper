-- #2249: resume cursors for upstream change-feed consumers
-- (services/upstream_feed.rs). One row per feed, keyed by the adapter's
-- stable feed_key; last_seq is the opaque upstream cursor (CouchDB seq for
-- npm). Reversible: DROP TABLE upstream_feed_state.
CREATE TABLE IF NOT EXISTS upstream_feed_state (
    feed_key TEXT PRIMARY KEY,
    last_seq TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
