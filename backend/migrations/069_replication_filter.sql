ALTER TABLE peer_repo_subscriptions ADD COLUMN IF NOT EXISTS replication_filter JSONB;

COMMENT ON COLUMN peer_repo_subscriptions.replication_filter IS 'JSON: {"include_patterns": ["^v\\d+\\."], "exclude_patterns": [".*-SNAPSHOT$"]}. NULL = replicate everything.';
