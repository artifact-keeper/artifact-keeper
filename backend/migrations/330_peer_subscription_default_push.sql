-- #5293: `pull` replication is not implemented (no sync task producer selects
-- it), yet it was the column default, so a subscription written without a
-- mode never replicated anything. The API now defaults to `push` and refuses
-- `pull`; make the column default agree. Existing `pull` rows are left as
-- they are and named at startup (`warn_inactive_pull_replication`).
ALTER TABLE peer_repo_subscriptions ALTER COLUMN replication_mode SET DEFAULT 'push';
