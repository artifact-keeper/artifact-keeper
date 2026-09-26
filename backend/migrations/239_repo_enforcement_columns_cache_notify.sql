-- Widen `ak_repository_changed_notify` (migration 142) to the enforcement
-- columns `CachedRepo` now carries (#3778).
--
-- The Maven proxy hot path resolves repository metadata from the 60-second
-- in-process `repo_cache` instead of re-querying `repositories` on every GET,
-- so the cache entry grew `promotion_only` / `age_gate_*` / `curation_*` to
-- stay a faithful snapshot of the row. Those gates must not go stale for a
-- whole TTL when an admin flips them, so a change to any of them now
-- publishes the same `repository_changed` event the original seven columns
-- already did — every replica evicts the entry and the next request
-- re-reads the row. Still deliberately NOT fired for `updated_at`-only
-- writes.

DROP TRIGGER IF EXISTS ak_repository_changed_notify ON repositories;
CREATE TRIGGER ak_repository_changed_notify
    AFTER UPDATE ON repositories
    FOR EACH ROW
    WHEN (
        OLD.key IS DISTINCT FROM NEW.key
        OR OLD.format IS DISTINCT FROM NEW.format
        OR OLD.repo_type IS DISTINCT FROM NEW.repo_type
        OR OLD.upstream_url IS DISTINCT FROM NEW.upstream_url
        OR OLD.storage_backend IS DISTINCT FROM NEW.storage_backend
        OR OLD.storage_path IS DISTINCT FROM NEW.storage_path
        OR OLD.is_public IS DISTINCT FROM NEW.is_public
        OR OLD.promotion_only IS DISTINCT FROM NEW.promotion_only
        OR OLD.age_gate_enabled IS DISTINCT FROM NEW.age_gate_enabled
        OR OLD.age_gate_min_age_days IS DISTINCT FROM NEW.age_gate_min_age_days
        OR OLD.age_gate_mode IS DISTINCT FROM NEW.age_gate_mode
        OR OLD.curation_enabled IS DISTINCT FROM NEW.curation_enabled
        OR OLD.curation_default_action IS DISTINCT FROM NEW.curation_default_action
    )
    EXECUTE FUNCTION ak_notify_repository_changed();
