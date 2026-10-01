-- #3912: quarantine identity for proxy-cached content.
--
-- The Package Age Policy hold for proxied content has always lived in the
-- cache-entry sidecar (`CacheMetadata.quarantine_until`, #1770); the
-- persisted catalog row had no mirror of it, so a held proxied artifact had
-- no releasable identity: `POST /api/v1/quarantine/{artifact_id}/release`
-- acts on `artifacts`, and proxy-cached content deliberately has no row
-- there (#1278). These two columns give every cached object the same
-- releasable identity the hosted side has, keyed on the catalog's own
-- (repository_id, path):
--
--   * `quarantine_until`       mirrors the sidecar hold at cache-commit
--                              time (NULL = not held);
--   * `quarantine_released_at` stamps an admin's manual release via
--                              `POST /api/v1/quarantine/proxy-cache/{key}/release`;
--                              reset to NULL by the next cache write for the
--                              path, which is a fresh upstream evaluation.
--
-- ADD COLUMN with no default is catalogue-only on PG 11+; existing rows are
-- simply "not held" (their sidecars remain the read-path authority). No new
-- index: the release endpoint looks rows up by the existing
-- (repository_id, path) unique key, and nothing else reads these columns.

ALTER TABLE proxy_cache_artifacts
    ADD COLUMN quarantine_until TIMESTAMPTZ,
    ADD COLUMN quarantine_released_at TIMESTAMPTZ;
