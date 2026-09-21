-- no-transaction
-- #4050: make "which artifacts did this upstream supply?" an indexed
-- query. That is the incident question origin exists to answer — a
-- compromised or typosquatted upstream is named, and every artifact it
-- ever supplied must be found — so it must not require a seq scan of the
-- catalogue. CONCURRENTLY so the build never blocks uploads; on a
-- million-row artifacts table this is two table scans with no write
-- block, needing room for the new index alongside the old table.
-- Soft-deleted rows are excluded: nobody audits upstream exposure against
-- rows the catalogue no longer serves.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_origin_upstream_url
    ON artifacts ((origin ->> 'upstream_url'))
    WHERE is_deleted = false;
