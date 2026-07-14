-- Index role_assignments(repository_id) for the CVE blast-radius
-- accessible-users enumeration (#2386).
--
-- role_assignments' only index today is its UNIQUE(user_id, role_id,
-- repository_id) constraint, whose leading column is user_id. The enumeration
-- filters `repository_id = $1 OR repository_id IS NULL` (a non-leading column),
-- so that constraint cannot serve it and large deployments seq-scan the table.
-- This partial-free btree serves both the `= $repo` and `IS NULL` scans.
--
-- Non-blocking, idempotent; no data change.
CREATE INDEX IF NOT EXISTS idx_role_assignments_repository_id
    ON role_assignments(repository_id);
