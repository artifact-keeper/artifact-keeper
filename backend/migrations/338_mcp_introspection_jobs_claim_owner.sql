-- #5465: an introspection claim is bound to the authenticated worker that
-- took it. `claimed_by_user_id` is the principal (the `mcp:introspect` API
-- token's user, normally a service account) of the claim request; a
-- completion is accepted only from that same principal, so possessing a
-- claim token is not enough for another worker.
--
-- The binding is to the user, not to the API token: a worker that rotates
-- its token (or re-authenticates with another `mcp:introspect` token of the
-- same service account) during a claim can still complete it. The
-- authenticated request carries no token id to bind to in any case.
--
-- `claimed_by` (TEXT) stays the self-reported `workerId` label; it is not an
-- identity and is not checked.
--
-- Nullable, no default: no rewrite of `mcp_introspection_jobs` (the foreign
-- key's validation scans it once; it is a small queue table).
-- A claim taken before this migration has no owner and is completable by no
-- one (fail-closed). Its lease (10 minutes) expires, the reaper returns it to
-- the queue, and the next claim records an owner, so no job is wedged.
-- `ON DELETE SET NULL`: a deleted worker principal's open claim likewise
-- becomes uncompletable and is reaped.
ALTER TABLE mcp_introspection_jobs
    ADD COLUMN IF NOT EXISTS claimed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Backs the foreign key's `ON DELETE SET NULL`: deleting a user finds its
-- jobs by index instead of scanning the queue.
CREATE INDEX IF NOT EXISTS idx_mcp_introspection_jobs_claimed_by_user
    ON mcp_introspection_jobs (claimed_by_user_id)
    WHERE claimed_by_user_id IS NOT NULL;
