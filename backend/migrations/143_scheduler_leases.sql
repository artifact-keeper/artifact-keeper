-- Cluster-wide singleton job leases (cluster_work module).
--
-- Multiple backend replicas share one Postgres database, but several periodic
-- jobs (health monitoring, bootstrap reindex, curation sync, ...) are written
-- as if exactly one process runs them. This table provides a durable lease so
-- one replica at a time owns a named job.
--
-- Semantics (see backend/src/services/cluster_work.rs):
--   * A lease is claimed by upsert: the INSERT wins when no row exists; the
--     conflicting UPDATE wins only when the existing lease has expired or is
--     already owned by the same owner (renewal).
--   * `claim_token` is the correctness guard: finalize/renew/release must
--     match it. `owner_id` is diagnostic and enables cheap self-renewal.
--   * Expired leases are reclaimed in place; rows are never required to be
--     deleted for progress.
CREATE TABLE scheduler_leases (
    job_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    claim_token UUID NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE scheduler_leases IS
    'Cluster-wide singleton leases for background jobs; claimed/renewed/released by claim_token';
COMMENT ON COLUMN scheduler_leases.owner_id IS
    'Diagnostic worker identity (host:pid:boot-uuid); NOT the correctness guard';
COMMENT ON COLUMN scheduler_leases.claim_token IS
    'Random per-claim token; renew/release must match it';
