-- Migration 191: age-gate age-source modes (#2264 / #1558 follow-up): where the cooldown
-- clock starts for a repository.
--
--   upstream_publish_time: the registry-reported publish timestamp (the
--     #2066 model; npm packument `time`, PyPI `upload-time`). Trustworthy
--     only insofar as the upstream registry is.
--   first_seen: the first time THIS server observed the version for the
--     repository. An AK-local freshness control that needs no upstream
--     metadata and cannot be backdated by a publisher.
--
-- Default preserves existing behavior for every repository already using the
-- gate.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS age_gate_mode TEXT NOT NULL DEFAULT 'upstream_publish_time'
        CHECK (age_gate_mode IN ('upstream_publish_time', 'first_seen'));

-- Bind each review's recorded basis to the policy it was measured under.
--
-- A review row's `upstream_published_at` is only meaningful relative to the
-- age source (mode) and upstream registry it was resolved against: a
-- publish-time basis must not satisfy a `first_seen` gate, and a basis
-- recorded against one upstream must not survive a repoint to another. These
-- columns carry that identity; `AgeGateService::check` and the background
-- sweep refuse to honor a basis (or an automatic approval) whose identity
-- does not match the repository's current policy.
--
-- NULL identity marks pre-upgrade rows, with an explicit disposition:
--   * manually reviewed rows (reviewed_by IS NOT NULL) keep their effect --
--     they are administrator decisions made before identities were recorded;
--   * automatically approved rows (reviewed_by IS NULL) are no longer honored
--     as sticky allows; the decision is recomputed from the current basis on
--     every request, so legacy automatic approvals cannot bypass a mode
--     switch, a raised threshold, or a repointed upstream;
--   * pending rows are swept only while the repository still runs
--     `upstream_publish_time` (the only mode that existed before this
--     migration), and are re-stamped with a full identity on their next
--     request.
ALTER TABLE age_gate_reviews
    ADD COLUMN IF NOT EXISTS basis_mode TEXT
        CHECK (basis_mode IN ('upstream_publish_time', 'first_seen')),
    ADD COLUMN IF NOT EXISTS basis_upstream_fingerprint TEXT;

-- First-observation records backing `first_seen` mode.
--
-- Insert-once: rows are written with ON CONFLICT DO NOTHING and never
-- updated, so concurrent requests and replicas race benignly (the earliest
-- observation wins) and repeated listings can never push a version's clock
-- forward.
--
-- `upstream_fingerprint` (sha256 of the repository's normalized upstream URL)
-- is part of the identity on purpose. Without it, repointing a remote at a
-- different registry would let a same-named version inherit the elapsed age
-- of the version it replaces -- an observation is only meaningful about the
-- upstream it was made against. Re-pointing therefore starts a fresh clock
-- rather than requiring every repository-update path to remember to
-- invalidate (the same "remember to call it" bug class #2264 removes from
-- the download gate).
CREATE TABLE IF NOT EXISTS age_gate_version_observations (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    upstream_fingerprint TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, upstream_fingerprint, package_name, package_version)
);

-- Upgrade disposition for repositories whose gate is enabled on a
-- (format, mode) pair this server cannot enforce: the config PUT endpoint
-- rejects newly enabling unenforceable (format, mode) pairs. For formats in
-- the capability matrix (npm and pypi in both modes; go in first_seen mode),
-- an enabled-but-unenforceable configuration fails closed (503) at the proxy
-- seam. Formats outside the age-gate capability matrix pass through via the
-- format capability matrix check.
