-- Issue #4055: re-evaluate stored environments when advisory data changes.
--
-- #4054 stores environments and the component -> environment reverse index,
-- but the answer it gives is only as fresh as the last scan: an environment
-- scanned clean in March is not clean in June if an advisory against an
-- installed component was published in April. Three tables close that gap
-- without any artifact changing:
--
--   advisory_deltas                  -- the trigger queue. The advisory
--                                       client's cache refresh is where new
--                                       advisory data ENTERS this system; a
--                                       refresh whose advisory-id set differs
--                                       from the previously cached answer
--                                       upserts one row per (ecosystem, name)
--                                       (UNIQUE + upsert collapses a burst of
--                                       per-version cache misses on the same
--                                       package into a single pending delta).
--                                       Persisted, not an in-memory channel,
--                                       so a delta detected on a replica that
--                                       does not hold the scheduler lease is
--                                       still processed by the one that does.
--
--   environment_advisory_state       -- current affectedness: a row present
--                                       means "this environment IS affected
--                                       by this advisory through this
--                                       component version". State is what an
--                                       operator page reads; transitions are
--                                       what an operator is paged ABOUT.
--
--   environment_advisory_transitions -- the event log. Only TRANSITIONS are
--                                       recorded (new-affected /
--                                       no-longer-affected): steady state is
--                                       not an event worth surfacing (#4088).
--
-- The delta lookup keys on (ecosystem, name) -- the identity an advisory
-- carries -- so it needs an index on exactly that, distinct from the #4054
-- purl_base index (which keys single-purl lookups, version included).
-- Partial on purl_base NOT NULL for the same reason the #4054 index is:
-- versionless memberships can never match an advisory version range.

CREATE TABLE IF NOT EXISTS advisory_deltas (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The feed ecosystem as detected (OSV naming: "PyPI", "npm",
    -- "crates.io") and the package name as the feed named it. Mapping to the
    -- stored purl-type ecosystem and name normalisation happens at
    -- processing time, in one place.
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    -- The advisory-id set observed after the change. Informational: the
    -- re-evaluation re-queries the feed for current truth rather than
    -- trusting the detection-time snapshot.
    advisory_ids TEXT[] NOT NULL DEFAULT '{}',
    -- Retry budget: a delta whose feed answer stays degraded is retried on
    -- later ticks and given up on after a bounded number of attempts, so one
    -- unreachable feed cannot stall the queue.
    attempts INTEGER NOT NULL DEFAULT 0,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    UNIQUE (ecosystem, name)
);

CREATE INDEX IF NOT EXISTS idx_advisory_deltas_pending
    ON advisory_deltas (id)
    WHERE processed_at IS NULL;

CREATE TABLE IF NOT EXISTS environment_advisory_state (
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    advisory_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    summary TEXT,
    severity TEXT,
    fixed_version TEXT,
    source_url TEXT,
    affected_since TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (environment_id, advisory_id, ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS environment_advisory_transitions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    advisory_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('new-affected', 'no-longer-affected')),
    -- Denormalised advisory detail so the event stands alone after the
    -- advisory ages out of the state table.
    summary TEXT,
    severity TEXT,
    fixed_version TEXT,
    source_url TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_env_advisory_transitions_time
    ON environment_advisory_transitions (detected_at);

CREATE INDEX IF NOT EXISTS idx_env_advisory_transitions_environment
    ON environment_advisory_transitions (environment_id, detected_at);

-- The delta-path lookup key: (ecosystem, name) over versioned memberships
-- (the partial predicate matches the lookup's WHERE clause exactly, so the
-- planner can always use it). Re-evaluation cost is O(stored versions of
-- the delta's one package), never a scan over environments.
CREATE INDEX IF NOT EXISTS idx_environment_packages_identity
    ON environment_packages (ecosystem, name)
    WHERE version IS NOT NULL;
