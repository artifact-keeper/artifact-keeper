-- Issue #4054: stored environments and the component -> environment reverse
-- index.
--
-- #4052 parses a lockfile into a per-(environment, platform) dependency
-- graph; #4053 renders that graph as SBOM documents but persists nothing.
-- The incident question "what do we have to fix?" is asked against
-- environments, so the parsed graph must be stored: one `environments` row
-- per (repository, name), one `environment_packages` row per (scope,
-- package) membership, one `environment_edges` row per resolved edge.
--
-- The reverse index is `idx_environment_packages_purl_base`: "which stored
-- environments contain component X" is an index scan over the purl base
-- (the purl with qualifiers stripped -- the identity an advisory carries),
-- never a graph scan. Per-platform answers fall out of the scope columns.
-- The full qualified purl (#4041) is stored alongside for display.
--
-- All three tables are born here, so the indexes build on empty tables and
-- no concurrent build is needed (docs/operations/online-migrations.md).

CREATE TABLE IF NOT EXISTS environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    lockfile_format TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Identity: re-ingesting (repository, name) REPLACES the stored graph.
    -- A re-solved environment is a new fact; stale membership would keep
    -- answering "are we exposed?" with an environment nobody runs anymore.
    UNIQUE (repository_id, name)
);

CREATE TABLE IF NOT EXISTS environment_packages (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    -- The (environment, platform) scope axes of #4052. NULL when the
    -- lockfile format has no such axis; compared with IS NOT DISTINCT FROM.
    scope_environment TEXT,
    scope_platform TEXT,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    -- Full purl (build/channel/subdir-qualified for conda) for display.
    purl TEXT,
    -- purl with qualifiers stripped: the index key, matching how an
    -- advisory names a component. NULL when no purl can be formed (a
    -- versionless entry); such memberships exist but are not addressable
    -- by the reverse index.
    purl_base TEXT,
    package_key TEXT NOT NULL,
    is_root BOOLEAN NOT NULL DEFAULT false
);

-- The reverse index itself: purl base -> memberships across every stored
-- environment. Partial: NULL purl_base rows can never match a lookup.
CREATE INDEX IF NOT EXISTS idx_environment_packages_purl_base
    ON environment_packages (purl_base)
    WHERE purl_base IS NOT NULL;

-- Reloading one scope's graph for the inclusion-path answer (and replacing
-- an environment on re-ingest).
CREATE INDEX IF NOT EXISTS idx_environment_packages_environment
    ON environment_packages (environment_id, scope_environment, scope_platform);

CREATE TABLE IF NOT EXISTS environment_edges (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    scope_environment TEXT,
    scope_platform TEXT,
    from_key TEXT NOT NULL,
    to_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    requirement TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_environment_edges_environment
    ON environment_edges (environment_id, scope_environment, scope_platform);
