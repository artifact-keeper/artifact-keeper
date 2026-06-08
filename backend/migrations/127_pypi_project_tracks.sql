-- PEP 708 (Simple Repository API v1.2) dependency-confusion mitigation.
--
-- A `tracks` declaration is an OPERATOR-controlled statement that a locally
-- owned project is the same project as an upstream one, so it is safe for a
-- virtual repository to merge (union) versions across members for that name.
--
-- Without such a declaration, a virtual repo must NOT merge an externally owned
-- project into a name a local member owns (that is the dependency-confusion
-- hole: an internal `acme-sdk` silently pulling in an unrelated public
-- `acme-sdk`). See #1600.
--
-- The declaration is attached to the repository whose project owns the name
-- (the local/hosted member), mirroring PEP 708 where `tracks` is a property of
-- the project's own repository. `tracks_url` records the upstream Simple index
-- project URL the local project tracks, and is emitted as `meta.tracks` /
-- `pypi:tracks` in the Simple API responses.

CREATE TABLE IF NOT EXISTS pypi_project_tracks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    -- PEP 503 normalized project name (lowercase, runs of [-_.] collapsed to -).
    normalized_name VARCHAR(512) NOT NULL,
    -- Upstream Simple index project URL this local project tracks, e.g.
    -- https://pypi.org/simple/acme-sdk/ . Emitted verbatim as the tracks value.
    tracks_url      TEXT NOT NULL,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, normalized_name)
);

CREATE INDEX IF NOT EXISTS idx_pypi_project_tracks_repo_name
    ON pypi_project_tracks (repository_id, normalized_name);
