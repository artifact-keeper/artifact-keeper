-- Server-side image builds: a repository-scoped record of every container
-- image the image builder produced (or tried to) from a structured spec.
--
-- The builder never accepts a user-authored Dockerfile: `spec` is the
-- structured request (base image, packages, env, labels) and `containerfile`
-- is the text the server rendered from it — kept verbatim so the build can
-- be audited and reproduced. `log` is the buildctl output, appended while
-- the build runs and capped by the service; `digest` is the manifest digest
-- of the pushed tag once the build succeeded.
--
-- Rows outlive the tag they produced (a deleted tag keeps its build history);
-- they go with their repository.
CREATE TABLE image_builds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    image TEXT NOT NULL,
    tag TEXT NOT NULL,
    spec JSONB NOT NULL,
    containerfile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    digest TEXT,
    log TEXT NOT NULL DEFAULT '',
    error TEXT,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_by_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX idx_image_builds_repo_created ON image_builds(repository_id, created_at DESC);
