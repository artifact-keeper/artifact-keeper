-- Package curation: rules engine and package catalog

-- Curation rules (explicit allow/block lists)
CREATE TABLE IF NOT EXISTS curation_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staging_repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    package_pattern TEXT NOT NULL,
    version_constraint TEXT NOT NULL DEFAULT '*',
    architecture    TEXT NOT NULL DEFAULT '*',
    action          TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    priority        INT NOT NULL DEFAULT 100,
    reason          TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_curation_rules_repo ON curation_rules(staging_repo_id) WHERE staging_repo_id IS NOT NULL;
CREATE INDEX idx_curation_rules_global ON curation_rules(priority) WHERE staging_repo_id IS NULL;

-- Curation package catalog (upstream packages tracked through staging)
CREATE TABLE IF NOT EXISTS curation_packages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staging_repo_id     UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    remote_repo_id      UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    format              TEXT NOT NULL,
    package_name        TEXT NOT NULL,
    version             TEXT NOT NULL,
    release             TEXT,
    architecture        TEXT,
    checksum_sha256     TEXT,
    upstream_path       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'blocked', 'review')),
    evaluated_at        TIMESTAMPTZ,
    evaluated_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    evaluation_reason   TEXT,
    rule_id             UUID REFERENCES curation_rules(id) ON DELETE SET NULL,
    metadata            JSONB NOT NULL DEFAULT '{}',
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    upstream_updated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_curation_pkg_unique ON curation_packages(staging_repo_id, format, package_name, version, COALESCE(release, ''), COALESCE(architecture, ''));
CREATE INDEX idx_curation_pkg_status ON curation_packages(staging_repo_id, status);
CREATE INDEX idx_curation_pkg_name ON curation_packages(staging_repo_id, package_name);

-- Curation columns on repositories table
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS curation_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS curation_source_repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS curation_target_repo_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS curation_default_action TEXT NOT NULL DEFAULT 'allow' CHECK (curation_default_action IN ('allow', 'review')),
    ADD COLUMN IF NOT EXISTS curation_sync_interval_secs INT NOT NULL DEFAULT 3600,
    ADD COLUMN IF NOT EXISTS curation_auto_fetch BOOLEAN NOT NULL DEFAULT false;
