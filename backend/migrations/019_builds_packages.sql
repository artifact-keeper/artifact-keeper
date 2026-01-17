-- Builds table for tracking CI/CD builds
CREATE TABLE IF NOT EXISTS builds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    build_number INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, success, failed, cancelled
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT,
    agent VARCHAR(255),
    artifact_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Build artifacts table
CREATE TABLE IF NOT EXISTS build_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id UUID NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    module_name VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Packages table for package management
CREATE TABLE IF NOT EXISTS packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    description TEXT,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    download_count BIGINT NOT NULL DEFAULT 0,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, name, version)
);

-- Package versions table for version history
CREATE TABLE IF NOT EXISTS package_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id UUID NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version VARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    download_count BIGINT NOT NULL DEFAULT 0,
    checksum_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(package_id, version)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_builds_status ON builds(status);
CREATE INDEX IF NOT EXISTS idx_builds_build_number ON builds(build_number DESC);
CREATE INDEX IF NOT EXISTS idx_builds_created_at ON builds(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_build_artifacts_build_id ON build_artifacts(build_id);
CREATE INDEX IF NOT EXISTS idx_packages_repository_id ON packages(repository_id);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_package_versions_package_id ON package_versions(package_id);
