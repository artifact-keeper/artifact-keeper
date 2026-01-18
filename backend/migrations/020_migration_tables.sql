-- Migration tables for Artifactory to Artifact Keeper migration
-- Feature: 004-artifactory-migration

-- Source connections for Artifactory instances
CREATE TABLE IF NOT EXISTS source_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    url VARCHAR(512) NOT NULL,
    auth_type VARCHAR(50) NOT NULL CHECK (auth_type IN ('api_token', 'basic_auth')),
    credentials_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    verified_at TIMESTAMPTZ,
    UNIQUE(name, created_by)
);

-- Migration jobs
CREATE TABLE IF NOT EXISTS migration_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_connection_id UUID NOT NULL REFERENCES source_connections(id),
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'assessing', 'ready', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    job_type VARCHAR(50) NOT NULL DEFAULT 'full'
        CHECK (job_type IN ('full', 'incremental', 'assessment')),
    config JSONB NOT NULL DEFAULT '{}',
    total_items INTEGER DEFAULT 0,
    completed_items INTEGER DEFAULT 0,
    failed_items INTEGER DEFAULT 0,
    skipped_items INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    transferred_bytes BIGINT DEFAULT 0,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    error_summary TEXT
);

-- Migration items (individual artifacts, repos, users, etc.)
CREATE TABLE IF NOT EXISTS migration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES migration_jobs(id) ON DELETE CASCADE,
    item_type VARCHAR(50) NOT NULL
        CHECK (item_type IN ('repository', 'artifact', 'user', 'group', 'permission', 'property')),
    source_path TEXT NOT NULL,
    target_path TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'skipped')),
    size_bytes BIGINT DEFAULT 0,
    checksum_source VARCHAR(64),
    checksum_target VARCHAR(64),
    metadata JSONB,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Migration reports
CREATE TABLE IF NOT EXISTS migration_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE REFERENCES migration_jobs(id) ON DELETE CASCADE,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    summary JSONB NOT NULL DEFAULT '{}',
    warnings JSONB NOT NULL DEFAULT '[]',
    errors JSONB NOT NULL DEFAULT '[]',
    recommendations JSONB NOT NULL DEFAULT '[]'
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_migration_jobs_status ON migration_jobs(status);
CREATE INDEX IF NOT EXISTS idx_migration_jobs_created_by ON migration_jobs(created_by);
CREATE INDEX IF NOT EXISTS idx_migration_items_job_status ON migration_items(job_id, status);
CREATE INDEX IF NOT EXISTS idx_migration_items_job_type ON migration_items(job_id, item_type);
CREATE INDEX IF NOT EXISTS idx_source_connections_created_by ON source_connections(created_by);
