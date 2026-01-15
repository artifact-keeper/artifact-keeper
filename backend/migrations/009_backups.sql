-- Create backup_status enum
CREATE TYPE backup_status AS ENUM ('pending', 'in_progress', 'completed', 'failed', 'cancelled');

-- Create backup_type enum
CREATE TYPE backup_type AS ENUM ('full', 'incremental', 'metadata_only');

-- Create backup_jobs table
CREATE TABLE backup_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    backup_type backup_type NOT NULL,
    status backup_status NOT NULL DEFAULT 'pending',
    storage_destination VARCHAR(2048) NOT NULL,
    include_repositories UUID[], -- NULL means all
    include_metadata BOOLEAN NOT NULL DEFAULT true,
    include_configs BOOLEAN NOT NULL DEFAULT true,
    compression VARCHAR(20) NOT NULL DEFAULT 'gzip',
    encryption_enabled BOOLEAN NOT NULL DEFAULT false,
    encryption_key_id VARCHAR(255),
    total_size_bytes BIGINT,
    files_count INTEGER,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create backup_schedules table
CREATE TABLE backup_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    backup_type backup_type NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    storage_destination VARCHAR(2048) NOT NULL,
    include_repositories UUID[],
    retention_days INTEGER NOT NULL DEFAULT 30,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create restore_jobs table
CREATE TABLE restore_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_job_id UUID REFERENCES backup_jobs(id) ON DELETE SET NULL,
    source_path VARCHAR(2048) NOT NULL,
    status backup_status NOT NULL DEFAULT 'pending',
    restore_metadata BOOLEAN NOT NULL DEFAULT true,
    restore_artifacts BOOLEAN NOT NULL DEFAULT true,
    target_repositories UUID[], -- NULL means all from backup
    files_restored INTEGER,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_backup_jobs_status ON backup_jobs(status, created_at);
CREATE INDEX idx_backup_schedules_next ON backup_schedules(is_enabled, next_run_at);
CREATE INDEX idx_restore_jobs_status ON restore_jobs(status, created_at);
