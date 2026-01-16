-- Create backups table for backup_service.rs
-- Note: backup_jobs table exists for scheduled backups; this backups table is for direct backup operations

-- Add 'metadata' value to backup_type enum if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'metadata' AND enumtypid = 'backup_type'::regtype) THEN
        ALTER TYPE backup_type ADD VALUE 'metadata';
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type backup_type NOT NULL,
    status backup_status NOT NULL DEFAULT 'pending',
    storage_path VARCHAR(2048),
    size_bytes BIGINT,
    artifact_count BIGINT,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    metadata JSONB,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_backups_status ON backups(status, created_at);
CREATE INDEX IF NOT EXISTS idx_backups_type ON backups(backup_type);
