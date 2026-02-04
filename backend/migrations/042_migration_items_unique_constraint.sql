-- Add unique constraint on migration_items for resume support
-- Prevents duplicate items when re-processing after resume
CREATE UNIQUE INDEX IF NOT EXISTS idx_migration_items_job_source
    ON migration_items(job_id, source_path);
