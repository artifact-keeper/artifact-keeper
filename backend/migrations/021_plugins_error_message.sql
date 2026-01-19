-- Migration 021: Add error_message column to plugins table
-- This column stores error information when a plugin fails to load or execute

ALTER TABLE plugins
    ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Add a comment explaining the column
COMMENT ON COLUMN plugins.error_message IS 'Stores error message when plugin status is "error"';
