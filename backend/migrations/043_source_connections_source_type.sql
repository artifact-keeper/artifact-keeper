-- Add source_type column to support Nexus and other registries
ALTER TABLE source_connections
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(50) NOT NULL DEFAULT 'artifactory';
