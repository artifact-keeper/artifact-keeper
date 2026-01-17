-- Create plugin_config table for storing plugin configuration key-value pairs
CREATE TABLE IF NOT EXISTS plugin_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plugin_id UUID NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,
    value TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(plugin_id, key)
);

-- Create repository_config table for repository-specific settings
CREATE TABLE IF NOT EXISTS repository_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,
    value TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, key)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_plugin_config_plugin ON plugin_config(plugin_id);
CREATE INDEX IF NOT EXISTS idx_repository_config_repo ON repository_config(repository_id);
CREATE INDEX IF NOT EXISTS idx_repository_config_key ON repository_config(repository_id, key);
