-- Create plugin_status enum
CREATE TYPE plugin_status AS ENUM ('active', 'disabled', 'error');

-- Create plugin_type enum
CREATE TYPE plugin_type AS ENUM ('format_handler', 'storage_backend', 'authentication', 'authorization', 'webhook', 'custom');

-- Create plugins table
CREATE TABLE plugins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    version VARCHAR(50) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    author VARCHAR(255),
    homepage VARCHAR(2048),
    status plugin_status NOT NULL DEFAULT 'disabled',
    plugin_type plugin_type NOT NULL,
    config JSONB,
    config_schema JSONB,
    installed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    enabled_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create plugin_hooks table
CREATE TABLE plugin_hooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plugin_id UUID NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    hook_type VARCHAR(100) NOT NULL,
    handler_name VARCHAR(255) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(plugin_id, hook_type, handler_name)
);

-- Create plugin_events table (for plugin event logging)
CREATE TABLE plugin_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plugin_id UUID NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_plugins_status ON plugins(status);
CREATE INDEX idx_plugins_type ON plugins(plugin_type);
CREATE INDEX idx_plugin_hooks_type ON plugin_hooks(hook_type, is_enabled, priority);
CREATE INDEX idx_plugin_events_plugin ON plugin_events(plugin_id, created_at);
CREATE INDEX idx_plugin_events_severity ON plugin_events(severity, created_at);
