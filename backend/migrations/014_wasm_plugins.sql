-- Migration 014: WASM Plugin System
-- Adds support for WASM-based format handler plugins

-- Add new enum types for plugin source and format handler type
DO $$ BEGIN
    CREATE TYPE plugin_source_type AS ENUM (
        'core',      -- Compiled-in Rust handler
        'wasm_git',  -- Installed from Git repository
        'wasm_zip',  -- Installed from ZIP file
        'wasm_local' -- Installed from local file path
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE format_handler_type AS ENUM (
        'core',    -- Compiled-in Rust handler
        'wasm'     -- WASM plugin handler
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Extend plugins table with WASM-specific fields
ALTER TABLE plugins
    ADD COLUMN IF NOT EXISTS source_type plugin_source_type NOT NULL DEFAULT 'core',
    ADD COLUMN IF NOT EXISTS source_url VARCHAR(1000),
    ADD COLUMN IF NOT EXISTS source_ref VARCHAR(200),
    ADD COLUMN IF NOT EXISTS wasm_path VARCHAR(500),
    ADD COLUMN IF NOT EXISTS manifest JSONB,
    ADD COLUMN IF NOT EXISTS capabilities JSONB,
    ADD COLUMN IF NOT EXISTS resource_limits JSONB,
    ADD COLUMN IF NOT EXISTS license VARCHAR(100);

-- Create format_handlers table to track all format handlers (core and WASM)
CREATE TABLE IF NOT EXISTS format_handlers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    format_key VARCHAR(50) UNIQUE NOT NULL,
    plugin_id UUID REFERENCES plugins(id) ON DELETE SET NULL,
    handler_type format_handler_type NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    extensions TEXT[] NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient format handler lookups
CREATE INDEX IF NOT EXISTS idx_format_handlers_format_key ON format_handlers(format_key);
CREATE INDEX IF NOT EXISTS idx_format_handlers_plugin_id ON format_handlers(plugin_id);
CREATE INDEX IF NOT EXISTS idx_format_handlers_enabled ON format_handlers(is_enabled) WHERE is_enabled = true;

-- Seed core format handlers (these match the existing compiled-in handlers)
INSERT INTO format_handlers (format_key, handler_type, display_name, description, extensions, is_enabled, priority)
VALUES
    ('maven', 'core', 'Maven', 'Maven repository format for Java artifacts', ARRAY['.jar', '.pom', '.war', '.ear'], true, 100),
    ('npm', 'core', 'npm', 'Node.js package manager', ARRAY['.tgz'], true, 100),
    ('pypi', 'core', 'PyPI', 'Python Package Index', ARRAY['.whl', '.tar.gz'], true, 100),
    ('nuget', 'core', 'NuGet', '.NET package manager', ARRAY['.nupkg'], true, 100),
    ('cargo', 'core', 'Cargo', 'Rust package manager', ARRAY['.crate'], true, 100),
    ('go', 'core', 'Go Modules', 'Go module proxy', ARRAY['.zip', '.mod'], true, 100),
    ('oci', 'core', 'OCI/Docker', 'Container images (OCI format)', ARRAY[], true, 100),
    ('helm', 'core', 'Helm', 'Kubernetes package manager', ARRAY['.tgz'], true, 100),
    ('debian', 'core', 'Debian', 'Debian packages', ARRAY['.deb'], true, 100),
    ('rpm', 'core', 'RPM', 'Red Hat packages', ARRAY['.rpm'], true, 100),
    ('rubygems', 'core', 'RubyGems', 'Ruby gems', ARRAY['.gem'], true, 100),
    ('conan', 'core', 'Conan', 'C/C++ package manager', ARRAY['.tgz'], true, 100),
    ('generic', 'core', 'Generic', 'Generic artifact storage', ARRAY[], true, 0)
ON CONFLICT (format_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    extensions = EXCLUDED.extensions;

-- Add trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_format_handlers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS format_handlers_updated_at ON format_handlers;
CREATE TRIGGER format_handlers_updated_at
    BEFORE UPDATE ON format_handlers
    FOR EACH ROW
    EXECUTE FUNCTION update_format_handlers_updated_at();
