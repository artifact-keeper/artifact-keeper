-- Create system_settings table for configuration storage
CREATE TABLE system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_sensitive BOOLEAN NOT NULL DEFAULT false,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create ldap_configs table
CREATE TABLE ldap_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    server_url VARCHAR(2048) NOT NULL,
    bind_dn VARCHAR(512),
    bind_password_encrypted VARCHAR(1024),
    user_base_dn VARCHAR(512) NOT NULL,
    user_filter VARCHAR(512) NOT NULL DEFAULT '(uid={0})',
    group_base_dn VARCHAR(512),
    group_filter VARCHAR(512),
    email_attribute VARCHAR(100) NOT NULL DEFAULT 'mail',
    display_name_attribute VARCHAR(100) NOT NULL DEFAULT 'cn',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create saml_configs table
CREATE TABLE saml_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    entity_id VARCHAR(512) NOT NULL,
    sso_url VARCHAR(2048) NOT NULL,
    slo_url VARCHAR(2048),
    certificate TEXT NOT NULL,
    name_id_format VARCHAR(255) NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create oidc_configs table
CREATE TABLE oidc_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    issuer_url VARCHAR(2048) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted VARCHAR(1024) NOT NULL,
    scopes VARCHAR[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email'],
    attribute_mapping JSONB NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default system settings
INSERT INTO system_settings (key, value, description) VALUES
    ('storage.default_backend', '"filesystem"', 'Default storage backend for new repositories'),
    ('storage.deduplication_enabled', 'true', 'Enable content-addressable storage deduplication'),
    ('security.password_min_length', '12', 'Minimum password length'),
    ('security.session_timeout_minutes', '480', 'Session timeout in minutes'),
    ('security.api_token_max_age_days', '365', 'Maximum API token validity in days'),
    ('ui.theme', '"light"', 'Default UI theme'),
    ('ui.items_per_page', '25', 'Default pagination size');

-- Create indexes
CREATE INDEX idx_ldap_configs_enabled ON ldap_configs(is_enabled, priority);
CREATE INDEX idx_saml_configs_enabled ON saml_configs(is_enabled);
CREATE INDEX idx_oidc_configs_enabled ON oidc_configs(is_enabled);
