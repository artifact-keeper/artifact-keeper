-- Add missing columns to OIDC configs
ALTER TABLE oidc_configs
    ADD COLUMN auto_create_users BOOLEAN NOT NULL DEFAULT true;

-- Add missing columns to LDAP configs
ALTER TABLE ldap_configs
    ADD COLUMN username_attribute VARCHAR(100) NOT NULL DEFAULT 'uid',
    ADD COLUMN groups_attribute VARCHAR(100) NOT NULL DEFAULT 'memberOf',
    ADD COLUMN admin_group_dn VARCHAR(512),
    ADD COLUMN use_starttls BOOLEAN NOT NULL DEFAULT false;

-- Add missing columns to SAML configs
ALTER TABLE saml_configs
    ADD COLUMN sp_entity_id VARCHAR(512) NOT NULL DEFAULT 'artifact-keeper',
    ADD COLUMN sign_requests BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN require_signed_assertions BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN admin_group VARCHAR(255);

-- Create SSO sessions table for CSRF state during OAuth/SAML flows
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_type VARCHAR(20) NOT NULL,
    provider_id UUID NOT NULL,
    state VARCHAR(512) UNIQUE NOT NULL,
    nonce VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX idx_sso_sessions_state ON sso_sessions(state);
