-- Create auth_provider enum
CREATE TYPE auth_provider AS ENUM ('local', 'ldap', 'saml', 'oidc');

-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    auth_provider auth_provider NOT NULL DEFAULT 'local',
    external_id VARCHAR(512),
    display_name VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_admin BOOLEAN NOT NULL DEFAULT false,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_external_id ON users(auth_provider, external_id);

-- Admin user is created programmatically on first boot with a random password.
-- See main.rs: provision_admin_user()
