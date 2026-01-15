-- Create permission_type enum
CREATE TYPE permission_type AS ENUM ('read', 'write', 'delete', 'admin');

-- Create roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create permission_grants table
CREATE TABLE permission_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    repository_id UUID, -- NULL means all repositories
    permission permission_type NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create role_assignments table
CREATE TABLE role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    repository_id UUID, -- NULL means global assignment
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, role_id, repository_id)
);

-- Create default roles
INSERT INTO roles (name, description, is_system) VALUES
    ('admin', 'Full system access', true),
    ('developer', 'Read/write access to assigned repositories', true),
    ('reader', 'Read-only access to assigned repositories', true);

-- Grant admin role to admin user
INSERT INTO role_assignments (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'admin';
