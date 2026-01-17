-- Groups table for organizing users
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User group memberships
CREATE TABLE IF NOT EXISTS user_group_members (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Permissions table for fine-grained access control
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type VARCHAR(50) NOT NULL, -- 'user' or 'group'
    principal_id UUID NOT NULL,
    target_type VARCHAR(50) NOT NULL, -- 'repository', 'group', 'artifact'
    target_id UUID NOT NULL,
    actions TEXT[] NOT NULL DEFAULT '{}', -- array of actions: 'read', 'write', 'delete', 'admin'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(principal_type, principal_id, target_type, target_id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_user_group_members_group_id ON user_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_permissions_principal ON permissions(principal_type, principal_id);
CREATE INDEX IF NOT EXISTS idx_permissions_target ON permissions(target_type, target_id);
