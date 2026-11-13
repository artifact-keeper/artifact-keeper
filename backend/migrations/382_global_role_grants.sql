-- Instance-wide roles held by a user, or by every member of a group, read by PermissionService::has_global_capability
-- Kept out of role_assignments so the existing repository access checks are not affected
CREATE TABLE IF NOT EXISTS user_global_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS group_global_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, role_id)
);

-- A security-reviewer grant written into role_assignments before this migration moves over
INSERT INTO user_global_roles (user_id, role_id)
SELECT ra.user_id, ra.role_id
FROM role_assignments ra
JOIN roles r ON r.id = ra.role_id
WHERE ra.repository_id IS NULL AND r.name = 'security-reviewer'
ON CONFLICT DO NOTHING;

DELETE FROM role_assignments ra
USING roles r
WHERE r.id = ra.role_id AND ra.repository_id IS NULL AND r.name = 'security-reviewer';
