-- Establish durable, action-aware repository ownership without switching
-- existing installations to the new authorization model in one step.
--
-- The built-in roles were originally seeded with empty `permissions` arrays,
-- so action-aware checks had to infer capabilities from role names. Populate
-- the intended capabilities first; endpoint enforcement can then migrate to
-- these values independently.
UPDATE roles
SET permissions = CASE name
        WHEN 'admin' THEN ARRAY['read', 'write', 'delete', 'admin']::TEXT[]
        WHEN 'developer' THEN ARRAY['read', 'write']::TEXT[]
        WHEN 'reader' THEN ARRAY['read']::TEXT[]
    END,
    updated_at = NOW()
WHERE name IN ('admin', 'developer', 'reader');

-- Keep repository ownership distinct from the legacy developer role. The
-- `admin` capability is durable: a fine-grained rule may narrow an ordinary
-- role, but it must not silently strip the repository owner of control.
INSERT INTO roles (name, description, permissions, is_system)
VALUES (
    'repository-owner',
    'Full control of assigned repositories',
    ARRAY['read', 'write', 'delete', 'admin']::TEXT[],
    true
)
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description,
    permissions = EXCLUDED.permissions,
    is_system = true,
    updated_at = NOW();

-- Repositories created after migration 128 have an authoritative creator.
-- Add the owner role alongside the existing developer assignment so upgrades
-- are additive and remain compatible with code that still reads legacy roles.
INSERT INTO role_assignments (user_id, role_id, repository_id)
SELECT repo.created_by, owner_role.id, repo.id
FROM repositories repo
CROSS JOIN roles owner_role
WHERE owner_role.name = 'repository-owner'
  AND repo.created_by IS NOT NULL
ON CONFLICT (user_id, role_id, repository_id) DO NOTHING;

-- Older repositories have no `created_by` value. On a rule-less repository,
-- every repository-scoped developer currently receives the legacy mutation
-- capability and may therefore be the historical owner. Preserve that
-- effective access during the staged migration by promoting those principals
-- to explicit owners. Repositories already governed by repository/project
-- rules are deliberately left alone because their ACL is authoritative.
INSERT INTO role_assignments (user_id, role_id, repository_id)
SELECT legacy.user_id, owner_role.id, legacy.repository_id
FROM role_assignments legacy
JOIN roles legacy_role ON legacy_role.id = legacy.role_id
JOIN repositories repo ON repo.id = legacy.repository_id
CROSS JOIN roles owner_role
WHERE legacy_role.name = 'developer'
  AND owner_role.name = 'repository-owner'
  AND repo.created_by IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM permissions permission
      WHERE (permission.target_type = 'repository' AND permission.target_id = repo.id)
         OR (
             permission.target_type = 'project'
             AND permission.target_id = repo.project_id
         )
  )
ON CONFLICT (user_id, role_id, repository_id) DO NOTHING;
