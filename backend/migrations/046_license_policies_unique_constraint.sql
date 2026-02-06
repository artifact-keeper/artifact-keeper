-- Add unique constraint for license policy upsert
-- Policies are unique by (repository_id, name), where NULL repository_id means global
-- Uses COALESCE to handle NULL repository_id in the unique constraint

CREATE UNIQUE INDEX IF NOT EXISTS idx_license_policies_repo_name
    ON license_policies (COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
