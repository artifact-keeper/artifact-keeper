-- IAM policy snapshot invalidation (#4214).
--
-- The IAM shadow evaluator caches a snapshot built from the legacy
-- authorization tables and flushes it on the cache-invalidation channel of
-- migration 142. That migration notifies only for `permissions`,
-- `user_group_members` and group deletes; the snapshot also reads the tables
-- below. Each trigger publishes the existing `permissions_changed` event
-- (`ak_notify_permissions_changed()`), which every replica already
-- understands: an older replica in a rolling upgrade flushes its permission
-- cache, nothing more. A new event kind would make older replicas fall back to
-- a conservative flush of every authorization cache on each write.
--
-- Row-level, and on UPDATE only when a row actually changed: a statement-level
-- trigger fires for statements that match no row, and the SSO login paths run
-- `UPDATE users SET ..., is_admin = $3, last_login_at = NOW() WHERE ... AND
-- (... IS DISTINCT FROM ...)` on every login, which would flush every
-- replica's permission cache per login. Postgres delivers identical
-- notifications of one transaction once, so a bulk write still publishes a
-- single event.

DROP TRIGGER IF EXISTS ak_iam_roles_changed_notify ON roles;
CREATE TRIGGER ak_iam_roles_changed_notify
    AFTER INSERT OR DELETE ON roles
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_roles_updated_notify ON roles;
CREATE TRIGGER ak_iam_roles_updated_notify
    AFTER UPDATE ON roles
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_role_assignments_changed_notify ON role_assignments;
CREATE TRIGGER ak_iam_role_assignments_changed_notify
    AFTER INSERT OR DELETE ON role_assignments
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_role_assignments_updated_notify ON role_assignments;
CREATE TRIGGER ak_iam_role_assignments_updated_notify
    AFTER UPDATE ON role_assignments
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_user_roles_changed_notify ON user_roles;
CREATE TRIGGER ak_iam_user_roles_changed_notify
    AFTER INSERT OR DELETE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_user_roles_updated_notify ON user_roles;
CREATE TRIGGER ak_iam_user_roles_updated_notify
    AFTER UPDATE ON user_roles
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_permission_grants_changed_notify ON permission_grants;
CREATE TRIGGER ak_iam_permission_grants_changed_notify
    AFTER INSERT OR DELETE ON permission_grants
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_permission_grants_updated_notify ON permission_grants;
CREATE TRIGGER ak_iam_permission_grants_updated_notify
    AFTER UPDATE ON permission_grants
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

-- Deletes are already covered by migration 142.
DROP TRIGGER IF EXISTS ak_iam_groups_changed_notify ON groups;
CREATE TRIGGER ak_iam_groups_changed_notify
    AFTER INSERT ON groups
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_groups_updated_notify ON groups;
CREATE TRIGGER ak_iam_groups_updated_notify
    AFTER UPDATE ON groups
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_projects_changed_notify ON projects;
CREATE TRIGGER ak_iam_projects_changed_notify
    AFTER INSERT OR DELETE ON projects
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_projects_updated_notify ON projects;
CREATE TRIGGER ak_iam_projects_updated_notify
    AFTER UPDATE ON projects
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

-- `last_used_at` is written on every token use; only the ceiling matters.
DROP TRIGGER IF EXISTS ak_iam_api_tokens_changed_notify ON api_tokens;
CREATE TRIGGER ak_iam_api_tokens_changed_notify
    AFTER INSERT OR DELETE ON api_tokens
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_api_tokens_updated_notify ON api_tokens;
CREATE TRIGGER ak_iam_api_tokens_updated_notify
    AFTER UPDATE ON api_tokens
    FOR EACH ROW WHEN (
        OLD.scopes IS DISTINCT FROM NEW.scopes
        OR OLD.repo_selector IS DISTINCT FROM NEW.repo_selector
        OR OLD.user_id IS DISTINCT FROM NEW.user_id
    )
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_api_token_repositories_changed_notify ON api_token_repositories;
CREATE TRIGGER ak_iam_api_token_repositories_changed_notify
    AFTER INSERT OR DELETE ON api_token_repositories
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_api_token_repositories_updated_notify ON api_token_repositories;
CREATE TRIGGER ak_iam_api_token_repositories_updated_notify
    AFTER UPDATE ON api_token_repositories
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_ci_mappings_changed_notify ON ci_oidc_identity_mappings;
CREATE TRIGGER ak_iam_ci_mappings_changed_notify
    AFTER INSERT OR DELETE ON ci_oidc_identity_mappings
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_ci_mappings_updated_notify ON ci_oidc_identity_mappings;
CREATE TRIGGER ak_iam_ci_mappings_updated_notify
    AFTER UPDATE ON ci_oidc_identity_mappings
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_ci_providers_changed_notify ON ci_oidc_providers;
CREATE TRIGGER ak_iam_ci_providers_changed_notify
    AFTER INSERT OR DELETE ON ci_oidc_providers
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_ci_providers_updated_notify ON ci_oidc_providers;
CREATE TRIGGER ak_iam_ci_providers_updated_notify
    AFTER UPDATE ON ci_oidc_providers
    FOR EACH ROW WHEN (OLD.provider_type IS DISTINCT FROM NEW.provider_type)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_oidc_configs_changed_notify ON oidc_configs;
CREATE TRIGGER ak_iam_oidc_configs_changed_notify
    AFTER INSERT OR DELETE ON oidc_configs
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_oidc_configs_updated_notify ON oidc_configs;
CREATE TRIGGER ak_iam_oidc_configs_updated_notify
    AFTER UPDATE ON oidc_configs
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_ldap_configs_changed_notify ON ldap_configs;
CREATE TRIGGER ak_iam_ldap_configs_changed_notify
    AFTER INSERT OR DELETE ON ldap_configs
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_ldap_configs_updated_notify ON ldap_configs;
CREATE TRIGGER ak_iam_ldap_configs_updated_notify
    AFTER UPDATE ON ldap_configs
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

DROP TRIGGER IF EXISTS ak_iam_saml_configs_changed_notify ON saml_configs;
CREATE TRIGGER ak_iam_saml_configs_changed_notify
    AFTER INSERT OR DELETE ON saml_configs
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_saml_configs_updated_notify ON saml_configs;
CREATE TRIGGER ak_iam_saml_configs_updated_notify
    AFTER UPDATE ON saml_configs
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
    EXECUTE FUNCTION ak_notify_permissions_changed();

-- Deactivation and deletion are already published by migration 142. Login
-- writes (`last_login_at`, an unchanged `is_admin`) never fire.
DROP TRIGGER IF EXISTS ak_iam_users_changed_notify ON users;
CREATE TRIGGER ak_iam_users_changed_notify
    AFTER INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION ak_notify_permissions_changed();
DROP TRIGGER IF EXISTS ak_iam_users_updated_notify ON users;
CREATE TRIGGER ak_iam_users_updated_notify
    AFTER UPDATE ON users
    FOR EACH ROW WHEN (
        OLD.is_admin IS DISTINCT FROM NEW.is_admin
        OR OLD.is_service_account IS DISTINCT FROM NEW.is_service_account
        OR OLD.external_id IS DISTINCT FROM NEW.external_id
        OR OLD.username IS DISTINCT FROM NEW.username
        OR OLD.auth_provider IS DISTINCT FROM NEW.auth_provider
    )
    EXECUTE FUNCTION ak_notify_permissions_changed();

-- Visibility and key changes are published by `repository_changed`
-- (migration 245); a move to another project was not.
DROP TRIGGER IF EXISTS ak_iam_repository_project_changed_notify ON repositories;
CREATE TRIGGER ak_iam_repository_project_changed_notify
    AFTER UPDATE OF project_id ON repositories
    FOR EACH ROW WHEN (OLD.project_id IS DISTINCT FROM NEW.project_id)
    EXECUTE FUNCTION ak_notify_permissions_changed();
