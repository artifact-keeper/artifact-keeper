//! Database adapter: reads the legacy authorization tables into a
//! [`LegacyAuthorizationState`].
//!
//! Read-only by construction: it issues only `SELECT`s, selects no credential
//! column (password hashes, token hashes, token prefixes), and takes a plain
//! connection so the caller decides the transaction it runs in.

use sqlx::{FromRow, PgConnection, PgPool};
use uuid::Uuid;

use super::legacy::{
    LegacyAuthSource, LegacyAuthorizationState, LegacyCiMapping, LegacyGroup, LegacyMembership,
    LegacyPrincipal, LegacyProject, LegacyRepository, LegacyRole, LegacyRoleAssignment, LegacyRule,
    LegacySsoAdminConfig, LegacySsoConfig, LegacyToken, LegacyUser, LegacyUserRole,
};

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    auth_provider: String,
    is_admin: bool,
    is_active: bool,
    is_service_account: bool,
}

#[derive(FromRow)]
struct RoleRow {
    id: Uuid,
    name: String,
    permissions: Vec<String>,
}

#[derive(FromRow)]
struct AssignmentRow {
    id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    repository_id: Option<Uuid>,
}

#[derive(FromRow)]
struct RuleRow {
    id: Uuid,
    principal_type: String,
    principal_id: Uuid,
    target_type: String,
    target_id: Uuid,
    actions: Vec<String>,
    conditions: Option<serde_json::Value>,
}

#[derive(FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    external_source: Option<String>,
    external_provider_id: Option<Uuid>,
}

#[derive(FromRow)]
struct MembershipRow {
    user_id: Uuid,
    group_id: Uuid,
}

#[derive(FromRow)]
struct RepositoryRow {
    id: Uuid,
    key: String,
    project_id: Option<Uuid>,
}

#[derive(FromRow)]
struct ProjectRow {
    id: Uuid,
    key: String,
}

#[derive(FromRow)]
struct TokenRow {
    id: Uuid,
    user_id: Uuid,
    scopes: Vec<String>,
    repo_selector: Option<serde_json::Value>,
}

#[derive(FromRow)]
struct TokenRepoRow {
    token_id: Uuid,
    repo_id: Uuid,
}

#[derive(FromRow)]
struct CiMappingRow {
    id: Uuid,
    provider_id: Uuid,
    provider_type: Option<String>,
    allowed_repo_ids: Option<Vec<Uuid>>,
    group_binding_ids: Option<Vec<Uuid>>,
    is_enabled: bool,
    service_account_id: Option<Uuid>,
}

fn principal(kind: &str, id: Uuid) -> LegacyPrincipal {
    match kind {
        "user" => LegacyPrincipal::User(id),
        "service_account" => LegacyPrincipal::ServiceAccount(id),
        "group" => LegacyPrincipal::Group(id),
        "anonymous" => LegacyPrincipal::Anonymous,
        other => LegacyPrincipal::Unknown {
            principal_type: other.to_string(),
            id,
        },
    }
}

/// Read the database part of the legacy authorization state.
///
/// Rows are returned sorted by primary key so that the result is stable for a
/// given database state. SSO settings are not stored here and are captured
/// separately.
pub async fn read_database_state(
    conn: &mut PgConnection,
) -> Result<LegacyAuthorizationState, sqlx::Error> {
    let users: Vec<UserRow> = sqlx::query_as(
        "SELECT id, username, auth_provider::text AS auth_provider, is_admin, is_active, \
                is_service_account \
         FROM users ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let roles: Vec<RoleRow> = sqlx::query_as("SELECT id, name, permissions FROM roles ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    let assignments: Vec<AssignmentRow> = sqlx::query_as(
        "SELECT id, user_id, role_id, repository_id FROM role_assignments ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, principal_type, principal_id, target_type, target_id, actions, conditions \
         FROM permissions ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let groups: Vec<GroupRow> = sqlx::query_as(
        "SELECT id, name, external_source, external_provider_id FROM groups ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let memberships: Vec<MembershipRow> = sqlx::query_as(
        "SELECT user_id, group_id FROM user_group_members ORDER BY group_id, user_id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let repositories: Vec<RepositoryRow> =
        sqlx::query_as("SELECT id, key, project_id FROM repositories ORDER BY id")
            .fetch_all(&mut *conn)
            .await?;
    let projects: Vec<ProjectRow> = sqlx::query_as("SELECT id, key FROM projects ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    // Never the token's secret material: only what limits its authority.
    let tokens: Vec<TokenRow> =
        sqlx::query_as("SELECT id, user_id, scopes, repo_selector FROM api_tokens ORDER BY id")
            .fetch_all(&mut *conn)
            .await?;
    let token_repos: Vec<TokenRepoRow> = sqlx::query_as(
        "SELECT token_id, repo_id FROM api_token_repositories ORDER BY token_id, repo_id",
    )
    .fetch_all(&mut *conn)
    .await?;
    // The mapping's service account carries the external id `ci:<provider>:<mapping>`.
    let mappings: Vec<CiMappingRow> = sqlx::query_as(
        "SELECT m.id, m.provider_id, m.allowed_repo_ids, m.group_binding_ids, m.is_enabled, \
                (SELECT p.provider_type::text FROM ci_oidc_providers p WHERE p.id = m.provider_id) \
                    AS provider_type, \
                (SELECT u.id FROM users u \
                  WHERE u.external_id = 'ci:' || m.provider_id::text || ':' || m.id::text \
                  ORDER BY u.id LIMIT 1) AS service_account_id \
         FROM ci_oidc_identity_mappings m ORDER BY m.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let user_roles: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT user_id, role_id FROM user_roles ORDER BY user_id, role_id")
            .fetch_all(&mut *conn)
            .await?;
    let permission_grants: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM permission_grants ORDER BY id")
            .fetch_all(&mut *conn)
            .await?;

    Ok(LegacyAuthorizationState {
        users: users
            .into_iter()
            .map(|u| LegacyUser {
                id: u.id,
                username: u.username,
                auth_source: if u.auth_provider == "local" {
                    LegacyAuthSource::Local
                } else {
                    LegacyAuthSource::External(u.auth_provider)
                },
                is_admin: u.is_admin,
                is_active: u.is_active,
                is_service_account: u.is_service_account,
            })
            .collect(),
        roles: roles
            .into_iter()
            .map(|r| LegacyRole {
                id: r.id,
                name: r.name,
                permissions: r.permissions,
            })
            .collect(),
        role_assignments: assignments
            .into_iter()
            .map(|a| LegacyRoleAssignment {
                id: a.id,
                user_id: a.user_id,
                role_id: a.role_id,
                repository_id: a.repository_id,
            })
            .collect(),
        rules: rules
            .into_iter()
            .map(|r| LegacyRule {
                id: r.id,
                principal: principal(&r.principal_type, r.principal_id),
                target_type: r.target_type,
                target_id: r.target_id,
                actions: r.actions,
                conditions: r.conditions,
            })
            .collect(),
        groups: groups
            .into_iter()
            .map(|g| LegacyGroup {
                id: g.id,
                name: g.name,
                external_source: g.external_source,
                external_provider_id: g.external_provider_id,
            })
            .collect(),
        memberships: memberships
            .into_iter()
            .map(|m| LegacyMembership {
                user_id: m.user_id,
                group_id: m.group_id,
            })
            .collect(),
        repositories: repositories
            .into_iter()
            .map(|r| LegacyRepository {
                id: r.id,
                key: r.key,
                project_id: r.project_id,
            })
            .collect(),
        projects: projects
            .into_iter()
            .map(|p| LegacyProject {
                id: p.id,
                key: p.key,
            })
            .collect(),
        tokens: tokens
            .into_iter()
            .map(|t| {
                let repos: Vec<Uuid> = token_repos
                    .iter()
                    .filter(|r| r.token_id == t.id)
                    .map(|r| r.repo_id)
                    .collect();
                LegacyToken {
                    id: t.id,
                    user_id: t.user_id,
                    scopes: t.scopes,
                    allowed_repo_ids: (!repos.is_empty()).then_some(repos),
                    repo_selector: t.repo_selector,
                }
            })
            .collect(),
        ci_mappings: mappings
            .into_iter()
            .map(|m| LegacyCiMapping {
                id: m.id,
                provider_id: m.provider_id,
                provider_type: m.provider_type,
                service_account_id: m.service_account_id,
                group_binding_ids: m.group_binding_ids,
                allowed_repo_ids: m.allowed_repo_ids,
                is_enabled: m.is_enabled,
            })
            .collect(),
        sso: Default::default(),
        user_roles: user_roles
            .into_iter()
            .map(|(user_id, role_id)| LegacyUserRole { user_id, role_id })
            .collect(),
        permission_grants,
    })
}

/// The administrator-group settings of the configured identity providers.
///
/// Reads only the admin-group columns and the `admin_group` mapping key, never
/// a client secret, bind password or certificate. A provider whose stored
/// mapping is not a JSON object is listed as unreadable instead of being
/// treated as having no administrator group.
pub async fn read_sso_config(conn: &mut PgConnection) -> Result<LegacySsoConfig, sqlx::Error> {
    let mut config = LegacySsoConfig::default();

    let oidc: Vec<(String, bool, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT name, is_enabled, attribute_mapping FROM oidc_configs ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut oidc_groups = Vec::new();
    for (name, enabled, mapping) in oidc {
        match mapping {
            Some(serde_json::Value::Object(map)) => {
                if let Some(group) = map
                    .get("admin_group")
                    .and_then(|v| v.as_str())
                    .filter(|g| !g.is_empty())
                {
                    oidc_groups.push(group.to_string());
                }
            }
            _ if enabled => config.unreadable_providers.push(format!("oidc:{name}")),
            _ => {}
        }
    }

    let ldap: Vec<Option<String>> =
        sqlx::query_scalar("SELECT admin_group_dn FROM ldap_configs ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;
    let mut ldap_groups = Vec::new();
    for dn in ldap.into_iter().flatten().filter(|d| !d.is_empty()) {
        if let Some(cn) = ldap_common_name(&dn) {
            ldap_groups.push(cn);
        }
        ldap_groups.push(dn);
    }

    let saml: Vec<Option<String>> =
        sqlx::query_scalar("SELECT admin_group FROM saml_configs ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;
    let saml_groups: Vec<String> = saml
        .into_iter()
        .flatten()
        .filter(|g| !g.is_empty())
        .collect();

    for (provider, mut groups) in [
        ("oidc", oidc_groups),
        ("ldap", ldap_groups),
        ("saml", saml_groups),
    ] {
        groups.sort();
        groups.dedup();
        if !groups.is_empty() {
            config.providers.push(LegacySsoAdminConfig {
                provider: provider.to_string(),
                admin_groups: groups,
            });
        }
    }
    config.unreadable_providers.sort();
    Ok(config)
}

/// The value of the first `cn=` component of a DN, if any.
fn ldap_common_name(dn: &str) -> Option<String> {
    dn.split(',').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("cn")
            .then(|| value.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Begin a transaction that sees one coherent snapshot and cannot write.
pub async fn begin_snapshot(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Must be the first statement of the transaction.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Capture the legacy authorization state: the database tables and the
/// non-secret SSO settings, all from one repeatable-read snapshot. A later call
/// observes whatever was committed in between; nothing is cached.
pub async fn capture_legacy_state(pool: &PgPool) -> Result<LegacyAuthorizationState, sqlx::Error> {
    let mut tx = begin_snapshot(pool).await?;
    let mut state = read_database_state(&mut tx).await?;
    state.sso = read_sso_config(&mut tx).await?;
    // Read-only: nothing to commit.
    tx.rollback().await?;
    Ok(state)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// The reader's own source (everything before this test module) must not
    /// contain a statement that writes.
    #[test]
    fn reader_source_contains_only_selects() {
        let src = include_str!("reader.rs");
        let production = src.split("mod tests {").next().unwrap().to_uppercase();
        for verb in [
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "TRUNCATE ",
            "ALTER ",
            "DROP ",
            "CREATE ",
        ] {
            assert!(
                !production.contains(&format!("\"{verb}"))
                    && !production.contains(&format!(" {verb}INTO")),
                "reader.rs contains a `{verb}` statement"
            );
        }
        // And it never selects a credential column.
        let lower = src.split("mod tests {").next().unwrap().to_lowercase();
        for column in [
            "password_hash",
            "token_hash",
            "token_prefix",
            "client_secret",
            "bind_password",
        ] {
            assert!(!lower.contains(column), "reader.rs selects `{column}`");
        }
    }

    #[tokio::test]
    async fn reads_seeded_rows_in_a_read_only_transaction_without_secrets() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, username) = tdh::create_user(&pool).await;
        let (service_account, _) = tdh::create_service_account(&pool).await;
        let (group, group_name) = tdh::create_group(&pool).await;
        let (repo, _key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_role(&pool, repo, user, "developer").await;

        let password_secret = format!("PW-SECRET-{}", Uuid::new_v4());
        let token_secret = format!("TOKEN-SECRET-{}", Uuid::new_v4());
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(user)
            .bind(&password_secret)
            .execute(&pool)
            .await
            .unwrap();
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO projects (id, key, name) VALUES ($1, $2, 'p')")
            .bind(project)
            .bind(format!("proj-{project}"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE repositories SET project_id = $2 WHERE id = $1")
            .bind(repo)
            .bind(project)
            .execute(&pool)
            .await
            .unwrap();
        let rule = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO permissions (id, principal_type, principal_id, target_type, target_id, actions, conditions) \
             VALUES ($1, 'group', $2, 'repository', $3, ARRAY['read','write'], '{\"allowed_cidrs\":[\"10.0.0.0/8\"]}'::jsonb)",
        )
        .bind(rule)
        .bind(group)
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(user)
            .bind(group)
            .execute(&pool)
            .await
            .unwrap();
        let token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes) \
             VALUES ($1, $2, 'ci', $3, 'abcd1234', ARRAY['read:artifacts'])",
        )
        .bind(token)
        .bind(user)
        .bind(&token_secret)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(token)
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        let provider = Uuid::new_v4();
        let mapping = Uuid::new_v4();
        sqlx::query("INSERT INTO ci_oidc_providers (id, name, issuer_url) VALUES ($1, $2, 'https://issuer.test')")
            .bind(provider)
            .bind(format!("prov-{provider}"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ci_oidc_identity_mappings (id, provider_id, name, allowed_repo_ids, group_binding_ids) \
             VALUES ($1, $2, 'm', ARRAY[$3]::uuid[], ARRAY[$4]::uuid[])",
        )
        .bind(mapping)
        .bind(provider)
        .bind(repo)
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE users SET external_id = $2 WHERE id = $1")
            .bind(service_account)
            .bind(format!("ci:{provider}:{mapping}"))
            .execute(&pool)
            .await
            .unwrap();

        // A write attempted inside this transaction would fail.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .unwrap();
        let state = read_database_state(&mut tx)
            .await
            .expect("read legacy state");
        tx.rollback().await.unwrap();

        let u = state.users.iter().find(|u| u.id == user).expect("user");
        assert_eq!(u.username, username);
        assert_eq!(u.auth_source, LegacyAuthSource::Local);
        assert!(!u.is_admin && !u.is_service_account);
        assert!(state
            .users
            .iter()
            .any(|u| u.id == service_account && u.is_service_account));
        assert!(state
            .roles
            .iter()
            .any(|r| r.name == "developer" && !r.permissions.is_empty()));
        assert!(state
            .role_assignments
            .iter()
            .any(|a| a.user_id == user && a.repository_id == Some(repo)));
        let r = state.rules.iter().find(|r| r.id == rule).expect("rule");
        assert_eq!(r.principal, LegacyPrincipal::Group(group));
        assert_eq!(r.target_type, "repository");
        assert_eq!(r.actions, vec!["read".to_string(), "write".to_string()]);
        assert_eq!(
            r.conditions.as_ref().unwrap()["allowed_cidrs"][0],
            "10.0.0.0/8"
        );
        assert!(state
            .groups
            .iter()
            .any(|g| g.id == group && g.name == group_name));
        assert!(state
            .memberships
            .iter()
            .any(|m| m.user_id == user && m.group_id == group));
        assert!(state
            .repositories
            .iter()
            .any(|r| r.id == repo && r.project_id == Some(project)));
        assert!(state.projects.iter().any(|p| p.id == project));
        let t = state.tokens.iter().find(|t| t.id == token).expect("token");
        assert_eq!(t.scopes, vec!["read:artifacts".to_string()]);
        assert_eq!(t.allowed_repo_ids, Some(vec![repo]));
        let m = state
            .ci_mappings
            .iter()
            .find(|m| m.id == mapping)
            .expect("mapping");
        assert_eq!(m.service_account_id, Some(service_account));
        assert_eq!(m.group_binding_ids, Some(vec![group]));
        assert_eq!(m.allowed_repo_ids, Some(vec![repo]));

        let dump = format!("{state:?}");
        assert!(!dump.contains(&password_secret), "password hash leaked");
        assert!(!dump.contains(&token_secret), "token hash leaked");
        assert!(!dump.contains("abcd1234"), "token prefix leaked");

        // Cleanup.
        let _ = sqlx::query("DELETE FROM ci_oidc_identity_mappings WHERE id = $1")
            .bind(mapping)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM ci_oidc_providers WHERE id = $1")
            .bind(provider)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(token)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(rule)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
            .bind(group)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo, user).await;
        let _ = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(service_account)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sso_admin_settings_are_read_without_provider_secrets() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let tag = Uuid::new_v4();
        let secret = format!("SSO-SECRET-{tag}");
        let oidc = format!("oidc-{tag}");
        let broken = format!("broken-{tag}");
        let ldap = format!("ldap-{tag}");
        let saml = format!("saml-{tag}");
        sqlx::query(
            "INSERT INTO oidc_configs (name, issuer_url, client_id, client_secret_encrypted, attribute_mapping) \
             VALUES ($1, 'https://idp.test', 'cid', $2, '{\"admin_group\": \"corp-admins\"}'::jsonb), \
                    ($3, 'https://idp2.test', 'cid', $2, '[]'::jsonb)",
        )
        .bind(&oidc)
        .bind(&secret)
        .bind(&broken)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ldap_configs (name, server_url, user_base_dn, bind_password_encrypted, admin_group_dn) \
             VALUES ($1, 'ldap://x', 'dc=x', $2, 'cn=ldap-admins,ou=groups,dc=x')",
        )
        .bind(&ldap)
        .bind(&secret)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO saml_configs (name, entity_id, sso_url, certificate, admin_group) \
             VALUES ($1, 'e', 'https://sso.test', $2, 'saml-admins')",
        )
        .bind(&saml)
        .bind(&secret)
        .execute(&pool)
        .await
        .unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let config = read_sso_config(&mut conn).await.unwrap();
        drop(conn);
        let groups = |provider: &str| -> Vec<String> {
            config
                .providers
                .iter()
                .filter(|p| p.provider == provider)
                .flat_map(|p| p.admin_groups.clone())
                .collect()
        };
        assert!(groups("oidc").contains(&"corp-admins".to_string()));
        assert!(
            groups("ldap").contains(&"ldap-admins".to_string()),
            "common name"
        );
        assert!(
            groups("ldap").contains(&"cn=ldap-admins,ou=groups,dc=x".to_string()),
            "full DN"
        );
        assert!(groups("saml").contains(&"saml-admins".to_string()));
        // A provider whose mapping is not an object is unreadable, not "no admins".
        assert!(config
            .unreadable_providers
            .contains(&format!("oidc:{broken}")));
        assert!(
            !format!("{config:?}").contains(&secret),
            "provider secret leaked"
        );

        let _ = sqlx::query("DELETE FROM oidc_configs WHERE name = $1 OR name = $2")
            .bind(&oidc)
            .bind(&broken)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM ldap_configs WHERE name = $1")
            .bind(&ldap)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM saml_configs WHERE name = $1")
            .bind(&saml)
            .execute(&pool)
            .await;
    }

    #[test]
    fn ldap_common_names_are_extracted_from_dns() {
        assert_eq!(
            ldap_common_name("cn=admins,ou=g,dc=x").as_deref(),
            Some("admins")
        );
        assert_eq!(
            ldap_common_name("OU=g, CN = Ops ,dc=x").as_deref(),
            Some("Ops")
        );
        assert_eq!(ldap_common_name("ou=g,dc=x"), None);
        assert_eq!(ldap_common_name("cn=,dc=x"), None);
        assert_eq!(ldap_common_name("not a dn"), None);
    }

    #[tokio::test]
    async fn a_snapshot_is_repeatable_read_only_and_a_later_capture_sees_commits() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let mut tx = begin_snapshot(&pool).await.unwrap();
        let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let read_only: String = sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(isolation, "repeatable read");
        assert_eq!(read_only, "on");

        // Take the snapshot, then commit a change from another connection.
        let before = read_database_state(&mut tx).await.unwrap();
        let (late_user, _) = tdh::create_user(&pool).await;
        let again = read_database_state(&mut tx).await.unwrap();
        assert_eq!(
            before.users, again.users,
            "one coherent state within a snapshot"
        );
        assert!(!again.users.iter().any(|u| u.id == late_user));
        // A write in the snapshot is refused.
        assert!(sqlx::query("DELETE FROM user_roles")
            .execute(&mut *tx)
            .await
            .is_err());
        tx.rollback().await.unwrap();

        // The next capture observes the committed change, with no backfill.
        let next = capture_legacy_state(&pool).await.unwrap();
        assert!(next.users.iter().any(|u| u.id == late_user));
        tdh::cleanup_user(&pool, late_user).await;
    }
}
