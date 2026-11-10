//! Admin API for the global `security-reviewer` role: the users and groups
//! that may decide package exceptions

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_export::details as audit_details;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};

const ROLE: &str = "security-reviewer";
const WHAT: &str = "security reviewers";

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_security_reviewers))
        .route(
            "/users/:id",
            put(grant_user_security_reviewer).delete(revoke_user_security_reviewer),
        )
        .route(
            "/groups/:id",
            put(grant_group_security_reviewer).delete(revoke_group_security_reviewer),
        )
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct SecurityReviewerUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct SecurityReviewerGroup {
    pub id: Uuid,
    pub name: String,
    /// Identity provider that owns the membership (`oidc`, `saml`, `ldap`), null for a local group
    pub external_source: Option<String>,
    pub member_count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityReviewersResponse {
    pub users: Vec<SecurityReviewerUser>,
    pub groups: Vec<SecurityReviewerGroup>,
}

#[derive(Clone, Copy)]
enum Grantee {
    User,
    Group,
}

impl Grantee {
    /// 404 for an unknown id, 400 for a service account
    async fn check(self, db: &sqlx::PgPool, id: Uuid) -> Result<()> {
        let sql = match self {
            Grantee::User => "SELECT is_service_account FROM users WHERE id = $1",
            Grantee::Group => "SELECT false FROM groups WHERE id = $1",
        };
        match sqlx::query_scalar::<_, bool>(sql)
            .bind(id)
            .fetch_optional(db)
            .await?
        {
            None => Err(AppError::NotFound(self.not_found().to_string())),
            Some(true) => Err(AppError::Validation(
                "A service account cannot be a security reviewer".to_string(),
            )),
            Some(false) => Ok(()),
        }
    }

    fn not_found(self) -> &'static str {
        match self {
            Grantee::User => "User not found",
            Grantee::Group => "Group not found",
        }
    }

    fn grant_sql(self) -> &'static str {
        match self {
            Grantee::User => {
                "INSERT INTO user_global_roles (user_id, role_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING"
            }
            Grantee::Group => {
                "INSERT INTO group_global_roles (group_id, role_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING"
            }
        }
    }

    fn revoke_sql(self) -> &'static str {
        match self {
            Grantee::User => "DELETE FROM user_global_roles WHERE user_id = $1 AND role_id = $2",
            Grantee::Group => "DELETE FROM group_global_roles WHERE group_id = $1 AND role_id = $2",
        }
    }

    fn resource_type(self) -> ResourceType {
        match self {
            Grantee::User => ResourceType::User,
            Grantee::Group => ResourceType::Group,
        }
    }
}

async fn role_id(db: &sqlx::PgPool) -> Result<Uuid> {
    sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
        .bind(ROLE)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| AppError::Internal(format!("role {ROLE} is missing")))
}

async fn audit(
    state: &SharedState,
    auth: &AuthExtension,
    action: AuditAction,
    grantee: Grantee,
    id: Uuid,
    role_id: Uuid,
) {
    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::for_principal(action, grantee.resource_type(), auth)
            .resource(id)
            .details_typed(audit_details::PermissionDetails {
                actor_id: auth.user_id,
                role_id,
                grantee_id: id,
                repository_id: None,
            }),
    )
    .await;
}

async fn grant(
    state: SharedState,
    auth: AuthExtension,
    grantee: Grantee,
    id: Uuid,
) -> Result<StatusCode> {
    auth.require_unscoped_admin(WHAT)?;
    grantee.check(&state.db, id).await?;
    let role_id = role_id(&state.db).await?;
    let inserted = sqlx::query(grantee.grant_sql())
        .bind(id)
        .bind(role_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if inserted > 0 {
        audit(
            &state,
            &auth,
            AuditAction::RoleAssigned,
            grantee,
            id,
            role_id,
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(
    state: SharedState,
    auth: AuthExtension,
    grantee: Grantee,
    id: Uuid,
) -> Result<StatusCode> {
    auth.require_unscoped_admin(WHAT)?;
    let role_id = role_id(&state.db).await?;
    let deleted = sqlx::query(grantee.revoke_sql())
        .bind(id)
        .bind(role_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(AppError::NotFound(format!("Not a security reviewer: {id}")));
    }
    audit(
        &state,
        &auth,
        AuditAction::RoleRevoked,
        grantee,
        id,
        role_id,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// List the users and groups holding the global security-reviewer role
///
/// Administrators can always review and are not listed
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/admin/security-reviewers",
    tag = "admin",
    responses(
        (status = 200, description = "Security reviewers", body = SecurityReviewersResponse),
        (status = 403, description = "Admin access required"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_security_reviewers(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<SecurityReviewersResponse>> {
    auth.require_unscoped_admin(WHAT)?;
    let users = sqlx::query_as::<_, SecurityReviewerUser>(
        "SELECT u.id, u.username, u.display_name, u.is_active \
         FROM users u JOIN user_global_roles ugr ON ugr.user_id = u.id \
         JOIN roles r ON r.id = ugr.role_id WHERE r.name = $1 ORDER BY u.username",
    )
    .bind(ROLE)
    .fetch_all(&state.db)
    .await?;
    let groups = sqlx::query_as::<_, SecurityReviewerGroup>(
        "SELECT g.id, g.name, g.external_source, \
         (SELECT COUNT(*) FROM user_group_members m WHERE m.group_id = g.id) AS member_count \
         FROM groups g JOIN group_global_roles ggr ON ggr.group_id = g.id \
         JOIN roles r ON r.id = ggr.role_id WHERE r.name = $1 ORDER BY g.name",
    )
    .bind(ROLE)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(SecurityReviewersResponse { users, groups }))
}

/// Make a user a security reviewer (idempotent)
#[utoipa::path(
    put,
    path = "/users/{id}",
    context_path = "/api/v1/admin/security-reviewers",
    tag = "admin",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "The user is a security reviewer"),
        (status = 400, description = "Service accounts cannot be security reviewers"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn grant_user_security_reviewer(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    grant(state, auth, Grantee::User, id).await
}

/// Remove a user's direct security-reviewer grant
#[utoipa::path(
    delete,
    path = "/users/{id}",
    context_path = "/api/v1/admin/security-reviewers",
    tag = "admin",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "Grant removed"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "The user holds no direct grant"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_user_security_reviewer(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    revoke(state, auth, Grantee::User, id).await
}

/// Make every member of a group a security reviewer (idempotent)
///
/// SSO-synced groups work too, membership follows the identity provider
#[utoipa::path(
    put,
    path = "/groups/{id}",
    context_path = "/api/v1/admin/security-reviewers",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 204, description = "The group's members are security reviewers"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Group not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn grant_group_security_reviewer(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    grant(state, auth, Grantee::Group, id).await
}

/// Remove a group's security-reviewer grant
#[utoipa::path(
    delete,
    path = "/groups/{id}",
    context_path = "/api/v1/admin/security-reviewers",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Grant removed"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "The group holds no grant"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_group_security_reviewer(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    revoke(state, auth, Grantee::Group, id).await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_security_reviewers,
        grant_user_security_reviewer,
        revoke_user_security_reviewer,
        grant_group_security_reviewer,
        revoke_group_security_reviewer,
    ),
    components(schemas(SecurityReviewerUser, SecurityReviewerGroup, SecurityReviewersResponse))
)]
pub struct SecurityReviewersApiDoc;

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::permission_service::PermissionService;
    use axum::body::{Body, Bytes};
    use axum::http::Request;
    use sqlx::PgPool;

    async fn call(
        app: Router<SharedState>,
        state: &SharedState,
        auth: &AuthExtension,
        method: &str,
        uri: String,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, Bytes) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("request");
        tdh::send(
            tdh::router_with_auth_ext(app, state.clone(), auth.clone()),
            req,
        )
        .await
    }

    async fn reviewers(
        state: &SharedState,
        auth: &AuthExtension,
        method: &str,
        uri: String,
    ) -> StatusCode {
        call(router(), state, auth, method, uri, None).await.0
    }

    async fn can_review(pool: &PgPool, user_id: Uuid) -> bool {
        PermissionService::new(pool.clone())
            .has_global_capability(user_id, "security_review")
            .await
            .expect("capability query")
    }

    async fn listed(
        state: &SharedState,
        admin: &AuthExtension,
        key: &str,
        id: Uuid,
    ) -> Option<serde_json::Value> {
        let (status, body) = call(router(), state, admin, "GET", "/".into(), None).await;
        assert_eq!(status, StatusCode::OK);
        let list: serde_json::Value = serde_json::from_slice(&body).expect("json");
        list[key]
            .as_array()
            .expect("array")
            .iter()
            .find(|e| e["id"] == id.to_string())
            .cloned()
    }

    async fn join(pool: &PgPool, user_id: Uuid, group_id: Uuid) {
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(group_id)
            .execute(pool)
            .await
            .expect("join group");
    }

    async fn leave(pool: &PgPool, user_id: Uuid, group_id: Uuid) {
        sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(group_id)
            .execute(pool)
            .await
            .expect("leave group");
    }

    async fn setup() -> Option<(PgPool, SharedState, AuthExtension)> {
        let pool = tdh::try_pool().await?;
        let state = tdh::build_state(pool.clone(), "/tmp/ph-sec-reviewers");
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        Some((pool, state, tdh::admin_auth(admin_id, &admin_name)))
    }

    #[tokio::test]
    async fn db_admin_grants_and_revokes_a_user() {
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let uri = format!("/users/{user_id}");

        assert!(!can_review(&pool, user_id).await);
        for _ in 0..2 {
            assert_eq!(
                reviewers(&state, &admin, "PUT", uri.clone()).await,
                StatusCode::NO_CONTENT
            );
        }
        assert!(can_review(&pool, user_id).await);
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_global_roles WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(rows, 1, "a second grant is a no-op");
        assert!(listed(&state, &admin, "users", user_id).await.is_some());
        assert_eq!(
            tdh::audit_count_eventually(&pool, user_id, "ROLE_ASSIGNED", 1).await,
            1
        );

        assert_eq!(
            reviewers(&state, &admin, "DELETE", uri.clone()).await,
            StatusCode::NO_CONTENT
        );
        assert!(!can_review(&pool, user_id).await);
        assert!(listed(&state, &admin, "users", user_id).await.is_none());
        assert_eq!(
            tdh::audit_count_eventually(&pool, user_id, "ROLE_REVOKED", 1).await,
            1
        );
        assert_eq!(
            reviewers(&state, &admin, "DELETE", uri).await,
            StatusCode::NOT_FOUND
        );
    }

    /// A reviewer grant gives no repository access, not even a grant-holder view of a
    /// private repository
    #[tokio::test]
    async fn db_a_direct_grant_opens_no_private_repository() {
        use crate::services::repository_service::{RepoAccess, RepoVisibility, RepositoryService};
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let (repo_id, key, _) = tdh::create_repo(&pool, "local", "npm").await;
        sqlx::query("UPDATE repositories SET visibility = 'private' WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("make private");
        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/users/{user_id}")).await,
            StatusCode::NO_CONTENT
        );
        assert!(can_review(&pool, user_id).await);

        let repos = RepositoryService::new(pool.clone());
        // TENANT-GATE-ONLY: the grant must not even count as holding a grant on the repository
        assert!(!repos
            .user_can_access_repo(repo_id, user_id, RepoAccess::TenantOnly)
            .await
            .expect("tenant check"));
        for (visibility, expected) in [
            (RepoVisibility::All, true),
            (RepoVisibility::User(user_id), false),
        ] {
            let (rows, _) = repos
                .list(0, 10, None, None, visibility, Some(&key), None)
                .await
                .expect("listing");
            assert_eq!(
                rows.iter().any(|r| r.id == repo_id),
                expected,
                "a reviewer must not see a private repository it holds no grant on"
            );
        }

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn db_group_grant_follows_membership() {
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (group_id, _) = tdh::create_group(&pool).await;
        let (member, _) = tdh::create_user(&pool).await;
        let (newcomer, _) = tdh::create_user(&pool).await;
        let (robot, _) = tdh::create_service_account(&pool).await;
        join(&pool, member, group_id).await;
        join(&pool, robot, group_id).await;
        let uri = format!("/groups/{group_id}");

        assert!(!can_review(&pool, member).await);
        assert_eq!(
            reviewers(&state, &admin, "PUT", uri.clone()).await,
            StatusCode::NO_CONTENT
        );
        assert!(can_review(&pool, member).await);
        assert!(!can_review(&pool, newcomer).await);
        assert!(
            !can_review(&pool, robot).await,
            "service accounts never review"
        );
        let row = listed(&state, &admin, "groups", group_id)
            .await
            .expect("group listed");
        assert_eq!(row["member_count"], 2);
        assert_eq!(
            tdh::audit_count_eventually(&pool, group_id, "ROLE_ASSIGNED", 1).await,
            1
        );

        join(&pool, newcomer, group_id).await;
        assert!(can_review(&pool, newcomer).await, "joining grants it");
        leave(&pool, member, group_id).await;
        assert!(!can_review(&pool, member).await, "leaving revokes it");

        assert_eq!(
            reviewers(&state, &admin, "DELETE", uri.clone()).await,
            StatusCode::NO_CONTENT
        );
        assert!(!can_review(&pool, newcomer).await);
        assert!(listed(&state, &admin, "groups", group_id).await.is_none());
        assert_eq!(
            reviewers(&state, &admin, "DELETE", uri).await,
            StatusCode::NOT_FOUND
        );

        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn db_sso_group_grant_follows_the_identity_provider() {
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let provider = Uuid::new_v4();
        let name = format!("ph-sec-sso-{provider}");
        let sync = |groups: Vec<String>| {
            let pool = pool.clone();
            async move {
                crate::api::handlers::sso::sync_federated_groups_to_local_groups(
                    &pool, user_id, provider, "oidc", &groups,
                )
                .await
                .expect("group sync")
            }
        };

        sync(vec![name.clone()]).await;
        let group_id: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE name = $1")
            .bind(&name)
            .fetch_one(&pool)
            .await
            .expect("federated group");
        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/groups/{group_id}")).await,
            StatusCode::NO_CONTENT
        );
        assert!(can_review(&pool, user_id).await);

        sync(vec![]).await;
        assert!(
            !can_review(&pool, user_id).await,
            "dropped from the IdP group"
        );

        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn db_only_admins_manage_reviewers() {
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (caller_id, caller_name) = tdh::create_user(&pool).await;
        let caller = tdh::make_auth(caller_id, &caller_name);
        let (group_id, _) = tdh::create_group(&pool).await;

        for (method, uri) in [
            ("GET", "/".to_string()),
            ("PUT", format!("/users/{caller_id}")),
            ("DELETE", format!("/users/{caller_id}")),
            ("PUT", format!("/groups/{group_id}")),
            ("DELETE", format!("/groups/{group_id}")),
        ] {
            assert_eq!(
                reviewers(&state, &caller, method, uri.clone()).await,
                StatusCode::FORBIDDEN,
                "{method} {uri}"
            );
        }
        assert!(!can_review(&pool, caller_id).await);
        assert!(listed(&state, &admin, "groups", group_id).await.is_none());

        let (robot, _) = tdh::create_service_account(&pool).await;
        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/users/{robot}")).await,
            StatusCode::BAD_REQUEST
        );
        let ghost = Uuid::new_v4();
        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/users/{ghost}")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/groups/{ghost}")).await,
            StatusCode::NOT_FOUND
        );

        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn db_delegated_group_admin_cannot_add_members_to_a_reviewer_group() {
        let Some((pool, state, admin)) = setup().await else {
            return;
        };
        let (group_id, _) = tdh::create_group(&pool).await;
        let (delegate_id, delegate_name) = tdh::create_user(&pool).await;
        let delegate = tdh::make_auth(delegate_id, &delegate_name);
        let rule =
            tdh::grant_permission(&pool, "user", delegate_id, "group", group_id, &["admin"]).await;
        let (newcomer, _) = tdh::create_user(&pool).await;
        let add = |auth: AuthExtension| {
            let state = state.clone();
            async move {
                call(
                    crate::api::handlers::groups::router(),
                    &state,
                    &auth,
                    "POST",
                    format!("/{group_id}/members"),
                    Some(serde_json::json!({ "user_ids": [newcomer] })),
                )
                .await
                .0
            }
        };

        assert_eq!(
            add(delegate.clone()).await,
            StatusCode::OK,
            "delegation works on a plain group"
        );
        leave(&pool, newcomer, group_id).await;

        assert_eq!(
            reviewers(&state, &admin, "PUT", format!("/groups/{group_id}")).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(add(delegate).await, StatusCode::FORBIDDEN);
        assert!(!can_review(&pool, newcomer).await);
        assert_eq!(add(admin).await, StatusCode::OK);
        assert!(can_review(&pool, newcomer).await);

        let _ = sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(rule)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
    }
}
