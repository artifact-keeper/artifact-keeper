//! Project management handlers (#2472, P1).
//!
//! Projects are a metadata grouping of repositories. Membership grants are
//! stored in the existing `permissions` table with `target_type = 'project'`
//! (no third authz store): a grant on a project is inherited by every
//! repository whose `repositories.project_id` points at it (read plane via
//! `repository_service::permissions_grant_exists`, write plane via
//! `permission_service::{query_actions, has_any_rules_for_target}`).
//!
//! All endpoints are admin-only in P1 (the project-admin role arrives in P2).
//! Mutations mirror `handlers::permissions`: the body is taken as raw `Bytes`
//! so the authorization gate runs BEFORE deserialization, and every mutation
//! of the `permissions` table invalidates the permission cache.

use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::project::Project;

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create project routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_projects).post(create_project))
        .route(
            "/:id",
            get(get_project).put(update_project).delete(delete_project),
        )
        .route(
            "/:id/members",
            get(list_project_members)
                .post(add_project_member)
                .delete(remove_project_member),
        )
}

// ---------------------------------------------------------------------------
// Pure validation helpers (no DB, unit-testable in isolation)
// ---------------------------------------------------------------------------

/// Principal types accepted for project membership grants. Matches the
/// principal domain resolved by `PermissionService::query_actions` (`user`
/// directly, `group` via `user_group_members`).
pub(crate) fn valid_principal_type(principal_type: &str) -> bool {
    matches!(principal_type, "user" | "group")
}

/// Membership grants must carry at least one action: an empty action list is
/// indistinguishable from "rules exist but nothing granted" (deny), which is
/// never what a grant author intends.
pub(crate) fn actions_non_empty(actions: &[String]) -> bool {
    !actions.is_empty()
}

/// Validate that a project key is safe and well-formed. Same shape rules as
/// repository keys: 1-128 chars of `[A-Za-z0-9._-]`, no leading dot/hyphen,
/// no consecutive dots.
pub(crate) fn validate_project_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 {
        return Err(AppError::Validation(
            "Project key must be between 1 and 128 characters".to_string(),
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::Validation(
            "Project key must contain only alphanumeric characters, hyphens, underscores, and dots"
                .to_string(),
        ));
    }
    if key.starts_with('.') || key.starts_with('-') {
        return Err(AppError::Validation(
            "Project key must not start with a dot or hyphen".to_string(),
        ));
    }
    if key.contains("..") {
        return Err(AppError::Validation(
            "Project key must not contain consecutive dots".to_string(),
        ));
    }
    Ok(())
}

/// Validate a membership principal payload: known principal type and a
/// non-empty action list. Shared by the add-member handler and unit tests.
pub(crate) fn validate_member_grant(principal_type: &str, actions: &[String]) -> Result<()> {
    if !valid_principal_type(principal_type) {
        return Err(AppError::Validation(format!(
            "Invalid principal_type '{}': must be 'user' or 'group'",
            principal_type
        )));
    }
    if !actions_non_empty(actions) {
        return Err(AppError::Validation(
            "actions must contain at least one action".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    /// P1: stored only, NOT enforced (quota enforcement is P3).
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectListResponse {
    pub items: Vec<Project>,
}

/// One membership grant on a project: a `permissions` row with
/// `target_type = 'project'`.
#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct ProjectMemberRow {
    pub principal_type: String,
    pub principal_id: Uuid,
    pub actions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectMemberListResponse {
    pub items: Vec<ProjectMemberRow>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddProjectMemberRequest {
    /// "user" or "group".
    pub principal_type: String,
    pub principal_id: Uuid,
    /// Actions granted on every repository in the project (e.g. ["read"],
    /// ["read", "write"]).
    pub actions: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveProjectMemberRequest {
    pub principal_type: String,
    pub principal_id: Uuid,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List projects
#[utoipa::path(
    get,
    path = "",
    operation_id = "projects_list",
    context_path = "/api/v1/projects",
    tag = "projects",
    responses(
        (status = 200, description = "List of projects", body = ProjectListResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_projects(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
) -> Result<Json<ProjectListResponse>> {
    let auth = require_auth(auth)?;
    auth.require_admin()?;

    let items: Vec<Project> = sqlx::query_as(
        "SELECT id, key, name, description, quota_bytes, created_at, updated_at \
         FROM projects ORDER BY key",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ProjectListResponse { items }))
}

/// Create a project
#[utoipa::path(
    post,
    path = "",
    operation_id = "projects_create",
    context_path = "/api/v1/projects",
    tag = "projects",
    request_body = CreateProjectRequest,
    responses(
        (status = 200, description = "Project created", body = Project),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 409, description = "Project key already exists"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_project(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    body: Bytes,
) -> Result<Json<Project>> {
    // Gate BEFORE parsing the body (mirrors handlers::permissions, #1438 B10):
    // an unauthorized caller gets the canonical 401/403, never a body-shape error.
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    auth.require_admin()?;

    let payload: CreateProjectRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid project payload: {}", e)))?;

    validate_project_key(&payload.key)?;

    let project: Project = sqlx::query_as(
        "INSERT INTO projects (key, name, description, quota_bytes) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, key, name, description, quota_bytes, created_at, updated_at",
    )
    .bind(&payload.key)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(payload.quota_bytes)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict(format!("Project with key '{}' already exists", payload.key))
        } else {
            AppError::Database(msg)
        }
    })?;

    Ok(Json(project))
}

/// Get a project by ID
#[utoipa::path(
    get,
    path = "/{id}",
    operation_id = "projects_get",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    responses(
        (status = 200, description = "Project details", body = Project),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Project not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_project(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Project>> {
    let auth = require_auth(auth)?;
    auth.require_admin()?;

    let project: Project = sqlx::query_as(
        "SELECT id, key, name, description, quota_bytes, created_at, updated_at \
         FROM projects WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Project not found".to_string()))?;

    Ok(Json(project))
}

/// Update a project (COALESCE semantics: omitted fields are unchanged)
#[utoipa::path(
    put,
    path = "/{id}",
    operation_id = "projects_update",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    request_body = UpdateProjectRequest,
    responses(
        (status = 200, description = "Project updated", body = Project),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Project not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_project(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<Project>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    auth.require_admin()?;

    let payload: UpdateProjectRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid project payload: {}", e)))?;

    let project: Project = sqlx::query_as(
        "UPDATE projects SET \
             name = COALESCE($2, name), \
             description = COALESCE($3, description), \
             quota_bytes = COALESCE($4, quota_bytes), \
             updated_at = NOW() \
         WHERE id = $1 \
         RETURNING id, key, name, description, quota_bytes, created_at, updated_at",
    )
    .bind(id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(payload.quota_bytes)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Project not found".to_string()))?;

    Ok(Json(project))
}

/// Delete a project
///
/// Removes the project's membership grants and the project row in one
/// transaction. Repositories assigned to the project are automatically
/// unassigned (`project_id` -> NULL) by the FK's ON DELETE SET NULL.
#[utoipa::path(
    delete,
    path = "/{id}",
    operation_id = "projects_delete",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    responses(
        (status = 200, description = "Project deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Project not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_project(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    auth.require_admin()?;

    // One tx: grants + project row go together, so a failure never leaves
    // orphaned project grants that a recreated project id could never match
    // anyway, or a deleted grant set with a live project.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    sqlx::query("DELETE FROM permissions WHERE target_type = 'project' AND target_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let result = sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        let _ = tx.rollback().await;
        return Err(AppError::NotFound("Project not found".to_string()));
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Inherited grants just changed for every repository in the project.
    state.permission_service.invalidate_cache();

    Ok(())
}

/// List project members (grants on the project)
#[utoipa::path(
    get,
    path = "/{id}/members",
    operation_id = "projects_list_members",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    responses(
        (status = 200, description = "Project membership grants", body = ProjectMemberListResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Project not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_project_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProjectMemberListResponse>> {
    let auth = require_auth(auth)?;
    auth.require_admin()?;

    require_project_exists(&state, id).await?;

    let items: Vec<ProjectMemberRow> = sqlx::query_as(
        "SELECT principal_type, principal_id, actions \
         FROM permissions WHERE target_type = 'project' AND target_id = $1 \
         ORDER BY principal_type, principal_id",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ProjectMemberListResponse { items }))
}

/// Add or update a project membership grant
#[utoipa::path(
    post,
    path = "/{id}/members",
    operation_id = "projects_add_member",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    request_body = AddProjectMemberRequest,
    responses(
        (status = 200, description = "Membership grant upserted", body = ProjectMemberRow),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Project not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_project_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<ProjectMemberRow>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    auth.require_admin()?;

    let payload: AddProjectMemberRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid member payload: {}", e)))?;

    validate_member_grant(&payload.principal_type, &payload.actions)?;
    require_project_exists(&state, id).await?;

    let row: ProjectMemberRow = sqlx::query_as(
        "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
         VALUES ($1, $2, 'project', $3, $4) \
         ON CONFLICT (principal_type, principal_id, target_type, target_id) \
         DO UPDATE SET actions = EXCLUDED.actions, updated_at = NOW() \
         RETURNING principal_type, principal_id, actions",
    )
    .bind(&payload.principal_type)
    .bind(payload.principal_id)
    .bind(id)
    .bind(&payload.actions)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // The grant is inherited by every repository in the project; drop stale
    // cached denials immediately.
    state.permission_service.invalidate_cache();

    Ok(Json(row))
}

/// Remove a project membership grant
#[utoipa::path(
    delete,
    path = "/{id}/members",
    operation_id = "projects_remove_member",
    context_path = "/api/v1/projects",
    tag = "projects",
    params(("id" = Uuid, Path, description = "Project ID")),
    request_body = RemoveProjectMemberRequest,
    responses(
        (status = 200, description = "Membership grant removed"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Grant not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_project_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    auth.require_admin()?;

    let payload: RemoveProjectMemberRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid member payload: {}", e)))?;

    let result = sqlx::query(
        "DELETE FROM permissions \
         WHERE target_type = 'project' AND target_id = $1 \
           AND principal_type = $2 AND principal_id = $3",
    )
    .bind(id)
    .bind(&payload.principal_type)
    .bind(payload.principal_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Membership grant not found".to_string()));
    }

    // Cached positive grants for the removed principal must not outlive the
    // revocation.
    state.permission_service.invalidate_cache();

    Ok(())
}

/// 404 helper shared by the member endpoints so grants can never be attached
/// to (or listed for) a project id that does not exist.
async fn require_project_exists(state: &SharedState, id: Uuid) -> Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    if !exists {
        return Err(AppError::NotFound("Project not found".to_string()));
    }
    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_projects,
        create_project,
        get_project,
        update_project,
        delete_project,
        list_project_members,
        add_project_member,
        remove_project_member,
    ),
    components(schemas(
        Project,
        ProjectListResponse,
        CreateProjectRequest,
        UpdateProjectRequest,
        ProjectMemberRow,
        ProjectMemberListResponse,
        AddProjectMemberRequest,
        RemoveProjectMemberRequest,
    ))
)]
pub struct ProjectsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helpers: principal type domain
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_principal_type_user_and_group() {
        assert!(valid_principal_type("user"));
        assert!(valid_principal_type("group"));
    }

    #[test]
    fn test_invalid_principal_types_rejected() {
        assert!(!valid_principal_type("admin"));
        assert!(!valid_principal_type("service_account"));
        assert!(!valid_principal_type("USER"));
        assert!(!valid_principal_type(""));
        assert!(!valid_principal_type("project"));
    }

    // -----------------------------------------------------------------------
    // Pure helpers: actions
    // -----------------------------------------------------------------------

    #[test]
    fn test_actions_non_empty() {
        assert!(actions_non_empty(&["read".to_string()]));
        assert!(actions_non_empty(&[
            "read".to_string(),
            "write".to_string()
        ]));
        assert!(!actions_non_empty(&[]));
    }

    // -----------------------------------------------------------------------
    // Pure helpers: member grant validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_member_grant_accepts_user_read() {
        assert!(validate_member_grant("user", &["read".to_string()]).is_ok());
    }

    #[test]
    fn test_validate_member_grant_accepts_group_write() {
        assert!(validate_member_grant("group", &["read".to_string(), "write".to_string()]).is_ok());
    }

    #[test]
    fn test_validate_member_grant_rejects_bad_principal() {
        match validate_member_grant("robot", &["read".to_string()]) {
            Err(AppError::Validation(msg)) => assert!(msg.contains("principal_type")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_member_grant_rejects_empty_actions() {
        match validate_member_grant("user", &[]) {
            Err(AppError::Validation(msg)) => assert!(msg.contains("actions")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Pure helpers: project key validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_project_key_accepts_reasonable_keys() {
        assert!(validate_project_key("payments").is_ok());
        assert!(validate_project_key("team-a_2.0").is_ok());
        assert!(validate_project_key("_default").is_ok());
        assert!(validate_project_key(&"k".repeat(128)).is_ok());
    }

    #[test]
    fn test_validate_project_key_rejects_empty_and_too_long() {
        assert!(validate_project_key("").is_err());
        assert!(validate_project_key(&"k".repeat(129)).is_err());
    }

    #[test]
    fn test_validate_project_key_rejects_bad_chars() {
        assert!(validate_project_key("has space").is_err());
        assert!(validate_project_key("slash/key").is_err());
        assert!(validate_project_key("semi;colon").is_err());
    }

    #[test]
    fn test_validate_project_key_rejects_dot_hyphen_prefix_and_dotdot() {
        assert!(validate_project_key(".hidden").is_err());
        assert!(validate_project_key("-flag").is_err());
        assert!(validate_project_key("a..b").is_err());
    }

    // -----------------------------------------------------------------------
    // DTO deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_project_request_deserialize() {
        let req: CreateProjectRequest = serde_json::from_str(
            r#"{"key":"payments","name":"Payments","description":"d","quota_bytes":1024}"#,
        )
        .unwrap();
        assert_eq!(req.key, "payments");
        assert_eq!(req.name, "Payments");
        assert_eq!(req.description.as_deref(), Some("d"));
        assert_eq!(req.quota_bytes, Some(1024));
    }

    #[test]
    fn test_create_project_request_minimal() {
        let req: CreateProjectRequest =
            serde_json::from_str(r#"{"key":"p1","name":"P1"}"#).unwrap();
        assert!(req.description.is_none());
        assert!(req.quota_bytes.is_none());
    }

    #[test]
    fn test_create_project_request_missing_key_rejected() {
        assert!(serde_json::from_str::<CreateProjectRequest>(r#"{"name":"P1"}"#).is_err());
    }

    #[test]
    fn test_add_project_member_request_deserialize() {
        let pid = Uuid::new_v4();
        let req: AddProjectMemberRequest = serde_json::from_str(&format!(
            r#"{{"principal_type":"group","principal_id":"{}","actions":["read","write"]}}"#,
            pid
        ))
        .unwrap();
        assert_eq!(req.principal_type, "group");
        assert_eq!(req.principal_id, pid);
        assert_eq!(req.actions, vec!["read", "write"]);
    }

    #[test]
    fn test_update_project_request_all_optional() {
        let req: UpdateProjectRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.quota_bytes.is_none());
    }

    // -----------------------------------------------------------------------
    // Admin gating predicates (no DB): every project endpoint is admin-only
    // in P1, and mutations additionally require the matching token scope.
    // -----------------------------------------------------------------------

    fn non_admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "member".to_string(),
            email: "member@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn test_require_auth_rejects_anonymous() {
        assert!(matches!(
            require_auth(None),
            Err(AppError::Authentication(_))
        ));
    }

    #[test]
    fn test_non_admin_rejected_by_admin_gate() {
        let auth = non_admin_auth();
        assert!(matches!(
            auth.require_admin(),
            Err(AppError::Authorization(_))
        ));
    }

    #[test]
    fn test_read_scope_token_rejected_on_mutation_gate() {
        let auth = AuthExtension {
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["read".to_string()]),
            ..non_admin_auth()
        };
        assert!(auth.require_scope("write").is_err());
        assert!(auth.require_scope("delete").is_err());
    }

    // -----------------------------------------------------------------------
    // DB-gated integration tests. Skip cleanly when DATABASE_URL is unset,
    // mirroring the tdh convention used across handler suites.
    // -----------------------------------------------------------------------

    mod db {
        use super::super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use sqlx::PgPool;

        async fn create_project_row(pool: &PgPool, tag: &str) -> Uuid {
            let key = format!("prj-test-{}-{}", tag, Uuid::new_v4());
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO projects (key, name) VALUES ($1, $1) RETURNING id",
            )
            .bind(&key)
            .fetch_one(pool)
            .await
            .expect("create project")
        }

        async fn assign_repo_to_project(pool: &PgPool, repo_id: Uuid, project_id: Uuid) {
            sqlx::query("UPDATE repositories SET project_id = $2 WHERE id = $1")
                .bind(repo_id)
                .bind(project_id)
                .execute(pool)
                .await
                .expect("assign repo to project");
        }

        async fn grant_project_actions(
            pool: &PgPool,
            project_id: Uuid,
            user_id: Uuid,
            actions: &[&str],
        ) {
            let actions: Vec<String> = actions.iter().map(|s| s.to_string()).collect();
            sqlx::query(
                "INSERT INTO permissions \
                 (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ('user', $1, 'project', $2, $3)",
            )
            .bind(user_id)
            .bind(project_id)
            .bind(&actions)
            .execute(pool)
            .await
            .expect("grant project actions");
        }

        async fn cleanup_project(pool: &PgPool, project_id: Uuid) {
            let _ = sqlx::query(
                "DELETE FROM permissions WHERE target_type = 'project' AND target_id = $1",
            )
            .bind(project_id)
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM projects WHERE id = $1")
                .bind(project_id)
                .execute(pool)
                .await;
        }

        /// (1) READ plane: a project grant is inherited by an assigned private
        /// repository; a user without any grant stays denied.
        #[tokio::test]
        async fn test_project_grant_inherited_for_read_access() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let (member_id, _) = tdh::create_user(&pool).await;
            let (outsider_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "read").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;
            grant_project_actions(&pool, project_id, member_id, &["read"]).await;

            let svc = crate::services::repository_service::RepositoryService::new(pool.clone());
            assert!(
                svc.user_can_access_repo(repo_id, member_id).await.unwrap(),
                "project-read member must reach the assigned repository"
            );
            assert!(
                !svc.user_can_access_repo(repo_id, outsider_id)
                    .await
                    .unwrap(),
                "non-member must stay denied on the project repository"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, member_id).await;
            tdh::cleanup(&pool, repo_id, outsider_id).await;
        }

        /// (2) Cross-project isolation: a grant on project B conveys nothing
        /// on a repository assigned to project A.
        #[tokio::test]
        async fn test_cross_project_grant_does_not_leak() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let (user_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_a = create_project_row(&pool, "iso-a").await;
            let project_b = create_project_row(&pool, "iso-b").await;
            assign_repo_to_project(&pool, repo_id, project_a).await;
            grant_project_actions(&pool, project_b, user_id, &["read", "write"]).await;

            let svc = crate::services::repository_service::RepositoryService::new(pool.clone());
            assert!(
                !svc.user_can_access_repo(repo_id, user_id).await.unwrap(),
                "a grant on a DIFFERENT project must not open this repository"
            );

            cleanup_project(&pool, project_a).await;
            cleanup_project(&pool, project_b).await;
            tdh::cleanup(&pool, repo_id, user_id).await;
        }

        /// (3) Regression guard: a repository with project_id = NULL is
        /// untouched by project grants — no access widening for unassigned
        /// repositories.
        #[tokio::test]
        async fn test_null_project_repo_unaffected() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let (user_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "null").await;
            // Repo is NOT assigned to any project; user holds a project grant.
            grant_project_actions(&pool, project_id, user_id, &["read", "write"]).await;

            let svc = crate::services::repository_service::RepositoryService::new(pool.clone());
            assert!(
                !svc.user_can_access_repo(repo_id, user_id).await.unwrap(),
                "project grants must not reach a project-less repository"
            );

            // Write plane: the fine-grained gate must also stay disengaged.
            let perm = crate::services::permission_service::PermissionService::new(pool.clone());
            assert!(
                !perm
                    .has_any_rules_for_target("repository", repo_id)
                    .await
                    .unwrap(),
                "a NULL-project repository has no rules from project grants"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, user_id).await;
        }

        /// (4) Listing: a private project repository surfaces for the project
        /// member, stays hidden for a non-member, and the ?project= filter
        /// narrows results to the project.
        #[tokio::test]
        async fn test_listing_visibility_and_project_filter() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            use crate::services::repository_service::{RepoVisibility, RepositoryService};

            let (member_id, _) = tdh::create_user(&pool).await;
            let (outsider_id, _) = tdh::create_user(&pool).await;
            let (repo_id, repo_key, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "list").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;
            grant_project_actions(&pool, project_id, member_id, &["read"]).await;

            let svc = RepositoryService::new(pool.clone());
            let contains = |repos: &[crate::models::repository::Repository]| {
                repos.iter().any(|r| r.key == repo_key)
            };

            let (member_page, _) = svc
                .list(
                    0,
                    100,
                    None,
                    None,
                    RepoVisibility::User(member_id),
                    None,
                    None,
                )
                .await
                .unwrap();
            assert!(
                contains(&member_page),
                "project member must see the project repository in listings"
            );

            let (outsider_page, _) = svc
                .list(
                    0,
                    100,
                    None,
                    None,
                    RepoVisibility::User(outsider_id),
                    None,
                    None,
                )
                .await
                .unwrap();
            assert!(
                !contains(&outsider_page),
                "non-member must not see the private project repository"
            );

            // ?project= filter narrows to exactly the project's repos.
            let (filtered, total) = svc
                .list(
                    0,
                    100,
                    None,
                    None,
                    RepoVisibility::All,
                    None,
                    Some(project_id),
                )
                .await
                .unwrap();
            assert_eq!(total, 1, "project filter must count only project repos");
            assert!(contains(&filtered));
            assert!(filtered.iter().all(|r| r.project_id == Some(project_id)));

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, member_id).await;
            tdh::cleanup(&pool, repo_id, outsider_id).await;
        }

        /// (5) WRITE plane: with ONLY a project grant, the fine-grained gate
        /// engages (has_any_rules_for_target = true) and check_permission
        /// resolves inherited actions — write for the write member, deny for
        /// the read-only member and the non-member. Non-repository targets
        /// are untouched by the project arm.
        #[tokio::test]
        async fn test_write_plane_project_inheritance() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let (writer_id, _) = tdh::create_user(&pool).await;
            let (reader_id, _) = tdh::create_user(&pool).await;
            let (outsider_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "write").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;
            grant_project_actions(&pool, project_id, writer_id, &["read", "write"]).await;
            grant_project_actions(&pool, project_id, reader_id, &["read"]).await;

            let perm = crate::services::permission_service::PermissionService::new(pool.clone());

            assert!(
                perm.has_any_rules_for_target("repository", repo_id)
                    .await
                    .unwrap(),
                "a project-only grant must engage the fine-grained gate \
                 (otherwise the write path falls open)"
            );

            assert!(
                perm.check_permission(writer_id, "repository", repo_id, "write", false)
                    .await
                    .unwrap(),
                "project write member must inherit write on the repository"
            );
            assert!(
                !perm
                    .check_permission(reader_id, "repository", repo_id, "write", false)
                    .await
                    .unwrap(),
                "project read-only member must NOT inherit write"
            );
            assert!(
                perm.check_permission(reader_id, "repository", repo_id, "read", false)
                    .await
                    .unwrap(),
                "project read-only member must inherit read"
            );
            assert!(
                !perm
                    .check_permission(outsider_id, "repository", repo_id, "write", false)
                    .await
                    .unwrap(),
                "non-member must be denied write on the project repository"
            );

            // Non-repository target types never inherit through the project
            // arm: a 'group' target with the repo's id has no rules.
            assert!(
                !perm
                    .has_any_rules_for_target("group", repo_id)
                    .await
                    .unwrap(),
                "the project arm must be confined to repository targets"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, writer_id).await;
            tdh::cleanup(&pool, repo_id, reader_id).await;
            tdh::cleanup(&pool, repo_id, outsider_id).await;
        }

        /// (6) Cache: a cached negative check flips after a project grant is
        /// added and the cache is invalidated (the add-member handler calls
        /// invalidate_cache after every grant mutation).
        #[tokio::test]
        async fn test_cache_invalidation_after_grant() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let (user_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "cache").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;

            let perm = crate::services::permission_service::PermissionService::new(pool.clone());

            // Prime a negative entry.
            assert!(!perm
                .check_permission(user_id, "repository", repo_id, "read", false)
                .await
                .unwrap());

            grant_project_actions(&pool, project_id, user_id, &["read"]).await;
            perm.invalidate_cache();

            assert!(
                perm.check_permission(user_id, "repository", repo_id, "read", false)
                    .await
                    .unwrap(),
                "after grant + invalidate, the prior negative result must flip"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, user_id).await;
        }
    }

    // -----------------------------------------------------------------------
    // DB-gated HANDLER tests: drive the actual axum endpoints end-to-end
    // through the router (oneshot), so the CRUD/member handler bodies are
    // exercised under the coverage job's live Postgres. Skip cleanly when
    // DATABASE_URL is unset, mirroring the tdh convention.
    // -----------------------------------------------------------------------

    mod http {
        use super::super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use sqlx::PgPool;

        /// Connect + build a SharedState over a temp storage dir.
        async fn setup() -> Option<(PgPool, crate::api::SharedState)> {
            let pool = tdh::try_pool().await?;
            let dir = std::env::temp_dir().join(format!("prj-http-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("storage dir");
            let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
            Some((pool, state))
        }

        /// Router wired exactly like production nesting (auth injected).
        fn app(state: &crate::api::SharedState, auth: AuthExtension) -> axum::Router {
            tdh::router_with_auth(router(), state.clone(), auth)
        }

        fn admin() -> AuthExtension {
            tdh::admin_auth(Uuid::new_v4(), "prj-http-admin")
        }

        /// Build a JSON request for any method (tdh has no DELETE builder).
        fn req(method: &str, uri: &str, body: &str) -> Request<Body> {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build request")
        }

        async fn create_via_api(
            state: &crate::api::SharedState,
            key: &str,
        ) -> (StatusCode, serde_json::Value) {
            let body = format!(
                r#"{{"key":"{key}","name":"{key} name","description":"d","quota_bytes":1024}}"#
            );
            let (status, bytes) = tdh::send(app(state, admin()), req("POST", "/", &body)).await;
            let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }

        async fn cleanup_project_rows(pool: &PgPool, key: &str) {
            let _ = sqlx::query(
                "DELETE FROM permissions WHERE target_type = 'project' AND target_id IN \
                 (SELECT id FROM projects WHERE key = $1)",
            )
            .bind(key)
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM projects WHERE key = $1")
                .bind(key)
                .execute(pool)
                .await;
        }

        #[tokio::test]
        async fn http_project_crud_lifecycle() {
            let Some((pool, state)) = setup().await else {
                return;
            };
            let key = format!("prj-http-crud-{}", Uuid::new_v4().simple());

            // Create -> 200 with the persisted row echoed back.
            let (status, created) = create_via_api(&state, &key).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(created["key"], key.as_str());
            assert_eq!(created["quota_bytes"], 1024);
            let id = created["id"].as_str().expect("project id").to_string();

            // Duplicate key -> 409.
            let (dup_status, _) = create_via_api(&state, &key).await;
            assert_eq!(dup_status, StatusCode::CONFLICT);

            // Get -> 200; unknown id -> 404.
            let (status, bytes) = tdh::send(app(&state, admin()), tdh::get(format!("/{id}"))).await;
            assert_eq!(status, StatusCode::OK);
            let got: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(got["name"], format!("{key} name"));
            let (nf, _) = tdh::send(
                app(&state, admin()),
                tdh::get(format!("/{}", Uuid::new_v4())),
            )
            .await;
            assert_eq!(nf, StatusCode::NOT_FOUND);

            // List -> contains the created key.
            let (status, bytes) = tdh::send(app(&state, admin()), tdh::get("/".into())).await;
            assert_eq!(status, StatusCode::OK);
            let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(list["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["key"] == key.as_str()));

            // Update (COALESCE): only description changes; name survives.
            let (status, bytes) = tdh::send(
                app(&state, admin()),
                req("PUT", &format!("/{id}"), r#"{"description":"updated"}"#),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let upd: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(upd["description"], "updated");
            assert_eq!(upd["name"], format!("{key} name"));
            // Update of an unknown project -> 404.
            let (nf, _) = tdh::send(
                app(&state, admin()),
                req("PUT", &format!("/{}", Uuid::new_v4()), r#"{"name":"x"}"#),
            )
            .await;
            assert_eq!(nf, StatusCode::NOT_FOUND);

            // Delete -> 200, then Get/Delete -> 404.
            let (status, _) =
                tdh::send(app(&state, admin()), req("DELETE", &format!("/{id}"), "")).await;
            assert_eq!(status, StatusCode::OK);
            let (gone, _) = tdh::send(app(&state, admin()), tdh::get(format!("/{id}"))).await;
            assert_eq!(gone, StatusCode::NOT_FOUND);
            let (gone, _) =
                tdh::send(app(&state, admin()), req("DELETE", &format!("/{id}"), "")).await;
            assert_eq!(gone, StatusCode::NOT_FOUND);

            cleanup_project_rows(&pool, &key).await;
        }

        #[tokio::test]
        async fn http_create_project_validation_branches() {
            let Some((_pool, state)) = setup().await else {
                return;
            };
            // Malformed JSON -> 400 (post-gate parse maps to Validation).
            let (status, _) = tdh::send(app(&state, admin()), req("POST", "/", "{ not json")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            // Invalid key shape -> 400.
            let (status, _) = tdh::send(
                app(&state, admin()),
                req("POST", "/", r#"{"key":".bad","name":"x"}"#),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            // Malformed JSON on update -> 400.
            let (status, _) = tdh::send(
                app(&state, admin()),
                req("PUT", &format!("/{}", Uuid::new_v4()), "{ not json"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn http_member_grant_list_revoke_flow() {
            let Some((pool, state)) = setup().await else {
                return;
            };
            let key = format!("prj-http-mem-{}", Uuid::new_v4().simple());
            let (_, created) = create_via_api(&state, &key).await;
            let id = created["id"].as_str().expect("project id").to_string();
            let user_id = Uuid::new_v4();
            let group_id = Uuid::new_v4();

            // Grant a user -> 200 with the row echoed.
            let (status, bytes) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"user","principal_id":"{user_id}","actions":["read"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(row["actions"], serde_json::json!(["read"]));

            // Re-grant with different actions -> upsert (ON CONFLICT DO UPDATE).
            let (status, bytes) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"user","principal_id":"{user_id}","actions":["read","write"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(row["actions"], serde_json::json!(["read", "write"]));

            // Grant a group too, then list -> exactly 2 grants.
            let (status, _) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"group","principal_id":"{group_id}","actions":["read"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, bytes) =
                tdh::send(app(&state, admin()), tdh::get(format!("/{id}/members"))).await;
            assert_eq!(status, StatusCode::OK);
            let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(list["items"].as_array().unwrap().len(), 2);

            // Validation branches: bad principal / empty actions -> 400;
            // unknown project -> 404 for grant + member list.
            let (status, _) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"robot","principal_id":"{user_id}","actions":["read"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let (status, _) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"user","principal_id":"{user_id}","actions":[]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let ghost = Uuid::new_v4();
            let (status, _) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{ghost}/members"),
                    &format!(
                        r#"{{"principal_type":"user","principal_id":"{user_id}","actions":["read"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _) =
                tdh::send(app(&state, admin()), tdh::get(format!("/{ghost}/members"))).await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            // Revoke the user grant -> 200; revoke again -> 404; list -> 1 left.
            let revoke_body = format!(r#"{{"principal_type":"user","principal_id":"{user_id}"}}"#);
            let (status, _) = tdh::send(
                app(&state, admin()),
                req("DELETE", &format!("/{id}/members"), &revoke_body),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (status, _) = tdh::send(
                app(&state, admin()),
                req("DELETE", &format!("/{id}/members"), &revoke_body),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (_, bytes) =
                tdh::send(app(&state, admin()), tdh::get(format!("/{id}/members"))).await;
            let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(list["items"].as_array().unwrap().len(), 1);

            // Malformed revoke payload -> 400.
            let (status, _) = tdh::send(
                app(&state, admin()),
                req("DELETE", &format!("/{id}/members"), "{ not json"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            cleanup_project_rows(&pool, &key).await;
        }

        #[tokio::test]
        async fn http_project_delete_unassigns_repos_and_removes_grants() {
            let Some((pool, state)) = setup().await else {
                return;
            };
            let key = format!("prj-http-del-{}", Uuid::new_v4().simple());
            let (_, created) = create_via_api(&state, &key).await;
            let id = created["id"].as_str().expect("project id").to_string();
            let project_id: Uuid = id.parse().unwrap();

            let (user_id, _) = tdh::create_user(&pool).await;
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            sqlx::query("UPDATE repositories SET project_id = $2 WHERE id = $1")
                .bind(repo_id)
                .bind(project_id)
                .execute(&pool)
                .await
                .expect("assign repo");
            let (status, _) = tdh::send(
                app(&state, admin()),
                req(
                    "POST",
                    &format!("/{id}/members"),
                    &format!(
                        r#"{{"principal_type":"user","principal_id":"{user_id}","actions":["read"]}}"#
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            // Delete the project through the handler (single tx: grants +
            // project row; repos auto-unassign via ON DELETE SET NULL).
            let (status, _) =
                tdh::send(app(&state, admin()), req("DELETE", &format!("/{id}"), "")).await;
            assert_eq!(status, StatusCode::OK);

            let repo_project: Option<Uuid> =
                sqlx::query_scalar("SELECT project_id FROM repositories WHERE id = $1")
                    .bind(repo_id)
                    .fetch_one(&pool)
                    .await
                    .expect("repo row");
            assert_eq!(repo_project, None, "repo must be auto-unassigned");
            let grants: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM permissions \
                 WHERE target_type = 'project' AND target_id = $1",
            )
            .bind(project_id)
            .fetch_one(&pool)
            .await
            .expect("grant count");
            assert_eq!(grants, 0, "project grants must be removed with the project");

            tdh::cleanup(&pool, repo_id, user_id).await;
            cleanup_project_rows(&pool, &key).await;
        }

        #[tokio::test]
        async fn http_admin_and_scope_gates() {
            let Some((_pool, state)) = setup().await else {
                return;
            };
            // Non-admin user: every endpoint is 403 in P1.
            let non_admin = tdh::make_auth(Uuid::new_v4(), "prj-http-user");
            let (status, _) = tdh::send(app(&state, non_admin.clone()), tdh::get("/".into())).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = tdh::send(
                app(&state, non_admin.clone()),
                req("POST", "/", r#"{"key":"x","name":"x"}"#),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = tdh::send(
                app(&state, non_admin),
                req("DELETE", &format!("/{}", Uuid::new_v4()), ""),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);

            // Admin identity behind a READ-scoped API token: scope gate wins
            // on mutations (403 before any parse/DB write).
            let read_scope_admin = AuthExtension {
                is_api_token: true,
                is_service_account: true,
                scopes: Some(vec!["read".to_string()]),
                ..tdh::admin_auth(Uuid::new_v4(), "prj-http-ro-admin")
            };
            let (status, _) = tdh::send(
                app(&state, read_scope_admin.clone()),
                req("POST", "/", r#"{"key":"x","name":"x"}"#),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = tdh::send(
                app(&state, read_scope_admin),
                req("DELETE", &format!("/{}", Uuid::new_v4()), ""),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);

            // Anonymous -> 401 from the in-handler require_auth.
            let (status, _) = tdh::send(
                tdh::router_anon(router(), state.clone()),
                tdh::get("/".into()),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }
}
