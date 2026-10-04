//! Project management handlers (#2472, P1).
//!
//! Projects are a metadata grouping of repositories. Membership grants are
//! stored in the existing `permissions` table with `target_type = 'project'`
//! (no third authz store): a grant on a project is inherited by every
//! repository whose `repositories.project_id` points at it (read plane via
//! `repository_service::permissions_grant_exists`, write plane via
//! `permission_service::{query_actions, has_any_rules_for_target}`).
//!
//! Authorization (#2473, P2): list/create/delete stay global-admin-only
//! (tenant provisioning and a destructive cascade). The five per-project
//! management endpoints (get/update a project, list/add/remove its members)
//! also admit a *project admin*: a principal holding `admin` in a
//! `target_type = 'project'` grant on THAT project id (see
//! [`require_project_admin`]). Changing a project's `quota_bytes` stays
//! global-admin-only. The global `/api/v1/permissions` CRUD is untouched and
//! remains the global-admin escalation boundary.
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
/// and `service_account` directly — the resolver matches
/// `principal_type IN ('user','service_account')` since #2499/#2433 — and
/// `group` via `user_group_members`). Refusing `service_account` here (#3683)
/// left a service account with no project-level grant channel at all while
/// the read side happily resolved such a row.
pub(crate) fn valid_principal_type(principal_type: &str) -> bool {
    matches!(principal_type, "user" | "service_account" | "group")
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
            "Invalid principal_type '{}': must be 'user', 'service_account' or 'group'",
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

/// The action set that makes a principal a *project admin* (#2473).
///
/// Action matching in `PermissionService::check_permission` is exact-string:
/// `admin` does NOT imply `read`/`write`/`delete`. `admin` alone is the
/// management gate (this module's endpoints and repository creation in the
/// project); the other three carry the data-plane access every repository in
/// the project inherits. A project-admin grant therefore carries all four.
/// Peer access to repositories created later comes from project inheritance
/// (`query_actions` re-resolves per request): no per-repository grant is ever
/// written for project admins.
pub const PROJECT_ADMIN_ACTIONS: [&str; 4] = ["admin", "read", "write", "delete"];

/// Pure project-admin decision (#2473): a global admin always passes; anyone
/// else needs an `admin` grant on the project AND a credential that is not
/// restricted to a repository allowlist (a repo-scoped API token must not
/// be able to rewrite project-wide membership that reaches beyond the
/// repositories it was minted for).
pub(crate) fn project_admin_allowed(auth: &AuthExtension, has_project_admin_grant: bool) -> bool {
    auth.is_admin
        || (has_project_admin_grant
            && matches!(
                auth.access_scope(),
                crate::models::access_scope::AccessScope::Admin
            ))
}

/// Gate for the per-project management endpoints (#2473): `is_admin` OR an
/// `admin` grant on `project_id` (direct, service-account or via a group).
///
/// The grant lookup is bound to the path id, so a project admin of P is
/// denied on project Q. A non-existent project yields 403 for a non-admin
/// (never a 404 that would confirm the id), and the global-admin bypass runs
/// before any DB work.
pub(crate) async fn require_project_admin(
    state: &SharedState,
    auth: &AuthExtension,
    project_id: Uuid,
) -> Result<()> {
    if auth.is_admin {
        return Ok(());
    }
    // Skip the lookup entirely for a repo-restricted credential: it can never
    // pass `project_admin_allowed`, whatever grants its principal holds.
    let scope_ok = matches!(
        auth.access_scope(),
        crate::models::access_scope::AccessScope::Admin
    );
    let has_grant = scope_ok
        && state
            .permission_service
            .check_permission(auth.user_id, "project", project_id, "admin", false)
            .await?;
    if project_admin_allowed(auth, has_grant) {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Project admin access required".to_string(),
        ))
    }
}

/// Fields of an update that only a global admin may change (#2473). The
/// project quota is a provisioning control: a project admin raising its own
/// ceiling would defeat it.
pub(crate) fn update_needs_global_admin(payload: &UpdateProjectRequest) -> bool {
    payload.quota_bytes.is_some()
}

/// Does the caller hold repository-provisioning authority instance-wide?
/// A global admin, or a holder of `admin` on the system sentinel (the
/// pre-P2 gate for creating repositories anywhere).
pub(crate) async fn has_system_repo_admin(
    state: &SharedState,
    auth: &AuthExtension,
) -> Result<bool> {
    if auth.is_admin {
        return Ok(true);
    }
    state
        .permission_service
        .check_permission(
            auth.user_id,
            crate::services::permission_service::SYSTEM_TARGET_TYPE,
            crate::services::permission_service::SYSTEM_SENTINEL_ID,
            "admin",
            false,
        )
        .await
}

/// May the caller assign a repository to `project_id` (on create, or by
/// reassignment on update)? Instance-wide repository provisioners may assign
/// anywhere; anyone else needs project-admin on the destination project
/// (#2473), so a project admin can create repositories only inside the
/// project they administer. A missing or foreign project id is a denial.
pub(crate) async fn can_assign_to_project(
    state: &SharedState,
    auth: &AuthExtension,
    project_id: Uuid,
) -> Result<bool> {
    if has_system_repo_admin(state, auth).await? {
        return Ok(true);
    }
    is_project_admin(state, auth, project_id).await
}

/// [`require_project_admin`] as a boolean (a denial is `Ok(false)`, a
/// database failure is still an error).
pub(crate) async fn is_project_admin(
    state: &SharedState,
    auth: &AuthExtension,
    project_id: Uuid,
) -> Result<bool> {
    match require_project_admin(state, auth, project_id).await {
        Ok(()) => Ok(true),
        Err(AppError::Authorization(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Pure key-prefix convention check (#2473).
///
/// The convention is opt-in: a repository in project `customer-a` MAY be
/// keyed `customer-a-<name>`, and keys that do not use any project's prefix
/// are never constrained (keys stay flat and globally unique; no routing
/// change). What is validated is that a key which DOES take a project's
/// prefix belongs to that project: a repository assigned to project
/// `assigned` whose key starts with `<K>-` for one or more projects `K`
/// (`claimed`, as `(id, key)` pairs) must be assigned to one of them. This
/// stops a project admin from minting `customer-b-*` names inside their own
/// project.
///
/// `name_projects` controls whether the 400 names the claimed projects. It
/// is true only for global admins: a project admin probing `<guess>-x` keys
/// must not learn other tenants' project keys from the message (the
/// success/400 difference remains as a residual oracle, an accepted
/// trade-off).
pub(crate) fn check_repo_key_project_prefix(
    repo_key: &str,
    assigned: Uuid,
    claimed: &[(Uuid, String)],
    name_projects: bool,
) -> Result<()> {
    let claimed: Vec<&(Uuid, String)> = claimed
        .iter()
        .filter(|(_, k)| repo_key.starts_with(&format!("{k}-")))
        .collect();
    if claimed.is_empty() || claimed.iter().any(|(id, _)| *id == assigned) {
        return Ok(());
    }
    if !name_projects {
        return Err(AppError::Validation(format!(
            "Repository key '{repo_key}' uses another project's key prefix; \
             use '<project key>-<name>' of the assigned project or an unprefixed key"
        )));
    }
    let keys: Vec<&str> = claimed.iter().map(|(_, k)| k.as_str()).collect();
    Err(AppError::Validation(format!(
        "Repository key '{}' uses the key prefix of project '{}' but is not assigned to it",
        repo_key,
        keys.join("', '")
    )))
}

/// DB wrapper for [`check_repo_key_project_prefix`]: loads only the projects
/// whose `<key>-` is a prefix of `repo_key` (`left()` instead of `LIKE`, since
/// project keys may contain the `_` wildcard).
pub(crate) async fn validate_repo_key_project_prefix(
    state: &SharedState,
    repo_key: &str,
    assigned: Uuid,
    name_projects: bool,
) -> Result<()> {
    let claimed: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, key FROM projects WHERE left($1, length(key) + 1) = key || '-'")
            .bind(repo_key)
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    check_repo_key_project_prefix(repo_key, assigned, &claimed, name_projects)
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
    /// Global admin only: a project admin sending this field gets 403.
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
    /// "user", "service_account" or "group".
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
        (status = 403, description = "Global admin or project admin of this project required"),
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
    require_project_admin(&state, &auth, id).await?;

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
        (status = 403, description = "Global admin or project admin of this project required (quota_bytes: global admin only)"),
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
    require_project_admin(&state, &auth, id).await?;

    let payload: UpdateProjectRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid project payload: {}", e)))?;
    if update_needs_global_admin(&payload) {
        auth.require_admin()?;
    }

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
        (status = 403, description = "Global admin or project admin of this project required"),
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
    require_project_admin(&state, &auth, id).await?;

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
        (status = 403, description = "Global admin or project admin of this project required"),
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
    require_project_admin(&state, &auth, id).await?;

    let payload: AddProjectMemberRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid member payload: {}", e)))?;

    validate_member_grant(&payload.principal_type, &payload.actions)?;
    // #2503 (defense-in-depth): `validate_member_grant` only enforces the
    // project-member *type allowlist* (user|service_account|group) and
    // non-empty actions — it
    // never checks that `principal_id` actually names a principal of that type.
    // Without this, a mistyped grant (e.g. `principal_type = 'user'` naming a
    // service-account id) is upserted here and, because project grants are
    // inherited by every repository in the project and the resolver matches
    // `principal_type IN ('user','service_account')`, becomes effective for the
    // mistyped principal — the same class POST /permissions rejects. Reuse the
    // identical write-time correspondence check so this parallel writer agrees.
    state
        .permission_service
        .validate_principal(&payload.principal_type, payload.principal_id)
        .await?;
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
        (status = 403, description = "Global admin or project admin of this project required"),
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
    require_project_admin(&state, &auth, id).await?;

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

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helpers: principal type domain
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_principal_type_accepts_user_group_and_service_account() {
        assert!(valid_principal_type("user"));
        assert!(valid_principal_type("group"));
        // #3683: the resolver has matched `service_account` since #2499/#2433;
        // refusing it here was the authoring-side gap, not a guard.
        assert!(valid_principal_type("service_account"));
    }

    #[test]
    fn test_invalid_principal_types_rejected() {
        assert!(!valid_principal_type("admin"));
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
    // #2473 pure helpers: project-admin decision, quota guard, key prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_project_admin_actions_carry_full_access_set() {
        // check_permission is exact-string: `admin` alone grants no data
        // plane access, so the role must spell out every action.
        assert_eq!(PROJECT_ADMIN_ACTIONS, ["admin", "read", "write", "delete"]);
    }

    #[test]
    fn test_project_admin_allowed_matrix() {
        let admin = AuthExtension {
            is_admin: true,
            ..non_admin_auth()
        };
        assert!(project_admin_allowed(&admin, false));
        assert!(project_admin_allowed(&non_admin_auth(), true));
        assert!(!project_admin_allowed(&non_admin_auth(), false));
        // A repo-restricted credential never passes, grant or not.
        let restricted = AuthExtension {
            is_api_token: true,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Restricted(vec![
                Uuid::new_v4(),
            ]),
            ..non_admin_auth()
        };
        assert!(!project_admin_allowed(&restricted, true));
    }

    #[test]
    fn test_update_needs_global_admin_only_for_quota() {
        let rename: UpdateProjectRequest = serde_json::from_str(r#"{"name":"n"}"#).unwrap();
        assert!(!update_needs_global_admin(&rename));
        let quota: UpdateProjectRequest = serde_json::from_str(r#"{"quota_bytes":1}"#).unwrap();
        assert!(update_needs_global_admin(&quota));
    }

    #[test]
    fn test_key_prefix_unprefixed_keys_unconstrained() {
        let p = Uuid::new_v4();
        assert!(check_repo_key_project_prefix("npm-local", p, &[], false).is_ok());
    }

    #[test]
    fn test_key_prefix_own_project_accepted() {
        let p = Uuid::new_v4();
        let claimed = vec![(p, "customer-a".to_string())];
        assert!(check_repo_key_project_prefix("customer-a-npm", p, &claimed, false).is_ok());
    }

    #[test]
    fn test_key_prefix_foreign_project_rejected() {
        let mine = Uuid::new_v4();
        let other = Uuid::new_v4();
        let claimed = vec![(other, "customer-b".to_string())];
        // Global admins are told which project owns the prefix ...
        let err =
            check_repo_key_project_prefix("customer-b-npm", mine, &claimed, true).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("project 'customer-b'")),
            "{err:?}"
        );
        // ... everyone else gets a generic 400 that does not confirm the
        // other project's key beyond the key they themselves sent.
        let err =
            check_repo_key_project_prefix("customer-b-npm", mine, &claimed, false).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if !m.contains("project 'customer-b'")),
            "{err:?}"
        );
    }

    #[test]
    fn test_key_prefix_nested_project_keys() {
        // Projects `a` and `a-b` both prefix `a-b-npm`; either owner may use it.
        let a = Uuid::new_v4();
        let ab = Uuid::new_v4();
        let claimed = vec![(a, "a".to_string()), (ab, "a-b".to_string())];
        assert!(check_repo_key_project_prefix("a-b-npm", ab, &claimed, false).is_ok());
        assert!(check_repo_key_project_prefix("a-b-npm", a, &claimed, false).is_ok());
        assert!(check_repo_key_project_prefix("a-b-npm", Uuid::new_v4(), &claimed, false).is_err());
        // A claimed key that is not actually a `<key>-` prefix is ignored.
        let unrelated = vec![(a, "ab".to_string())];
        assert!(check_repo_key_project_prefix("a-b-npm", ab, &unrelated, false).is_ok());
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
                svc.user_can_access_repo(
                    repo_id,
                    member_id,
                    // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                    // this test was written to assert; the read-action narrowing has its own tests.
                    crate::services::repository_service::RepoAccess::TenantOnly
                )
                .await
                .unwrap(),
                "project-read member must reach the assigned repository"
            );
            assert!(
                !svc.user_can_access_repo(
                    repo_id,
                    outsider_id,
                    // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                    // this test was written to assert; the read-action narrowing has its own tests.
                    crate::services::repository_service::RepoAccess::TenantOnly
                )
                .await
                .unwrap(),
                "non-member must stay denied on the project repository"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, member_id).await;
            tdh::cleanup(&pool, repo_id, outsider_id).await;
        }

        /// #2503: `add_project_member` must reject a mistyped grant (a `user`-typed
        /// grant naming a service-account id) with a 400, exactly as
        /// `POST /permissions` does — otherwise the mistyped grant is upserted and,
        /// being inherited by the project's repositories, makes the SA effective.
        /// A well-typed member is still accepted, and no stray grant is written.
        #[tokio::test]
        async fn test_add_project_member_rejects_mistyped_principal() {
            use axum::extract::{Path, State};
            use axum::Extension;

            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let dir = std::env::temp_dir().join(format!("prj-mt-{}", Uuid::new_v4()));
            let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
            let (admin_id, admin_name) = tdh::create_user(&pool).await;
            let admin = AuthExtension {
                is_admin: true,
                ..tdh::make_auth(admin_id, &admin_name)
            };
            let (user_id, _) = tdh::create_user(&pool).await;
            let sa_id = Uuid::new_v4();
            let sa_name = format!("prj-mt-sa-{sa_id}");
            sqlx::query(
                r#"INSERT INTO users
                     (id, username, email, password_hash, auth_provider,
                      is_admin, is_active, is_service_account)
                   VALUES ($1, $2, $3, 'unused', 'local', false, true, true)"#,
            )
            .bind(sa_id)
            .bind(&sa_name)
            .bind(format!("{sa_name}@test.local"))
            .execute(&pool)
            .await
            .expect("seed service account");
            let (repo_id, _, _) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "mistype").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;

            let call = |auth: AuthExtension, ptype: &str, pid: Uuid| {
                let state = state.clone();
                let body = axum::body::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "principal_type": ptype,
                        "principal_id": pid,
                        "actions": ["read", "write"],
                    }))
                    .unwrap(),
                );
                async move {
                    add_project_member(State(state), Extension(Some(auth)), Path(project_id), body)
                        .await
                }
            };

            // Exploit: a `user`-typed grant naming a service-account id -> 400.
            let mistyped = call(admin.clone(), "user", sa_id).await;
            assert!(
                matches!(mistyped, Err(AppError::Validation(_))),
                "mistyped project-member grant (user id = SA) must be a 400, got {mistyped:?}"
            );

            // Resolve-time: the rejected grant was never written, so the SA has no
            // inherited access to the project's private repository.
            let svc = crate::services::repository_service::RepositoryService::new(pool.clone());
            assert!(
                !svc.user_can_access_repo(
                    repo_id,
                    sa_id,
                    // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                    // this test was written to assert; the read-action narrowing has its own tests.
                    crate::services::repository_service::RepoAccess::TenantOnly
                )
                .await
                .unwrap(),
                "a rejected mistyped grant must not make the SA effective on the project repo"
            );

            // Legit: a well-typed user member is still accepted (200).
            assert!(
                call(admin, "user", user_id).await.is_ok(),
                "a valid user member must still be accepted"
            );

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, user_id).await;
            let _ = sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
                .bind(admin_id)
                .bind(sa_id)
                .execute(&pool)
                .await;
        }

        /// #3683: a service account must be grantable through a project.
        ///
        /// `valid_principal_type` refused `service_account`, so a
        /// project-managed deployment had no channel at all to write the one
        /// principal type the read predicates already resolve
        /// (`permission_service::query_actions`,
        /// `repository_service::permissions_grant_exists`) — the service
        /// account's token then failed `require_repo_write_access` and the
        /// docker/generic push came back 403.
        ///
        /// Drives the reporter's shape end to end: add the SA as a project
        /// member, then assert its token clears the write gate on a private
        /// repository assigned to that project. Fails on main at the
        /// `add_project_member` call (400 Validation).
        #[tokio::test]
        async fn test_service_account_project_member_can_write_to_project_repo() {
            use crate::api::handlers::repositories::require_repo_write_access;
            use crate::models::access_scope::AccessScope;
            use crate::services::repository_service::RepositoryService;

            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let dir = std::env::temp_dir().join(format!("prj-sa-{}", Uuid::new_v4()));
            let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
            let (admin_id, admin_name) = tdh::create_user(&pool).await;
            let admin = tdh::admin_auth(admin_id, &admin_name);
            let (sa_id, sa_name) = tdh::create_service_account(&pool).await;
            let (repo_id, repo_key, repo_dir) = tdh::create_repo(&pool, "local", "generic").await;
            let project_id = create_project_row(&pool, "sa").await;
            assign_repo_to_project(&pool, repo_id, project_id).await;

            // The service account's own API token: action scopes only, no
            // repository restriction (the reporter's "w/o repo scope" case).
            let sa_auth = AuthExtension {
                is_api_token: true,
                is_service_account: true,
                scopes: Some(vec!["read".to_string(), "write".to_string()]),
                allowed_repo_ids: AccessScope::Admin,
                ..tdh::make_auth(sa_id, &sa_name)
            };
            let repo_service = RepositoryService::new(pool.clone());
            let repo = repo_service.get_by_key(&repo_key).await.expect("repo");

            let denied_before = require_repo_write_access(&sa_auth, &repo, &repo_service)
                .await
                .is_err();

            let call = |ptype: &str, pid: Uuid| {
                let state = state.clone();
                let admin = admin.clone();
                let body = axum::body::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "principal_type": ptype,
                        "principal_id": pid,
                        "actions": ["read", "write"],
                    }))
                    .unwrap(),
                );
                async move {
                    add_project_member(State(state), Extension(Some(admin)), Path(project_id), body)
                        .await
                }
            };

            let granted = call("service_account", sa_id).await;
            let grant_ok = granted.is_ok();
            state.permission_service.invalidate_cache();

            let allowed_after = require_repo_write_access(&sa_auth, &repo, &repo_service)
                .await
                .is_ok();
            let action_after = state
                .permission_service
                .check_repository_action(sa_id, repo_id, "write", false)
                .await
                .unwrap_or(false);

            // #2503 mistype guard is untouched: `validate_principal` runs right
            // after the type allowlist, so a `service_account`-typed grant naming
            // a plain user id is still a 400.
            let (plain_user_id, _) = tdh::create_user(&pool).await;
            let mistyped = call("service_account", plain_user_id).await;

            cleanup_project(&pool, project_id).await;
            tdh::cleanup(&pool, repo_id, sa_id).await;
            tdh::cleanup_user(&pool, plain_user_id).await;
            tdh::cleanup_user(&pool, admin_id).await;
            let _ = std::fs::remove_dir_all(&repo_dir);
            let _ = std::fs::remove_dir_all(&dir);

            assert!(
                denied_before,
                "precondition: the service account must start with no access"
            );
            assert!(
                grant_ok,
                "#3683: POST /projects/{{id}}/members must accept \
                 principal_type = 'service_account' (got {granted:?})"
            );
            assert!(
                allowed_after,
                "#3683: the granted service account's token must clear \
                 require_repo_write_access on the project's repository"
            );
            assert!(
                action_after,
                "#3683: the inherited project grant must also satisfy the \
                 canonical write-action check"
            );
            assert!(
                matches!(mistyped, Err(AppError::Validation(_))),
                "#2503 guard must survive: a 'service_account' grant naming a \
                 plain user id is still a 400, got {mistyped:?}"
            );
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
                !svc.user_can_access_repo(
                    repo_id,
                    user_id,
                    // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                    // this test was written to assert; the read-action narrowing has its own tests.
                    crate::services::repository_service::RepoAccess::TenantOnly
                )
                .await
                .unwrap(),
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
                !svc.user_can_access_repo(
                    repo_id,
                    user_id,
                    // TENANT-GATE-ONLY (#3331): pins the tenant predicate itself, which is what
                    // this test was written to assert; the read-action narrowing has its own tests.
                    crate::services::repository_service::RepoAccess::TenantOnly
                )
                .await
                .unwrap(),
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
        use crate::api::extractors::Json as RJson;
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
            // #2503: project-member grants are now validated for principal
            // type/id correspondence, so the grantees must be real principals.
            let (user_id, _) = tdh::create_user(&pool).await;
            let group_id = Uuid::new_v4();
            sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
                .bind(group_id)
                .bind(format!("prj-http-mem-grp-{group_id}"))
                .execute(&pool)
                .await
                .expect("seed group");

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
            let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
                .bind(group_id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user_id)
                .execute(&pool)
                .await;
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

        // -------------------------------------------------------------------
        // #2473: project-admin role and its containment red-team
        // -------------------------------------------------------------------

        /// Two projects (P administered by the caller, Q foreign) plus a real
        /// project-admin user holding [`PROJECT_ADMIN_ACTIONS`] on P only.
        struct Fixture {
            pool: PgPool,
            state: crate::api::SharedState,
            p: Uuid,
            p_key: String,
            q: Uuid,
            q_key: String,
            admin_user: Uuid,
            auth: AuthExtension,
        }

        async fn fixture() -> Option<Fixture> {
            let (pool, state) = setup().await?;
            let tag = Uuid::new_v4().simple().to_string();
            let p_key = format!("pa{}", &tag[..10]);
            let q_key = format!("pb{}", &tag[..10]);
            let (_, p) = create_via_api(&state, &p_key).await;
            let (_, q) = create_via_api(&state, &q_key).await;
            let p: Uuid = p["id"].as_str().unwrap().parse().unwrap();
            let q: Uuid = q["id"].as_str().unwrap().parse().unwrap();
            let (admin_user, username) = tdh::create_user(&pool).await;
            grant(&pool, "user", admin_user, p, &PROJECT_ADMIN_ACTIONS).await;
            let auth = tdh::make_auth(admin_user, &username);
            Some(Fixture {
                pool,
                state,
                p,
                p_key,
                q,
                q_key,
                admin_user,
                auth,
            })
        }

        async fn grant(pool: &PgPool, ptype: &str, pid: Uuid, project: Uuid, actions: &[&str]) {
            let actions: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
            sqlx::query(
                "INSERT INTO permissions \
                 (principal_type, principal_id, target_type, target_id, actions) \
                 VALUES ($1, $2, 'project', $3, $4)",
            )
            .bind(ptype)
            .bind(pid)
            .bind(project)
            .bind(&actions)
            .execute(pool)
            .await
            .expect("seed project grant");
        }

        async fn teardown(f: &Fixture) {
            let _ = sqlx::query(
                "DELETE FROM role_assignments WHERE repository_id IN \
                 (SELECT id FROM repositories WHERE project_id IN ($1, $2))",
            )
            .bind(f.p)
            .bind(f.q)
            .execute(&f.pool)
            .await;
            let _ = sqlx::query(
                "DELETE FROM permissions WHERE target_type = 'repository' AND target_id IN \
                 (SELECT id FROM repositories WHERE project_id IN ($1, $2))",
            )
            .bind(f.p)
            .bind(f.q)
            .execute(&f.pool)
            .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE project_id IN ($1, $2)")
                .bind(f.p)
                .bind(f.q)
                .execute(&f.pool)
                .await;
            cleanup_project_rows(&f.pool, &f.p_key).await;
            cleanup_project_rows(&f.pool, &f.q_key).await;
            tdh::cleanup_user(&f.pool, f.admin_user).await;
        }

        async fn call(
            state: &crate::api::SharedState,
            auth: &AuthExtension,
            method: &str,
            uri: String,
            body: &str,
        ) -> StatusCode {
            tdh::send(app(state, auth.clone()), req(method, &uri, body))
                .await
                .0
        }

        fn member_body(user: Uuid, actions: &str) -> String {
            format!(r#"{{"principal_type":"user","principal_id":"{user}","actions":{actions}}}"#)
        }

        fn remove_body(user: Uuid) -> String {
            format!(r#"{{"principal_type":"user","principal_id":"{user}"}}"#)
        }

        /// (e) Within-project management is intended and passes: get, rename,
        /// list/add/remove members on the project the caller administers.
        #[tokio::test]
        async fn http_project_admin_manages_own_project() {
            let Some(f) = fixture().await else {
                return;
            };
            let (s, a, p) = (&f.state, &f.auth, f.p);
            assert_eq!(call(s, a, "GET", format!("/{p}"), "").await, StatusCode::OK);
            assert_eq!(
                call(s, a, "PUT", format!("/{p}"), r#"{"name":"renamed"}"#).await,
                StatusCode::OK
            );
            assert_eq!(
                call(s, a, "GET", format!("/{p}/members"), "").await,
                StatusCode::OK
            );
            let (teammate, _) = tdh::create_user(&f.pool).await;
            assert_eq!(
                call(
                    s,
                    a,
                    "POST",
                    format!("/{p}/members"),
                    &member_body(teammate, r#"["read","write"]"#)
                )
                .await,
                StatusCode::OK
            );
            // A teammate can be promoted to peer project admin.
            assert_eq!(
                call(
                    s,
                    a,
                    "POST",
                    format!("/{p}/members"),
                    &member_body(teammate, r#"["admin","read","write","delete"]"#)
                )
                .await,
                StatusCode::OK
            );
            assert_eq!(
                call(
                    s,
                    a,
                    "DELETE",
                    format!("/{p}/members"),
                    &remove_body(teammate)
                )
                .await,
                StatusCode::OK
            );
            tdh::cleanup_user(&f.pool, teammate).await;
            teardown(&f).await;
        }

        /// (a) A project admin of P cannot manage project Q (path-id bound),
        /// and cannot reach the global-admin-only project endpoints or raise
        /// its own quota.
        #[tokio::test]
        async fn http_project_admin_cannot_manage_other_project() {
            let Some(f) = fixture().await else {
                return;
            };
            let (s, a, p, q) = (&f.state, &f.auth, f.p, f.q);
            let (victim, _) = tdh::create_user(&f.pool).await;
            for (method, uri, body) in [
                ("GET", format!("/{q}"), String::new()),
                ("PUT", format!("/{q}"), r#"{"name":"pwned"}"#.to_string()),
                ("GET", format!("/{q}/members"), String::new()),
                (
                    "POST",
                    format!("/{q}/members"),
                    member_body(f.admin_user, r#"["admin"]"#),
                ),
                ("DELETE", format!("/{q}/members"), remove_body(victim)),
                // Global-admin-only surface, even for the caller's own project.
                ("GET", "/".to_string(), String::new()),
                (
                    "POST",
                    "/".to_string(),
                    r#"{"key":"pa-new","name":"x"}"#.to_string(),
                ),
                ("DELETE", format!("/{p}"), String::new()),
                ("DELETE", format!("/{q}"), String::new()),
                (
                    "PUT",
                    format!("/{p}"),
                    r#"{"quota_bytes":999999999}"#.to_string(),
                ),
                // Unknown project id: 403, never a 404 confirming existence.
                ("GET", format!("/{}", Uuid::new_v4()), String::new()),
            ] {
                assert_eq!(
                    call(s, a, method, uri.clone(), &body).await,
                    StatusCode::FORBIDDEN,
                    "{method} {uri} must be denied to a project admin of another project"
                );
            }
            // Nothing leaked into Q's membership.
            let q_grants: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM permissions WHERE target_type = 'project' AND target_id = $1",
            )
            .bind(q)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            assert_eq!(q_grants, 0);
            tdh::cleanup_user(&f.pool, victim).await;
            teardown(&f).await;
        }

        /// The role is the `admin` action on the project: a read/write member
        /// is not a project admin, a repo-restricted token of a real project
        /// admin is refused, and a group-held admin grant works.
        #[tokio::test]
        async fn http_project_admin_grant_shape() {
            let Some(f) = fixture().await else {
                return;
            };
            let (s, p) = (&f.state, f.p);
            let (member, member_name) = tdh::create_user(&f.pool).await;
            grant(&f.pool, "user", member, p, &["read", "write", "delete"]).await;
            let member_auth = tdh::make_auth(member, &member_name);
            assert_eq!(
                call(s, &member_auth, "GET", format!("/{p}/members"), "").await,
                StatusCode::FORBIDDEN
            );

            let restricted = AuthExtension {
                is_api_token: true,
                allowed_repo_ids: crate::models::access_scope::AccessScope::Restricted(vec![
                    Uuid::new_v4(),
                ]),
                ..f.auth.clone()
            };
            assert_eq!(
                call(s, &restricted, "GET", format!("/{p}"), "").await,
                StatusCode::FORBIDDEN
            );

            let (grp_user, grp_name) = tdh::create_user(&f.pool).await;
            let group_id = Uuid::new_v4();
            sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
                .bind(group_id)
                .bind(format!("prj-admins-{group_id}"))
                .execute(&f.pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
                .bind(grp_user)
                .bind(group_id)
                .execute(&f.pool)
                .await
                .unwrap();
            grant(&f.pool, "group", group_id, p, &PROJECT_ADMIN_ACTIONS).await;
            f.state.permission_service.invalidate_cache();
            let grp_auth = tdh::make_auth(grp_user, &grp_name);
            assert_eq!(
                call(s, &grp_auth, "GET", format!("/{p}/members"), "").await,
                StatusCode::OK
            );

            let _ = sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
                .bind(group_id)
                .execute(&f.pool)
                .await;
            teardown(&f).await;
            let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
                .bind(group_id)
                .execute(&f.pool)
                .await;
            tdh::cleanup_user(&f.pool, member).await;
            tdh::cleanup_user(&f.pool, grp_user).await;
        }

        /// (b)+(c) No escalation: the global permissions CRUD stays
        /// global-admin-only for a project admin, and granting `admin` on a
        /// project never makes anyone a global admin.
        #[tokio::test]
        async fn http_project_admin_cannot_reach_global_permissions() {
            let Some(f) = fixture().await else {
                return;
            };
            let perms = |auth: &AuthExtension| {
                tdh::router_with_auth(
                    crate::api::handlers::permissions::router(),
                    f.state.clone(),
                    auth.clone(),
                )
            };
            let (status, _) = tdh::send(perms(&f.auth), tdh::get("/".into())).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let body = format!(
                r#"{{"principal_type":"user","principal_id":"{}","target_type":"system","target_id":"00000000-0000-0000-0000-000000000000","actions":["admin"]}}"#,
                f.admin_user
            );
            let (status, _) = tdh::send(perms(&f.auth), req("POST", "/", &body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN);

            // Self-grant on the own project (intended) leaves is_admin false.
            assert_eq!(
                call(
                    &f.state,
                    &f.auth,
                    "POST",
                    format!("/{}/members", f.p),
                    &member_body(f.admin_user, r#"["admin","read","write","delete"]"#)
                )
                .await,
                StatusCode::OK
            );
            let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
                .bind(f.admin_user)
                .fetch_one(&f.pool)
                .await
                .unwrap();
            assert!(!is_admin, "a project grant must never mint a global admin");
            teardown(&f).await;
        }

        fn repo_body(key: &str, project: Option<Uuid>) -> Bytes {
            let mut v = serde_json::json!({
                "key": key, "name": key, "format": "generic", "repo_type": "local"
            });
            if let Some(p) = project {
                v["project_id"] = serde_json::json!(p);
            }
            Bytes::from(serde_json::to_vec(&v).unwrap())
        }

        async fn create_repo_as(
            f: &Fixture,
            key: &str,
            project: Option<Uuid>,
        ) -> Result<RJson<crate::api::handlers::repositories::RepositoryResponse>> {
            create_repo_with(f, &f.auth, key, project).await
        }

        async fn create_repo_with(
            f: &Fixture,
            auth: &AuthExtension,
            key: &str,
            project: Option<Uuid>,
        ) -> Result<RJson<crate::api::handlers::repositories::RepositoryResponse>> {
            crate::api::handlers::repositories::create_repository(
                State(f.state.clone()),
                Extension(Some(auth.clone())),
                repo_body(key, project),
            )
            .await
        }

        async fn update_repo_with(
            f: &Fixture,
            auth: &AuthExtension,
            key: &str,
            body: serde_json::Value,
        ) -> Result<RJson<crate::api::handlers::repositories::RepositoryResponse>> {
            let payload: crate::api::handlers::repositories::UpdateRepositoryRequest =
                serde_json::from_value(body).expect("update payload");
            crate::api::handlers::repositories::update_repository(
                State(f.state.clone()),
                Extension(Some(auth.clone())),
                Path(key.to_string()),
                RJson(payload),
            )
            .await
        }

        /// (d) Repository creation: a project admin creates inside their own
        /// project (and gets data-plane access by inheritance, no per-repo
        /// fan-out needed), but not outside it, not unassigned, and not with
        /// another project's key prefix; nor can they move a repository into
        /// a project they do not administer.
        #[tokio::test]
        async fn http_project_admin_repository_create_containment() {
            let Some(f) = fixture().await else {
                return;
            };
            let own_key = format!("{}-generic", f.p_key);
            let RJson(repo) = create_repo_as(&f, &own_key, Some(f.p))
                .await
                .expect("project admin creates in own project");
            assert_eq!(repo.project_id, Some(f.p));
            f.state.permission_service.invalidate_cache();
            assert!(f
                .state
                .permission_service
                .check_permission(f.admin_user, "repository", repo.id, "write", false)
                .await
                .unwrap());

            // A teammate made project admin later inherits it too.
            let (peer, _) = tdh::create_user(&f.pool).await;
            grant(&f.pool, "user", peer, f.p, &PROJECT_ADMIN_ACTIONS).await;
            f.state.permission_service.invalidate_cache();
            assert!(f
                .state
                .permission_service
                .check_permission(peer, "repository", repo.id, "write", false)
                .await
                .unwrap());

            let tag = Uuid::new_v4().simple().to_string();
            for (key, project) in [
                (format!("x{}", &tag[..12]), Some(f.q)),
                (format!("y{}", &tag[..12]), None),
                (format!("z{}", &tag[..12]), Some(Uuid::new_v4())),
            ] {
                let err = create_repo_as(&f, &key, project).await.unwrap_err();
                assert!(
                    matches!(err, AppError::Authorization(_)),
                    "create {key} in {project:?} must be 403: {err:?}"
                );
            }
            // Foreign key prefix inside the own project: 400.
            let squat = format!("{}-generic", f.q_key);
            let err = create_repo_as(&f, &squat, Some(f.p)).await.unwrap_err();
            assert!(matches!(err, AppError::Validation(_)), "{err:?}");

            // Reassignment to a foreign project is refused even though the
            // caller holds (inherited) repository admin.
            let move_req: crate::api::handlers::repositories::UpdateRepositoryRequest =
                serde_json::from_value(serde_json::json!({ "project_id": f.q })).unwrap();
            let err = crate::api::handlers::repositories::update_repository(
                State(f.state.clone()),
                Extension(Some(f.auth.clone())),
                Path(own_key.clone()),
                RJson(move_req),
            )
            .await
            .unwrap_err();
            assert!(matches!(err, AppError::Authorization(_)), "{err:?}");
            let still: Option<Uuid> =
                sqlx::query_scalar("SELECT project_id FROM repositories WHERE id = $1")
                    .bind(repo.id)
                    .fetch_one(&f.pool)
                    .await
                    .unwrap();
            assert_eq!(still, Some(f.p));

            // Re-sending the unchanged assignment (full-form edit) is fine.
            let same: crate::api::handlers::repositories::UpdateRepositoryRequest =
                serde_json::from_value(
                    serde_json::json!({ "project_id": f.p, "description": "d" }),
                )
                .unwrap();
            crate::api::handlers::repositories::update_repository(
                State(f.state.clone()),
                Extension(Some(f.auth.clone())),
                Path(own_key.clone()),
                RJson(same),
            )
            .await
            .expect("unchanged assignment is not a reassignment");

            // Renaming into another project's prefix is refused too.
            let rename: crate::api::handlers::repositories::UpdateRepositoryRequest =
                serde_json::from_value(serde_json::json!({ "key": squat })).unwrap();
            let err = crate::api::handlers::repositories::update_repository(
                State(f.state.clone()),
                Extension(Some(f.auth.clone())),
                Path(own_key.clone()),
                RJson(rename),
            )
            .await
            .unwrap_err();
            assert!(matches!(err, AppError::Validation(_)), "{err:?}");

            tdh::cleanup_user(&f.pool, peer).await;
            teardown(&f).await;
        }

        /// Review fix (#2473): a repository created through project admin
        /// alone must NOT hand its creator the durable `repository-owner`
        /// role. That role carries `admin`, which `check_repository_action`
        /// honours regardless of project rules, so it would survive the
        /// creator's removal from the project (and let them keep minting
        /// repo tokens), invisibly to the project's member listing.
        #[tokio::test]
        async fn http_removed_project_admin_loses_created_repository() {
            let Some(f) = fixture().await else {
                return;
            };
            let key = format!("{}-revoke", f.p_key);
            let RJson(repo) = create_repo_as(&f, &key, Some(f.p))
                .await
                .expect("project admin creates in own project");
            let perms = &f.state.permission_service;
            assert!(perms
                .check_repository_action(f.admin_user, repo.id, "write", false)
                .await
                .unwrap());
            let (created_by, owner_roles): (Option<Uuid>, i64) = sqlx::query_as(
                "SELECT r.created_by, (SELECT COUNT(*) FROM role_assignments ra \
                 WHERE ra.repository_id = r.id AND ra.user_id = $2) \
                 FROM repositories r WHERE r.id = $1",
            )
            .bind(repo.id)
            .bind(f.admin_user)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            assert_eq!(created_by, Some(f.admin_user), "creator is still recorded");
            assert_eq!(
                owner_roles, 0,
                "no owner/developer role for a project-admin create"
            );

            // Remove the creator from the project (as a global admin).
            assert_eq!(
                call(
                    &f.state,
                    &admin(),
                    "DELETE",
                    format!("/{}/members", f.p),
                    &remove_body(f.admin_user)
                )
                .await,
                StatusCode::OK
            );
            for action in ["read", "write", "delete", "admin"] {
                assert!(
                    !perms
                        .check_repository_action(f.admin_user, repo.id, action, false)
                        .await
                        .unwrap(),
                    "removed project admin must lose {action} on the repo it created"
                );
            }
            let mint: crate::api::handlers::repo_tokens::CreateRepoTokenRequest =
                serde_json::from_value(serde_json::json!({
                    "name": "after-removal", "scopes": ["write:artifacts"]
                }))
                .unwrap();
            let err = crate::api::handlers::repo_tokens::create_repo_token(
                State(f.state.clone()),
                Extension(Some(f.auth.clone())),
                Path(key.clone()),
                RJson(mint),
            )
            .await
            .expect_err("a removed project admin cannot mint a repo token");
            // Private repo: existence-hidden 404, or the delegation-ceiling 403.
            assert!(
                matches!(err, AppError::Authorization(_) | AppError::NotFound(_)),
                "{err:?}"
            );
            teardown(&f).await;
        }

        /// Backward compatibility: a system-sentinel `admin` holder (an
        /// instance-wide repository provisioner) still creates without a
        /// project, assigns to any project, moves repositories between
        /// projects, and keeps the owner auto-grant.
        #[tokio::test]
        async fn http_sentinel_admin_keeps_provisioning_rights() {
            let Some(f) = fixture().await else {
                return;
            };
            let (prov, prov_name) = tdh::create_user(&f.pool).await;
            tdh::grant_permission(
                &f.pool,
                "user",
                prov,
                crate::services::permission_service::SYSTEM_TARGET_TYPE,
                crate::services::permission_service::SYSTEM_SENTINEL_ID,
                &["admin"],
            )
            .await;
            let prov_auth = tdh::make_auth(prov, &prov_name);
            let tag = Uuid::new_v4().simple().to_string();

            let loose = format!("s{}", &tag[..12]);
            let RJson(unassigned) = create_repo_with(&f, &prov_auth, &loose, None)
                .await
                .expect("sentinel admin creates without a project");
            let owner_roles: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM role_assignments WHERE repository_id = $1 AND user_id = $2",
            )
            .bind(unassigned.id)
            .bind(prov)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            assert!(owner_roles > 0, "provisioners keep the owner auto-grant");

            let in_q = format!("t{}", &tag[..12]);
            create_repo_with(&f, &prov_auth, &in_q, Some(f.q))
                .await
                .expect("sentinel admin assigns to any project");
            let in_p = format!("u{}", &tag[..12]);
            let RJson(p_repo) = create_repo_with(&f, &prov_auth, &in_p, Some(f.p))
                .await
                .expect("sentinel admin creates in P");
            // PATCH itself needs repository `admin` in `permissions` (pre-P2
            // gate, unchanged); the sentinel grant then satisfies the
            // destination-project check without project admin on Q.
            tdh::grant_repo_actions(&f.pool, p_repo.id, prov, &["admin"]).await;
            f.state.permission_service.invalidate_cache();
            let RJson(moved) = update_repo_with(
                &f,
                &prov_auth,
                &in_p,
                serde_json::json!({ "project_id": f.q }),
            )
            .await
            .expect("sentinel admin moves P -> Q");
            assert_eq!(moved.project_id, Some(f.q));

            let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
                .bind(unassigned.id)
                .execute(&f.pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(unassigned.id)
                .execute(&f.pool)
                .await;
            let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
                .bind(prov)
                .execute(&f.pool)
                .await;
            teardown(&f).await;
            tdh::cleanup_user(&f.pool, prov).await;
        }

        /// Update edge cases: re-sending the unchanged `project_id` is not a
        /// reassignment for a repository-level admin who is NOT a project
        /// admin, a pre-existing repository whose key squats another
        /// project's prefix stays editable for non-key fields, and the prefix
        /// rule binds global admins too (with a message naming the project).
        #[tokio::test]
        async fn http_repository_update_project_edge_cases() {
            let Some(f) = fixture().await else {
                return;
            };
            // A real users row: create records `created_by` (FK).
            let (global_id, global_name) = tdh::create_user(&f.pool).await;
            let global = tdh::admin_auth(global_id, &global_name);
            let tag = Uuid::new_v4().simple().to_string();
            let key = format!("{}-edge", f.p_key);
            let RJson(repo) = create_repo_with(&f, &global, &key, Some(f.p))
                .await
                .expect("admin creates in P");

            // Repo-level admin only: unchanged project_id (full-form edit) is 200,
            // a real move is 403.
            let (repo_admin, ra_name) = tdh::create_user(&f.pool).await;
            tdh::grant_repo_actions(&f.pool, repo.id, repo_admin, &["admin", "read", "write"])
                .await;
            let ra_auth = tdh::make_auth(repo_admin, &ra_name);
            update_repo_with(
                &f,
                &ra_auth,
                &key,
                serde_json::json!({ "project_id": f.p, "description": "full form" }),
            )
            .await
            .expect("unchanged assignment by a repo-level admin is not a reassignment");
            let err =
                update_repo_with(&f, &ra_auth, &key, serde_json::json!({ "project_id": f.q }))
                    .await
                    .unwrap_err();
            assert!(matches!(err, AppError::Authorization(_)), "{err:?}");

            // Legacy squatting row (predates P2): description-only PATCH is fine,
            // for the project admin and a global admin alike.
            let legacy_key = format!("{}-legacy{}", f.q_key, &tag[..6]);
            let (legacy_id, _, _) = tdh::create_repo(&f.pool, "local", "generic").await;
            sqlx::query("UPDATE repositories SET key = $2, project_id = $3 WHERE id = $1")
                .bind(legacy_id)
                .bind(&legacy_key)
                .bind(f.p)
                .execute(&f.pool)
                .await
                .unwrap();
            f.state.permission_service.invalidate_cache();
            update_repo_with(
                &f,
                &f.auth,
                &legacy_key,
                serde_json::json!({ "description": "d" }),
            )
            .await
            .expect("legacy squatting key stays editable by the project admin");
            update_repo_with(
                &f,
                &global,
                &legacy_key,
                serde_json::json!({ "description": "d2" }),
            )
            .await
            .expect("legacy squatting key stays editable by an admin");

            // The prefix rule applies to administrators as well.
            let squat = format!("{}-admin{}", f.q_key, &tag[..6]);
            let err = create_repo_with(&f, &global, &squat, Some(f.p))
                .await
                .unwrap_err();
            assert!(
                matches!(err, AppError::Validation(ref m) if m.contains(&format!("project '{}'", f.q_key))),
                "admins get the named-project 400: {err:?}"
            );
            // A project admin gets the generic message instead.
            let err = create_repo_as(&f, &squat, Some(f.p)).await.unwrap_err();
            assert!(
                matches!(err, AppError::Validation(ref m) if !m.contains(&format!("project '{}'", f.q_key))),
                "{err:?}"
            );

            let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
                .bind(repo_admin)
                .execute(&f.pool)
                .await;
            teardown(&f).await;
            tdh::cleanup_user(&f.pool, repo_admin).await;
            tdh::cleanup_user(&f.pool, global_id).await;
        }
    }
}
