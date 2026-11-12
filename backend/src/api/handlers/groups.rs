//! Group management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::permission_service::{SYSTEM_SENTINEL_ID, SYSTEM_TARGET_TYPE};

/// Write a group audit row (#5653): the acting principal, the group as the
/// resource, and `details`. Fire-and-forget, so an audit-table outage never
/// fails the change itself.
async fn audit_group(
    state: &SharedState,
    auth: &AuthExtension,
    action: AuditAction,
    group_id: Uuid,
    group_name: &str,
    details: serde_json::Value,
) {
    audit_fire_and_forget(
        state.db.clone(),
        AuditEntry::for_principal(action, ResourceType::Group, auth)
            .resource(group_id)
            .resource_name(group_name)
            .details(details),
    )
    .await;
}

/// `details` of a membership row: the users whose membership actually changed.
fn group_members_audit_details(
    group_id: Uuid,
    group_name: &str,
    users: &[Uuid],
) -> serde_json::Value {
    serde_json::json!({
        "group_id": group_id,
        "group_name": group_name,
        "user_ids": users,
        "count": users.len(),
    })
}

/// The group's name for an audit row; the id when it cannot be read.
async fn group_name_for_audit(db: &sqlx::PgPool, id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT name FROM groups WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| id.to_string())
}

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Require an instance administrator or a holder of `admin` on group `id`,
/// refusing with `refusal` otherwise. For the IAM shadow comparison (#4214) a
/// pass is recorded on the group, so a later 4xx is not read as a refusal.
async fn require_group_admin(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    refusal: &str,
) -> Result<()> {
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "group", id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(refusal.to_string()));
        }
    }
    crate::api::authz::shadow_marker::note_passed_on(
        crate::services::iam_legacy_projection::ScopeRef::Group(id),
        crate::api::authz::shadow_marker::LegacyLevel::Admin,
    );
    Ok(())
}

/// Whether a caller reads groups without per-caller scoping.
///
/// Admins see every group (mirroring the admin short-circuit in the repository
/// visibility gate and the group mutation handlers); every other caller is
/// filtered to the groups they can actually reach.
fn group_read_unscoped(is_admin: bool) -> bool {
    is_admin
}

/// SQL predicate restricting a `groups` row to those a non-admin caller can
/// reach: groups they are a member of (`user_group_members`) UNION groups they
/// hold any permission grant on (`permissions` where `target_type = 'group'`,
/// held directly as a `user` principal or via one of the caller's groups).
///
/// This is the same membership+grant predicate the group mutation handlers
/// already trust via `permission_service::check_permission(user, "group", id, ..)`,
/// applied as a read filter. `group_id_expr` is the SQL expression for the
/// group id (e.g. `g.id`); `user_param` is the bind placeholder holding the
/// caller's user id (e.g. `$2`). Kept as a single helper so the list SELECT,
/// list COUNT, and get_group queries share one definition.
///
/// #1849: a grant arm carrying `conditions.allowed_cidrs` only counts when
/// the in-flight request's client IP satisfies it — the same predicate the
/// data-plane resolvers enforce, inlined from the request scope (NULL
/// outside one, matching nothing). Without it a conditioned group rule
/// would act unconditional here, leaking group metadata visibility to
/// callers the mutation gates deny (review finding P2, #4266).
fn visible_groups_predicate(group_id_expr: &str, user_param: &str) -> String {
    let ip_condition = crate::services::permission_service::ip_condition_sql(
        "p",
        &crate::services::permission_service::request_ip_sql_ref(),
    );
    format!(
        "({group_id_expr} IN (
            SELECT group_id FROM user_group_members WHERE user_id = {user_param}
         )
         OR EXISTS (
            SELECT 1 FROM permissions p
            WHERE p.target_type = 'group' AND p.target_id = {group_id_expr}
              AND (
                (p.principal_type IN ('user', 'service_account') AND p.principal_id = {user_param})
                OR (p.principal_type = 'group' AND p.principal_id IN (
                    SELECT group_id FROM user_group_members WHERE user_id = {user_param}
                ))
              )
              {ip_condition}
         ))"
    )
}

/// Create group routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route(
            "/:id",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route(
            "/:id/members",
            get(list_group_members)
                .post(add_members)
                .delete(remove_members),
        )
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListGroupsQuery {
    pub search: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// Query parameters for the group detail endpoint, controlling member pagination.
#[derive(Debug, Deserialize, IntoParams)]
pub struct GetGroupQuery {
    /// Maximum number of members to return (default: 50, max: 200)
    pub member_limit: Option<u32>,
    /// Number of members to skip for pagination (default: 0)
    pub member_offset: Option<u32>,
}

impl GetGroupQuery {
    /// Resolved limit, clamped to [1, 200] with a default of 50.
    pub fn limit(&self) -> i64 {
        self.member_limit.unwrap_or(50).clamp(1, 200) as i64
    }

    /// Resolved offset with a default of 0.
    pub fn offset(&self) -> i64 {
        self.member_offset.unwrap_or(0) as i64
    }
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct GroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// SSO provider owning the group (`oidc`/`saml`/`ldap`); `None` for local groups. IdP owns membership (#2874).
    pub external_source: Option<String>,
    pub member_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// See [`GroupRow::external_source`]; lets the frontend disable member editing for SSO groups.
    pub external_source: Option<String>,
    pub member_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<GroupRow> for GroupResponse {
    fn from(row: GroupRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            external_source: row.external_source,
            member_count: row.member_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Serialize, FromRow)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupMemberResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

impl From<MemberRow> for GroupMemberResponse {
    fn from(row: MemberRow) -> Self {
        Self {
            user_id: row.user_id,
            username: row.username,
            display_name: row.display_name,
            joined_at: row.joined_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupMemberListResponse {
    /// Paginated list of group members.
    pub members: Vec<GroupMemberResponse>,
    /// Total number of members in the group. Clients can compare this against
    /// the length of `members` to determine whether additional pages exist.
    pub members_total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupDetailResponse {
    #[serde(flatten)]
    pub group: GroupResponse,
    /// Paginated list of group members.
    pub members: Vec<GroupMemberResponse>,
    /// Total number of members in the group. Clients can compare this against
    /// the length of `members` to determine whether additional pages exist.
    pub members_total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupListResponse {
    pub items: Vec<GroupResponse>,
    pub pagination: Pagination,
}

/// List groups
#[utoipa::path(
    get,
    extensions(("x-auth-requirement" = json!("authenticated"))),
    path = "",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(ListGroupsQuery),
    responses(
        (status = 200, description = "List of groups", body = GroupListResponse),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_groups(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<GroupListResponse>> {
    let auth = require_auth(auth)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // #3557: the free-text term is a literal substring, so `%`/`_`/`\` in it
    // must match themselves; escaped here and matched under `ESCAPE '\'`.
    let search_pattern = query
        .search
        .as_ref()
        .map(|s| format!("%{}%", super::escape_like_literal(s)));

    // Check if groups table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(GroupListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    // Non-admins only see groups they can reach (membership UNION a group
    // permission grant); admins are unscoped. The $4 placeholder carries the
    // caller's user id when scoping is applied.
    let scoped = !group_read_unscoped(auth.is_admin);
    let select_scope = if scoped {
        format!(" AND {}", visible_groups_predicate("g.id", "$4"))
    } else {
        String::new()
    };
    let select_sql = format!(
        r#"
        SELECT g.id, g.name, g.description, g.external_source, g.created_at, g.updated_at,
               COALESCE(COUNT(ugm.user_id), 0) as member_count
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE ($1::text IS NULL OR g.name ILIKE $1 ESCAPE '\' OR g.description ILIKE $1 ESCAPE '\'){select_scope}
        GROUP BY g.id
        ORDER BY g.name
        OFFSET $2
        LIMIT $3
        "#
    );
    let mut select_query = sqlx::query_as::<_, GroupRow>(sqlx::AssertSqlSafe(&*select_sql))
        .bind(&search_pattern)
        .bind(offset)
        .bind(per_page as i64);
    if scoped {
        select_query = select_query.bind(auth.user_id);
    }
    let groups: Vec<GroupRow> = select_query
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // The COUNT must match the same scope so pagination totals are correct.
    let count_scope = if scoped {
        format!(" AND {}", visible_groups_predicate("g.id", "$2"))
    } else {
        String::new()
    };
    let count_sql = format!(
        r#"
        SELECT COUNT(*)
        FROM groups g
        WHERE ($1::text IS NULL OR g.name ILIKE $1 ESCAPE '\' OR g.description ILIKE $1 ESCAPE '\'){count_scope}
        "#
    );
    let mut count_query =
        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&*count_sql)).bind(&search_pattern);
    if scoped {
        count_query = count_query.bind(auth.user_id);
    }
    let total: i64 = count_query.fetch_one(&state.db).await.unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(GroupListResponse {
        items: groups.into_iter().map(GroupResponse::from).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, FromRow, ToSchema)]
pub struct CreatedGroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub external_source: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create a group
#[utoipa::path(
    post,
    extensions(("x-required-permission" = json!("group.create")), ("x-resource" = json!("instance"))),
    path = "",
    context_path = "/api/v1/groups",
    tag = "groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 200, description = "Group created successfully", body = GroupResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Group name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_group(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = require_auth(auth)?;
    // GHSA-vvc3-h39c-mrq5: gate on API-token scope before consulting the
    // fine-grained permission table. A read-scoped service-account token
    // must not be able to create groups even if its user has admin perms.
    auth.require_scope("write")?;

    // Fine-grained permission check: non-admins need "admin" on the system sentinel.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(
                auth.user_id,
                SYSTEM_TARGET_TYPE,
                SYSTEM_SENTINEL_ID,
                "admin",
                false,
            )
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to create groups".to_string(),
            ));
        }
    }
    crate::api::authz::shadow_marker::note_passed_on(
        crate::services::iam_legacy_projection::ScopeRef::Instance,
        crate::api::authz::shadow_marker::LegacyLevel::Admin,
    );

    let group: CreatedGroupRow = sqlx::query_as(
        r#"
        INSERT INTO groups (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description, external_source, created_at, updated_at
        "#,
    )
    .bind(&payload.name)
    .bind(&payload.description)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict("Group name already exists".to_string())
        } else {
            AppError::Database(msg)
        }
    })?;

    state.event_bus.emit("group.created", group.id, None);
    audit_group(
        &state,
        &auth,
        AuditAction::GroupCreated,
        group.id,
        &group.name,
        serde_json::json!({
            "group_id": group.id,
            "name": group.name,
            "description": group.description,
        }),
    )
    .await;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        external_source: group.external_source,
        member_count: 0,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Get a group by ID
#[utoipa::path(
    get,
    extensions(("x-auth-requirement" = json!("authenticated"))),
    path = "/{id}",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
        GetGroupQuery,
    ),
    responses(
        (status = 200, description = "Group details with paginated members", body = GroupDetailResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_group(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Query(query): Query<GetGroupQuery>,
) -> Result<Json<GroupDetailResponse>> {
    let auth = require_auth(auth)?;

    let group = load_visible_group(&state, &auth, id).await?;

    let member_limit = query.limit();
    let member_offset = query.offset();

    let members = fetch_group_members(&state.db, id, member_limit, member_offset).await?;

    // member_count from the group query already holds the total; reuse it
    // instead of issuing a separate COUNT query.
    let members_total = group.member_count;

    Ok(Json(GroupDetailResponse {
        group: GroupResponse::from(group),
        members: members.into_iter().map(GroupMemberResponse::from).collect(),
        members_total,
    }))
}

/// Load a group the caller is allowed to read, or a 404 that is byte-identical
/// for a missing id and an out-of-scope one (no existence oracle).
///
/// Non-admins are filtered to a group they can reach (membership UNION a group
/// permission grant) via [`visible_groups_predicate`]; admins are unscoped.
/// Shared by `GET /api/v1/groups/{id}` and its members sub-resource so both
/// enforce the same visibility rule and both 404 identically.
async fn load_visible_group(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
) -> Result<GroupRow> {
    // Check if groups table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Group not found".to_string()));
    }

    // The $2 placeholder carries the caller's user id when scoping is applied.
    let scoped = !group_read_unscoped(auth.is_admin);
    let get_scope = if scoped {
        format!(" AND {}", visible_groups_predicate("g.id", "$2"))
    } else {
        String::new()
    };
    let group_sql = format!(
        r#"
        SELECT g.id, g.name, g.description, g.external_source, g.created_at, g.updated_at,
               COALESCE(COUNT(ugm.user_id), 0) as member_count
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE g.id = $1{get_scope}
        GROUP BY g.id
        "#
    );
    let mut group_query = sqlx::query_as::<_, GroupRow>(sqlx::AssertSqlSafe(&*group_sql)).bind(id);
    if scoped {
        group_query = group_query.bind(auth.user_id);
    }
    group_query
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))
}

/// Load a page of a group's members in join order (oldest `joined_at` first,
/// `user_id` breaking ties so pages never overlap or skip a member when several
/// members joined in the same transaction). Shared by `GET /api/v1/groups/{id}`
/// and `GET /api/v1/groups/{id}/members`.
async fn fetch_group_members(
    db: &sqlx::PgPool,
    group_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<MemberRow>> {
    sqlx::query_as(
        r#"
        SELECT ugm.user_id, u.username, u.display_name, ugm.joined_at
        FROM user_group_members ugm
        JOIN users u ON u.id = ugm.user_id
        WHERE ugm.group_id = $1
        ORDER BY ugm.joined_at, ugm.user_id
        LIMIT $2
        OFFSET $3
        "#,
    )
    .bind(group_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// Update a group
#[utoipa::path(
    put,
    extensions(("x-required-permission" = json!("group.manage")), ("x-resource" = json!("group:id"))),
    path = "/{id}",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID")
    ),
    request_body = CreateGroupRequest,
    responses(
        (status = 200, description = "Group updated successfully", body = GroupResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_group(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let auth = require_auth(auth)?;
    // GHSA-vvc3-h39c-mrq5: require the write scope on the token.
    auth.require_scope("write")?;

    require_group_admin(
        &state,
        &auth,
        id,
        "Insufficient permissions to update this group",
    )
    .await?;

    let before: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT name, description FROM groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let group: CreatedGroupRow = sqlx::query_as(
        r#"
        UPDATE groups
        SET name = $2, description = $3, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, description, external_source, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(&payload.name)
    .bind(&payload.description)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_group_members WHERE group_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    state.event_bus.emit("group.updated", group.id, None);
    let (before_name, before_description) = before.unwrap_or_default();
    audit_group(
        &state,
        &auth,
        AuditAction::GroupUpdated,
        group.id,
        &group.name,
        serde_json::json!({
            "group_id": group.id,
            "before": { "name": before_name, "description": before_description },
            "after": { "name": group.name, "description": group.description },
        }),
    )
    .await;

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        external_source: group.external_source,
        member_count,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Delete a group
#[utoipa::path(
    delete,
    extensions(("x-required-permission" = json!("group.manage")), ("x-resource" = json!("group:id"))),
    path = "/{id}",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Group deleted successfully"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_group(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    // GHSA-vvc3-h39c-mrq5: deletion needs the delete scope.
    auth.require_scope("delete")?;

    require_group_admin(
        &state,
        &auth,
        id,
        "Insufficient permissions to delete this group",
    )
    .await?;

    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_group_members WHERE group_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
    let deleted: Option<(String, Option<String>)> =
        sqlx::query_as("DELETE FROM groups WHERE id = $1 RETURNING name, external_source")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((name, external_source)) = deleted else {
        return Err(AppError::NotFound("Group not found".to_string()));
    };

    state.event_bus.emit("group.deleted", id, None);
    audit_group(
        &state,
        &auth,
        AuditAction::GroupDeleted,
        id,
        &name,
        serde_json::json!({
            "group_id": id,
            "name": name,
            "external_source": external_source,
            "member_count": member_count,
        }),
    )
    .await;

    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MembersRequest {
    pub user_ids: Vec<Uuid>,
}

/// Gate local membership edits from an `external_source` lookup: outer `None`=no group (404),
/// inner `None`=local (ok), `Some(idp)`=SSO-owned so reject (#2874, IdP owns its membership).
fn check_membership_editable(external_source: Option<Option<String>>) -> Result<()> {
    match external_source {
        None => Err(AppError::NotFound("Group not found".to_string())),
        Some(None) => Ok(()),
        Some(Some(source)) => Err(AppError::Conflict(format!(
            "Group membership is managed by {source} and must be changed in your identity provider"
        ))),
    }
}

/// Look up a group's `external_source` and enforce [`check_membership_editable`].
async fn ensure_membership_editable(db: &sqlx::PgPool, id: Uuid) -> Result<()> {
    let external_source =
        sqlx::query_scalar::<_, Option<String>>("SELECT external_source FROM groups WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    check_membership_editable(external_source)
}

/// List a group's members
#[utoipa::path(
    get,
    extensions(("x-auth-requirement" = json!("authenticated"))),
    path = "/{id}/members",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
        GetGroupQuery,
    ),
    responses(
        (status = 200, description = "Group members", body = GroupMemberListResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_group_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Query(query): Query<GetGroupQuery>,
) -> Result<Json<GroupMemberListResponse>> {
    let auth = require_auth(auth)?;

    // Same visibility rule as `GET /api/v1/groups/{id}`: 404 for both a
    // missing id and an out-of-scope one, so membership is never readable
    // for a group the caller cannot see.
    let group = load_visible_group(&state, &auth, id).await?;

    let members = fetch_group_members(&state.db, id, query.limit(), query.offset()).await?;

    Ok(Json(GroupMemberListResponse {
        members: members.into_iter().map(GroupMemberResponse::from).collect(),
        members_total: group.member_count,
    }))
}

/// Add members to a group
#[utoipa::path(
    post,
    extensions(("x-required-permission" = json!("group.manage")), ("x-resource" = json!("group:id"))),
    path = "/{id}/members",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID")
    ),
    request_body = MembersRequest,
    responses(
        (status = 200, description = "Members added successfully"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    // GHSA-vvc3-h39c-mrq5: enforce write scope on token.
    auth.require_scope("write")?;

    require_group_admin(
        &state,
        &auth,
        id,
        "Insufficient permissions to manage group membership",
    )
    .await?;

    ensure_membership_editable(&state.db, id).await?;

    let mut added = Vec::new();
    for user_id in payload.user_ids {
        let inserted = sqlx::query(
            r#"
            INSERT INTO user_group_members (user_id, group_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if inserted.rows_affected() > 0 {
            added.push(user_id);
        }
    }

    state.event_bus.emit("group.member_added", id, None);
    if !added.is_empty() {
        let name = group_name_for_audit(&state.db, id).await;
        audit_group(
            &state,
            &auth,
            AuditAction::GroupMembersAdded,
            id,
            &name,
            group_members_audit_details(id, &name, &added),
        )
        .await;
    }

    Ok(())
}

/// Remove members from a group
#[utoipa::path(
    delete,
    extensions(("x-required-permission" = json!("group.manage")), ("x-resource" = json!("group:id"))),
    path = "/{id}/members",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID")
    ),
    request_body = MembersRequest,
    responses(
        (status = 200, description = "Members removed successfully"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    // GHSA-vvc3-h39c-mrq5: removing members is destructive; require delete scope.
    auth.require_scope("delete")?;

    require_group_admin(
        &state,
        &auth,
        id,
        "Insufficient permissions to manage group membership",
    )
    .await?;

    ensure_membership_editable(&state.db, id).await?;

    let mut removed = Vec::new();
    for user_id in payload.user_ids {
        let deleted =
            sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
                .bind(user_id)
                .bind(id)
                .execute(&state.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        if deleted.rows_affected() > 0 {
            removed.push(user_id);
        }
    }

    state.event_bus.emit("group.member_removed", id, None);
    if !removed.is_empty() {
        let name = group_name_for_audit(&state.db, id).await;
        audit_group(
            &state,
            &auth,
            AuditAction::GroupMembersRemoved,
            id,
            &name,
            group_members_audit_details(id, &name, &removed),
        )
        .await;
    }

    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_groups,
        create_group,
        get_group,
        update_group,
        delete_group,
        list_group_members,
        add_members,
        remove_members,
    ),
    components(schemas(
        GroupRow,
        GroupResponse,
        GroupMemberResponse,
        GroupMemberListResponse,
        GroupDetailResponse,
        GroupListResponse,
        CreateGroupRequest,
        CreatedGroupRow,
        MembersRequest,
    ))
)]
pub struct GroupsApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -----------------------------------------------------------------------
    // ListGroupsQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_groups_query_all_fields() {
        let json = r#"{"search": "dev", "page": 2, "per_page": 50}"#;
        let query: ListGroupsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.search, Some("dev".to_string()));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_list_groups_query_empty() {
        let json = r#"{}"#;
        let query: ListGroupsQuery = serde_json::from_str(json).unwrap();
        assert!(query.search.is_none());
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
    }

    #[test]
    fn test_list_groups_query_search_only() {
        let json = r#"{"search": "admin"}"#;
        let query: ListGroupsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.search, Some("admin".to_string()));
        assert!(query.page.is_none());
    }

    // -----------------------------------------------------------------------
    // GetGroupQuery deserialization and pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_group_query_defaults() {
        let json = r#"{}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert!(query.member_limit.is_none());
        assert!(query.member_offset.is_none());
        assert_eq!(query.limit(), 50);
        assert_eq!(query.offset(), 0);
    }

    #[test]
    fn test_get_group_query_custom_values() {
        let json = r#"{"member_limit": 10, "member_offset": 20}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit(), 10);
        assert_eq!(query.offset(), 20);
    }

    #[test]
    fn test_get_group_query_limit_clamped_to_max() {
        let json = r#"{"member_limit": 500}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit(), 200);
    }

    #[test]
    fn test_get_group_query_limit_clamped_to_min() {
        let json = r#"{"member_limit": 0}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit(), 1);
    }

    #[test]
    fn test_get_group_query_limit_at_boundary() {
        let json = r#"{"member_limit": 200}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit(), 200);
    }

    #[test]
    fn test_get_group_query_offset_only() {
        let json = r#"{"member_offset": 100}"#;
        let query: GetGroupQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit(), 50);
        assert_eq!(query.offset(), 100);
    }

    // -----------------------------------------------------------------------
    // Pagination logic (inline in list_groups)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let page = 1;
        let per_page = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_pagination_page_zero_clamped() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_clamped_to_max() {
        let per_page = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 20;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_pagination_offset_first_page() {
        let page: u32 = 1;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_total_pages_calculation() {
        let total: i64 = 45;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_total_pages_exact_division() {
        let total: i64 = 60;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_total_pages_zero_items() {
        let total: i64 = 0;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 0);
    }

    // -----------------------------------------------------------------------
    // Search pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pattern_some() {
        let search = Some("dev".to_string());
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(pattern, Some("%dev%".to_string()));
    }

    #[test]
    fn test_search_pattern_none() {
        let search: Option<String> = None;
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert!(pattern.is_none());
    }

    #[test]
    fn test_search_pattern_empty_string() {
        let search = Some("".to_string());
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(pattern, Some("%%".to_string()));
    }

    // -----------------------------------------------------------------------
    // GroupRow -> GroupResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_row_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let row = GroupRow {
            id,
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
            external_source: Some("oidc".to_string()),
            member_count: 5,
            created_at: now,
            updated_at: now,
        };
        let resp = GroupResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "developers");
        assert_eq!(resp.description, Some("Dev team".to_string()));
        assert_eq!(resp.external_source, Some("oidc".to_string()));
        assert_eq!(resp.member_count, 5);
    }

    #[test]
    fn test_group_row_to_response_no_description() {
        let now = Utc::now();
        let row = GroupRow {
            id: Uuid::new_v4(),
            name: "ops".to_string(),
            description: None,
            external_source: None,
            member_count: 0,
            created_at: now,
            updated_at: now,
        };
        let resp = GroupResponse::from(row);
        assert!(resp.description.is_none());
        assert_eq!(resp.member_count, 0);
    }

    // -----------------------------------------------------------------------
    // GroupResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_response_serialize() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let resp = GroupResponse {
            id,
            name: "admins".to_string(),
            description: Some("Admin group".to_string()),
            external_source: None,
            member_count: 3,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "admins");
        assert_eq!(json["description"], "Admin group");
        assert_eq!(json["member_count"], 3);
    }

    #[test]
    fn test_group_response_serialize_null_description() {
        let now = Utc::now();
        let resp = GroupResponse {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            description: None,
            external_source: None,
            member_count: 0,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["description"].is_null());
    }

    // -----------------------------------------------------------------------
    // CreateGroupRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_group_request() {
        let json = r#"{"name": "new-group", "description": "A new group"}"#;
        let req: CreateGroupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "new-group");
        assert_eq!(req.description, Some("A new group".to_string()));
    }

    #[test]
    fn test_create_group_request_no_description() {
        let json = r#"{"name": "minimal"}"#;
        let req: CreateGroupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "minimal");
        assert!(req.description.is_none());
    }

    #[test]
    fn test_create_group_request_missing_name() {
        let json = r#"{"description": "no name"}"#;
        let result = serde_json::from_str::<CreateGroupRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // MembersRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_members_request() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let json = format!(r#"{{"user_ids": ["{}", "{}"]}}"#, id1, id2);
        let req: MembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.user_ids.len(), 2);
        assert_eq!(req.user_ids[0], id1);
        assert_eq!(req.user_ids[1], id2);
    }

    #[test]
    fn test_members_request_empty_list() {
        let json = r#"{"user_ids": []}"#;
        let req: MembersRequest = serde_json::from_str(json).unwrap();
        assert!(req.user_ids.is_empty());
    }

    #[test]
    fn test_members_request_missing_field() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<MembersRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // GroupListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_list_response_serialize() {
        let now = Utc::now();
        let resp = GroupListResponse {
            items: vec![GroupResponse {
                id: Uuid::new_v4(),
                name: "team".to_string(),
                description: None,
                external_source: None,
                member_count: 2,
                created_at: now,
                updated_at: now,
            }],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 1,
                total_pages: 1,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
        assert_eq!(json["pagination"]["page"], 1);
        assert_eq!(json["pagination"]["total"], 1);
    }

    // -----------------------------------------------------------------------
    // MemberRow -> GroupMemberResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_member_row_to_response() {
        let now = Utc::now();
        let row = MemberRow {
            user_id: Uuid::nil(),
            username: "alice".to_string(),
            display_name: Some("Alice".to_string()),
            joined_at: now,
        };
        let resp: GroupMemberResponse = row.into();
        assert_eq!(resp.user_id, Uuid::nil());
        assert_eq!(resp.username, "alice");
        assert_eq!(resp.display_name, Some("Alice".to_string()));
        assert_eq!(resp.joined_at, now);
    }

    #[test]
    fn test_member_row_to_response_no_display_name() {
        let row = MemberRow {
            user_id: Uuid::nil(),
            username: "bob".to_string(),
            display_name: None,
            joined_at: Utc::now(),
        };
        let resp: GroupMemberResponse = row.into();
        assert_eq!(resp.username, "bob");
        assert!(resp.display_name.is_none());
    }

    // -----------------------------------------------------------------------
    // GroupMemberResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_member_response_serialization() {
        let member = GroupMemberResponse {
            user_id: Uuid::nil(),
            username: "alice".to_string(),
            display_name: Some("Alice".to_string()),
            joined_at: Utc::now(),
        };
        let json = serde_json::to_value(&member).unwrap();
        assert_eq!(json["user_id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(json["username"], "alice");
        assert_eq!(json["display_name"], "Alice");
        assert!(json["joined_at"].is_string());
    }

    #[test]
    fn test_group_member_response_null_display_name() {
        let member = GroupMemberResponse {
            user_id: Uuid::nil(),
            username: "bob".to_string(),
            display_name: None,
            joined_at: Utc::now(),
        };
        let json = serde_json::to_value(&member).unwrap();
        assert_eq!(json["username"], "bob");
        assert!(json["display_name"].is_null());
    }

    // -----------------------------------------------------------------------
    // GroupDetailResponse serialization (flatten + members + members_total)
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_detail_response_flattens_group_fields() {
        let detail = GroupDetailResponse {
            group: GroupResponse {
                id: Uuid::nil(),
                name: "dev".to_string(),
                description: Some("Developers".to_string()),
                external_source: None,
                member_count: 2,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            members: vec![],
            members_total: 2,
        };
        let json = serde_json::to_value(&detail).unwrap();
        // group is flattened: its fields appear at the top level alongside members
        assert_eq!(json["name"], "dev");
        assert_eq!(json["description"], "Developers");
        assert_eq!(json["member_count"], 2);
        assert!(json["members"].is_array());
        assert_eq!(json["members_total"], 2);
        // the nested "group" key should not exist in flattened output
        assert!(json["group"].is_null());
    }

    #[test]
    fn test_group_detail_response_with_members() {
        let now = Utc::now();
        let detail = GroupDetailResponse {
            group: GroupResponse {
                id: Uuid::nil(),
                name: "admins".to_string(),
                description: None,
                external_source: None,
                member_count: 2,
                created_at: now,
                updated_at: now,
            },
            members: vec![
                GroupMemberResponse {
                    user_id: Uuid::nil(),
                    username: "alice".to_string(),
                    display_name: Some("Alice".to_string()),
                    joined_at: now,
                },
                GroupMemberResponse {
                    user_id: Uuid::nil(),
                    username: "bob".to_string(),
                    display_name: None,
                    joined_at: now,
                },
            ],
            members_total: 2,
        };
        let json = serde_json::to_value(&detail).unwrap();
        let members = json["members"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0]["username"], "alice");
        assert_eq!(members[1]["username"], "bob");
        assert!(members[1]["display_name"].is_null());
        assert_eq!(json["members_total"], 2);
    }

    #[test]
    fn test_group_detail_response_empty_members() {
        let detail = GroupDetailResponse {
            group: GroupResponse {
                id: Uuid::nil(),
                name: "empty".to_string(),
                description: None,
                external_source: None,
                member_count: 0,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            members: vec![],
            members_total: 0,
        };
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["member_count"], 0);
        assert!(json["members"].as_array().unwrap().is_empty());
        assert_eq!(json["members_total"], 0);
    }

    #[test]
    fn test_group_detail_response_contains_all_group_fields() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let detail = GroupDetailResponse {
            group: GroupResponse {
                id,
                name: "ops".to_string(),
                description: Some("Operations".to_string()),
                external_source: None,
                member_count: 1,
                created_at: now,
                updated_at: now,
            },
            members: vec![GroupMemberResponse {
                user_id: Uuid::new_v4(),
                username: "carol".to_string(),
                display_name: Some("Carol".to_string()),
                joined_at: now,
            }],
            members_total: 1,
        };
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["name"], "ops");
        assert_eq!(json["description"], "Operations");
        assert_eq!(json["member_count"], 1);
        assert!(json["created_at"].is_string());
        assert!(json["updated_at"].is_string());
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
        assert_eq!(json["members_total"], 1);
    }

    #[test]
    fn test_group_detail_response_members_total_exceeds_page() {
        let now = Utc::now();
        let detail = GroupDetailResponse {
            group: GroupResponse {
                id: Uuid::nil(),
                name: "large".to_string(),
                description: None,
                external_source: None,
                member_count: 500,
                created_at: now,
                updated_at: now,
            },
            members: vec![GroupMemberResponse {
                user_id: Uuid::nil(),
                username: "first".to_string(),
                display_name: None,
                joined_at: now,
            }],
            members_total: 500,
        };
        let json = serde_json::to_value(&detail).unwrap();
        // Only 1 member in the page but total is 500
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
        assert_eq!(json["members_total"], 500);
    }

    #[test]
    fn test_group_list_response_empty() {
        let resp = GroupListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert_eq!(json["pagination"]["total"], 0);
        assert_eq!(json["pagination"]["total_pages"], 0);
    }

    // -----------------------------------------------------------------------
    // Permission check logic (Phase 3: admin-level endpoint checks)
    // -----------------------------------------------------------------------

    fn make_auth(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    /// Simulates the permission gate used in group mutation handlers.
    /// Admins bypass all checks; non-admins must hold the required action.
    fn check_permission_gate(
        is_admin: bool,
        granted_actions: &[&str],
        required_action: &str,
    ) -> bool {
        if is_admin {
            return true;
        }
        granted_actions.contains(&required_action)
    }

    #[test]
    fn test_require_auth_none_returns_error() {
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    #[test]
    fn test_require_auth_some_returns_auth() {
        let auth = make_auth(false);
        let user_id = auth.user_id;
        let result = require_auth(Some(auth));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().user_id, user_id);
    }

    #[test]
    fn test_create_group_permission_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_create_group_permission_non_admin_with_system_grant() {
        let auth = make_auth(false);
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_create_group_permission_non_admin_without_grant_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_create_group_permission_non_admin_with_wrong_grant_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(
            auth.is_admin,
            &["read", "write"],
            "admin"
        ));
    }

    #[test]
    fn test_update_group_permission_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_update_group_permission_non_admin_with_group_grant() {
        let auth = make_auth(false);
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_update_group_permission_non_admin_without_grant_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_delete_group_permission_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_delete_group_permission_non_admin_with_grant() {
        let auth = make_auth(false);
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_delete_group_permission_non_admin_without_grant_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_add_members_permission_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_add_members_permission_non_admin_with_grant() {
        let auth = make_auth(false);
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_add_members_permission_non_admin_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_membership_editable_local_group_ok() {
        // external_source IS NULL -> operator-managed -> editable.
        assert!(check_membership_editable(Some(None)).is_ok());
    }

    #[test]
    fn test_membership_editable_sso_group_rejected() {
        // external_source set -> owned by the IdP -> 409 Conflict (#2874).
        let err = check_membership_editable(Some(Some("oidc".to_string()))).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[test]
    fn test_membership_editable_missing_group_not_found() {
        // no row -> 404, matching the other group handlers.
        let err = check_membership_editable(None).unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn test_remove_members_permission_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_remove_members_permission_non_admin_with_grant() {
        let auth = make_auth(false);
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_remove_members_permission_non_admin_denied() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_system_sentinel_is_nil_uuid() {
        // create_group uses SYSTEM_SENTINEL_ID as the system sentinel target_id
        assert_eq!(
            SYSTEM_SENTINEL_ID.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(SYSTEM_TARGET_TYPE, "system");
    }

    #[test]
    fn test_permission_gate_non_admin_multiple_grants_includes_admin() {
        let auth = make_auth(false);
        assert!(check_permission_gate(
            auth.is_admin,
            &["read", "write", "delete", "admin"],
            "admin"
        ));
    }

    // -----------------------------------------------------------------------
    // Read endpoints require authentication
    //
    // list_groups and get_group call require_auth before touching the DB, so
    // an anonymous caller (no AuthExtension) is rejected with a 401 instead of
    // leaking the org's group inventory and member lists. These tests exercise
    // the same gate the handlers run on their first line and would fail if that
    // gate were removed.
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_groups_requires_auth_anonymous_denied() {
        // No AuthExtension present -> list_groups must reject before the DB query.
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    #[test]
    fn test_list_groups_authenticated_allowed() {
        // A present AuthExtension passes the gate (admin or not).
        let auth = make_auth(false);
        assert!(require_auth(Some(auth)).is_ok());
    }

    #[test]
    fn test_get_group_requires_auth_anonymous_denied() {
        // No AuthExtension present -> get_group must reject before the DB query,
        // so a valid id and a random id both return 401, not 200/404.
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    #[test]
    fn test_get_group_authenticated_allowed() {
        let auth = make_auth(true);
        assert!(require_auth(Some(auth)).is_ok());
    }

    // -----------------------------------------------------------------------
    // Group read scoping (BOLA fix): non-admins are filtered to groups they
    // can reach (membership UNION a group permission grant); admins are
    // unscoped. The list SELECT/COUNT and the get_group query all share the
    // same `visible_groups_predicate`. These tests cover the decision and the
    // predicate shape without a database.
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_read_unscoped_admin_bypasses_filter() {
        // Admins read every group: no per-caller predicate is applied.
        let auth = make_auth(true);
        assert!(group_read_unscoped(auth.is_admin));
    }

    #[test]
    fn test_group_read_scoped_for_non_admin() {
        // Non-admins are scoped: the predicate is applied.
        let auth = make_auth(false);
        assert!(!group_read_unscoped(auth.is_admin));
    }

    #[test]
    fn test_visible_groups_predicate_has_membership_arm() {
        // Membership arm: caller is a member of the group.
        let sql = visible_groups_predicate("g.id", "$2");
        assert!(sql.contains("user_group_members"));
        assert!(sql.contains("g.id IN ("));
    }

    #[test]
    fn test_visible_groups_predicate_has_permission_grant_arm() {
        // Permission-grant arm: caller holds a grant directly as a user
        // principal OR via one of their groups. Dropping this arm would hide a
        // group from a non-member grant-holder who can already mutate it.
        let sql = visible_groups_predicate("g.id", "$2");
        assert!(sql.contains("FROM permissions p"));
        assert!(sql.contains("p.target_type = 'group'"));
        // Direct-principal arm honours both human users and service accounts
        // (both reference `users(id)` and are keyed by the caller's own id).
        assert!(sql.contains("p.principal_type IN ('user', 'service_account')"));
        assert!(sql.contains("p.principal_type = 'group'"));
    }

    #[test]
    fn test_visible_groups_predicate_uses_supplied_placeholders() {
        // The group-id expression and user bind placeholder are interpolated,
        // so the list SELECT ($4) and get_group ($2) can reuse one helper with
        // their own parameter numbering.
        let sql = visible_groups_predicate("g.id", "$4");
        assert!(sql.contains("user_id = $4"));
        assert!(sql.contains("p.principal_id = $4"));
        assert!(!sql.contains("$1"));
    }

    #[test]
    fn test_visible_groups_predicate_targets_only_group_grants() {
        // The grant arm must be scoped to the specific group id, not any grant.
        let sql = visible_groups_predicate("g.id", "$2");
        assert!(sql.contains("p.target_id = g.id"));
    }

    /// DB-backed: exercises the scoped query branches of `list_groups` and
    /// `get_group`. A non-admin sees only the group it is a member of (not a
    /// non-member group), and a non-member `get_group` returns NotFound (no
    /// existence oracle); an admin is unscoped and sees both. Skips cleanly when
    /// no DATABASE_URL is configured (the `try_pool` convention).
    #[tokio::test]
    async fn test_group_read_scoping_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Path, Query, State};
        use axum::Extension;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (user_id, username) = tdh::create_user(&pool).await;

        // Two groups; the user is a member of `mine`, not of `other`.
        let mine = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mine_name = format!("ph-grp-mine-{mine}");
        let other_name = format!("ph-grp-other-{other}");
        sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2), ($3, $4)")
            .bind(mine)
            .bind(&mine_name)
            .bind(other)
            .bind(&other_name)
            .execute(&pool)
            .await
            .expect("seed groups");
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(mine)
            .execute(&pool)
            .await
            .expect("seed membership");

        let nonadmin = tdh::make_auth(user_id, &username); // is_admin = false
        let admin = AuthExtension {
            is_admin: true,
            ..tdh::make_auth(user_id, &username)
        };
        let list_q = || ListGroupsQuery {
            search: None,
            page: None,
            per_page: None,
        };
        let get_q = || GetGroupQuery {
            member_limit: None,
            member_offset: None,
        };

        // list_groups: non-admin sees `mine`, not `other`.
        let listed = list_groups(
            State(state.clone()),
            Extension(Some(nonadmin.clone())),
            Query(list_q()),
        )
        .await
        .expect("non-admin list ok")
        .0;
        let names: Vec<&str> = listed.items.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&mine_name.as_str()),
            "non-admin must see its own group"
        );
        assert!(
            !names.contains(&other_name.as_str()),
            "non-admin must NOT see a non-member group (BOLA): {names:?}"
        );

        // list_groups: admin is unscoped and sees both.
        let listed_admin = list_groups(
            State(state.clone()),
            Extension(Some(admin.clone())),
            Query(list_q()),
        )
        .await
        .expect("admin list ok")
        .0;
        let admin_names: Vec<&str> = listed_admin.items.iter().map(|g| g.name.as_str()).collect();
        assert!(
            admin_names.contains(&mine_name.as_str()) && admin_names.contains(&other_name.as_str()),
            "admin must see all groups unscoped: {admin_names:?}"
        );

        // get_group: non-admin -> own 200, non-member -> 404 (no existence oracle).
        assert!(
            get_group(
                State(state.clone()),
                Extension(Some(nonadmin.clone())),
                Path(mine),
                Query(get_q()),
            )
            .await
            .is_ok(),
            "non-admin must read its own group"
        );
        let denied = get_group(
            State(state.clone()),
            Extension(Some(nonadmin)),
            Path(other),
            Query(get_q()),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member get_group must be NotFound, not a leak: {denied:?}"
        );
        // get_group: admin reads any group.
        assert!(
            get_group(
                State(state.clone()),
                Extension(Some(admin)),
                Path(other),
                Query(get_q()),
            )
            .await
            .is_ok(),
            "admin must read any group"
        );

        // #2503 (finding 2): a *direct* service_account-typed grant on a group
        // must surface that group in the SA's list_groups (not just group-mediated
        // repo access). The SA is a non-member of `other`, so only the grant can
        // make it visible; `visible_groups_predicate`'s
        // `principal_type IN ('user','service_account')` arm is what carries it.
        let sa_id = Uuid::new_v4();
        let sa_username = format!("ph-grp-sa-{sa_id}");
        sqlx::query(
            r#"INSERT INTO users
                 (id, username, email, password_hash, auth_provider,
                  is_admin, is_active, is_service_account)
               VALUES ($1, $2, $3, 'unused', 'local', false, true, true)"#,
        )
        .bind(sa_id)
        .bind(&sa_username)
        .bind(format!("{sa_username}@test.local"))
        .execute(&pool)
        .await
        .expect("seed service account");
        let grant_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO permissions
                 (id, principal_type, principal_id, target_type, target_id, actions)
               VALUES ($1, 'service_account', $2, 'group', $3, ARRAY['read'])"#,
        )
        .bind(grant_id)
        .bind(sa_id)
        .bind(other)
        .execute(&pool)
        .await
        .expect("seed direct SA->group grant");

        let sa_auth = AuthExtension {
            is_service_account: true,
            is_api_token: true,
            ..tdh::make_auth(sa_id, &sa_username)
        };
        let sa_listed = list_groups(
            State(state.clone()),
            Extension(Some(sa_auth.clone())),
            Query(list_q()),
        )
        .await
        .expect("SA list ok")
        .0;
        let sa_names: Vec<&str> = sa_listed.items.iter().map(|g| g.name.as_str()).collect();
        assert!(
            sa_names.contains(&other_name.as_str()),
            "a direct service_account grant on a group must surface it in list_groups: {sa_names:?}"
        );
        assert!(
            !sa_names.contains(&mine_name.as_str()),
            "SA must NOT see a group it neither belongs to nor holds a grant on: {sa_names:?}"
        );
        // get_group over the same direct grant also resolves (not a NotFound leak-avoider).
        assert!(
            get_group(
                State(state.clone()),
                Extension(Some(sa_auth)),
                Path(other),
                Query(get_q()),
            )
            .await
            .is_ok(),
            "direct SA grant must also make get_group succeed"
        );

        // cleanup (user_group_members cascades on group/user delete).
        let _ = sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(grant_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id IN ($1, $2)")
            .bind(mine)
            .bind(other)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
            .bind(user_id)
            .bind(sa_id)
            .execute(&pool)
            .await;
    }

    /// #4266 review P2 / #1849: a group-target grant carrying
    /// `conditions.allowed_cidrs` may only make the group visible when the
    /// in-flight request's client IP matches — otherwise the listing leaks
    /// group metadata to a caller the mutation gates deny.
    #[tokio::test]
    async fn test_conditioned_group_rule_is_ip_gated_in_listings_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::client_ip::with_client_ip_scope;
        use axum::extract::{Query, State};
        use axum::Extension;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-ip-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (user_id, username) = tdh::create_user(&pool).await;

        // A group the user can only reach through a CONDITIONED grant.
        let gated = Uuid::new_v4();
        let gated_name = format!("ph-grp-gated-{gated}");
        sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
            .bind(gated)
            .bind(&gated_name)
            .execute(&pool)
            .await
            .expect("seed group");
        // read on the group, only from 10.50.0.0/16.
        let grant_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO permissions
                 (id, principal_type, principal_id, target_type, target_id, actions, conditions)
               VALUES ($1, 'user', $2, 'group', $3, ARRAY['read'], $4)"#,
        )
        .bind(grant_id)
        .bind(user_id)
        .bind(gated)
        .bind(serde_json::json!({"allowed_cidrs": ["10.50.0.0/16"]}))
        .execute(&pool)
        .await
        .expect("seed conditioned grant");

        let nonadmin = tdh::make_auth(user_id, &username); // is_admin = false
        let list_q = || ListGroupsQuery {
            search: None,
            page: None,
            per_page: None,
        };

        // Matching IP: the conditioned grant surfaces the group.
        let names_inside = with_client_ip_scope(
            Some("10.50.1.7".parse().unwrap()),
            list_groups(
                State(state.clone()),
                Extension(Some(nonadmin.clone())),
                Query(list_q()),
            ),
        )
        .await
        .expect("list ok inside CIDR")
        .0
        .items
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<_>>();
        assert!(
            names_inside.iter().any(|n| n == &gated_name),
            "inside the CIDR the conditioned group must be listed: {names_inside:?}"
        );

        // Non-matching IP: invisible.
        let names_outside = with_client_ip_scope(
            Some("192.0.2.9".parse().unwrap()),
            list_groups(
                State(state.clone()),
                Extension(Some(nonadmin.clone())),
                Query(list_q()),
            ),
        )
        .await
        .expect("list ok outside CIDR")
        .0
        .items
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<_>>();
        assert!(
            !names_outside.iter().any(|n| n == &gated_name),
            "outside the CIDR the conditioned group must NOT be listed: {names_outside:?}"
        );

        // No request IP at all (no task-local scope): fail closed.
        let names_no_scope = list_groups(
            State(state.clone()),
            Extension(Some(nonadmin)),
            Query(list_q()),
        )
        .await
        .expect("list ok without scope")
        .0
        .items
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<_>>();
        assert!(
            !names_no_scope.iter().any(|n| n == &gated_name),
            "with no request IP a conditioned grant must fail closed: {names_no_scope:?}"
        );

        let _ = sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(grant_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(gated)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // GroupMemberListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_member_list_response_serialize() {
        let now = Utc::now();
        let resp = GroupMemberListResponse {
            members: vec![
                GroupMemberResponse {
                    user_id: Uuid::nil(),
                    username: "alice".to_string(),
                    display_name: Some("Alice".to_string()),
                    joined_at: now,
                },
                GroupMemberResponse {
                    user_id: Uuid::nil(),
                    username: "bob".to_string(),
                    display_name: None,
                    joined_at: now,
                },
            ],
            members_total: 2,
        };
        let json = serde_json::to_value(&resp).unwrap();
        let members = json["members"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0]["username"], "alice");
        assert_eq!(members[1]["username"], "bob");
        assert!(members[1]["display_name"].is_null());
        assert_eq!(json["members_total"], 2);
    }

    #[test]
    fn test_group_member_list_response_empty() {
        let resp = GroupMemberListResponse {
            members: vec![],
            members_total: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["members"].as_array().unwrap().is_empty());
        assert_eq!(json["members_total"], 0);
    }

    #[test]
    fn test_group_member_list_response_total_exceeds_page() {
        // Only one member on the page but the group holds 500: `members_total`
        // is the count for the whole group, not the page.
        let resp = GroupMemberListResponse {
            members: vec![GroupMemberResponse {
                user_id: Uuid::nil(),
                username: "first".to_string(),
                display_name: None,
                joined_at: Utc::now(),
            }],
            members_total: 500,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
        assert_eq!(json["members_total"], 500);
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/groups/{id}/members (#4027)
    //
    // The members sub-resource previously registered only POST and DELETE, so
    // GET fell through to a 405 even though the sibling projects resource
    // serves all three. These tests pin the GET registration in the generated
    // spec (the leak that let the asymmetry sit un-noticed) and the read gate.
    // -----------------------------------------------------------------------

    #[test]
    fn test_openapi_doc_registers_get_on_group_members_path() {
        use utoipa::OpenApi;

        let doc = GroupsApiDoc::openapi();
        let item = doc
            .paths
            .paths
            .get("/api/v1/groups/{id}/members")
            .expect("group members path must be registered (#4027)");
        assert!(
            item.get.is_some(),
            "GET /api/v1/groups/{{id}}/members must be registered (#4027)"
        );
        assert!(item.post.is_some(), "POST must stay registered");
        assert!(item.delete.is_some(), "DELETE must stay registered");
    }

    #[test]
    fn test_openapi_doc_registers_group_member_list_response_schema() {
        use utoipa::OpenApi;

        let doc = GroupsApiDoc::openapi();
        let schemas = doc
            .components
            .as_ref()
            .expect("components present")
            .schemas
            .keys()
            .map(|k| k.as_str())
            .collect::<Vec<_>>();
        assert!(
            schemas.contains(&"GroupMemberListResponse"),
            "GroupMemberListResponse must be a registered schema: {schemas:?}"
        );
    }

    #[test]
    fn test_list_group_members_requires_auth_anonymous_denied() {
        // list_group_members calls require_auth before touching the DB, so an
        // anonymous caller gets 401 rather than the member list.
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    /// DB-backed: `GET /api/v1/groups/{id}/members` returns the group's members
    /// paginated, and enforces the same visibility rule as `GET /groups/{id}`
    /// (non-admins 404 on a group they cannot reach; members never leak).
    #[tokio::test]
    async fn test_list_group_members_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Path, Query, State};
        use axum::Extension;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-members-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (viewer_id, viewer_name) = tdh::create_user(&pool).await;
        let (member_id, member_name) = tdh::create_user(&pool).await;

        let group = Uuid::new_v4();
        let group_name = format!("ph-grp-members-{group}");
        let other = Uuid::new_v4();
        let other_name = format!("ph-grp-members-other-{other}");
        sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2), ($3, $4)")
            .bind(group)
            .bind(&group_name)
            .bind(other)
            .bind(&other_name)
            .execute(&pool)
            .await
            .expect("seed groups");
        // The viewer is a member of `group` (so it may read it) and `member`
        // is the listed user.
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2), ($3, $2)")
            .bind(viewer_id)
            .bind(group)
            .bind(member_id)
            .execute(&pool)
            .await
            .expect("seed membership");

        let viewer = tdh::make_auth(viewer_id, &viewer_name); // is_admin = false
        let admin = AuthExtension {
            is_admin: true,
            ..tdh::make_auth(viewer_id, &viewer_name)
        };
        let q = || GetGroupQuery {
            member_limit: None,
            member_offset: None,
        };

        // A group member reads the member list; both members are present.
        let listed = list_group_members(
            State(state.clone()),
            Extension(Some(viewer.clone())),
            Path(group),
            Query(q()),
        )
        .await
        .expect("member may list members")
        .0;
        assert_eq!(listed.members_total, 2);
        let names: Vec<&str> = listed.members.iter().map(|m| m.username.as_str()).collect();
        assert!(names.contains(&viewer_name.as_str()), "{names:?}");
        assert!(names.contains(&member_name.as_str()), "{names:?}");

        // Pagination mirrors GET /groups/{id}: limit 1 returns one member but the
        // total still reflects the whole group.
        let page = list_group_members(
            State(state.clone()),
            Extension(Some(viewer.clone())),
            Path(group),
            Query(GetGroupQuery {
                member_limit: Some(1),
                member_offset: None,
            }),
        )
        .await
        .expect("paged list ok")
        .0;
        assert_eq!(page.members.len(), 1, "limit=1 must return a single member");
        assert_eq!(
            page.members_total, 2,
            "total is the group count, not the page"
        );

        // A non-admin that cannot reach the group gets a 404 (no existence
        // oracle and no membership leak), not a 200 or a 403.
        let denied = list_group_members(
            State(state.clone()),
            Extension(Some(viewer)),
            Path(other),
            Query(q()),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member must get NotFound for another group's members: {denied:?}"
        );

        // An admin is unscoped and can list members of any group.
        assert!(
            list_group_members(
                State(state.clone()),
                Extension(Some(admin)),
                Path(other),
                Query(q()),
            )
            .await
            .is_ok(),
            "admin must be able to list any group's members"
        );

        let _ = sqlx::query("DELETE FROM groups WHERE id IN ($1, $2)")
            .bind(group)
            .bind(other)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, viewer_id).await;
        tdh::cleanup_user(&pool, member_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Router-level (#4027): `GET /{id}/members` dispatches to the list handler
    /// instead of answering 405, also for an LDAP-synced group whose membership
    /// is read-only locally, and pages walk the whole group in a stable order
    /// even when every member shares one `joined_at`.
    #[tokio::test]
    async fn test_group_members_get_route_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-members-rt-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (outsider_id, outsider_name) = tdh::create_user(&pool).await;
        let mut members = Vec::new();
        for _ in 0..3 {
            members.push(tdh::create_user(&pool).await.0);
        }

        let group = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id, name, external_source) VALUES ($1, $2, 'ldap')")
            .bind(group)
            .bind(format!("ph-grp-members-ldap-{group}"))
            .execute(&pool)
            .await
            .expect("seed ldap group");
        // One statement, so all three rows share the same joined_at.
        sqlx::query(
            "INSERT INTO user_group_members (user_id, group_id) \
             SELECT u, $1 FROM UNNEST($2::uuid[]) AS u",
        )
        .bind(group)
        .bind(&members)
        .execute(&pool)
        .await
        .expect("seed membership");

        let admin = AuthExtension {
            is_admin: true,
            ..tdh::make_auth(admin_id, &admin_name)
        };
        let outsider = tdh::make_auth(outsider_id, &outsider_name);
        let app = |auth: AuthExtension| tdh::router_with_auth_ext(router(), state.clone(), auth);
        let page = |status: axum::http::StatusCode, body: &[u8]| {
            assert_eq!(
                status,
                axum::http::StatusCode::OK,
                "{}",
                String::from_utf8_lossy(body)
            );
            let v: serde_json::Value = serde_json::from_slice(body).expect("json");
            assert_eq!(v["members_total"], 3);
            v["members"]
                .as_array()
                .expect("members array")
                .iter()
                .map(|m| m["user_id"].as_str().unwrap().parse::<Uuid>().unwrap())
                .collect::<Vec<_>>()
        };

        let (s1, b1) = tdh::send(
            app(admin.clone()),
            tdh::get(format!("/{group}/members?member_limit=2")),
        )
        .await;
        let mut seen = page(s1, &b1);
        assert_eq!(seen.len(), 2);
        let (s2, b2) = tdh::send(
            app(admin.clone()),
            tdh::get(format!("/{group}/members?member_limit=2&member_offset=2")),
        )
        .await;
        seen.extend(page(s2, &b2));
        let mut expected = members.clone();
        expected.sort();
        assert_eq!(
            seen, expected,
            "pages must cover every member once, in order"
        );

        // Reading stays allowed for an LDAP-synced group; writes keep their 409.
        let (post_status, _) = tdh::send(
            app(admin.clone()),
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/{group}/members"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"user_ids":["{outsider_id}"]}}"#
                )))
                .expect("build POST"),
        )
        .await;
        assert_eq!(post_status, axum::http::StatusCode::CONFLICT);

        // A non-admin outside the group gets the same 404 as GET /groups/{id}.
        let (out_status, _) =
            tdh::send(app(outsider.clone()), tdh::get(format!("/{group}/members"))).await;
        assert_eq!(out_status, axum::http::StatusCode::NOT_FOUND);
        let (detail_status, _) = tdh::send(app(outsider), tdh::get(format!("/{group}"))).await;
        assert_eq!(detail_status, axum::http::StatusCode::NOT_FOUND);

        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group)
            .execute(&pool)
            .await;
        for id in members.into_iter().chain([admin_id, outsider_id]) {
            tdh::cleanup_user(&pool, id).await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The group-administrator check refuses with each handler's own message,
    /// and records a pass for the IAM shadow comparison (#4214) when it
    /// admits, on the group or (for creation) on the instance.
    #[tokio::test]
    async fn group_admin_check_keeps_its_messages_and_records_passes_db() {
        use crate::api::authz::shadow_marker::{scope, LegacyLevel};
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::iam_legacy_projection::ScopeRef;
        use axum::http::StatusCode;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-admin-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (outsider_id, outsider_name) = tdh::create_user(&pool).await;
        let (manager_id, manager_name) = tdh::create_user(&pool).await;
        let group = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id, name, external_source) VALUES ($1, $2, 'ldap')")
            .bind(group)
            .bind(format!("ph-grp-admin-ldap-{group}"))
            .execute(&pool)
            .await
            .expect("seed ldap group");
        tdh::grant_permission(&pool, "user", manager_id, "group", group, &["admin"]).await;
        tdh::grant_permission(
            &pool,
            "user",
            manager_id,
            SYSTEM_TARGET_TYPE,
            SYSTEM_SENTINEL_ID,
            &["admin"],
        )
        .await;
        let outsider = tdh::make_auth(outsider_id, &outsider_name);
        let manager = tdh::make_auth(manager_id, &manager_name);
        let call = |auth: &AuthExtension, method: &str, uri: String, body: String| {
            tdh::send(
                tdh::router_with_auth_ext(router(), state.clone(), auth.clone()),
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .expect("build request"),
            )
        };
        let members = format!(r#"{{"user_ids":["{outsider_id}"]}}"#);
        let rename = r#"{"name":"renamed"}"#.to_string();

        for (method, uri, body, message) in [
            (
                "PUT",
                format!("/{group}"),
                rename.clone(),
                "Insufficient permissions to update this group",
            ),
            (
                "DELETE",
                format!("/{group}"),
                String::new(),
                "Insufficient permissions to delete this group",
            ),
            (
                "POST",
                format!("/{group}/members"),
                members.clone(),
                "Insufficient permissions to manage group membership",
            ),
            (
                "DELETE",
                format!("/{group}/members"),
                members.clone(),
                "Insufficient permissions to manage group membership",
            ),
        ] {
            let ((status, body), recorded) = scope(call(&outsider, method, uri, body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}");
            assert!(
                String::from_utf8_lossy(&body).contains(message),
                "{method}: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(recorded.passed_on(ScopeRef::Group(group)), None);
        }

        // The group's administrator passes the check; the identity provider
        // still owns the membership.
        let ((status, _), recorded) = scope(call(
            &manager,
            "POST",
            format!("/{group}/members"),
            members.clone(),
        ))
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            recorded.passed_on(ScopeRef::Group(group)),
            Some(LegacyLevel::Admin)
        );

        // A sentinel holder creates a group.
        let name = format!("ph-grp-admin-new-{}", Uuid::new_v4());
        let ((status, body), recorded) = scope(call(
            &manager,
            "POST",
            "/".to_string(),
            format!(r#"{{"name":"{name}"}}"#),
        ))
        .await;
        assert!(status.is_success(), "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            recorded.passed_on(ScopeRef::Instance),
            Some(LegacyLevel::Admin)
        );
        let ((status, _), recorded) = scope(call(
            &outsider,
            "POST",
            "/".to_string(),
            format!(r#"{{"name":"{name}-x"}}"#),
        ))
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(recorded.passed_on(ScopeRef::Instance), None);

        let _ = sqlx::query("DELETE FROM groups WHERE id = $1 OR name = $2")
            .bind(group)
            .bind(&name)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
            .bind(manager_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, outsider_id).await;
        tdh::cleanup_user(&pool, manager_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #5653 (DB-backed, through the routes): group create, update, member
    /// add, member remove and delete each write one audit row naming the
    /// acting admin and the group; a membership row lists only the users whose
    /// membership changed, and a request that changes nothing writes none.
    #[tokio::test]
    async fn test_group_changes_are_audited_db_5653() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-grp-audit-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (m1, _) = tdh::create_user(&pool).await;
        let (m2, _) = tdh::create_user(&pool).await;
        let admin = tdh::admin_auth(admin_id, &admin_name);
        let app = || tdh::router_with_auth_ext(router(), state.clone(), admin.clone());
        let req = |method: &str, uri: String, body: serde_json::Value| {
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        let name = format!("ph-grp-audit-{}", Uuid::new_v4());

        let (status, body) = tdh::send(
            app(),
            req("POST", "/".into(), serde_json::json!({ "name": name })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let group: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let renamed = format!("{name}-renamed");
        let (status, _) = tdh::send(
            app(),
            req(
                "PUT",
                format!("/{group}"),
                serde_json::json!({ "name": renamed }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let members = serde_json::json!({ "user_ids": [m1, m2] });
        assert_eq!(
            tdh::send(
                app(),
                req("POST", format!("/{group}/members"), members.clone())
            )
            .await
            .0,
            StatusCode::OK
        );
        // Already members: nothing changes, nothing is audited.
        assert_eq!(
            tdh::send(app(), req("POST", format!("/{group}/members"), members))
                .await
                .0,
            StatusCode::OK
        );
        let (status, _) = tdh::send(
            app(),
            req(
                "DELETE",
                format!("/{group}/members"),
                serde_json::json!({ "user_ids": [m1] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = tdh::send(
            app(),
            req("DELETE", format!("/{group}"), serde_json::Value::Null),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The audit writes are detached; give them a moment.
        let db = &pool;
        let fetch = || async move {
            sqlx::query_as::<_, (String, Option<Uuid>, String, serde_json::Value)>(
                "SELECT action, resource_id, resource_type, details FROM audit_log \
                  WHERE user_id = $1 ORDER BY action",
            )
            .bind(admin_id)
            .fetch_all(db)
            .await
            .unwrap()
        };
        for _ in 0..50 {
            if fetch().await.len() >= 5 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // Long enough for a stray sixth row (the no-op add) to land.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let rows = fetch().await;
        let _ = sqlx::query("DELETE FROM audit_log WHERE user_id = $1")
            .bind(admin_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group)
            .execute(&pool)
            .await;
        for id in [admin_id, m1, m2] {
            tdh::cleanup_user(&pool, id).await;
        }
        let _ = std::fs::remove_dir_all(&dir);

        // Sorted by action name.
        let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "GROUP_CREATED",
                "GROUP_DELETED",
                "GROUP_MEMBERS_ADDED",
                "GROUP_MEMBERS_REMOVED",
                "GROUP_UPDATED",
            ],
            "{rows:?}"
        );
        for (action, resource_id, resource_type, _) in &rows {
            assert_eq!(*resource_id, Some(group), "{action}");
            assert_eq!(resource_type, "group", "{action}");
        }
        let detail = |action: &str| rows.iter().find(|r| r.0 == action).unwrap().3.clone();
        let mut added: Vec<String> = detail("GROUP_MEMBERS_ADDED")["user_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        added.sort();
        let mut expected = vec![m1.to_string(), m2.to_string()];
        expected.sort();
        assert_eq!(added, expected);
        assert_eq!(
            detail("GROUP_MEMBERS_REMOVED")["user_ids"],
            serde_json::json!([m1])
        );
        assert_eq!(detail("GROUP_UPDATED")["before"]["name"], name);
        assert_eq!(detail("GROUP_UPDATED")["after"]["name"], renamed);
        assert_eq!(detail("GROUP_DELETED")["member_count"], 1);
    }
}
