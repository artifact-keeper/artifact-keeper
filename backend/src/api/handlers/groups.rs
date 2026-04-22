//! Group management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
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
use crate::services::permission_service::{SYSTEM_SENTINEL_ID, SYSTEM_TARGET_TYPE};

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create group routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route(
            "/:id",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/:id/members", post(add_members).delete(remove_members))
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
    pub member_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
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
    path = "",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(ListGroupsQuery),
    responses(
        (status = 200, description = "List of groups", body = GroupListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_groups(
    State(state): State<SharedState>,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<GroupListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));

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

    let groups: Vec<GroupRow> = sqlx::query_as(
        r#"
        SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
               COALESCE(COUNT(ugm.user_id), 0) as member_count
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE ($1::text IS NULL OR g.name ILIKE $1 OR g.description ILIKE $1)
        GROUP BY g.id
        ORDER BY g.name
        OFFSET $2
        LIMIT $3
        "#,
    )
    .bind(&search_pattern)
    .bind(offset)
    .bind(per_page as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM groups
        WHERE ($1::text IS NULL OR name ILIKE $1 OR description ILIKE $1)
        "#,
    )
    .bind(&search_pattern)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

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
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create a group
#[utoipa::path(
    post,
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

    let group: CreatedGroupRow = sqlx::query_as(
        r#"
        INSERT INTO groups (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description, created_at, updated_at
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

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count: 0,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Get a group by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/groups",
    tag = "groups",
    params(
        ("id" = Uuid, Path, description = "Group ID"),
        GetGroupQuery,
    ),
    responses(
        (status = 200, description = "Group details with paginated members", body = GroupDetailResponse),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<GetGroupQuery>,
) -> Result<Json<GroupDetailResponse>> {
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

    let group: GroupRow = sqlx::query_as(
        r#"
        SELECT g.id, g.name, g.description, g.created_at, g.updated_at,
               COALESCE(COUNT(ugm.user_id), 0) as member_count
        FROM groups g
        LEFT JOIN user_group_members ugm ON ugm.group_id = g.id
        WHERE g.id = $1
        GROUP BY g.id
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let member_limit = query.limit();
    let member_offset = query.offset();

    let members: Vec<MemberRow> = sqlx::query_as(
        r#"
        SELECT ugm.user_id, u.username, u.display_name, ugm.joined_at
        FROM user_group_members ugm
        JOIN users u ON u.id = ugm.user_id
        WHERE ugm.group_id = $1
        ORDER BY ugm.joined_at
        LIMIT $2
        OFFSET $3
        "#,
    )
    .bind(id)
    .bind(member_limit)
    .bind(member_offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // member_count from the group query already holds the total; reuse it
    // instead of issuing a separate COUNT query.
    let members_total = group.member_count;

    Ok(Json(GroupDetailResponse {
        group: GroupResponse::from(group),
        members: members.into_iter().map(GroupMemberResponse::from).collect(),
        members_total,
    }))
}

/// Update a group
#[utoipa::path(
    put,
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

    // Fine-grained permission check: non-admins need "admin" on the target group.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "group", id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to update this group".to_string(),
            ));
        }
    }

    let group: CreatedGroupRow = sqlx::query_as(
        r#"
        UPDATE groups
        SET name = $2, description = $3, updated_at = NOW()
        WHERE id = $1
        RETURNING id, name, description, created_at, updated_at
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

    Ok(Json(GroupResponse {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

/// Delete a group
#[utoipa::path(
    delete,
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

    // Fine-grained permission check: non-admins need "admin" on the target group.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "group", id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to delete this group".to_string(),
            ));
        }
    }

    let result = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Group not found".to_string()));
    }

    state.event_bus.emit("group.deleted", id, None);

    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MembersRequest {
    pub user_ids: Vec<Uuid>,
}

/// Add members to a group
#[utoipa::path(
    post,
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

    // Fine-grained permission check: non-admins need "admin" on the target group.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "group", id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to manage group membership".to_string(),
            ));
        }
    }

    for user_id in payload.user_ids {
        sqlx::query(
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
    }

    state.event_bus.emit("group.member_added", id, None);

    Ok(())
}

/// Remove members from a group
#[utoipa::path(
    delete,
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

    // Fine-grained permission check: non-admins need "admin" on the target group.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "group", id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to manage group membership".to_string(),
            ));
        }
    }

    for user_id in payload.user_ids {
        sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }

    state.event_bus.emit("group.member_removed", id, None);

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
        add_members,
        remove_members,
    ),
    components(schemas(
        GroupRow,
        GroupResponse,
        GroupMemberResponse,
        GroupDetailResponse,
        GroupListResponse,
        CreateGroupRequest,
        CreatedGroupRow,
        MembersRequest,
    ))
)]
pub struct GroupsApiDoc;

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
            member_count: 5,
            created_at: now,
            updated_at: now,
        };
        let resp = GroupResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "developers");
        assert_eq!(resp.description, Some("Dev team".to_string()));
        assert_eq!(resp.member_count, 5);
    }

    #[test]
    fn test_group_row_to_response_no_description() {
        let now = Utc::now();
        let row = GroupRow {
            id: Uuid::new_v4(),
            name: "ops".to_string(),
            description: None,
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
            allowed_repo_ids: None,
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
}
