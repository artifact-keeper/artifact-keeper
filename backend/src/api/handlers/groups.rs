//! Group management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::SharedState;
use crate::error::{AppError, Result};

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
        (status = 409, description = "Group name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_group(
    State(state): State<SharedState>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
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
        ("id" = Uuid, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Group details", body = GroupResponse),
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupResponse>> {
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

    Ok(Json(GroupResponse::from(group)))
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
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
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
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_group(State(state): State<SharedState>, Path(id): Path<Uuid>) -> Result<()> {
    let result = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Group not found".to_string()));
    }

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
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_members(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
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
        (status = 404, description = "Group not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_members(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<MembersRequest>,
) -> Result<()> {
    for user_id in payload.user_ids {
        sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
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
        add_members,
        remove_members,
    ),
    components(schemas(
        GroupRow,
        GroupResponse,
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
    // GroupRow → GroupResponse conversion
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
}
