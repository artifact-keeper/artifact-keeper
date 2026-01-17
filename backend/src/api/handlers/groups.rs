//! Group management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

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

#[derive(Debug, Deserialize)]
pub struct ListGroupsQuery {
    pub search: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub member_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct GroupListResponse {
    pub items: Vec<GroupResponse>,
    pub pagination: Pagination,
}

/// List groups
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
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')"
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
        "#
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
        "#
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

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct CreatedGroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create a group
pub async fn create_group(
    State(state): State<SharedState>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>> {
    let group: CreatedGroupRow = sqlx::query_as(
        r#"
        INSERT INTO groups (name, description)
        VALUES ($1, $2)
        RETURNING id, name, description, created_at, updated_at
        "#
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
pub async fn get_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<GroupResponse>> {
    // Check if groups table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'groups')"
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
        "#
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    Ok(Json(GroupResponse::from(group)))
}

/// Update a group
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
        "#
    )
    .bind(id)
    .bind(&payload.name)
    .bind(&payload.description)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Group not found".to_string()))?;

    let member_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_group_members WHERE group_id = $1"
    )
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
pub async fn delete_group(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<()> {
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

#[derive(Debug, Deserialize)]
pub struct MembersRequest {
    pub user_ids: Vec<Uuid>,
}

/// Add members to a group
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
            "#
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
