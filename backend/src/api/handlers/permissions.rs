//! Permission management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create permission routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_permissions).post(create_permission))
        .route(
            "/:id",
            get(get_permission)
                .put(update_permission)
                .delete(delete_permission),
        )
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPermissionsQuery {
    pub principal_type: Option<String>,
    pub principal_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PermissionRow {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub principal_name: Option<String>,
    pub target_type: String,
    pub target_id: Uuid,
    pub target_name: Option<String>,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub principal_name: Option<String>,
    pub target_type: String,
    pub target_id: Uuid,
    pub target_name: Option<String>,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PermissionRow> for PermissionResponse {
    fn from(row: PermissionRow) -> Self {
        Self {
            id: row.id,
            principal_type: row.principal_type,
            principal_id: row.principal_id,
            principal_name: row.principal_name,
            target_type: row.target_type,
            target_id: row.target_id,
            target_name: row.target_name,
            actions: row.actions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionListResponse {
    pub items: Vec<PermissionResponse>,
    pub pagination: Pagination,
}

/// List permissions
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(ListPermissionsQuery),
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_permissions(
    State(state): State<SharedState>,
    Query(query): Query<ListPermissionsQuery>,
) -> Result<Json<PermissionListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // Check if permissions table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'permissions')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(PermissionListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    let permissions: Vec<PermissionRow> = sqlx::query_as(
        r#"
        SELECT p.id, p.principal_type, p.principal_id, p.target_type, p.target_id,
               p.actions, p.created_at, p.updated_at,
               CASE
                   WHEN p.principal_type = 'user' THEN u.username
                   WHEN p.principal_type = 'group' THEN g.name
               END as principal_name,
               CASE
                   WHEN p.target_type = 'repository' THEN r.name
               END as target_name
        FROM permissions p
        LEFT JOIN users u ON p.principal_type = 'user' AND p.principal_id = u.id
        LEFT JOIN groups g ON p.principal_type = 'group' AND p.principal_id = g.id
        LEFT JOIN repositories r ON p.target_type = 'repository' AND p.target_id = r.id
        WHERE ($1::text IS NULL OR p.principal_type = $1)
          AND ($2::uuid IS NULL OR p.principal_id = $2)
          AND ($3::text IS NULL OR p.target_type = $3)
          AND ($4::uuid IS NULL OR p.target_id = $4)
        ORDER BY p.created_at DESC
        OFFSET $5
        LIMIT $6
        "#,
    )
    .bind(&query.principal_type)
    .bind(query.principal_id)
    .bind(&query.target_type)
    .bind(query.target_id)
    .bind(offset)
    .bind(per_page as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM permissions
        WHERE ($1::text IS NULL OR principal_type = $1)
          AND ($2::uuid IS NULL OR principal_id = $2)
          AND ($3::text IS NULL OR target_type = $3)
          AND ($4::uuid IS NULL OR target_id = $4)
        "#,
    )
    .bind(&query.principal_type)
    .bind(query.principal_id)
    .bind(&query.target_type)
    .bind(query.target_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(PermissionListResponse {
        items: permissions
            .into_iter()
            .map(PermissionResponse::from)
            .collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    pub principal_type: String,
    pub principal_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub actions: Vec<String>,
}

#[derive(Debug, FromRow, ToSchema)]
pub struct CreatedPermissionRow {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Create a permission
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    request_body = CreatePermissionRequest,
    responses(
        (status = 200, description = "Permission created successfully", body = PermissionResponse),
        (status = 409, description = "Permission already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_permission(
    State(state): State<SharedState>,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let permission: CreatedPermissionRow = sqlx::query_as(
        r#"
        INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, principal_type, principal_id, target_type, target_id, actions, created_at, updated_at
        "#
    )
    .bind(&payload.principal_type)
    .bind(payload.principal_id)
    .bind(&payload.target_type)
    .bind(payload.target_id)
    .bind(&payload.actions)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            AppError::Conflict("Permission already exists".to_string())
        } else {
            AppError::Database(msg)
        }
    })?;

    Ok(Json(PermissionResponse {
        id: permission.id,
        principal_type: permission.principal_type,
        principal_id: permission.principal_id,
        principal_name: None,
        target_type: permission.target_type,
        target_id: permission.target_id,
        target_name: None,
        actions: permission.actions,
        created_at: permission.created_at,
        updated_at: permission.updated_at,
    }))
}

/// Get a permission by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 200, description = "Permission details", body = PermissionResponse),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionResponse>> {
    // Check if permissions table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'permissions')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }

    let permission: PermissionRow = sqlx::query_as(
        r#"
        SELECT p.id, p.principal_type, p.principal_id, p.target_type, p.target_id,
               p.actions, p.created_at, p.updated_at,
               CASE
                   WHEN p.principal_type = 'user' THEN u.username
                   WHEN p.principal_type = 'group' THEN g.name
               END as principal_name,
               CASE
                   WHEN p.target_type = 'repository' THEN r.name
               END as target_name
        FROM permissions p
        LEFT JOIN users u ON p.principal_type = 'user' AND p.principal_id = u.id
        LEFT JOIN groups g ON p.principal_type = 'group' AND p.principal_id = g.id
        LEFT JOIN repositories r ON p.target_type = 'repository' AND p.target_id = r.id
        WHERE p.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    Ok(Json(PermissionResponse::from(permission)))
}

/// Update a permission
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    request_body = CreatePermissionRequest,
    responses(
        (status = 200, description = "Permission updated successfully", body = PermissionResponse),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>> {
    let permission: CreatedPermissionRow = sqlx::query_as(
        r#"
        UPDATE permissions
        SET principal_type = $2, principal_id = $3, target_type = $4, target_id = $5,
            actions = $6, updated_at = NOW()
        WHERE id = $1
        RETURNING id, principal_type, principal_id, target_type, target_id, actions, created_at, updated_at
        "#
    )
    .bind(id)
    .bind(&payload.principal_type)
    .bind(payload.principal_id)
    .bind(&payload.target_type)
    .bind(payload.target_id)
    .bind(&payload.actions)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    Ok(Json(PermissionResponse {
        id: permission.id,
        principal_type: permission.principal_type,
        principal_id: permission.principal_id,
        principal_name: None,
        target_type: permission.target_type,
        target_id: permission.target_id,
        target_name: None,
        actions: permission.actions,
        created_at: permission.created_at,
        updated_at: permission.updated_at,
    }))
}

/// Delete a permission
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 200, description = "Permission deleted successfully"),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_permission(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }

    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_permissions,
        create_permission,
        get_permission,
        update_permission,
        delete_permission,
    ),
    components(schemas(
        PermissionRow,
        PermissionResponse,
        PermissionListResponse,
        CreatePermissionRequest,
        CreatedPermissionRow,
    ))
)]
pub struct PermissionsApiDoc;
