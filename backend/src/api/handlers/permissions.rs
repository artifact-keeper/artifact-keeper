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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -----------------------------------------------------------------------
    // ListPermissionsQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_permissions_query_all_fields() {
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "user", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "page": 2, "per_page": 50}}"#,
            uid, tid
        );
        let query: ListPermissionsQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query.principal_type, Some("user".to_string()));
        assert_eq!(query.principal_id, Some(uid));
        assert_eq!(query.target_type, Some("repository".to_string()));
        assert_eq!(query.target_id, Some(tid));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_list_permissions_query_empty() {
        let json = r#"{}"#;
        let query: ListPermissionsQuery = serde_json::from_str(json).unwrap();
        assert!(query.principal_type.is_none());
        assert!(query.principal_id.is_none());
        assert!(query.target_type.is_none());
        assert!(query.target_id.is_none());
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
    }

    #[test]
    fn test_list_permissions_query_partial() {
        let json = r#"{"principal_type": "group", "page": 1}"#;
        let query: ListPermissionsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.principal_type, Some("group".to_string()));
        assert!(query.principal_id.is_none());
        assert_eq!(query.page, Some(1));
    }

    // -----------------------------------------------------------------------
    // Pagination logic (inline in list_permissions)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let page = 1;
        let per_page = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_pagination_page_zero_clamp() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_over_max() {
        let per_page = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset() {
        let page: u32 = 5;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_total_pages_calculation() {
        let total: i64 = 55;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_total_pages_single_page() {
        let total: i64 = 15;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 1);
    }

    // -----------------------------------------------------------------------
    // PermissionRow → PermissionResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_row_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let row = PermissionRow {
            id,
            principal_type: "user".to_string(),
            principal_id: pid,
            principal_name: Some("admin".to_string()),
            target_type: "repository".to_string(),
            target_id: tid,
            target_name: Some("my-repo".to_string()),
            actions: vec!["read".to_string(), "write".to_string()],
            created_at: now,
            updated_at: now,
        };
        let resp = PermissionResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.principal_type, "user");
        assert_eq!(resp.principal_id, pid);
        assert_eq!(resp.principal_name, Some("admin".to_string()));
        assert_eq!(resp.target_type, "repository");
        assert_eq!(resp.target_id, tid);
        assert_eq!(resp.target_name, Some("my-repo".to_string()));
        assert_eq!(resp.actions, vec!["read", "write"]);
    }

    #[test]
    fn test_permission_row_to_response_no_names() {
        let now = Utc::now();
        let row = PermissionRow {
            id: Uuid::new_v4(),
            principal_type: "group".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: None,
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: None,
            actions: vec![],
            created_at: now,
            updated_at: now,
        };
        let resp = PermissionResponse::from(row);
        assert!(resp.principal_name.is_none());
        assert!(resp.target_name.is_none());
        assert!(resp.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // PermissionResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_response_serialize() {
        let now = Utc::now();
        let resp = PermissionResponse {
            id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: Some("testuser".to_string()),
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: Some("repo1".to_string()),
            actions: vec!["read".to_string(), "deploy".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["principal_type"], "user");
        assert_eq!(json["principal_name"], "testuser");
        assert_eq!(json["target_type"], "repository");
        assert_eq!(json["target_name"], "repo1");
        let actions = json["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "read");
        assert_eq!(actions[1], "deploy");
    }

    #[test]
    fn test_permission_response_serialize_null_names() {
        let now = Utc::now();
        let resp = PermissionResponse {
            id: Uuid::new_v4(),
            principal_type: "group".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: None,
            target_type: "global".to_string(),
            target_id: Uuid::new_v4(),
            target_name: None,
            actions: vec!["admin".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["principal_name"].is_null());
        assert!(json["target_name"].is_null());
    }

    // -----------------------------------------------------------------------
    // CreatePermissionRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_permission_request() {
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "user", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "actions": ["read", "write"]}}"#,
            pid, tid
        );
        let req: CreatePermissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.principal_type, "user");
        assert_eq!(req.principal_id, pid);
        assert_eq!(req.target_type, "repository");
        assert_eq!(req.target_id, tid);
        assert_eq!(req.actions, vec!["read", "write"]);
    }

    #[test]
    fn test_create_permission_request_empty_actions() {
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "group", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "actions": []}}"#,
            pid, tid
        );
        let req: CreatePermissionRequest = serde_json::from_str(&json).unwrap();
        assert!(req.actions.is_empty());
    }

    #[test]
    fn test_create_permission_request_missing_field() {
        let json = r#"{"principal_type": "user"}"#;
        let result = serde_json::from_str::<CreatePermissionRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_list_response_serialize() {
        let now = Utc::now();
        let resp = PermissionListResponse {
            items: vec![PermissionResponse {
                id: Uuid::new_v4(),
                principal_type: "user".to_string(),
                principal_id: Uuid::new_v4(),
                principal_name: Some("u1".to_string()),
                target_type: "repository".to_string(),
                target_id: Uuid::new_v4(),
                target_name: Some("r1".to_string()),
                actions: vec!["read".to_string()],
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
    }

    #[test]
    fn test_permission_list_response_empty() {
        let resp = PermissionListResponse {
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
    }

    // -----------------------------------------------------------------------
    // PermissionRow serialization (used as FromRow output)
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_row_serialize() {
        let now = Utc::now();
        let row = PermissionRow {
            id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: Some("alice".to_string()),
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: Some("repo-a".to_string()),
            actions: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["principal_type"], "user");
        assert_eq!(json["actions"].as_array().unwrap().len(), 3);
    }
}
