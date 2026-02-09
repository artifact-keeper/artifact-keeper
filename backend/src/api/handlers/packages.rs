//! Package management handlers.

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

/// Create package routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_packages))
        .route("/:id", get(get_package))
        .route("/:id/versions", get(get_package_versions))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPackagesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub repository_key: Option<String>,
    pub format: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PackageRow {
    pub id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: String,
    pub format: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: String,
    pub format: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

impl From<PackageRow> for PackageResponse {
    fn from(row: PackageRow) -> Self {
        Self {
            id: row.id,
            repository_key: row.repository_key,
            name: row.name,
            version: row.version,
            format: row.format,
            description: row.description,
            size_bytes: row.size_bytes,
            download_count: row.download_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
            metadata: row.metadata,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageListResponse {
    pub items: Vec<PackageResponse>,
    pub pagination: Pagination,
}

/// List packages
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(ListPackagesQuery),
    responses(
        (status = 200, description = "Paginated list of packages", body = PackageListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_packages(
    State(state): State<SharedState>,
    Query(query): Query<ListPackagesQuery>,
) -> Result<Json<PackageListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(24).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));

    // Check if packages table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'packages')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(PackageListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    let packages: Vec<PackageRow> = sqlx::query_as(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, p.download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::text IS NULL OR r.key = $1)
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3)
        ORDER BY p.updated_at DESC
        OFFSET $4
        LIMIT $5
        "#,
    )
    .bind(&query.repository_key)
    .bind(&query.format)
    .bind(&search_pattern)
    .bind(offset)
    .bind(per_page as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::text IS NULL OR r.key = $1)
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3)
        "#,
    )
    .bind(&query.repository_key)
    .bind(&query.format)
    .bind(&search_pattern)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(PackageListResponse {
        items: packages.into_iter().map(PackageResponse::from).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a package by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(
        ("id" = Uuid, Path, description = "Package ID")
    ),
    responses(
        (status = 200, description = "Package details", body = PackageResponse),
        (status = 404, description = "Package not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_package(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageResponse>> {
    // Check if packages table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'packages')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    let package: PackageRow = sqlx::query_as(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, p.download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE p.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Package not found".to_string()))?;

    Ok(Json(PackageResponse::from(package)))
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PackageVersionRow {
    pub version: String,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub checksum_sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageVersionResponse {
    pub version: String,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub checksum_sha256: String,
}

impl From<PackageVersionRow> for PackageVersionResponse {
    fn from(row: PackageVersionRow) -> Self {
        Self {
            version: row.version,
            size_bytes: row.size_bytes,
            download_count: row.download_count,
            created_at: row.created_at,
            checksum_sha256: row.checksum_sha256,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageVersionsResponse {
    pub versions: Vec<PackageVersionResponse>,
}

/// Get package versions
#[utoipa::path(
    get,
    path = "/{id}/versions",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(
        ("id" = Uuid, Path, description = "Package ID")
    ),
    responses(
        (status = 200, description = "List of package versions", body = PackageVersionsResponse),
        (status = 404, description = "Package not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_package_versions(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageVersionsResponse>> {
    // Check if packages table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'packages')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // First verify the package exists
    let package_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM packages WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);

    if !package_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // Check if package_versions table exists
    let versions_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'package_versions')"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !versions_table_exists {
        return Ok(Json(PackageVersionsResponse { versions: vec![] }));
    }

    let versions: Vec<PackageVersionRow> = sqlx::query_as(
        r#"
        SELECT version, size_bytes, download_count, created_at, checksum_sha256
        FROM package_versions
        WHERE package_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PackageVersionsResponse {
        versions: versions
            .into_iter()
            .map(PackageVersionResponse::from)
            .collect(),
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(list_packages, get_package, get_package_versions),
    components(schemas(
        PackageRow,
        PackageResponse,
        PackageListResponse,
        PackageVersionRow,
        PackageVersionResponse,
        PackageVersionsResponse,
    ))
)]
pub struct PackagesApiDoc;
