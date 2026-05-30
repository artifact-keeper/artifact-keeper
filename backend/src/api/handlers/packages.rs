//! Package management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::curation_service::version_compare;

/// Check if the packages table exists in the database.
async fn packages_table_exists(db: &sqlx::PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'packages')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

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
    #[serde(alias = "q")]
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListPackagesQuery>,
) -> Result<Json<PackageListResponse>> {
    let public_only = auth.is_none();
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(24).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));

    let table_exists = packages_table_exists(&state.db).await;

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
          AND ($6::bool = false OR r.is_public = true)
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
    .bind(public_only)
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
          AND ($4::bool = false OR r.is_public = true)
        "#,
    )
    .bind(&query.repository_key)
    .bind(&query.format)
    .bind(&search_pattern)
    .bind(public_only)
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageResponse>> {
    let public_only = auth.is_none();

    let table_exists = packages_table_exists(&state.db).await;

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
          AND ($2::bool = false OR r.is_public = true)
        "#,
    )
    .bind(id)
    .bind(public_only)
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
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageVersionsResponse>> {
    let public_only = auth.is_none();

    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // Verify the package exists and belongs to a visible repository
    let package_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM packages p
            JOIN repositories r ON r.id = p.repository_id
            WHERE p.id = $1
              AND ($2::bool = false OR r.is_public = true)
        )
        "#,
    )
    .bind(id)
    .bind(public_only)
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

    let mut versions: Vec<PackageVersionRow> = sqlx::query_as(
        r#"
        SELECT version, size_bytes, download_count, created_at, checksum_sha256
        FROM package_versions
        WHERE package_id = $1
        "#,
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    versions.sort_by(|a, b| match version_compare(&a.version, &b.version) {
        n if n < 0 => std::cmp::Ordering::Greater,
        n if n > 0 => std::cmp::Ordering::Less,
        _ => b.created_at.cmp(&a.created_at),
    });

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json;

    fn make_package_row() -> PackageRow {
        let now = Utc::now();
        PackageRow {
            id: Uuid::new_v4(),
            repository_key: "my-repo".to_string(),
            name: "my-package".to_string(),
            version: "1.0.0".to_string(),
            format: "npm".to_string(),
            description: Some("A test package".to_string()),
            size_bytes: 1024,
            download_count: 42,
            created_at: now,
            updated_at: now,
            metadata: Some(serde_json::json!({"license": "MIT"})),
        }
    }

    fn make_version_row() -> PackageVersionRow {
        PackageVersionRow {
            version: "2.0.0".to_string(),
            size_bytes: 2048,
            download_count: 10,
            created_at: Utc::now(),
            checksum_sha256: "abc123def456".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // PackageRow -> PackageResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_row_to_response_all_fields() {
        let row = make_package_row();
        let id = row.id;
        let resp = PackageResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.repository_key, "my-repo");
        assert_eq!(resp.name, "my-package");
        assert_eq!(resp.version, "1.0.0");
        assert_eq!(resp.format, "npm");
        assert_eq!(resp.description.as_deref(), Some("A test package"));
        assert_eq!(resp.size_bytes, 1024);
        assert_eq!(resp.download_count, 42);
        assert!(resp.metadata.is_some());
    }

    #[test]
    fn test_package_row_to_response_no_description() {
        let mut row = make_package_row();
        row.description = None;
        let resp = PackageResponse::from(row);
        assert!(resp.description.is_none());
    }

    #[test]
    fn test_package_row_to_response_no_metadata() {
        let mut row = make_package_row();
        row.metadata = None;
        let resp = PackageResponse::from(row);
        assert!(resp.metadata.is_none());
    }

    #[test]
    fn test_package_row_to_response_zero_size() {
        let mut row = make_package_row();
        row.size_bytes = 0;
        let resp = PackageResponse::from(row);
        assert_eq!(resp.size_bytes, 0);
    }

    #[test]
    fn test_package_row_to_response_zero_downloads() {
        let mut row = make_package_row();
        row.download_count = 0;
        let resp = PackageResponse::from(row);
        assert_eq!(resp.download_count, 0);
    }

    // -----------------------------------------------------------------------
    // PackageVersionRow -> PackageVersionResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_row_to_response() {
        let row = make_version_row();
        let resp = PackageVersionResponse::from(row);
        assert_eq!(resp.version, "2.0.0");
        assert_eq!(resp.size_bytes, 2048);
        assert_eq!(resp.download_count, 10);
        assert_eq!(resp.checksum_sha256, "abc123def456");
    }

    #[test]
    fn test_version_row_to_response_empty_checksum() {
        let mut row = make_version_row();
        row.checksum_sha256 = String::new();
        let resp = PackageVersionResponse::from(row);
        assert_eq!(resp.checksum_sha256, "");
    }

    // -----------------------------------------------------------------------
    // ListPackagesQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_packages_query_empty() {
        let json = r#"{}"#;
        let query: ListPackagesQuery = serde_json::from_str(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.repository_key.is_none());
        assert!(query.format.is_none());
        assert!(query.search.is_none());
    }

    #[test]
    fn test_list_packages_query_full() {
        let json = serde_json::json!({
            "page": 2,
            "per_page": 50,
            "repository_key": "main-repo",
            "format": "maven",
            "search": "spring"
        });
        let query: ListPackagesQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.repository_key.as_deref(), Some("main-repo"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.search.as_deref(), Some("spring"));
    }

    #[test]
    fn test_list_packages_query_q_alias() {
        let json = serde_json::json!({
            "q": "shared-pkg"
        });
        let query: ListPackagesQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.search.as_deref(), Some("shared-pkg"));
    }

    // -----------------------------------------------------------------------
    // Pagination logic (simulating handler code)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let query = ListPackagesQuery {
            page: None,
            per_page: None,
            repository_key: None,
            format: None,
            search: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(24).min(100);
        assert_eq!(page, 1);
        assert_eq!(per_page, 24);
    }

    #[test]
    fn test_pagination_page_zero_clamped_to_one() {
        let query = ListPackagesQuery {
            page: Some(0),
            per_page: None,
            repository_key: None,
            format: None,
            search: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_clamped_to_100() {
        let query = ListPackagesQuery {
            page: None,
            per_page: Some(200),
            repository_key: None,
            format: None,
            search: None,
        };
        let per_page = query.per_page.unwrap_or(24).min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_pagination_offset_first_page() {
        let page: u32 = 1;
        let per_page: u32 = 24;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_total_pages_calculation() {
        let total: i64 = 50;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3); // ceil(50/24) = 3
    }

    #[test]
    fn test_total_pages_exact_division() {
        let total: i64 = 48;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 2);
    }

    #[test]
    fn test_total_pages_zero_total() {
        let total: i64 = 0;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 0);
    }

    // -----------------------------------------------------------------------
    // Search pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pattern_some() {
        let search = Some("react".to_string());
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(pattern.as_deref(), Some("%react%"));
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
        assert_eq!(pattern.as_deref(), Some("%%"));
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_response_serialize() {
        let row = make_package_row();
        let resp = PackageResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["id"].is_string());
        assert_eq!(json["repository_key"], "my-repo");
        assert_eq!(json["name"], "my-package");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["format"], "npm");
        assert_eq!(json["size_bytes"], 1024);
        assert_eq!(json["download_count"], 42);
    }

    #[test]
    fn test_package_version_response_serialize() {
        let row = make_version_row();
        let resp = PackageVersionResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["version"], "2.0.0");
        assert_eq!(json["size_bytes"], 2048);
        assert_eq!(json["checksum_sha256"], "abc123def456");
    }

    #[test]
    fn test_package_versions_response_serialize_empty() {
        let resp = PackageVersionsResponse { versions: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_package_list_response_serialize() {
        let resp = PackageListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 24,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert_eq!(json["pagination"]["page"], 1);
        assert_eq!(json["pagination"]["per_page"], 24);
        assert_eq!(json["pagination"]["total"], 0);
    }
}
