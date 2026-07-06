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
use crate::models::access_scope::AccessScope;
use crate::services::curation_service::version_compare;
use crate::services::repository_service::{
    build_visibility_clause_for, RepoVisibility, VisibilityBind,
};

/// Map an optional authenticated principal to the repository visibility scope
/// used to filter package listings. Mirrors `list_repositories` so that the
/// packages endpoints enforce the same per-user authorization model
/// (public repos plus any repo the user holds a role assignment for) instead
/// of treating every authenticated caller as entitled to all packages.
fn repo_visibility_for(auth: Option<&AuthExtension>) -> RepoVisibility {
    match auth {
        None => RepoVisibility::PublicOnly,
        Some(a) if a.is_admin => RepoVisibility::All,
        // Repo-scoped token: restrict strictly to the token's allowed set.
        Some(a) if matches!(a.allowed_repo_ids, AccessScope::Restricted(_)) => RepoVisibility::Ids(
            a.allowed_repo_ids
                .as_allowed_repo_ids()
                .unwrap_or_default()
                .to_vec(),
        ),
        Some(a) => RepoVisibility::User(a.user_id),
    }
}

/// Split a [`VisibilityBind`] into the two concrete shapes its parameter can
/// take (single `user_id` uuid vs `uuid[]`). Exactly one is `Some` per call;
/// the unused one binds as a typed NULL the clause never references.
fn split_visibility_bind(bind: VisibilityBind) -> (Option<Uuid>, Option<Vec<Uuid>>) {
    match bind {
        VisibilityBind::User(uid) => (uid, None),
        VisibilityBind::Ids(ids) => (None, Some(ids)),
    }
}

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
    let visibility = repo_visibility_for(auth.as_ref());
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

    // Per-user repository visibility. The page query binds the visibility
    // parameter at $6 (after repository_key/format/search/offset/limit); the
    // count query binds it at $4 (after repository_key/format/search). The
    // generated `$N` MUST line up with the `.bind()` order below.
    let (page_clause, page_bind) = build_visibility_clause_for(&visibility, "r", 6);
    let (count_clause, count_bind) = build_visibility_clause_for(&visibility, "r", 4);
    let (page_user_id, page_ids) = split_visibility_bind(page_bind);
    let (count_user_id, count_ids) = split_visibility_bind(count_bind);

    let page_sql = format!(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, p.download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::text IS NULL OR r.key = $1)
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3)
          AND ({page_clause})
        ORDER BY p.updated_at DESC
        OFFSET $4
        LIMIT $5
        "#
    );
    let page_query = sqlx::query_as::<_, PackageRow>(&page_sql)
        .bind(&query.repository_key)
        .bind(&query.format)
        .bind(&search_pattern)
        .bind(offset)
        .bind(per_page as i64);
    // $6 shape depends on the visibility variant (single uuid vs uuid[]).
    let page_query = match &page_ids {
        Some(ids) => page_query.bind(ids.clone()),
        None => page_query.bind(page_user_id),
    };
    let packages: Vec<PackageRow> = page_query
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let count_sql = format!(
        r#"
        SELECT COUNT(*)
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::text IS NULL OR r.key = $1)
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3)
          AND ({count_clause})
        "#
    );
    let count_query = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&query.repository_key)
        .bind(&query.format)
        .bind(&search_pattern);
    // $4 shape depends on the visibility variant (single uuid vs uuid[]).
    let count_query = match &count_ids {
        Some(ids) => count_query.bind(ids.clone()),
        None => count_query.bind(count_user_id),
    };
    let total: i64 = count_query.fetch_one(&state.db).await.unwrap_or(0);

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
    let visibility = repo_visibility_for(auth.as_ref());

    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // The visibility parameter is bound at $2 (after the package id at $1).
    let (clause, bind) = build_visibility_clause_for(&visibility, "r", 2);
    let (user_id, ids) = split_visibility_bind(bind);

    let sql = format!(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, p.download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE p.id = $1
          AND ({clause})
        "#
    );
    let query = sqlx::query_as::<_, PackageRow>(&sql).bind(id);
    // $2 shape depends on the visibility variant (single uuid vs uuid[]).
    let query = match &ids {
        Some(ids) => query.bind(ids.clone()),
        None => query.bind(user_id),
    };
    let package: PackageRow = query
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
    let visibility = repo_visibility_for(auth.as_ref());

    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // Verify the package exists and belongs to a repository visible to the
    // caller. The visibility parameter is bound at $2 (after the id at $1).
    let (clause, bind) = build_visibility_clause_for(&visibility, "r", 2);
    let (user_id, ids) = split_visibility_bind(bind);

    let exists_sql = format!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM packages p
            JOIN repositories r ON r.id = p.repository_id
            WHERE p.id = $1
              AND ({clause})
        )
        "#
    );
    let exists_query = sqlx::query_scalar::<_, bool>(&exists_sql).bind(id);
    // $2 shape depends on the visibility variant (single uuid vs uuid[]).
    let exists_query = match &ids {
        Some(ids) => exists_query.bind(ids.clone()),
        None => exists_query.bind(user_id),
    };
    let package_exists: bool = exists_query.fetch_one(&state.db).await.unwrap_or(false);

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

    fn make_auth(user_id: Uuid, is_admin: bool, allowed: Option<Vec<Uuid>>) -> AuthExtension {
        AuthExtension {
            user_id,
            username: "tester".to_string(),
            email: "tester@example.com".to_string(),
            is_admin,
            is_api_token: allowed.is_some(),
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::from(allowed),
            iat_ms: None,
        }
    }

    // -----------------------------------------------------------------------
    // repo_visibility_for: per-user authorization mapping (mirrors list_repositories)
    // -----------------------------------------------------------------------

    #[test]
    fn test_visibility_anonymous_is_public_only() {
        assert_eq!(repo_visibility_for(None), RepoVisibility::PublicOnly);
    }

    #[test]
    fn test_visibility_admin_is_all() {
        let auth = make_auth(Uuid::new_v4(), true, None);
        assert_eq!(repo_visibility_for(Some(&auth)), RepoVisibility::All);
    }

    #[test]
    fn test_visibility_authenticated_non_admin_is_user_scope() {
        let uid = Uuid::new_v4();
        let auth = make_auth(uid, false, None);
        assert_eq!(repo_visibility_for(Some(&auth)), RepoVisibility::User(uid));
    }

    #[test]
    fn test_visibility_scoped_token_is_ids() {
        let repo = Uuid::new_v4();
        let auth = make_auth(Uuid::new_v4(), false, Some(vec![repo]));
        assert_eq!(
            repo_visibility_for(Some(&auth)),
            RepoVisibility::Ids(vec![repo])
        );
    }

    #[test]
    fn test_visibility_admin_scoped_token_still_all() {
        // Admin bypasses scope restrictions, matching list_repositories.
        let auth = make_auth(Uuid::new_v4(), true, Some(vec![Uuid::new_v4()]));
        assert_eq!(repo_visibility_for(Some(&auth)), RepoVisibility::All);
    }

    #[test]
    fn test_split_visibility_bind_user_and_ids() {
        let uid = Uuid::new_v4();
        assert_eq!(
            split_visibility_bind(VisibilityBind::User(Some(uid))),
            (Some(uid), None)
        );
        assert_eq!(
            split_visibility_bind(VisibilityBind::User(None)),
            (None, None)
        );
        let a = Uuid::new_v4();
        assert_eq!(
            split_visibility_bind(VisibilityBind::Ids(vec![a])),
            (None, Some(vec![a]))
        );
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

    // -----------------------------------------------------------------------
    // DB-backed visibility tests: the listing/detail/versions endpoints must
    // enforce per-user repository visibility (skip cleanly without
    // DATABASE_URL, same as the other handler suites).
    // -----------------------------------------------------------------------
    mod visibility_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        /// Insert a minimal `packages` row in `repo_id` and return its id.
        async fn seed_package(pool: &sqlx::PgPool, repo_id: Uuid) -> Uuid {
            sqlx::query_scalar(
                "INSERT INTO packages (repository_id, name, version, size_bytes) \
                 VALUES ($1, 'vis-test-pkg', '1.0.0', 1) RETURNING id",
            )
            .bind(repo_id)
            .fetch_one(pool)
            .await
            .expect("seed package")
        }

        async fn set_repo_public(pool: &sqlx::PgPool, repo_id: Uuid) {
            sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
                .bind(repo_id)
                .execute(pool)
                .await
                .expect("set is_public");
        }

        /// Build the packages router with `auth` injected (None = anonymous).
        fn app_for(f: &tdh::Fixture, auth: Option<AuthExtension>) -> axum::Router {
            match auth {
                Some(a) => tdh::router_with_auth(router(), f.state.clone(), a),
                None => f.router_anon(router()),
            }
        }

        /// How many packages of the fixture repo the caller can see in the
        /// listing (filtered by repository_key so parallel tests don't leak in).
        async fn visible_total(f: &tdh::Fixture, auth: Option<AuthExtension>) -> i64 {
            let (status, body) = tdh::send(
                app_for(f, auth),
                tdh::get(format!("/?repository_key={}", f.repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("listing json");
            json["pagination"]["total"].as_i64().expect("total")
        }

        /// Status the caller gets for a packages-router GET (detail/versions).
        async fn status_of(
            f: &tdh::Fixture,
            auth: Option<AuthExtension>,
            path: String,
        ) -> StatusCode {
            let (status, _) = tdh::send(app_for(f, auth), tdh::get(path)).await;
            status
        }

        #[tokio::test]
        async fn test_private_repo_packages_hidden_without_access() {
            // create_repo leaves is_public at its default (false): private.
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            // A user with no role assignment on the repo.
            let outsider = || Some(make_auth(Uuid::new_v4(), false, None));

            assert_eq!(visible_total(&f, None).await, 0);
            assert_eq!(visible_total(&f, outsider()).await, 0);
            assert_eq!(
                status_of(&f, None, format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&f, outsider(), format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&f, outsider(), format!("/{pkg}/versions")).await,
                StatusCode::NOT_FOUND
            );
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_private_repo_packages_visible_with_grant_or_admin() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            // Fixture::setup grants the fixture user a repo-scoped role.
            let granted = || Some(make_auth(f.user_id, false, None));
            let admin = || Some(make_auth(Uuid::new_v4(), true, None));

            assert_eq!(visible_total(&f, granted()).await, 1);
            assert_eq!(visible_total(&f, admin()).await, 1);
            assert_eq!(
                status_of(&f, granted(), format!("/{pkg}")).await,
                StatusCode::OK
            );
            assert_eq!(
                status_of(&f, admin(), format!("/{pkg}")).await,
                StatusCode::OK
            );
            assert_eq!(
                status_of(&f, granted(), format!("/{pkg}/versions")).await,
                StatusCode::OK
            );
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_public_repo_packages_visible_to_anonymous() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            set_repo_public(&f.pool, f.repo_id).await;

            assert_eq!(visible_total(&f, None).await, 1);
            assert_eq!(status_of(&f, None, format!("/{pkg}")).await, StatusCode::OK);
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_repo_scoped_token_limited_to_allowed_repos() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            let scoped_to = |ids: Vec<Uuid>| Some(make_auth(f.user_id, false, Some(ids)));

            // Token scoped to a different repository: nothing visible, even
            // though the underlying user holds a grant on the fixture repo.
            assert_eq!(visible_total(&f, scoped_to(vec![Uuid::new_v4()])).await, 0);
            assert_eq!(
                status_of(&f, scoped_to(vec![Uuid::new_v4()]), format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );

            // Token scoped to the fixture repository: visible.
            assert_eq!(visible_total(&f, scoped_to(vec![f.repo_id])).await, 1);
            assert_eq!(
                status_of(&f, scoped_to(vec![f.repo_id]), format!("/{pkg}")).await,
                StatusCode::OK
            );
            f.teardown().await;
        }
    }
}
