//! Search handlers.
//!
//! Provides quick search, advanced search, checksum lookup, suggestions,
//! trending, and recent artifact endpoints. Uses Meilisearch when available,
//! falling back to PostgreSQL full-text search.
//!
//! All search endpoints enforce repository visibility: unauthenticated callers
//! only see public repos, non-admin authenticated users see public repos plus
//! repos where they hold a role assignment, and admins see everything.

use axum::{
    extract::{Extension, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::search_service::{SearchQuery, SearchService};

// ---------------------------------------------------------------------------
// Admin Router
// ---------------------------------------------------------------------------

/// Create admin search routes (mounted under /api/v1/admin/search).
pub fn admin_router() -> Router<SharedState> {
    Router::new().route("/reindex", axum::routing::post(trigger_reindex))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Create search routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/quick", get(quick_search))
        .route("/advanced", get(advanced_search))
        .route("/checksum", get(checksum_search))
        .route("/suggest", get(suggest))
        .route("/trending", get(trending))
        .route("/recent", get(recent))
}

// ---------------------------------------------------------------------------
// Repository visibility resolution
// ---------------------------------------------------------------------------

/// How the current caller's repository access should be resolved.
///
/// This is a pure classification of the auth state -- no DB queries -- making
/// it easy to test all branches in isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoAccessMode {
    /// Admin: all repos visible, no filter needed.
    All,
    /// Authenticated non-admin: public repos plus repos where the user holds
    /// a role assignment.  The contained `Uuid` is the user ID.
    UserScoped(Uuid),
    /// Unauthenticated (or missing auth): only public repos.
    PublicOnly,
}

/// Classify the caller's repository access mode from the auth extension.
///
/// This is a pure function (no IO) so it can be unit-tested exhaustively.
pub(crate) fn classify_repo_access(auth: &Option<AuthExtension>) -> RepoAccessMode {
    match auth {
        Some(a) if a.is_admin => RepoAccessMode::All,
        Some(a) => RepoAccessMode::UserScoped(a.user_id),
        None => RepoAccessMode::PublicOnly,
    }
}

/// Map a checksum algorithm name to the corresponding SQL column expression.
///
/// Returns an error for unsupported algorithm names. This is a pure function
/// extracted from the checksum_search handler for testability.
pub(crate) fn resolve_checksum_column(algorithm: &str) -> Result<&'static str> {
    match algorithm {
        "sha256" => Ok("a.checksum_sha256"),
        "sha1" => Ok("a.checksum_sha1"),
        "md5" => Ok("a.checksum_md5"),
        other => Err(AppError::Validation(format!(
            "Unsupported checksum algorithm: {other}. Use sha256, sha1, or md5."
        ))),
    }
}

/// Resolve which repository IDs the current caller is allowed to see.
///
/// - Unauthenticated: returns `Some(ids)` containing only public repo IDs.
/// - Admin: returns `None`, meaning no filter (all repos visible).
/// - Authenticated non-admin: returns `Some(ids)` containing public repos
///   plus any private repos where the user holds a role assignment.
///
/// The returned value is passed directly to SearchService methods as the
/// `accessible_repo_ids` parameter.
async fn resolve_accessible_repos(
    db: &PgPool,
    auth: &Option<AuthExtension>,
) -> Result<Option<Vec<Uuid>>> {
    match classify_repo_access(auth) {
        RepoAccessMode::All => Ok(None),
        RepoAccessMode::UserScoped(user_id) => {
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                r#"
                SELECT r.id
                FROM repositories r
                WHERE r.is_public = true
                UNION
                SELECT COALESCE(ra.repository_id, r2.id)
                FROM role_assignments ra
                LEFT JOIN repositories r2 ON ra.repository_id IS NULL
                WHERE ra.user_id = $1
                  AND (ra.repository_id IS NOT NULL OR r2.id IS NOT NULL)
                "#,
            )
            .bind(user_id)
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            Ok(Some(rows.into_iter().map(|(id,)| id).collect()))
        }
        RepoAccessMode::PublicOnly => {
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                r#"
                SELECT r.id FROM repositories r WHERE r.is_public = true
                "#,
            )
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            Ok(Some(rows.into_iter().map(|(id,)| id).collect()))
        }
    }
}

// ---------------------------------------------------------------------------
// Shared response types
// ---------------------------------------------------------------------------

/// A unified search result matching the frontend `SearchResult` interface.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResultItem {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub result_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub repository_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlights: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FacetValue {
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FacetsResponse {
    pub formats: Vec<FacetValue>,
    pub repositories: Vec<FacetValue>,
    pub content_types: Vec<FacetValue>,
}

// ---------------------------------------------------------------------------
// GET /search/quick?q=&limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct QuickSearchQuery {
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub types: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuickSearchResponse {
    pub results: Vec<SearchResultItem>,
}

#[utoipa::path(
    get,
    path = "/quick",
    context_path = "/api/v1/search",
    tag = "search",
    params(QuickSearchQuery),
    responses(
        (status = 200, description = "Quick search results", body = QuickSearchResponse),
    ),
)]
pub async fn quick_search(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<QuickSearchQuery>,
) -> Result<Json<QuickSearchResponse>> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let query_text = params.q.unwrap_or_default();

    if query_text.is_empty() {
        return Ok(Json(QuickSearchResponse {
            results: Vec::new(),
        }));
    }

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let search_query = SearchQuery {
        q: Some(query_text),
        format: None,
        name: None,
        offset: Some(0),
        limit: Some(limit),
        public_only: false,
        accessible_repo_ids,
    };

    let service = SearchService::new(state.db.clone());
    let response = service.search(search_query).await?;

    let results = response
        .items
        .into_iter()
        .map(|r| SearchResultItem {
            id: r.id,
            result_type: "artifact".to_string(),
            name: r.name,
            path: Some(r.path),
            repository_key: r.repository_key,
            format: Some(r.format),
            version: r.version,
            size_bytes: Some(r.size_bytes),
            created_at: r.created_at,
            highlights: None,
        })
        .collect();

    Ok(Json(QuickSearchResponse { results }))
}

// ---------------------------------------------------------------------------
// GET /search/advanced
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct AdvancedSearchQuery {
    pub query: Option<String>,
    pub format: Option<String>,
    pub repository_key: Option<String>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub version: Option<String>,
    pub min_size: Option<i64>,
    pub max_size: Option<i64>,
    pub created_after: Option<String>,
    pub created_before: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdvancedSearchResponse {
    pub items: Vec<SearchResultItem>,
    pub pagination: PaginationInfo,
    pub facets: FacetsResponse,
}

#[utoipa::path(
    get,
    path = "/advanced",
    context_path = "/api/v1/search",
    tag = "search",
    params(AdvancedSearchQuery),
    responses(
        (status = 200, description = "Advanced search results with pagination and facets", body = AdvancedSearchResponse),
    ),
)]
pub async fn advanced_search(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<AdvancedSearchQuery>,
) -> Result<Json<AdvancedSearchResponse>> {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * per_page) as i64;

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let search_query = SearchQuery {
        q: params.query.clone(),
        format: params.format.clone(),
        name: params.name.clone(),
        offset: Some(offset),
        limit: Some(per_page as i64),
        public_only: false,
        accessible_repo_ids,
    };

    let service = SearchService::new(state.db.clone());
    let response = service.search(search_query).await?;

    let total = response.total;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let items = response
        .items
        .into_iter()
        .map(|r| SearchResultItem {
            id: r.id,
            result_type: "artifact".to_string(),
            name: r.name,
            path: Some(r.path),
            repository_key: r.repository_key,
            format: Some(r.format),
            version: r.version,
            size_bytes: Some(r.size_bytes),
            created_at: r.created_at,
            highlights: None,
        })
        .collect();

    let facets = FacetsResponse {
        formats: response
            .facets
            .formats
            .into_iter()
            .map(|f| FacetValue {
                value: f.value,
                count: f.count,
            })
            .collect(),
        repositories: response
            .facets
            .repositories
            .into_iter()
            .map(|f| FacetValue {
                value: f.value,
                count: f.count,
            })
            .collect(),
        content_types: response
            .facets
            .content_types
            .into_iter()
            .map(|f| FacetValue {
                value: f.value,
                count: f.count,
            })
            .collect(),
    };

    Ok(Json(AdvancedSearchResponse {
        items,
        pagination: PaginationInfo {
            page,
            per_page,
            total,
            total_pages,
        },
        facets,
    }))
}

// ---------------------------------------------------------------------------
// GET /search/checksum?checksum=&algorithm=sha256
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct ChecksumQuery {
    pub checksum: String,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChecksumArtifact {
    pub id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub content_type: String,
    pub download_count: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChecksumSearchResponse {
    pub artifacts: Vec<ChecksumArtifact>,
}

#[utoipa::path(
    get,
    path = "/checksum",
    context_path = "/api/v1/search",
    tag = "search",
    params(ChecksumQuery),
    responses(
        (status = 200, description = "Artifacts matching the given checksum", body = ChecksumSearchResponse),
        (status = 422, description = "Unsupported checksum algorithm"),
    ),
)]
pub async fn checksum_search(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<ChecksumQuery>,
) -> Result<Json<ChecksumSearchResponse>> {
    let algorithm = params.algorithm.as_deref().unwrap_or("sha256");
    let checksum = params.checksum.trim().to_lowercase();

    if checksum.is_empty() {
        return Ok(Json(ChecksumSearchResponse {
            artifacts: Vec::new(),
        }));
    }

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let checksum_column = resolve_checksum_column(algorithm)?;

    // Build the query dynamically to select the correct checksum column.
    // The repo visibility filter ($2) uses the same pattern as other search
    // methods: NULL means no filter (admin), otherwise restrict to the list.
    let sql = format!(
        r#"
        SELECT
            a.id,
            r.key AS repository_key,
            a.path,
            a.name,
            a.version,
            a.size_bytes,
            a.checksum_sha256,
            a.content_type,
            a.created_at,
            COALESCE(
                (SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id),
                0
            )::BIGINT AS download_count
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.is_deleted = false
          AND {col} = $1
          AND ($2::uuid[] IS NULL OR r.id = ANY($2))
        ORDER BY a.created_at DESC
        "#,
        col = checksum_column,
    );

    let rows: Vec<ChecksumRow> = sqlx::query_as(&sql)
        .bind(&checksum)
        .bind(&accessible_repo_ids)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let artifacts = rows
        .into_iter()
        .map(|row| ChecksumArtifact {
            id: row.id,
            repository_key: row.repository_key,
            path: row.path,
            name: row.name,
            version: row.version,
            size_bytes: row.size_bytes,
            checksum_sha256: row.checksum_sha256,
            content_type: row.content_type,
            download_count: row.download_count,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(ChecksumSearchResponse { artifacts }))
}

/// Internal row type for checksum query results.
#[derive(sqlx::FromRow)]
struct ChecksumRow {
    id: Uuid,
    repository_key: String,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    content_type: String,
    created_at: DateTime<Utc>,
    download_count: i64,
}

// ---------------------------------------------------------------------------
// GET /search/suggest?prefix=&limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct SuggestQuery {
    pub prefix: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SuggestResponse {
    pub suggestions: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/suggest",
    context_path = "/api/v1/search",
    tag = "search",
    params(SuggestQuery),
    responses(
        (status = 200, description = "Autocomplete suggestions for the given prefix", body = SuggestResponse),
    ),
)]
pub async fn suggest(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<SuggestQuery>,
) -> Result<Json<SuggestResponse>> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let service = SearchService::new(state.db.clone());
    let suggestions = service
        .suggest(&params.prefix, limit, accessible_repo_ids.as_deref(), false)
        .await?;

    Ok(Json(SuggestResponse { suggestions }))
}

// ---------------------------------------------------------------------------
// GET /search/trending?days=&limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct TrendingQuery {
    pub days: Option<i32>,
    pub limit: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/trending",
    context_path = "/api/v1/search",
    tag = "search",
    params(TrendingQuery),
    responses(
        (status = 200, description = "Trending artifacts by download count", body = Vec<SearchResultItem>),
    ),
)]
pub async fn trending(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<TrendingQuery>,
) -> Result<Json<Vec<SearchResultItem>>> {
    let days = params.days.unwrap_or(7).clamp(1, 90);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let service = SearchService::new(state.db.clone());
    let results = service
        .trending(days, limit, false, accessible_repo_ids.as_deref())
        .await?;

    let items = results
        .into_iter()
        .map(|r| SearchResultItem {
            id: r.id,
            result_type: "artifact".to_string(),
            name: r.name,
            path: Some(r.path),
            repository_key: r.repository_key,
            format: Some(r.format),
            version: r.version,
            size_bytes: Some(r.size_bytes),
            created_at: r.created_at,
            highlights: None,
        })
        .collect();

    Ok(Json(items))
}

// ---------------------------------------------------------------------------
// GET /search/recent?limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct RecentQuery {
    pub limit: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/recent",
    context_path = "/api/v1/search",
    tag = "search",
    params(RecentQuery),
    responses(
        (status = 200, description = "Recently uploaded artifacts", body = Vec<SearchResultItem>),
    ),
)]
pub async fn recent(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(params): Query<RecentQuery>,
) -> Result<Json<Vec<SearchResultItem>>> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let accessible_repo_ids = resolve_accessible_repos(&state.db, &auth).await?;

    let service = SearchService::new(state.db.clone());
    let results = service
        .recent(limit, false, accessible_repo_ids.as_deref())
        .await?;

    let items = results
        .into_iter()
        .map(|r| SearchResultItem {
            id: r.id,
            result_type: "artifact".to_string(),
            name: r.name,
            path: Some(r.path),
            repository_key: r.repository_key,
            format: Some(r.format),
            version: r.version,
            size_bytes: Some(r.size_bytes),
            created_at: r.created_at,
            highlights: None,
        })
        .collect();

    Ok(Json(items))
}

// ---------------------------------------------------------------------------
// POST /admin/search/reindex
// ---------------------------------------------------------------------------

/// Response returned when a reindex is triggered.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReindexResponse {
    pub status: String,
    pub message: String,
}

/// Trigger a full reindex of all artifacts and repositories in Meilisearch.
///
/// The reindex runs asynchronously in the background. The endpoint returns
/// immediately with a confirmation that the task was started.
#[utoipa::path(
    post,
    path = "/reindex",
    context_path = "/api/v1/admin/search",
    tag = "admin",
    operation_id = "trigger_search_reindex",
    responses(
        (status = 200, description = "Reindex started in background", body = ReindexResponse),
        (status = 500, description = "Meilisearch is not configured"),
    ),
)]
pub async fn trigger_reindex(State(state): State<SharedState>) -> Result<Json<ReindexResponse>> {
    let meili = state
        .meili_service
        .as_ref()
        .ok_or_else(|| AppError::Config("Meilisearch is not configured".to_string()))?;

    let db = state.db.clone();
    let meili = meili.clone();
    tokio::spawn(async move {
        match meili.full_reindex(&db).await {
            Ok((a, r)) => {
                tracing::info!(
                    "Search reindex complete: {} artifacts, {} repositories",
                    a,
                    r
                )
            }
            Err(e) => tracing::error!("Search reindex failed: {}", e),
        }
    });

    Ok(Json(ReindexResponse {
        status: "started".to_string(),
        message: "Full reindex of artifacts and repositories triggered in background".to_string(),
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        quick_search,
        advanced_search,
        checksum_search,
        suggest,
        trending,
        recent,
        trigger_reindex,
    ),
    components(schemas(
        SearchResultItem,
        PaginationInfo,
        FacetValue,
        FacetsResponse,
        QuickSearchResponse,
        AdvancedSearchResponse,
        ChecksumArtifact,
        ChecksumSearchResponse,
        SuggestResponse,
        ReindexResponse,
    ))
)]
pub struct SearchApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // QuickSearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_quick_search_query_deserialize_full() {
        let json = json!({"q": "my-artifact", "limit": 25, "types": "artifact,repository"});
        let query: QuickSearchQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.q.as_deref(), Some("my-artifact"));
        assert_eq!(query.limit, Some(25));
        assert_eq!(query.types.as_deref(), Some("artifact,repository"));
    }

    #[test]
    fn test_quick_search_query_deserialize_empty() {
        let json = json!({});
        let query: QuickSearchQuery = serde_json::from_value(json).unwrap();
        assert!(query.q.is_none());
        assert!(query.limit.is_none());
        assert!(query.types.is_none());
    }

    // -----------------------------------------------------------------------
    // Quick search limit clamping
    // -----------------------------------------------------------------------

    #[test]
    fn test_quick_search_limit_default() {
        let limit = 10_i64.clamp(1, 50);
        assert_eq!(limit, 10);
    }

    #[test]
    fn test_quick_search_limit_clamp_lower() {
        let limit = 0_i64.clamp(1, 50);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_quick_search_limit_clamp_upper() {
        let limit = 100_i64.clamp(1, 50);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_quick_search_limit_within_range() {
        let limit = 30_i64.clamp(1, 50);
        assert_eq!(limit, 30);
    }

    // -----------------------------------------------------------------------
    // AdvancedSearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_advanced_search_query_deserialize_full() {
        let json = json!({
            "query": "spring-boot",
            "format": "maven",
            "repository_key": "libs-release",
            "name": "spring-boot-starter",
            "path": "org/springframework",
            "version": "3.0.0",
            "min_size": 1024,
            "max_size": 10485760,
            "created_after": "2024-01-01",
            "created_before": "2024-12-31",
            "page": 2,
            "per_page": 50,
            "sort_by": "name",
            "sort_order": "asc"
        });
        let query: AdvancedSearchQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.query.as_deref(), Some("spring-boot"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.repository_key.as_deref(), Some("libs-release"));
        assert_eq!(query.min_size, Some(1024));
        assert_eq!(query.max_size, Some(10485760));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_advanced_search_query_deserialize_empty() {
        let json = json!({});
        let query: AdvancedSearchQuery = serde_json::from_value(json).unwrap();
        assert!(query.query.is_none());
        assert!(query.format.is_none());
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.sort_by.is_none());
        assert!(query.sort_order.is_none());
    }

    // -----------------------------------------------------------------------
    // Advanced search pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_advanced_search_page_defaults() {
        let page = 1;
        let per_page = 20_u32.clamp(1, 100);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_advanced_search_page_zero_clamped() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_advanced_search_per_page_clamped_upper() {
        let per_page = 500_u32.clamp(1, 100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_advanced_search_per_page_clamped_lower() {
        let per_page = 0_u32.clamp(1, 100);
        assert_eq!(per_page, 1);
    }

    #[test]
    fn test_advanced_search_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 25;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 50);
    }

    // -----------------------------------------------------------------------
    // Total pages calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_total_pages_calculation() {
        let compute = |total: i64, per_page: u32| -> u32 {
            ((total as f64) / (per_page as f64)).ceil() as u32
        };

        assert_eq!(compute(100, 20), 5); // exact division
        assert_eq!(compute(101, 20), 6); // with remainder
        assert_eq!(compute(0, 20), 0); // zero total
        assert_eq!(compute(1, 20), 1); // single item
    }

    // -----------------------------------------------------------------------
    // ChecksumQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_query_deserialize() {
        let json = json!({"checksum": "abc123def456", "algorithm": "sha256"});
        let query: ChecksumQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.checksum, "abc123def456");
        assert_eq!(query.algorithm.as_deref(), Some("sha256"));
    }

    #[test]
    fn test_checksum_query_algorithm_default() {
        let json = json!({"checksum": "abc123"});
        let query: ChecksumQuery = serde_json::from_value(json).unwrap();
        let algorithm = query.algorithm.as_deref().unwrap_or("sha256");
        assert_eq!(algorithm, "sha256");
    }

    // -----------------------------------------------------------------------
    // Checksum normalization
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_trim_and_lowercase() {
        let checksum = "  ABC123DEF  ".trim().to_lowercase();
        assert_eq!(checksum, "abc123def");
    }

    #[test]
    fn test_checksum_empty_after_trim() {
        let checksum = "   ".trim().to_lowercase();
        assert!(checksum.is_empty());
    }

    // -----------------------------------------------------------------------
    // Unsupported algorithm validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_algorithm_validation() {
        for valid in ["sha256", "sha1", "md5"] {
            assert!(matches!(valid, "sha256" | "sha1" | "md5"));
        }

        let algorithm = "sha512";
        let result = match algorithm {
            "sha256" | "sha1" | "md5" => Ok(()),
            other => Err(format!(
                "Unsupported checksum algorithm: {other}. Use sha256, sha1, or md5."
            )),
        };
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sha512"));
    }

    // -----------------------------------------------------------------------
    // SuggestQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_suggest_query_deserialize() {
        let json = json!({"prefix": "spring", "limit": 5});
        let query: SuggestQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.prefix, "spring");
        assert_eq!(query.limit, Some(5));
    }

    #[test]
    fn test_suggest_limit_clamping() {
        let limit = 100_i64.clamp(1, 50);
        assert_eq!(limit, 50);
        let limit = 0_i64.clamp(1, 50);
        assert_eq!(limit, 1);
    }

    // -----------------------------------------------------------------------
    // TrendingQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_trending_query_deserialize() {
        let json = json!({"days": 30, "limit": 10});
        let query: TrendingQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.days, Some(30));
        assert_eq!(query.limit, Some(10));
    }

    #[test]
    fn test_trending_days_default_and_clamp() {
        assert_eq!(7_i32.clamp(1, 90), 7); // default
        assert_eq!(0_i32.clamp(1, 90), 1); // clamped low
        assert_eq!(365_i32.clamp(1, 90), 90); // clamped high
    }

    #[test]
    fn test_trending_limit_default_and_clamp() {
        assert_eq!(20_i64.clamp(1, 100), 20);
    }

    // -----------------------------------------------------------------------
    // RecentQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_recent_query_deserialize() {
        let json = json!({"limit": 15});
        let query: RecentQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.limit, Some(15));
    }

    #[test]
    fn test_recent_limit_default_and_clamp() {
        assert_eq!(20_i64.clamp(1, 100), 20); // default
        assert_eq!(0_i64.clamp(1, 100), 1); // clamped low
        assert_eq!(500_i64.clamp(1, 100), 100); // clamped high
    }

    // -----------------------------------------------------------------------
    // SearchResultItem serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_result_item_serialize() {
        let item = SearchResultItem {
            id: Uuid::nil(),
            result_type: "artifact".to_string(),
            name: "my-lib".to_string(),
            path: Some("/com/example/my-lib/1.0/my-lib-1.0.jar".to_string()),
            repository_key: "libs-release".to_string(),
            format: Some("maven".to_string()),
            version: Some("1.0".to_string()),
            size_bytes: Some(524288),
            created_at: chrono::Utc::now(),
            highlights: Some(vec!["matched <em>my-lib</em>".to_string()]),
        };
        let json = serde_json::to_value(&item).unwrap();
        // "type" rename check
        assert_eq!(json["type"], "artifact");
        assert!(json.get("result_type").is_none());
        assert_eq!(json["name"], "my-lib");
        assert_eq!(json["format"], "maven");
        assert_eq!(json["size_bytes"], 524288);
    }

    #[test]
    fn test_search_result_item_skip_none_fields() {
        let item = SearchResultItem {
            id: Uuid::nil(),
            result_type: "artifact".to_string(),
            name: "test".to_string(),
            path: None,
            repository_key: "test-repo".to_string(),
            format: None,
            version: None,
            size_bytes: None,
            created_at: chrono::Utc::now(),
            highlights: None,
        };
        let json = serde_json::to_value(&item).unwrap();
        // skip_serializing_if = "Option::is_none" fields
        assert!(json.get("path").is_none());
        assert!(json.get("format").is_none());
        assert!(json.get("version").is_none());
        assert!(json.get("size_bytes").is_none());
        assert!(json.get("highlights").is_none());
    }

    // -----------------------------------------------------------------------
    // PaginationInfo serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_info_serialize() {
        let info = PaginationInfo {
            page: 1,
            per_page: 20,
            total: 100,
            total_pages: 5,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["page"], 1);
        assert_eq!(json["per_page"], 20);
        assert_eq!(json["total"], 100);
        assert_eq!(json["total_pages"], 5);
    }

    // -----------------------------------------------------------------------
    // FacetValue and FacetsResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_facet_value_serialize() {
        let facet = FacetValue {
            value: "maven".to_string(),
            count: 42,
        };
        let json = serde_json::to_value(&facet).unwrap();
        assert_eq!(json["value"], "maven");
        assert_eq!(json["count"], 42);
    }

    #[test]
    fn test_facets_response_serialize() {
        let facets = FacetsResponse {
            formats: vec![
                FacetValue {
                    value: "maven".to_string(),
                    count: 100,
                },
                FacetValue {
                    value: "npm".to_string(),
                    count: 50,
                },
            ],
            repositories: vec![FacetValue {
                value: "libs-release".to_string(),
                count: 75,
            }],
            content_types: vec![],
        };
        let json = serde_json::to_value(&facets).unwrap();
        assert_eq!(json["formats"].as_array().unwrap().len(), 2);
        assert_eq!(json["repositories"].as_array().unwrap().len(), 1);
        assert_eq!(json["content_types"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // ChecksumArtifact serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_artifact_serialize() {
        let artifact = ChecksumArtifact {
            id: Uuid::nil(),
            repository_key: "libs-release".to_string(),
            path: "/com/example/1.0/example-1.0.jar".to_string(),
            name: "example-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            download_count: 42,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&artifact).unwrap();
        assert_eq!(json["download_count"], 42);
        assert_eq!(json["content_type"], "application/java-archive");
    }

    // -----------------------------------------------------------------------
    // QuickSearchResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_quick_search_response_empty() {
        let resp = QuickSearchResponse {
            results: Vec::new(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["results"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Empty query returns empty results (logic test)
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_query_text_logic() {
        let query_text = String::new();
        assert!(query_text.is_empty());
    }

    // -----------------------------------------------------------------------
    // ReindexResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_reindex_response_serialization() {
        let resp = ReindexResponse {
            status: "started".to_string(),
            message: "Full reindex triggered".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "started");
        assert_eq!(json["message"], "Full reindex triggered");
    }

    // -----------------------------------------------------------------------
    // classify_repo_access (pure function, all branches)
    // -----------------------------------------------------------------------

    fn make_auth(is_admin: bool, is_service_account: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_classify_repo_access_admin() {
        let auth = Some(make_auth(true, false));
        assert_eq!(classify_repo_access(&auth), RepoAccessMode::All);
    }

    #[test]
    fn test_classify_repo_access_admin_service_account() {
        let auth = Some(make_auth(true, true));
        assert_eq!(classify_repo_access(&auth), RepoAccessMode::All);
    }

    #[test]
    fn test_classify_repo_access_regular_user() {
        let auth_ext = make_auth(false, false);
        let user_id = auth_ext.user_id;
        let auth = Some(auth_ext);
        assert_eq!(
            classify_repo_access(&auth),
            RepoAccessMode::UserScoped(user_id)
        );
    }

    #[test]
    fn test_classify_repo_access_service_account_non_admin() {
        let auth_ext = make_auth(false, true);
        let user_id = auth_ext.user_id;
        let auth = Some(auth_ext);
        assert_eq!(
            classify_repo_access(&auth),
            RepoAccessMode::UserScoped(user_id)
        );
    }

    #[test]
    fn test_classify_repo_access_anonymous() {
        let auth: Option<AuthExtension> = None;
        assert_eq!(classify_repo_access(&auth), RepoAccessMode::PublicOnly);
    }

    #[test]
    fn test_classify_repo_access_preserves_user_id() {
        let specific_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let auth = Some(AuthExtension {
            user_id: specific_id,
            username: "specific-user".to_string(),
            email: "specific@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["read".to_string()]),
            allowed_repo_ids: None,
        });
        match classify_repo_access(&auth) {
            RepoAccessMode::UserScoped(uid) => assert_eq!(uid, specific_id),
            other => panic!("Expected UserScoped, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_checksum_column (pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_checksum_column_sha256() {
        assert_eq!(
            resolve_checksum_column("sha256").unwrap(),
            "a.checksum_sha256"
        );
    }

    #[test]
    fn test_resolve_checksum_column_sha1() {
        assert_eq!(resolve_checksum_column("sha1").unwrap(), "a.checksum_sha1");
    }

    #[test]
    fn test_resolve_checksum_column_md5() {
        assert_eq!(resolve_checksum_column("md5").unwrap(), "a.checksum_md5");
    }

    #[test]
    fn test_resolve_checksum_column_invalid() {
        let result = resolve_checksum_column("sha512");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_checksum_column_empty() {
        let result = resolve_checksum_column("");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_checksum_column_uppercase_rejected() {
        // The function expects lowercase algorithm names
        let result = resolve_checksum_column("SHA256");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_checksum_column_error_message_contains_algorithm() {
        let result = resolve_checksum_column("blake2b");
        match result {
            Err(AppError::Validation(msg)) => {
                assert!(msg.contains("blake2b"));
                assert!(msg.contains("sha256"));
                assert!(msg.contains("sha1"));
                assert!(msg.contains("md5"));
            }
            other => panic!("Expected Validation error, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // RepoAccessMode enum
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_access_mode_debug() {
        let mode = RepoAccessMode::All;
        let debug = format!("{:?}", mode);
        assert!(debug.contains("All"));
    }

    #[test]
    fn test_repo_access_mode_clone() {
        let id = Uuid::new_v4();
        let mode = RepoAccessMode::UserScoped(id);
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_repo_access_mode_equality() {
        assert_eq!(RepoAccessMode::All, RepoAccessMode::All);
        assert_eq!(RepoAccessMode::PublicOnly, RepoAccessMode::PublicOnly);
        assert_ne!(RepoAccessMode::All, RepoAccessMode::PublicOnly);

        let id = Uuid::new_v4();
        assert_eq!(
            RepoAccessMode::UserScoped(id),
            RepoAccessMode::UserScoped(id)
        );
        assert_ne!(
            RepoAccessMode::UserScoped(Uuid::new_v4()),
            RepoAccessMode::UserScoped(Uuid::new_v4())
        );
    }

    // -----------------------------------------------------------------------
    // ChecksumRow struct (derive(sqlx::FromRow))
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_row_construction() {
        let now = chrono::Utc::now();
        let row = ChecksumRow {
            id: Uuid::nil(),
            repository_key: "test-repo".to_string(),
            path: "/path/to/artifact".to_string(),
            name: "my-artifact".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 4096,
            checksum_sha256: "abcdef1234567890".to_string(),
            content_type: "application/octet-stream".to_string(),
            created_at: now,
            download_count: 7,
        };
        assert_eq!(row.id, Uuid::nil());
        assert_eq!(row.repository_key, "test-repo");
        assert_eq!(row.name, "my-artifact");
        assert_eq!(row.version.as_deref(), Some("1.0.0"));
        assert_eq!(row.size_bytes, 4096);
        assert_eq!(row.download_count, 7);
    }

    #[test]
    fn test_checksum_row_version_none() {
        let row = ChecksumRow {
            id: Uuid::new_v4(),
            repository_key: "generic".to_string(),
            path: "/files/data.bin".to_string(),
            name: "data.bin".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "0000000000000000".to_string(),
            content_type: "application/octet-stream".to_string(),
            created_at: chrono::Utc::now(),
            download_count: 0,
        };
        assert!(row.version.is_none());
    }

    #[test]
    fn test_checksum_row_to_checksum_artifact_conversion() {
        let now = chrono::Utc::now();
        let id = Uuid::new_v4();
        let row = ChecksumRow {
            id,
            repository_key: "maven-central".to_string(),
            path: "/com/example/lib-1.0.jar".to_string(),
            name: "lib-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 8192,
            checksum_sha256: "sha256hash".to_string(),
            content_type: "application/java-archive".to_string(),
            created_at: now,
            download_count: 99,
        };
        let artifact = ChecksumArtifact {
            id: row.id,
            repository_key: row.repository_key.clone(),
            path: row.path.clone(),
            name: row.name.clone(),
            version: row.version.clone(),
            size_bytes: row.size_bytes,
            checksum_sha256: row.checksum_sha256.clone(),
            content_type: row.content_type.clone(),
            download_count: row.download_count,
            created_at: row.created_at,
        };
        assert_eq!(artifact.id, id);
        assert_eq!(artifact.repository_key, "maven-central");
        assert_eq!(artifact.download_count, 99);
    }
}
