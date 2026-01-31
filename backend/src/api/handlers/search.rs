//! Search handlers.
//!
//! Provides quick search, advanced search, checksum lookup, suggestions,
//! trending, and recent artifact endpoints. Uses Meilisearch when available,
//! falling back to PostgreSQL full-text search.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::search_service::{SearchQuery, SearchService};

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
// Shared response types
// ---------------------------------------------------------------------------

/// A unified search result matching the frontend `SearchResult` interface.
#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct FacetValue {
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct FacetsResponse {
    pub formats: Vec<FacetValue>,
    pub repositories: Vec<FacetValue>,
    pub content_types: Vec<FacetValue>,
}

// ---------------------------------------------------------------------------
// GET /search/quick?q=&limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QuickSearchQuery {
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub types: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QuickSearchResponse {
    pub results: Vec<SearchResultItem>,
}

pub async fn quick_search(
    State(state): State<SharedState>,
    Query(params): Query<QuickSearchQuery>,
) -> Result<Json<QuickSearchResponse>> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let query_text = params.q.unwrap_or_default();

    if query_text.is_empty() {
        return Ok(Json(QuickSearchResponse {
            results: Vec::new(),
        }));
    }

    let search_query = SearchQuery {
        q: Some(query_text),
        format: None,
        name: None,
        offset: Some(0),
        limit: Some(limit),
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct AdvancedSearchResponse {
    pub items: Vec<SearchResultItem>,
    pub pagination: PaginationInfo,
    pub facets: FacetsResponse,
}

pub async fn advanced_search(
    State(state): State<SharedState>,
    Query(params): Query<AdvancedSearchQuery>,
) -> Result<Json<AdvancedSearchResponse>> {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * per_page) as i64;

    let search_query = SearchQuery {
        q: params.query.clone(),
        format: params.format.clone(),
        name: params.name.clone(),
        offset: Some(offset),
        limit: Some(per_page as i64),
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

#[derive(Debug, Deserialize)]
pub struct ChecksumQuery {
    pub checksum: String,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct ChecksumSearchResponse {
    pub artifacts: Vec<ChecksumArtifact>,
}

pub async fn checksum_search(
    State(state): State<SharedState>,
    Query(params): Query<ChecksumQuery>,
) -> Result<Json<ChecksumSearchResponse>> {
    let algorithm = params.algorithm.as_deref().unwrap_or("sha256");
    let checksum = params.checksum.trim().to_lowercase();

    if checksum.is_empty() {
        return Ok(Json(ChecksumSearchResponse {
            artifacts: Vec::new(),
        }));
    }

    let artifacts = match algorithm {
        "sha256" => {
            sqlx::query_as!(
                ChecksumRow,
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
                    ) AS "download_count!"
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND a.checksum_sha256 = $1
                ORDER BY a.created_at DESC
                "#,
                checksum
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        }
        "sha1" => {
            sqlx::query_as!(
                ChecksumRow,
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
                    ) AS "download_count!"
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND a.checksum_sha1 = $1
                ORDER BY a.created_at DESC
                "#,
                checksum
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        }
        "md5" => {
            sqlx::query_as!(
                ChecksumRow,
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
                    ) AS "download_count!"
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND a.checksum_md5 = $1
                ORDER BY a.created_at DESC
                "#,
                checksum
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        }
        other => {
            return Err(AppError::Validation(format!(
                "Unsupported checksum algorithm: {other}. Use sha256, sha1, or md5."
            )));
        }
    };

    let artifacts = artifacts
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

#[derive(Debug, Deserialize)]
pub struct SuggestQuery {
    pub prefix: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SuggestResponse {
    pub suggestions: Vec<String>,
}

pub async fn suggest(
    State(state): State<SharedState>,
    Query(params): Query<SuggestQuery>,
) -> Result<Json<SuggestResponse>> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);

    let service = SearchService::new(state.db.clone());
    let suggestions = service.suggest(&params.prefix, limit).await?;

    Ok(Json(SuggestResponse { suggestions }))
}

// ---------------------------------------------------------------------------
// GET /search/trending?days=&limit=
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TrendingQuery {
    pub days: Option<i32>,
    pub limit: Option<i64>,
}

pub async fn trending(
    State(state): State<SharedState>,
    Query(params): Query<TrendingQuery>,
) -> Result<Json<Vec<SearchResultItem>>> {
    let days = params.days.unwrap_or(7).clamp(1, 90);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let service = SearchService::new(state.db.clone());
    let results = service.trending(days, limit).await?;

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

#[derive(Debug, Deserialize)]
pub struct RecentQuery {
    pub limit: Option<i64>,
}

pub async fn recent(
    State(state): State<SharedState>,
    Query(params): Query<RecentQuery>,
) -> Result<Json<Vec<SearchResultItem>>> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let service = SearchService::new(state.db.clone());
    let results = service.recent(limit).await?;

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
