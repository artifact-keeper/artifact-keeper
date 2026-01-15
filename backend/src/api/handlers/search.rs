//! Search handlers.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::Result;
use crate::services::search_service::{SearchQuery, SearchService};

/// Create search routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/artifacts", get(search_artifacts))
        .route("/suggest", get(suggest))
        .route("/trending", get(trending))
        .route("/recent", get(recent))
}

#[derive(Debug, Deserialize)]
pub struct SearchArtifactsQuery {
    /// Full-text search query
    pub q: Option<String>,

    /// Filter by format
    pub format: Option<String>,

    /// Filter by name pattern (supports wildcards)
    pub name: Option<String>,

    /// Page number (1-indexed)
    pub page: Option<u32>,

    /// Results per page (max 100)
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SearchResultResponse {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub format: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
    pub download_count: i64,
    pub score: f32,
}

#[derive(Debug, Serialize)]
pub struct FacetResponse {
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct FacetsResponse {
    pub formats: Vec<FacetResponse>,
    pub repositories: Vec<FacetResponse>,
    pub content_types: Vec<FacetResponse>,
}

#[derive(Debug, Serialize)]
pub struct SearchResultsResponse {
    pub items: Vec<SearchResultResponse>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
    pub facets: FacetsResponse,
}

/// Search artifacts across repositories
pub async fn search_artifacts(
    State(state): State<SharedState>,
    Query(query): Query<SearchArtifactsQuery>,
) -> Result<Json<SearchResultsResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let search_query = SearchQuery {
        q: query.q.clone(),
        format: query.format.clone(),
        name: query.name.clone(),
        offset: Some(offset),
        limit: Some(per_page as i64),
    };

    let service = SearchService::new(state.db.clone());
    let response = service.search(search_query).await?;

    let total_pages = ((response.total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(SearchResultsResponse {
        items: response
            .items
            .into_iter()
            .map(|r| SearchResultResponse {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score,
            })
            .collect(),
        total: response.total,
        page,
        per_page,
        total_pages,
        facets: FacetsResponse {
            formats: response
                .facets
                .formats
                .into_iter()
                .map(|f| FacetResponse {
                    value: f.value,
                    count: f.count,
                })
                .collect(),
            repositories: response
                .facets
                .repositories
                .into_iter()
                .map(|f| FacetResponse {
                    value: f.value,
                    count: f.count,
                })
                .collect(),
            content_types: response
                .facets
                .content_types
                .into_iter()
                .map(|f| FacetResponse {
                    value: f.value,
                    count: f.count,
                })
                .collect(),
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct SuggestQuery {
    pub prefix: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SuggestResponse {
    pub suggestions: Vec<String>,
}

/// Get search suggestions
pub async fn suggest(
    State(state): State<SharedState>,
    Query(query): Query<SuggestQuery>,
) -> Result<Json<SuggestResponse>> {
    let limit = query.limit.unwrap_or(10).min(50);

    let service = SearchService::new(state.db.clone());
    let suggestions = service.suggest(&query.prefix, limit).await?;

    Ok(Json(SuggestResponse { suggestions }))
}

#[derive(Debug, Deserialize)]
pub struct TrendingQuery {
    pub days: Option<i32>,
    pub limit: Option<i64>,
}

/// Get trending artifacts
pub async fn trending(
    State(state): State<SharedState>,
    Query(query): Query<TrendingQuery>,
) -> Result<Json<Vec<SearchResultResponse>>> {
    let days = query.days.unwrap_or(7).max(1).min(90);
    let limit = query.limit.unwrap_or(20).min(100);

    let service = SearchService::new(state.db.clone());
    let results = service.trending(days, limit).await?;

    Ok(Json(
        results
            .into_iter()
            .map(|r| SearchResultResponse {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct RecentQuery {
    pub limit: Option<i64>,
}

/// Get recently added artifacts
pub async fn recent(
    State(state): State<SharedState>,
    Query(query): Query<RecentQuery>,
) -> Result<Json<Vec<SearchResultResponse>>> {
    let limit = query.limit.unwrap_or(20).min(100);

    let service = SearchService::new(state.db.clone());
    let results = service.recent(limit).await?;

    Ok(Json(
        results
            .into_iter()
            .map(|r| SearchResultResponse {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score,
            })
            .collect(),
    ))
}
