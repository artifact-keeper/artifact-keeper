//! Search service for artifact discovery.
//!
//! Provides full-text search across artifacts with faceted filtering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::RepositoryFormat;

/// Search result item
#[derive(Debug, Serialize)]
pub struct SearchResult {
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

/// Search query
#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    /// Free-text query
    pub q: Option<String>,
    /// Filter by format
    pub format: Option<String>,
    /// Filter by name pattern
    pub name: Option<String>,
    /// Offset for pagination
    pub offset: Option<i64>,
    /// Limit for pagination
    pub limit: Option<i64>,
}

/// Search response with pagination and facets
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub items: Vec<SearchResult>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
    pub facets: SearchFacets,
}

/// Faceted search counts
#[derive(Debug, Serialize, Default)]
pub struct SearchFacets {
    pub formats: Vec<FacetCount>,
    pub repositories: Vec<FacetCount>,
    pub content_types: Vec<FacetCount>,
}

/// Count for a facet value
#[derive(Debug, Serialize)]
pub struct FacetCount {
    pub value: String,
    pub count: i64,
}

/// Search service
pub struct SearchService {
    db: PgPool,
}

impl SearchService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Execute a search query
    pub async fn search(&self, query: SearchQuery) -> Result<SearchResponse> {
        let offset = query.offset.unwrap_or(0).max(0);
        let limit = query.limit.unwrap_or(20).min(100).max(1);

        let items = self.execute_search(&query, offset, limit).await?;
        let total = self.count_results(&query).await?;
        let facets = self.get_facets().await?;

        Ok(SearchResponse {
            items,
            total,
            offset,
            limit,
            facets,
        })
    }

    async fn execute_search(
        &self,
        query: &SearchQuery,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<SearchResult>> {
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        let name_filter = query.name.as_ref().map(|n| n.replace('*', "%"));

        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) as "download_count!",
                1.0::real as score
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
            ORDER BY a.created_at DESC
            OFFSET $4
            LIMIT $5
            "#,
            q_filter,
            query.format,
            name_filter,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score.unwrap_or(1.0),
            })
            .collect())
    }

    async fn count_results(&self, query: &SearchQuery) -> Result<i64> {
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        let name_filter = query.name.as_ref().map(|n| n.replace('*', "%"));

        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
            "#,
            q_filter,
            query.format,
            name_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(count)
    }

    async fn get_facets(&self) -> Result<SearchFacets> {
        // Format facets
        let format_facets = sqlx::query!(
            r#"
            SELECT r.format::text as "value!", COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            GROUP BY r.format
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Repository facets
        let repo_facets = sqlx::query!(
            r#"
            SELECT r.key as "value!", COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            GROUP BY r.key
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Content type facets
        let ct_facets = sqlx::query!(
            r#"
            SELECT a.content_type as "value!", COUNT(*) as "count!"
            FROM artifacts a
            WHERE a.is_deleted = false
            GROUP BY a.content_type
            ORDER BY 2 DESC
            LIMIT 20
            "#
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(SearchFacets {
            formats: format_facets
                .into_iter()
                .map(|r| FacetCount { value: r.value, count: r.count })
                .collect(),
            repositories: repo_facets
                .into_iter()
                .map(|r| FacetCount { value: r.value, count: r.count })
                .collect(),
            content_types: ct_facets
                .into_iter()
                .map(|r| FacetCount { value: r.value, count: r.count })
                .collect(),
        })
    }

    /// Suggest completions for search terms
    pub async fn suggest(&self, prefix: &str, limit: i64) -> Result<Vec<String>> {
        let pattern = format!("{}%", prefix);

        let suggestions = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT name
            FROM artifacts
            WHERE name ILIKE $1 AND is_deleted = false
            ORDER BY name
            LIMIT $2
            "#,
            pattern,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(suggestions)
    }

    /// Get trending artifacts (most downloaded recently)
    pub async fn trending(&self, days: i32, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COUNT(ds.id) as "download_count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN download_statistics ds ON ds.artifact_id = a.id
                AND ds.downloaded_at >= NOW() - make_interval(days => $1)
            WHERE a.is_deleted = false
            GROUP BY a.id, r.id
            ORDER BY 11 DESC
            LIMIT $2
            "#,
            days,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: 1.0,
            })
            .collect())
    }

    /// Get recently added artifacts
    pub async fn recent(&self, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query!(
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.key as repository_key,
                a.path,
                a.name,
                a.version,
                r.format::text as format,
                a.size_bytes,
                a.content_type,
                a.created_at,
                COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) as "download_count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
            ORDER BY a.created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                repository_id: r.repository_id,
                repository_key: r.repository_key,
                path: r.path,
                name: r.name,
                version: r.version,
                format: r.format.unwrap_or_default(),
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: 1.0,
            })
            .collect())
    }
}
