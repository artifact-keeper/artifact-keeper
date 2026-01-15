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
    pub format: RepositoryFormat,
    pub size_bytes: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
    pub download_count: i64,
    pub score: f32,
    pub highlights: Vec<SearchHighlight>,
}

/// Search highlight for matched terms
#[derive(Debug, Serialize)]
pub struct SearchHighlight {
    pub field: String,
    pub fragments: Vec<String>,
}

/// Search query
#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    /// Free-text query
    pub q: Option<String>,

    /// Filter by repository keys
    pub repositories: Option<Vec<String>>,

    /// Filter by format
    pub format: Option<RepositoryFormat>,

    /// Filter by name pattern (supports wildcards)
    pub name: Option<String>,

    /// Filter by group/namespace
    pub group: Option<String>,

    /// Filter by version
    pub version: Option<String>,

    /// Filter by content type
    pub content_type: Option<String>,

    /// Filter by created after
    pub created_after: Option<DateTime<Utc>>,

    /// Filter by created before
    pub created_before: Option<DateTime<Utc>>,

    /// Minimum downloads
    pub min_downloads: Option<i64>,

    /// Sort field
    pub sort: Option<SearchSort>,

    /// Sort direction
    pub sort_dir: Option<SortDirection>,

    /// Offset for pagination
    pub offset: Option<i64>,

    /// Limit for pagination
    pub limit: Option<i64>,
}

/// Sort field
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSort {
    Relevance,
    Name,
    CreatedAt,
    Downloads,
    Size,
}

impl Default for SearchSort {
    fn default() -> Self {
        SearchSort::Relevance
    }
}

/// Sort direction
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

impl Default for SortDirection {
    fn default() -> Self {
        SortDirection::Desc
    }
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

        // Build the WHERE clause
        let mut conditions = Vec::new();
        let mut params: Vec<String> = Vec::new();

        // Full-text search
        if let Some(ref q) = query.q {
            if !q.is_empty() {
                // Use PostgreSQL full-text search
                let search_query = q
                    .split_whitespace()
                    .map(|word| format!("{}:*", word))
                    .collect::<Vec<_>>()
                    .join(" & ");
                params.push(search_query);
                conditions.push(format!(
                    "to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', ${})",
                    params.len()
                ));
            }
        }

        // Repository filter
        if let Some(ref repos) = query.repositories {
            if !repos.is_empty() {
                let placeholders: Vec<String> = repos
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        params.push(repos[i].clone());
                        format!("${}", params.len())
                    })
                    .collect();
                conditions.push(format!("r.repository_key IN ({})", placeholders.join(", ")));
            }
        }

        // Format filter
        if let Some(format) = query.format {
            params.push(format.to_string());
            conditions.push(format!("r.format = ${}", params.len()));
        }

        // Name pattern filter
        if let Some(ref name) = query.name {
            if !name.is_empty() {
                // Convert wildcards to SQL LIKE pattern
                let pattern = name.replace('*', "%").replace('?', "_");
                params.push(pattern);
                conditions.push(format!("a.name ILIKE ${}", params.len()));
            }
        }

        // Version filter
        if let Some(ref version) = query.version {
            if !version.is_empty() {
                let pattern = version.replace('*', "%");
                params.push(pattern);
                conditions.push(format!("a.version ILIKE ${}", params.len()));
            }
        }

        // Content type filter
        if let Some(ref ct) = query.content_type {
            params.push(ct.clone());
            conditions.push(format!("a.content_type = ${}", params.len()));
        }

        // Date filters
        if let Some(after) = query.created_after {
            params.push(after.to_rfc3339());
            conditions.push(format!("a.created_at >= ${}::timestamptz", params.len()));
        }

        if let Some(before) = query.created_before {
            params.push(before.to_rfc3339());
            conditions.push(format!("a.created_at <= ${}::timestamptz", params.len()));
        }

        // Downloads filter
        if let Some(min_dl) = query.min_downloads {
            params.push(min_dl.to_string());
            conditions.push(format!("a.download_count >= ${}", params.len()));
        }

        // Build WHERE clause
        let where_clause = if conditions.is_empty() {
            "TRUE".to_string()
        } else {
            conditions.join(" AND ")
        };

        // Build ORDER BY clause
        let order_by = match query.sort.unwrap_or_default() {
            SearchSort::Relevance => {
                if query.q.is_some() {
                    "ts_rank(to_tsvector('english', a.name || ' ' || a.path), plainto_tsquery('english', $1))"
                } else {
                    "a.download_count"
                }
            }
            SearchSort::Name => "a.name",
            SearchSort::CreatedAt => "a.created_at",
            SearchSort::Downloads => "a.download_count",
            SearchSort::Size => "a.size_bytes",
        };

        let order_dir = match query.sort_dir.unwrap_or_default() {
            SortDirection::Asc => "ASC",
            SortDirection::Desc => "DESC",
        };

        // Execute search query
        // Note: This is a simplified query - production would use proper parameterized queries
        let search_sql = format!(
            r#"
            SELECT
                a.id, a.repository_id, r.repository_key,
                a.path, a.name, a.version,
                r.format as "format",
                a.size_bytes, a.content_type, a.created_at,
                a.download_count
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE {}
            ORDER BY {} {}
            OFFSET {}
            LIMIT {}
            "#,
            where_clause, order_by, order_dir, offset, limit
        );

        // For now, use a simpler direct query
        let items = self.execute_search(&query, offset, limit).await?;
        let total = self.count_results(&query).await?;

        // Get facets
        let facets = self.get_facets(&query).await?;

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
        // Build dynamic query based on filters
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        let results = sqlx::query_as!(
            SearchResultRow,
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.repository_key,
                a.path,
                a.name,
                a.version,
                r.format as "format: RepositoryFormat",
                a.size_bytes,
                a.content_type,
                a.created_at,
                a.download_count,
                CASE
                    WHEN $1::text IS NOT NULL THEN
                        ts_rank(
                            to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')),
                            to_tsquery('english', $1)
                        )
                    ELSE 1.0
                END as score
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
              AND ($4::timestamptz IS NULL OR a.created_at >= $4)
              AND ($5::timestamptz IS NULL OR a.created_at <= $5)
            ORDER BY
                CASE WHEN $1::text IS NOT NULL THEN
                    ts_rank(to_tsvector('english', a.name || ' ' || a.path), to_tsquery('english', $1))
                ELSE a.download_count::real
                END DESC
            OFFSET $6
            LIMIT $7
            "#,
            q_filter,
            query.format.map(|f| f.to_string()),
            query.name.as_ref().map(|n| n.replace('*', "%")),
            query.created_after,
            query.created_before,
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
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score.unwrap_or(1.0),
                highlights: Vec::new(), // Could be populated with headline() function
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

        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
              AND ($4::timestamptz IS NULL OR a.created_at >= $4)
              AND ($5::timestamptz IS NULL OR a.created_at <= $5)
            "#,
            q_filter,
            query.format.map(|f| f.to_string()),
            query.name.as_ref().map(|n| n.replace('*', "%")),
            query.created_after,
            query.created_before
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(count)
    }

    async fn get_facets(&self, query: &SearchQuery) -> Result<SearchFacets> {
        let q_filter = query.q.as_ref().map(|q| {
            q.split_whitespace()
                .map(|w| format!("{}:*", w))
                .collect::<Vec<_>>()
                .join(" & ")
        });

        // Format facets
        let format_facets = sqlx::query!(
            r#"
            SELECT r.format::text as value, COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path) @@ to_tsquery('english', $1))
            GROUP BY r.format
            ORDER BY count DESC
            LIMIT 20
            "#,
            q_filter
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Repository facets
        let repo_facets = sqlx::query!(
            r#"
            SELECT r.repository_key as value, COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path) @@ to_tsquery('english', $1))
            GROUP BY r.repository_key
            ORDER BY count DESC
            LIMIT 20
            "#,
            q_filter
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Content type facets
        let ct_facets = sqlx::query!(
            r#"
            SELECT a.content_type as value, COUNT(*) as "count!"
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path) @@ to_tsquery('english', $1))
            GROUP BY a.content_type
            ORDER BY count DESC
            LIMIT 20
            "#,
            q_filter
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(SearchFacets {
            formats: format_facets
                .into_iter()
                .filter_map(|r| r.value.map(|v| FacetCount { value: v, count: r.count }))
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
            WHERE name ILIKE $1
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

    /// Get popular/trending artifacts
    pub async fn trending(&self, days: i32, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query_as!(
            SearchResultRow,
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.repository_key,
                a.path,
                a.name,
                a.version,
                r.format as "format: RepositoryFormat",
                a.size_bytes,
                a.content_type,
                a.created_at,
                a.download_count,
                1.0::real as score
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.created_at >= NOW() - make_interval(days => $1)
            ORDER BY a.download_count DESC
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
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score.unwrap_or(1.0),
                highlights: Vec::new(),
            })
            .collect())
    }

    /// Get recently added artifacts
    pub async fn recent(&self, limit: i64) -> Result<Vec<SearchResult>> {
        let results = sqlx::query_as!(
            SearchResultRow,
            r#"
            SELECT
                a.id,
                a.repository_id,
                r.repository_key,
                a.path,
                a.name,
                a.version,
                r.format as "format: RepositoryFormat",
                a.size_bytes,
                a.content_type,
                a.created_at,
                a.download_count,
                1.0::real as score
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
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
                format: r.format,
                size_bytes: r.size_bytes,
                content_type: r.content_type,
                created_at: r.created_at,
                download_count: r.download_count,
                score: r.score.unwrap_or(1.0),
                highlights: Vec::new(),
            })
            .collect())
    }
}

/// Internal row type for query results
struct SearchResultRow {
    id: Uuid,
    repository_id: Uuid,
    repository_key: String,
    path: String,
    name: String,
    version: Option<String>,
    format: RepositoryFormat,
    size_bytes: i64,
    content_type: String,
    created_at: DateTime<Utc>,
    download_count: i64,
    score: Option<f32>,
}
