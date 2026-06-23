//! Search service for artifact discovery.
//!
//! Provides full-text search across artifacts with faceted filtering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

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
    /// When true, only return results from public repositories.
    #[serde(default)]
    pub public_only: bool,
    /// Repository IDs the caller is allowed to see. `None` means no filter
    /// (admin or unrestricted). `Some(ids)` restricts results to those repos.
    /// When set, `public_only` is ignored because this list already encodes
    /// the correct visibility.
    #[serde(skip)]
    pub accessible_repo_ids: Option<Vec<Uuid>>,
    /// Sort field. Accepted values: `created_at` (default), `name`, `size`
    /// (alias: `size_bytes`), `downloads` (alias: `download_count`).
    /// Unknown values are rejected with HTTP 400 VALIDATION_ERROR so typos
    /// surface visibly instead of silently downgrading to `created_at`.
    pub sort_by: Option<String>,
    /// Sort direction: `asc` or `desc`. Default is `desc`. Honored for every
    /// supported sort field. The previous implementation hardcoded `desc`
    /// when the size sort branch was added, which is the bug fixed here.
    pub sort_order: Option<String>,
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

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Build a PostgreSQL full-text search query from a free-text input.
///
/// Each whitespace-separated word is sanitized to a bare lexeme, gets a `:*`
/// prefix-match suffix, and words are joined with `&` (AND).  Returns None if
/// the input is None.
///
/// The resulting string is fed to the strict `to_tsquery('english', $1)`, which
/// treats `& | ! ( ) : *` as operators and raises a SQL error on any malformed
/// expression.  Because the input is free user text, each token is reduced to an
/// allowlisted lexeme (ASCII alphanumeric plus the package-name characters
/// `_ - . @ / +`) before the `:*` prefix marker is appended.  Tokens that
/// sanitize to empty are dropped.  This guarantees the bound `$1` is always a
/// syntactically valid (or empty) tsquery, so `to_tsquery` never raises and an
/// all-metacharacter input returns an empty match instead of an HTTP 500.
pub(crate) fn build_tsquery_filter(q: Option<&str>) -> Option<String> {
    q.map(|q| {
        q.split_whitespace()
            .map(sanitize_tsquery_lexeme)
            .filter(|w| !w.is_empty())
            .map(|w| format!("{}:*", w))
            .collect::<Vec<_>>()
            .join(" & ")
    })
}

/// Reduce a single whitespace-delimited token to a bare tsquery lexeme by
/// keeping only allowlisted characters: ASCII alphanumeric plus the
/// package-name characters `_ - . @ / +`.  Every tsquery metacharacter
/// (`& | ! ( ) : *` and others) is stripped, so the result can never sit in
/// operator position and break `to_tsquery`.
fn sanitize_tsquery_lexeme(token: &str) -> String {
    token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '/' | '+'))
        .collect()
}

/// Convert a user-facing wildcard name filter (using `*`) to a SQL ILIKE
/// pattern (using `%`).  Returns None if the input is None.
pub(crate) fn build_name_filter(name: Option<&str>) -> Option<String> {
    name.map(|n| n.replace('*', "%"))
}

/// Normalize pagination offset: default 0, clamp to non-negative.
pub(crate) fn normalize_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).max(0)
}

/// Normalize pagination limit: default 20, clamp to `[1, 100]`.
pub(crate) fn normalize_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(20).clamp(1, 100)
}

/// Build the ILIKE pattern for suggest completions.
pub(crate) fn build_suggest_pattern(prefix: &str) -> String {
    format!("{}%", prefix)
}

/// Translate the user-facing `sort_by` and `sort_order` parameters into a
/// safe SQL ORDER BY clause.
///
/// This is a whitelist: only the explicitly enumerated `sort_by` values are
/// accepted. Anything else returns `AppError::Validation` so the API surfaces
/// `400 VALIDATION_ERROR` rather than silently downgrading to `created_at`
/// (the previous behavior made typos and not-yet-implemented fields look
/// identical to "no sort", which was a UX trap caught in PR #1384 review).
///
/// `None` still falls back to the default (`created_at DESC`); the strict
/// rejection only applies to non-empty, non-whitelisted values.
///
/// Because the return value is `&'static str`, no caller input is ever
/// spliced into the query string -- the SQL injection guard is structural.
///
/// Supported `sort_by` values:
/// - `created_at` (default when `None`)
/// - `name` -> `a.name`
/// - `size` / `size_bytes` -> `a.size_bytes`
/// - `downloads` -> the same correlated subquery that populates the
///   `download_count` column in `SELECT`. Ordering on a scalar subquery
///   expression is portable Postgres and avoids needing a CTE.
///
/// `sort_order` accepts `asc` / `desc` case-insensitively; any other value
/// (including `None`) defaults to `desc`. We are intentionally lenient on
/// `sort_order` because picking the "wrong" direction is harmless -- it
/// can't break SQL and it's obvious from the result ordering.
pub(crate) fn build_order_by_clause(
    sort_by: Option<&str>,
    sort_order: Option<&str>,
) -> Result<&'static str> {
    let asc = matches!(
        sort_order.map(str::to_ascii_lowercase).as_deref(),
        Some("asc")
    );
    let normalized = sort_by.map(str::to_ascii_lowercase);
    let clause = match normalized.as_deref() {
        // None or explicit "created_at" -> default sort.
        None | Some("created_at") => {
            if asc {
                "a.created_at ASC, a.id ASC"
            } else {
                "a.created_at DESC, a.id DESC"
            }
        }
        Some("name") => {
            if asc {
                "a.name ASC, a.id ASC"
            } else {
                "a.name DESC, a.id DESC"
            }
        }
        Some("size") | Some("size_bytes") => {
            if asc {
                "a.size_bytes ASC, a.id ASC"
            } else {
                "a.size_bytes DESC, a.id DESC"
            }
        }
        Some("downloads") | Some("download_count") => {
            // Mirror the COALESCE expression used in the SELECT list so the
            // sort key matches the column we report to the client. The
            // entire ORDER BY string is a compile-time `&'static str`, so
            // there is no injection surface here.
            if asc {
                "COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) ASC, a.id ASC"
            } else {
                "COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0) DESC, a.id DESC"
            }
        }
        Some(other) => {
            return Err(AppError::Validation(format!(
                "Unsupported sort_by value: {other:?}. Supported values: created_at, name, size, downloads."
            )));
        }
    };
    Ok(clause)
}

/// Row type returned by all search SQL queries (12 fields).
type SearchResultRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    i64,
    String,
    DateTime<Utc>,
    i64,
    f32,
);

/// Convert a database row tuple into a [`SearchResult`].
fn row_to_search_result(r: SearchResultRow) -> SearchResult {
    SearchResult {
        id: r.0,
        repository_id: r.1,
        repository_key: r.2,
        path: r.3,
        name: r.4,
        version: r.5,
        format: r.6.unwrap_or_default(),
        size_bytes: r.7,
        content_type: r.8,
        created_at: r.9,
        download_count: r.10,
        score: r.11,
    }
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
        let offset = normalize_offset(query.offset);
        let limit = normalize_limit(query.limit);

        let items = self.execute_search(&query, offset, limit).await?;
        let total = self.count_results(&query).await?;
        let facets = self
            .get_facets(query.accessible_repo_ids.as_deref(), query.public_only)
            .await?;

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
        let q_filter = build_tsquery_filter(query.q.as_deref());
        let name_filter = build_name_filter(query.name.as_deref());

        // The ORDER BY clause is built from a whitelisted helper, so it is
        // safe to splice into the SQL string. We never use the raw query
        // params here. Unknown `sort_by` returns AppError::Validation, which
        // surfaces as HTTP 400 VALIDATION_ERROR to the caller (PR #1384).
        let order_by =
            build_order_by_clause(query.sort_by.as_deref(), query.sort_order.as_deref())?;

        // When accessible_repo_ids is provided, filter by that list instead of
        // the coarse public_only flag. An empty list means "no repos visible"
        // (should not normally happen). None means "all repos" (admin).
        let sql = format!(
            r#"
                SELECT
                    a.id,
                    a.repository_id,
                    r.key,
                    a.path,
                    a.name,
                    a.version,
                    r.format::text,
                    a.size_bytes,
                    a.content_type,
                    a.created_at,
                    COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0)::BIGINT,
                    1.0::real
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
                  AND ($2::text IS NULL OR r.format::text = $2)
                  AND ($3::text IS NULL OR a.name ILIKE $3)
                  AND ($7::uuid[] IS NULL OR r.id = ANY($7))
                  AND ($6 = false OR r.is_public = true)
                ORDER BY {order_by}
                OFFSET $4
                LIMIT $5
                "#,
            order_by = order_by,
        );

        let rows: Vec<SearchResultRow> = sqlx::query_as(&sql)
            .bind(&q_filter)
            .bind(&query.format)
            .bind(&name_filter)
            .bind(offset)
            .bind(limit)
            .bind(query.public_only)
            .bind(&query.accessible_repo_ids)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(row_to_search_result).collect())
    }

    async fn count_results(&self, query: &SearchQuery) -> Result<i64> {
        let q_filter = build_tsquery_filter(query.q.as_deref());
        let name_filter = build_name_filter(query.name.as_deref());

        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::text IS NULL OR to_tsvector('english', a.name || ' ' || a.path || ' ' || COALESCE(a.version, '')) @@ to_tsquery('english', $1))
              AND ($2::text IS NULL OR r.format::text = $2)
              AND ($3::text IS NULL OR a.name ILIKE $3)
              AND ($5::uuid[] IS NULL OR r.id = ANY($5))
              AND ($4 = false OR r.is_public = true)
            "#,
        )
        .bind(&q_filter)
        .bind(&query.format)
        .bind(&name_filter)
        .bind(query.public_only)
        .bind(&query.accessible_repo_ids)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(count.0)
    }

    /// Fetch a single facet dimension (e.g. format, repository key, content type).
    ///
    /// `group_expr` is the SQL expression that appears in both SELECT and
    /// GROUP BY (e.g. `"r.format::text"` or `"a.content_type"`).
    async fn fetch_facet_counts(
        &self,
        group_expr: &str,
        accessible_repo_ids: Option<&[Uuid]>,
        public_only: bool,
    ) -> Result<Vec<FacetCount>> {
        let sql = format!(
            r#"
            SELECT {expr}, COUNT(*)::BIGINT
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.is_deleted = false
              AND ($1::uuid[] IS NULL OR r.id = ANY($1))
              AND ($2 = false OR r.is_public = true)
            GROUP BY {expr}
            ORDER BY 2 DESC
            LIMIT 20
            "#,
            expr = group_expr,
        );

        let rows: Vec<(String, i64)> = sqlx::query_as(&sql)
            .bind(accessible_repo_ids)
            .bind(public_only)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|(value, count)| FacetCount { value, count })
            .collect())
    }

    async fn get_facets(
        &self,
        accessible_repo_ids: Option<&[Uuid]>,
        public_only: bool,
    ) -> Result<SearchFacets> {
        let formats = self
            .fetch_facet_counts("r.format::text", accessible_repo_ids, public_only)
            .await?;
        let repositories = self
            .fetch_facet_counts("r.key", accessible_repo_ids, public_only)
            .await?;
        let content_types = self
            .fetch_facet_counts("a.content_type", accessible_repo_ids, public_only)
            .await?;

        Ok(SearchFacets {
            formats,
            repositories,
            content_types,
        })
    }

    /// Suggest completions for search terms, scoped to accessible repositories.
    pub async fn suggest(
        &self,
        prefix: &str,
        limit: i64,
        accessible_repo_ids: Option<&[Uuid]>,
        public_only: bool,
    ) -> Result<Vec<String>> {
        let pattern = build_suggest_pattern(prefix);

        let suggestions: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT a.name
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.name ILIKE $1 AND a.is_deleted = false
              AND ($3::uuid[] IS NULL OR r.id = ANY($3))
              AND ($4 = false OR r.is_public = true)
            ORDER BY a.name
            LIMIT $2
            "#,
        )
        .bind(&pattern)
        .bind(limit)
        .bind(accessible_repo_ids)
        .bind(public_only)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(suggestions.into_iter().map(|(name,)| name).collect())
    }

    /// Get trending artifacts (most downloaded recently)
    pub async fn trending(
        &self,
        days: i32,
        limit: i64,
        public_only: bool,
        accessible_repo_ids: Option<&[Uuid]>,
    ) -> Result<Vec<SearchResult>> {
        let rows: Vec<SearchResultRow> = sqlx::query_as(
            r#"
                SELECT
                    a.id,
                    a.repository_id,
                    r.key,
                    a.path,
                    a.name,
                    a.version,
                    r.format::text,
                    a.size_bytes,
                    a.content_type,
                    a.created_at,
                    COUNT(ds.id)::BIGINT,
                    1.0::real
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                LEFT JOIN download_statistics ds ON ds.artifact_id = a.id
                    AND ds.downloaded_at >= NOW() - make_interval(days => $1)
                WHERE a.is_deleted = false
                  AND ($4::uuid[] IS NULL OR r.id = ANY($4))
                  AND ($3 = false OR r.is_public = true)
                GROUP BY a.id, r.id
                ORDER BY 11 DESC
                LIMIT $2
                "#,
        )
        .bind(days)
        .bind(limit)
        .bind(public_only)
        .bind(accessible_repo_ids)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(row_to_search_result).collect())
    }

    /// Get recently added artifacts
    pub async fn recent(
        &self,
        limit: i64,
        public_only: bool,
        accessible_repo_ids: Option<&[Uuid]>,
    ) -> Result<Vec<SearchResult>> {
        let rows: Vec<SearchResultRow> = sqlx::query_as(
            r#"
                SELECT
                    a.id,
                    a.repository_id,
                    r.key,
                    a.path,
                    a.name,
                    a.version,
                    r.format::text,
                    a.size_bytes,
                    a.content_type,
                    a.created_at,
                    COALESCE((SELECT COUNT(*) FROM download_statistics ds WHERE ds.artifact_id = a.id), 0)::BIGINT,
                    1.0::real
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND ($3::uuid[] IS NULL OR r.id = ANY($3))
                  AND ($2 = false OR r.is_public = true)
                ORDER BY a.created_at DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .bind(public_only)
            .bind(accessible_repo_ids)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(row_to_search_result).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SearchQuery default and deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_default() {
        let query = SearchQuery::default();
        assert!(query.q.is_none());
        assert!(query.format.is_none());
        assert!(query.name.is_none());
        assert!(query.offset.is_none());
        assert!(query.limit.is_none());
        assert!(!query.public_only);
    }

    #[test]
    fn test_search_query_deserialization() {
        let json = r#"{"q": "my-artifact", "format": "maven", "offset": 10, "limit": 50}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.q.as_deref(), Some("my-artifact"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.offset, Some(10));
        assert_eq!(query.limit, Some(50));
        assert!(query.name.is_none());
    }

    #[test]
    fn test_search_query_deserialization_partial() {
        let json = r#"{"q": "test"}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.q.as_deref(), Some("test"));
        assert!(query.format.is_none());
        assert!(query.offset.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_search_query_deserialization_empty() {
        let json = r#"{}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(query.q.is_none());
    }

    #[test]
    fn test_search_query_with_name_filter() {
        let json = r#"{"name": "my-lib*"}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.name.as_deref(), Some("my-lib*"));
    }

    // -----------------------------------------------------------------------
    // normalize_offset (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_offset_none() {
        assert_eq!(normalize_offset(None), 0);
    }

    #[test]
    fn test_normalize_offset_negative() {
        assert_eq!(normalize_offset(Some(-5)), 0);
    }

    #[test]
    fn test_normalize_offset_positive() {
        assert_eq!(normalize_offset(Some(20)), 20);
    }

    #[test]
    fn test_normalize_offset_zero() {
        assert_eq!(normalize_offset(Some(0)), 0);
    }

    // -----------------------------------------------------------------------
    // normalize_limit (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_limit_none() {
        assert_eq!(normalize_limit(None), 20);
    }

    #[test]
    fn test_normalize_limit_zero() {
        assert_eq!(normalize_limit(Some(0)), 1);
    }

    #[test]
    fn test_normalize_limit_over_max() {
        assert_eq!(normalize_limit(Some(500)), 100);
    }

    #[test]
    fn test_normalize_limit_normal() {
        assert_eq!(normalize_limit(Some(50)), 50);
    }

    #[test]
    fn test_normalize_limit_negative() {
        assert_eq!(normalize_limit(Some(-10)), 1);
    }

    #[test]
    fn test_normalize_limit_boundary_one() {
        assert_eq!(normalize_limit(Some(1)), 1);
    }

    #[test]
    fn test_normalize_limit_boundary_hundred() {
        assert_eq!(normalize_limit(Some(100)), 100);
    }

    // -----------------------------------------------------------------------
    // build_tsquery_filter (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_tsquery_filter_single_word() {
        assert_eq!(
            build_tsquery_filter(Some("artifact")).as_deref(),
            Some("artifact:*")
        );
    }

    #[test]
    fn test_build_tsquery_filter_multiple_words() {
        assert_eq!(
            build_tsquery_filter(Some("my awesome artifact")).as_deref(),
            Some("my:* & awesome:* & artifact:*")
        );
    }

    #[test]
    fn test_build_tsquery_filter_none() {
        assert!(build_tsquery_filter(None).is_none());
    }

    #[test]
    fn test_build_tsquery_filter_empty_string() {
        // Empty string split by whitespace yields no tokens
        assert_eq!(build_tsquery_filter(Some("")).as_deref(), Some(""));
    }

    #[test]
    fn test_build_tsquery_filter_extra_whitespace() {
        assert_eq!(
            build_tsquery_filter(Some("  foo   bar  ")).as_deref(),
            Some("foo:* & bar:*")
        );
    }

    // -----------------------------------------------------------------------
    // build_tsquery_filter robustness (#1890): free text containing tsquery
    // metacharacters must produce a valid/empty tsquery, never a malformed one
    // that makes the strict to_tsquery raise -> AppError::Database -> HTTP 500.
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_tsquery_filter_all_operators_yields_empty() {
        // Every token is pure metacharacters -> sanitizes to empty -> dropped.
        assert_eq!(build_tsquery_filter(Some("& | ! ( )")).as_deref(), Some(""));
    }

    #[test]
    fn test_build_tsquery_filter_prefix_marker_token() {
        assert_eq!(build_tsquery_filter(Some(":*")).as_deref(), Some(""));
    }

    #[test]
    fn test_build_tsquery_filter_open_paren() {
        assert_eq!(build_tsquery_filter(Some("(")).as_deref(), Some(""));
    }

    #[test]
    fn test_build_tsquery_filter_strips_inline_operators() {
        // Trailing ":* &" and bare "bar" both sanitize to bare lexemes.
        assert_eq!(
            build_tsquery_filter(Some("foo:* & bar")).as_deref(),
            Some("foo:* & bar:*")
        );
    }

    #[test]
    fn test_build_tsquery_filter_ampersand_inside_token() {
        // "a&b" -> "ab" (metachar dropped), one prefix token.
        assert_eq!(build_tsquery_filter(Some("a&b")).as_deref(), Some("ab:*"));
    }

    #[test]
    fn test_build_tsquery_filter_keeps_package_name_chars() {
        // Allowlisted punctuation in real package names is preserved.
        assert_eq!(
            build_tsquery_filter(Some("spring-boot.v2")).as_deref(),
            Some("spring-boot.v2:*")
        );
        assert_eq!(
            build_tsquery_filter(Some("@scope/pkg")).as_deref(),
            Some("@scope/pkg:*")
        );
        assert_eq!(
            build_tsquery_filter(Some("1.2.0+build")).as_deref(),
            Some("1.2.0+build:*")
        );
    }

    #[test]
    fn test_build_tsquery_filter_metachars_produce_no_operators() {
        // General contract: an all-metacharacter input contains no parens,
        // no negation, and no dangling operator in the output.
        let out = build_tsquery_filter(Some("!(a:* | b) & ((")).unwrap();
        // Sanitized tokens: "a", "b" -> "a:* & b:*". No raw parens / "!".
        assert!(!out.contains('('));
        assert!(!out.contains(')'));
        assert!(!out.contains('!'));
        assert_eq!(out, "a:* & b:*");
    }

    // -----------------------------------------------------------------------
    // build_name_filter (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_name_filter_wildcard() {
        assert_eq!(
            build_name_filter(Some("my-lib*")).as_deref(),
            Some("my-lib%")
        );
    }

    #[test]
    fn test_build_name_filter_multiple_wildcards() {
        assert_eq!(
            build_name_filter(Some("*my*lib*")).as_deref(),
            Some("%my%lib%")
        );
    }

    #[test]
    fn test_build_name_filter_none() {
        assert!(build_name_filter(None).is_none());
    }

    #[test]
    fn test_build_name_filter_no_wildcard() {
        assert_eq!(
            build_name_filter(Some("exact-name")).as_deref(),
            Some("exact-name")
        );
    }

    // -----------------------------------------------------------------------
    // build_suggest_pattern (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_suggest_pattern_basic() {
        assert_eq!(build_suggest_pattern("my-lib"), "my-lib%");
    }

    #[test]
    fn test_build_suggest_pattern_empty() {
        assert_eq!(build_suggest_pattern(""), "%");
    }

    #[test]
    fn test_build_suggest_pattern_with_special_chars() {
        assert_eq!(build_suggest_pattern("@scope/pkg"), "@scope/pkg%");
    }

    // -----------------------------------------------------------------------
    // SearchResult construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_result_serialization() {
        let result = SearchResult {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "maven-central".to_string(),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib".to_string(),
            version: Some("1.0".to_string()),
            format: "maven".to_string(),
            size_bytes: 1024,
            content_type: "application/java-archive".to_string(),
            created_at: DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            download_count: 42,
            score: 1.0,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "lib");
        assert_eq!(json["version"], "1.0");
        assert_eq!(json["format"], "maven");
        assert_eq!(json["size_bytes"], 1024);
        assert_eq!(json["download_count"], 42);
        assert_eq!(json["score"], 1.0);
    }

    #[test]
    fn test_search_result_version_none() {
        let result = SearchResult {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            repository_key: "generic".to_string(),
            path: "files/readme.txt".to_string(),
            name: "readme.txt".to_string(),
            version: None,
            format: "generic".to_string(),
            size_bytes: 256,
            content_type: "text/plain".to_string(),
            created_at: Utc::now(),
            download_count: 0,
            score: 0.5,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["version"].is_null());
    }

    // -----------------------------------------------------------------------
    // SearchFacets
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_facets_default() {
        let facets = SearchFacets::default();
        assert!(facets.formats.is_empty());
        assert!(facets.repositories.is_empty());
        assert!(facets.content_types.is_empty());
    }

    #[test]
    fn test_facet_count_serialization() {
        let facet = FacetCount {
            value: "maven".to_string(),
            count: 100,
        };
        let json = serde_json::to_value(&facet).unwrap();
        assert_eq!(json["value"], "maven");
        assert_eq!(json["count"], 100);
    }

    // -----------------------------------------------------------------------
    // SearchResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_response_serialization() {
        let response = SearchResponse {
            items: vec![],
            total: 0,
            offset: 0,
            limit: 20,
            facets: SearchFacets::default(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["total"], 0);
        assert_eq!(json["offset"], 0);
        assert_eq!(json["limit"], 20);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Suggest pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_suggest_pattern_construction() {
        let prefix = "my-lib";
        let pattern = format!("{}%", prefix);
        assert_eq!(pattern, "my-lib%");
    }

    #[test]
    fn test_suggest_pattern_empty_prefix() {
        let prefix = "";
        let pattern = format!("{}%", prefix);
        assert_eq!(pattern, "%");
    }

    // -----------------------------------------------------------------------
    // public_only field behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_public_only_defaults_false() {
        let json = r#"{"q": "test"}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(!query.public_only);
    }

    #[test]
    fn test_search_query_public_only_explicit_true() {
        let json = r#"{"q": "test", "public_only": true}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(query.public_only);
    }

    #[test]
    fn test_search_query_public_only_explicit_false() {
        let json = r#"{"public_only": false}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(!query.public_only);
    }

    // -----------------------------------------------------------------------
    // row_to_search_result
    // -----------------------------------------------------------------------

    #[test]
    fn test_row_to_search_result_all_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let row: SearchResultRow = (
            id,
            repo_id,
            "my-repo".to_string(),
            "com/example/lib.jar".to_string(),
            "lib".to_string(),
            Some("1.0".to_string()),
            Some("maven".to_string()),
            2048,
            "application/java-archive".to_string(),
            now,
            10,
            0.95,
        );
        let result = row_to_search_result(row);
        assert_eq!(result.id, id);
        assert_eq!(result.repository_id, repo_id);
        assert_eq!(result.repository_key, "my-repo");
        assert_eq!(result.path, "com/example/lib.jar");
        assert_eq!(result.name, "lib");
        assert_eq!(result.version.as_deref(), Some("1.0"));
        assert_eq!(result.format, "maven");
        assert_eq!(result.size_bytes, 2048);
        assert_eq!(result.content_type, "application/java-archive");
        assert_eq!(result.created_at, now);
        assert_eq!(result.download_count, 10);
        assert!((result.score - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_row_to_search_result_none_format() {
        let row: SearchResultRow = (
            Uuid::nil(),
            Uuid::nil(),
            "repo".to_string(),
            "path".to_string(),
            "name".to_string(),
            None,
            None, // format is None
            0,
            "text/plain".to_string(),
            Utc::now(),
            0,
            1.0,
        );
        let result = row_to_search_result(row);
        assert_eq!(result.format, ""); // unwrap_or_default
        assert!(result.version.is_none());
    }

    // -----------------------------------------------------------------------
    // SearchQuery accessible_repo_ids field
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_accessible_repo_ids_default_none() {
        let query = SearchQuery::default();
        assert!(query.accessible_repo_ids.is_none());
    }

    #[test]
    fn test_search_query_accessible_repo_ids_skipped_in_deserialization() {
        // accessible_repo_ids has #[serde(skip)], so even if provided in JSON
        // it should not be deserialized.
        let json =
            r#"{"q": "test", "accessible_repo_ids": ["12345678-1234-1234-1234-123456789abc"]}"#;
        let query: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(query.accessible_repo_ids.is_none());
    }

    #[test]
    fn test_search_query_accessible_repo_ids_set_programmatically() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let query = SearchQuery {
            accessible_repo_ids: Some(vec![id1, id2]),
            ..Default::default()
        };
        let ids = query.accessible_repo_ids.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_search_query_accessible_repo_ids_empty_vec() {
        let query = SearchQuery {
            accessible_repo_ids: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(query.accessible_repo_ids.unwrap().len(), 0);
    }

    #[test]
    fn test_search_query_accessible_repo_ids_as_deref() {
        let id = Uuid::new_v4();
        let query = SearchQuery {
            accessible_repo_ids: Some(vec![id]),
            ..Default::default()
        };
        let slice: Option<&[Uuid]> = query.accessible_repo_ids.as_deref();
        assert_eq!(slice.unwrap().len(), 1);
        assert_eq!(slice.unwrap()[0], id);

        let empty_query = SearchQuery::default();
        assert!(empty_query.accessible_repo_ids.as_deref().is_none());
    }

    #[test]
    fn test_search_query_with_all_fields_and_accessible_repo_ids() {
        let id = Uuid::new_v4();
        let query = SearchQuery {
            q: Some("spring-boot".to_string()),
            format: Some("maven".to_string()),
            name: Some("spring*".to_string()),
            offset: Some(10),
            limit: Some(25),
            public_only: false,
            accessible_repo_ids: Some(vec![id]),
            sort_by: None,
            sort_order: None,
        };
        assert_eq!(query.q.as_deref(), Some("spring-boot"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.accessible_repo_ids.as_ref().unwrap().len(), 1);
        assert!(!query.public_only);
    }

    // -----------------------------------------------------------------------
    // build_order_by_clause -- regression for issue #1372 and PR #1384 review
    //
    // The previous SQL hardcoded `ORDER BY a.created_at DESC`, so passing
    // `sort_by=size&sort_order=asc` had no effect: the smallest artifact
    // never bubbled to the head of the results. These tests pin the
    // contract: every supported sort_by (including `downloads`) honors
    // sort_order, and unknown fields are now rejected with 400 instead of
    // silently downgrading to `created_at` (PR #1384 review).
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_order_by_default_is_created_at_desc() {
        let clause = build_order_by_clause(None, None).expect("default must be Ok");
        assert!(clause.contains("a.created_at"));
        assert!(clause.contains("DESC"));
        assert!(!clause.contains("ASC"));
    }

    #[test]
    fn test_build_order_by_created_at_asc() {
        let clause = build_order_by_clause(Some("created_at"), Some("asc")).unwrap();
        assert!(clause.contains("a.created_at"));
        assert!(clause.contains("ASC"));
    }

    #[test]
    fn test_build_order_by_size_desc() {
        let clause = build_order_by_clause(Some("size"), Some("desc")).unwrap();
        assert!(
            clause.contains("a.size_bytes") && clause.contains("DESC"),
            "expected size_bytes DESC, got {}",
            clause
        );
    }

    #[test]
    fn test_build_order_by_size_asc_regression_1372() {
        // The core regression: this previously returned a clause that
        // still ordered by created_at DESC, ignoring asc/size entirely.
        let clause = build_order_by_clause(Some("size"), Some("asc")).unwrap();
        assert!(
            clause.contains("a.size_bytes") && clause.contains("ASC"),
            "expected size_bytes ASC (issue #1372), got {}",
            clause
        );
        assert!(
            !clause.contains("DESC"),
            "ASC sort must not include DESC, got {}",
            clause
        );
    }

    #[test]
    fn test_build_order_by_size_bytes_alias_accepted() {
        // Accept the canonical column name too, so an API caller using the
        // raw column doesn't get rejected.
        let clause = build_order_by_clause(Some("size_bytes"), Some("asc")).unwrap();
        assert!(clause.contains("a.size_bytes"));
        assert!(clause.contains("ASC"));
    }

    #[test]
    fn test_build_order_by_name_asc_and_desc() {
        let asc = build_order_by_clause(Some("name"), Some("asc")).unwrap();
        let desc = build_order_by_clause(Some("name"), Some("desc")).unwrap();
        assert!(asc.contains("a.name") && asc.contains("ASC"));
        assert!(desc.contains("a.name") && desc.contains("DESC"));
        assert_ne!(asc, desc, "asc and desc must produce different clauses");
    }

    #[test]
    fn test_build_order_by_sort_order_is_case_insensitive() {
        let upper = build_order_by_clause(Some("size"), Some("ASC")).unwrap();
        let lower = build_order_by_clause(Some("size"), Some("asc")).unwrap();
        let mixed = build_order_by_clause(Some("size"), Some("AsC")).unwrap();
        assert_eq!(upper, lower);
        assert_eq!(mixed, lower);
    }

    #[test]
    fn test_build_order_by_downloads_asc_and_desc_pr_1384() {
        // PR #1384 review: `downloads` used to silently fall through to
        // created_at. It now sorts on the same correlated subquery that
        // populates the `download_count` column in SELECT.
        let asc = build_order_by_clause(Some("downloads"), Some("asc")).unwrap();
        let desc = build_order_by_clause(Some("downloads"), Some("desc")).unwrap();
        assert!(
            asc.contains("download_statistics") && asc.contains("ASC"),
            "expected downloads ASC clause, got {}",
            asc
        );
        assert!(
            desc.contains("download_statistics") && desc.contains("DESC"),
            "expected downloads DESC clause, got {}",
            desc
        );
        assert_ne!(asc, desc);
        // Belt-and-braces: must not collapse to a created_at clause.
        assert!(
            !asc.contains("a.created_at"),
            "downloads asc must not fall back to created_at, got {}",
            asc
        );
        assert!(
            !desc.contains("a.created_at"),
            "downloads desc must not fall back to created_at, got {}",
            desc
        );
    }

    #[test]
    fn test_build_order_by_download_count_alias_accepted() {
        // Accept the underlying column-style alias the same way `size_bytes`
        // mirrors `size`.
        let clause = build_order_by_clause(Some("download_count"), Some("desc")).unwrap();
        assert!(clause.contains("download_statistics"));
        assert!(clause.contains("DESC"));
    }

    #[test]
    fn test_build_order_by_unknown_sort_field_returns_validation_error_pr_1384() {
        // PR #1384 review: silent fallback to created_at made typos and
        // not-yet-implemented sort fields look identical to "no sort". The
        // contract is now strict -- unknown values return AppError::Validation
        // (HTTP 400 VALIDATION_ERROR), so typos surface visibly.
        let err = build_order_by_clause(Some("popularity"), Some("desc"))
            .expect_err("unknown sort_by must be rejected");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("popularity"),
                    "error message must echo the bad sort_by, got {}",
                    msg
                );
                assert!(
                    msg.contains("created_at")
                        && msg.contains("name")
                        && msg.contains("size")
                        && msg.contains("downloads"),
                    "error message must list supported values, got {}",
                    msg
                );
            }
            other => panic!("expected AppError::Validation, got {:?}", other),
        }
    }

    #[test]
    fn test_build_order_by_unknown_sort_field_does_not_splice_into_sql() {
        // The whitelist still guards against injection: an attacker-shaped
        // value is rejected (not spliced) and never reaches the SQL string.
        let err = build_order_by_clause(Some("'; DROP TABLE artifacts; --"), Some("desc"))
            .expect_err("malicious sort_by must be rejected");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_build_order_by_unknown_sort_order_defaults_to_desc() {
        // sort_order is intentionally lenient -- a bad direction can't break
        // SQL and is obvious from the result ordering.
        let clause = build_order_by_clause(Some("size"), Some("sideways")).unwrap();
        assert!(clause.contains("a.size_bytes"));
        assert!(clause.contains("DESC"));
    }

    #[test]
    fn test_build_order_by_returns_static_str_so_no_attacker_text_is_spliced() {
        // The Ok variant is a `&'static str` -- proves at compile time that
        // no caller input can leak into the SQL string.
        let _: Result<&'static str> = build_order_by_clause(Some("name"), Some("asc"));
    }

    #[test]
    fn test_build_order_by_asc_and_desc_flip_head_for_size() {
        // Mirrors the E2E expectation in #1372: with a dataset that has
        // distinct sizes, sort_order=asc and sort_order=desc must produce
        // different SQL, which is what guarantees a different head hit.
        let asc = build_order_by_clause(Some("size"), Some("asc")).unwrap();
        let desc = build_order_by_clause(Some("size"), Some("desc")).unwrap();
        assert_ne!(
            asc, desc,
            "sort_order=asc and sort_order=desc on sort_by=size must produce different ORDER BY clauses (issue #1372)"
        );
    }

    // -----------------------------------------------------------------------
    // SearchQuery::{sort_by, sort_order} -- new fields added in PR #1384.
    // Pin the default + serde behavior so the wire contract is locked.
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_default_sort_by_and_sort_order_are_none() {
        let q = SearchQuery::default();
        assert!(q.sort_by.is_none(), "default sort_by must be None");
        assert!(q.sort_order.is_none(), "default sort_order must be None");
    }

    #[test]
    fn test_search_query_deserializes_sort_by_and_sort_order() {
        let json = r#"{"q": "x", "sort_by": "size", "sort_order": "asc"}"#;
        let q: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.sort_by.as_deref(), Some("size"));
        assert_eq!(q.sort_order.as_deref(), Some("asc"));
    }

    #[test]
    fn test_search_query_deserializes_with_only_sort_by() {
        // sort_order is independently optional -- not specifying it must
        // leave the field None so the helper can fall back to DESC.
        let json = r#"{"sort_by": "downloads"}"#;
        let q: SearchQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.sort_by.as_deref(), Some("downloads"));
        assert!(q.sort_order.is_none());
    }

    #[test]
    fn test_search_query_deserializes_with_only_sort_order() {
        // Mirror: passing sort_order without sort_by must still parse,
        // even though the resulting query falls back to the default
        // `created_at` field.
        let json = r#"{"sort_order": "desc"}"#;
        let q: SearchQuery = serde_json::from_str(json).unwrap();
        assert!(q.sort_by.is_none());
        assert_eq!(q.sort_order.as_deref(), Some("desc"));
    }

    #[test]
    fn test_search_query_round_trip_through_build_order_by_clause() {
        // Tie SearchQuery and build_order_by_clause together so a future
        // refactor that renames either side surfaces immediately.
        let q = SearchQuery {
            sort_by: Some("size".to_string()),
            sort_order: Some("asc".to_string()),
            ..Default::default()
        };
        let clause = build_order_by_clause(q.sort_by.as_deref(), q.sort_order.as_deref()).unwrap();
        assert!(clause.contains("a.size_bytes"));
        assert!(clause.contains("ASC"));
    }

    #[test]
    fn test_search_query_invalid_sort_by_surfaces_validation_error_through_helper() {
        // Verify the integration shape end-to-end: SearchQuery with a bad
        // sort_by, fed to build_order_by_clause, must return Validation.
        let q = SearchQuery {
            sort_by: Some("popularity".to_string()),
            sort_order: Some("desc".to_string()),
            ..Default::default()
        };
        let err = build_order_by_clause(q.sort_by.as_deref(), q.sort_order.as_deref())
            .expect_err("unknown sort_by must propagate as Validation");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
