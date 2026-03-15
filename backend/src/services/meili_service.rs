//! Meilisearch integration service for full-text search indexing.

use chrono::{DateTime, Utc};
use meilisearch_sdk::client::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{AppError, Result};

const ARTIFACTS_INDEX: &str = "artifacts";
const REPOSITORIES_INDEX: &str = "repositories";
const BATCH_SIZE: usize = 1000;

/// Document representing an artifact in the search index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDocument {
    pub id: String,
    pub name: String,
    pub path: String,
    pub version: Option<String>,
    pub format: String,
    pub repository_id: String,
    pub repository_key: String,
    pub repository_name: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub download_count: i64,
    pub created_at: i64,
}

/// Document representing a repository in the search index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryDocument {
    pub id: String,
    pub name: String,
    pub key: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: bool,
    pub created_at: i64,
}

/// Search results wrapper.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResults<T> {
    pub hits: Vec<T>,
    pub total_hits: usize,
    pub processing_time_ms: usize,
    pub query: String,
}

/// Meilisearch service for indexing and searching artifacts and repositories.
pub struct MeiliService {
    client: Client,
}

impl MeiliService {
    /// Create a new MeiliService connected to the given Meilisearch instance.
    pub fn new(url: &str, api_key: &str) -> Result<Self> {
        let client = Client::new(url, Some(api_key))
            .map_err(|e| AppError::Config(format!("Failed to create Meilisearch client: {}", e)))?;
        Ok(Self { client })
    }

    /// Configure indexes with appropriate searchable, filterable, and sortable attributes.
    pub async fn configure_indexes(&self) -> Result<()> {
        // Configure artifacts index
        let artifacts_index = self.client.index(ARTIFACTS_INDEX);

        artifacts_index
            .set_searchable_attributes([
                "name",
                "path",
                "version",
                "repository_key",
                "repository_name",
                "content_type",
            ])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts searchable attributes: {}",
                    e
                ))
            })?;

        artifacts_index
            .set_filterable_attributes([
                "format",
                "repository_key",
                "repository_id",
                "content_type",
                "size_bytes",
                "created_at",
            ])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts filterable attributes: {}",
                    e
                ))
            })?;

        artifacts_index
            .set_sortable_attributes(["created_at", "size_bytes", "name", "download_count"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set artifacts sortable attributes: {}",
                    e
                ))
            })?;

        // Configure repositories index
        let repos_index = self.client.index(REPOSITORIES_INDEX);

        repos_index
            .set_searchable_attributes(["name", "key", "description", "format"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set repositories searchable attributes: {}",
                    e
                ))
            })?;

        repos_index
            .set_filterable_attributes(["format", "repo_type", "is_public"])
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set repositories filterable attributes: {}",
                    e
                ))
            })?;

        tracing::info!("Meilisearch indexes configured successfully");
        Ok(())
    }

    /// Index a single artifact document.
    pub async fn index_artifact(&self, doc: &ArtifactDocument) -> Result<()> {
        self.client
            .index(ARTIFACTS_INDEX)
            .add_documents(&[doc], Some("id"))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index artifact: {}", e)))?;
        Ok(())
    }

    /// Index a single repository document.
    pub async fn index_repository(&self, doc: &RepositoryDocument) -> Result<()> {
        self.client
            .index(REPOSITORIES_INDEX)
            .add_documents(&[doc], Some("id"))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index repository: {}", e)))?;
        Ok(())
    }

    /// Remove an artifact from the search index.
    pub async fn remove_artifact(&self, artifact_id: &str) -> Result<()> {
        self.client
            .index(ARTIFACTS_INDEX)
            .delete_document(artifact_id)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove artifact from index: {}", e))
            })?;
        Ok(())
    }

    /// Remove a repository from the search index.
    pub async fn remove_repository(&self, repository_id: &str) -> Result<()> {
        self.client
            .index(REPOSITORIES_INDEX)
            .delete_document(repository_id)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove repository from index: {}", e))
            })?;
        Ok(())
    }

    /// Search artifacts by query string with optional filters.
    pub async fn search_artifacts(
        &self,
        query: &str,
        filter: Option<&str>,
        sort: Option<&[&str]>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<ArtifactDocument>> {
        let index = self.client.index(ARTIFACTS_INDEX);
        let mut search = index.search();
        search.with_query(query);
        search.with_limit(limit);
        search.with_offset(offset);

        if let Some(f) = filter {
            search.with_filter(f);
        }
        if let Some(s) = sort {
            search.with_sort(s);
        }

        let results = search
            .execute::<ArtifactDocument>()
            .await
            .map_err(|e| AppError::Internal(format!("Artifact search failed: {}", e)))?;

        let hits: Vec<ArtifactDocument> = results.hits.into_iter().map(|hit| hit.result).collect();

        Ok(SearchResults {
            total_hits: results.estimated_total_hits.unwrap_or(hits.len()),
            processing_time_ms: results.processing_time_ms,
            query: query.to_string(),
            hits,
        })
    }

    /// Search repositories by query string with optional filters.
    pub async fn search_repositories(
        &self,
        query: &str,
        filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<RepositoryDocument>> {
        let index = self.client.index(REPOSITORIES_INDEX);
        let mut search = index.search();
        search.with_query(query);
        search.with_limit(limit);
        search.with_offset(offset);

        if let Some(f) = filter {
            search.with_filter(f);
        }

        let results = search
            .execute::<RepositoryDocument>()
            .await
            .map_err(|e| AppError::Internal(format!("Repository search failed: {}", e)))?;

        let hits: Vec<RepositoryDocument> =
            results.hits.into_iter().map(|hit| hit.result).collect();

        Ok(SearchResults {
            total_hits: results.estimated_total_hits.unwrap_or(hits.len()),
            processing_time_ms: results.processing_time_ms,
            query: query.to_string(),
            hits,
        })
    }

    /// Check if the artifacts index is empty (used to trigger initial reindex).
    pub async fn is_index_empty(&self) -> Result<bool> {
        let stats = self
            .client
            .index(ARTIFACTS_INDEX)
            .get_stats()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get index stats: {}", e)))?;

        Ok(stats.number_of_documents == 0)
    }

    /// Reindex all artifacts from the database into Meilisearch.
    ///
    /// Uses cursor-based pagination to avoid loading all rows into memory.
    /// Artifacts inserted concurrently during a reindex may be skipped;
    /// they are indexed individually via [`index_artifact`] on creation.
    pub async fn full_reindex_artifacts(&self, db: &PgPool) -> Result<usize> {
        tracing::info!("Starting full artifact reindex");

        let index = self.client.index(ARTIFACTS_INDEX);
        let page_size: i64 = BATCH_SIZE as i64;
        let mut last_id: Option<Uuid> = None;
        let mut total = 0usize;

        loop {
            let rows = sqlx::query_as::<_, ArtifactRow>(
                r#"
                SELECT
                    a.id,
                    a.name,
                    a.path,
                    a.version,
                    a.content_type,
                    a.size_bytes,
                    a.created_at,
                    r.id AS repository_id,
                    r.key AS repository_key,
                    r.name AS repository_name,
                    r.format::text AS format
                FROM artifacts a
                INNER JOIN repositories r ON a.repository_id = r.id
                WHERE a.is_deleted = false
                  AND ($1::uuid IS NULL OR a.id > $1)
                ORDER BY a.id
                LIMIT $2
                "#,
            )
            .bind(last_id)
            .bind(page_size)
            .fetch_all(db)
            .await
            .map_err(|e| {
                AppError::Database(format!(
                    "Failed to fetch artifacts for reindex (after {} documents): {}",
                    total, e
                ))
            })?;

            if rows.is_empty() {
                break;
            }

            let artifact_ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
            let download_counts: HashMap<Uuid, i64> =
                sqlx::query_as::<_, ArtifactDownloadCountRow>(
                    r#"
                SELECT artifact_id, COUNT(*)::BIGINT AS download_count
                FROM download_statistics
                WHERE artifact_id = ANY($1)
                GROUP BY artifact_id
                "#,
                )
                .bind(&artifact_ids)
                .fetch_all(db)
                .await
                .map_err(|e| {
                    AppError::Database(format!(
                        "Failed to fetch artifact download counts for reindex (after {} documents): {}",
                        total, e
                    ))
                })?
                .into_iter()
                .map(|row| (row.artifact_id, row.download_count))
                .collect();

            last_id = rows.last().map(|row| row.id);
            let documents = build_artifact_batch(rows, &download_counts);

            total += documents.len();
            index
                .add_documents(&documents, Some("id"))
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to batch index artifacts (after {} documents): {}",
                        total, e
                    ))
                })?;

            tracing::info!(
                batch = documents.len(),
                total_so_far = total,
                "Indexed artifact batch"
            );
        }

        tracing::info!("Artifact reindex complete: {} documents indexed", total);
        Ok(total)
    }

    /// Reindex all repositories from the database into Meilisearch.
    ///
    /// Uses cursor-based pagination to avoid loading all rows into memory.
    /// Repositories inserted concurrently during a reindex may be skipped;
    /// they are indexed individually via [`index_repository`] on creation.
    pub async fn full_reindex_repositories(&self, db: &PgPool) -> Result<usize> {
        tracing::info!("Starting full repository reindex");

        let index = self.client.index(REPOSITORIES_INDEX);
        let page_size: i64 = BATCH_SIZE as i64;
        let mut last_id: Option<Uuid> = None;
        let mut total = 0usize;

        loop {
            let rows = sqlx::query_as::<_, RepositoryRow>(
                r#"
                SELECT
                    id,
                    name,
                    key,
                    description,
                    format::text AS format,
                    repo_type::text AS repo_type,
                    is_public,
                    created_at
                FROM repositories
                WHERE ($1::uuid IS NULL OR id > $1)
                ORDER BY id
                LIMIT $2
                "#,
            )
            .bind(last_id)
            .bind(page_size)
            .fetch_all(db)
            .await
            .map_err(|e| {
                AppError::Database(format!(
                    "Failed to fetch repositories for reindex (after {} documents): {}",
                    total, e
                ))
            })?;

            if rows.is_empty() {
                break;
            }

            last_id = rows.last().map(|row| row.id);
            let documents = build_repository_batch(rows);

            total += documents.len();
            index
                .add_documents(&documents, Some("id"))
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to batch index repositories (after {} documents): {}",
                        total, e
                    ))
                })?;

            tracing::info!(
                batch = documents.len(),
                total_so_far = total,
                "Indexed repository batch"
            );
        }

        tracing::info!("Repository reindex complete: {} documents indexed", total);
        Ok(total)
    }

    /// Run a full reindex of both artifacts and repositories.
    ///
    /// Returns the count of (artifacts, repositories) indexed.
    pub async fn full_reindex(&self, db: &PgPool) -> Result<(usize, usize)> {
        let artifacts = self.full_reindex_artifacts(db).await?;
        tracing::info!("Artifact reindex phase complete, proceeding to repositories");
        let repositories = self.full_reindex_repositories(db).await?;
        tracing::info!("Full reindex complete");
        Ok((artifacts, repositories))
    }
}

/// Internal row type for artifact reindex queries.
#[derive(Debug, sqlx::FromRow)]
struct ArtifactRow {
    id: Uuid,
    name: String,
    path: String,
    version: Option<String>,
    content_type: String,
    size_bytes: i64,
    created_at: DateTime<Utc>,
    repository_id: Uuid,
    repository_key: String,
    repository_name: String,
    format: String,
}

/// Internal row type for repository reindex queries.
#[derive(Debug, sqlx::FromRow)]
struct RepositoryRow {
    id: Uuid,
    name: String,
    key: String,
    description: Option<String>,
    format: String,
    repo_type: String,
    is_public: bool,
    created_at: DateTime<Utc>,
}

/// Internal row type for per-artifact download count aggregation.
#[derive(Debug, sqlx::FromRow)]
struct ArtifactDownloadCountRow {
    artifact_id: Uuid,
    download_count: i64,
}

/// Build a batch of [`ArtifactDocument`]s from database rows and per-artifact download counts.
///
/// Artifacts with no entry in `download_counts` default to 0,
/// matching the previous `COALESCE(ds.download_count, 0)` behavior.
fn build_artifact_batch(
    rows: Vec<ArtifactRow>,
    download_counts: &HashMap<Uuid, i64>,
) -> Vec<ArtifactDocument> {
    rows.into_iter()
        .map(|row| {
            let dc = download_counts.get(&row.id).copied().unwrap_or_default();
            artifact_document_from_row(row, dc)
        })
        .collect()
}

/// Build a batch of [`RepositoryDocument`]s from database rows.
fn build_repository_batch(rows: Vec<RepositoryRow>) -> Vec<RepositoryDocument> {
    rows.into_iter().map(repository_document_from_row).collect()
}

fn artifact_document_from_row(row: ArtifactRow, download_count: i64) -> ArtifactDocument {
    ArtifactDocument {
        id: row.id.to_string(),
        name: row.name,
        path: row.path,
        version: row.version,
        format: row.format,
        repository_id: row.repository_id.to_string(),
        repository_key: row.repository_key,
        repository_name: row.repository_name,
        content_type: row.content_type,
        size_bytes: row.size_bytes,
        download_count,
        created_at: row.created_at.timestamp(),
    }
}

fn repository_document_from_row(row: RepositoryRow) -> RepositoryDocument {
    RepositoryDocument {
        id: row.id.to_string(),
        name: row.name,
        key: row.key,
        description: row.description,
        format: row.format,
        repo_type: row.repo_type,
        is_public: row.is_public,
        created_at: row.created_at.timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    fn meili_service_source() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/services/meili_service.rs"
        ))
    }

    fn function_source<'a>(source: &'a str, fn_name: &str) -> &'a str {
        let needle = format!("fn {}(", fn_name);
        let start = source
            .find(&needle)
            .unwrap_or_else(|| panic!("failed to find function {fn_name}"));
        let remainder = &source[start..];
        // Find the next function definition or end of impl block as boundary
        let end = remainder[1..]
            .find("\n    pub ")
            .or_else(|| remainder[1..].find("\n}"))
            .map(|i| i + 1)
            .unwrap_or(remainder.len());
        &remainder[..end]
    }

    // -----------------------------------------------------------------------
    // function_source helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_function_source_extracts_correct_boundary_for_last_method() {
        // full_reindex is the last pub method in the impl block.
        // function_source should not leak into structs/functions outside the impl.
        let source = function_source(meili_service_source(), "full_reindex");
        assert!(
            source.contains("full_reindex_artifacts"),
            "full_reindex body should reference full_reindex_artifacts"
        );
        assert!(
            !source.contains("struct ArtifactRow"),
            "full_reindex should not leak past the impl block into struct definitions"
        );
    }

    // -----------------------------------------------------------------------
    // Constructor tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_returns_result() {
        // MeiliService::new should return Result, not panic on invalid input
        let source = function_source(meili_service_source(), "new");
        assert!(
            source.contains("-> Result<Self>"),
            "MeiliService::new should return Result<Self>"
        );
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(ARTIFACTS_INDEX, "artifacts");
        assert_eq!(REPOSITORIES_INDEX, "repositories");
        assert_eq!(BATCH_SIZE, 1000);
    }

    // -----------------------------------------------------------------------
    // Pagination page_size derived from BATCH_SIZE
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_size_fits_i64_for_pagination() {
        // full_reindex uses `BATCH_SIZE as i64` for query LIMIT params
        let page_size: i64 = BATCH_SIZE as i64;
        assert_eq!(page_size, 1000);
        assert!(page_size > 0);
    }

    #[test]
    fn test_full_reindex_artifacts_uses_cursor_pagination_without_offset() {
        let source = function_source(meili_service_source(), "full_reindex_artifacts");

        assert!(
            source.contains("a.id > $1"),
            "artifact reindex should paginate from the last indexed id"
        );
        assert!(
            !source.contains("OFFSET"),
            "artifact reindex should not use OFFSET pagination on a live table"
        );
    }

    #[test]
    fn test_full_reindex_repositories_uses_cursor_pagination_without_offset() {
        let source = function_source(meili_service_source(), "full_reindex_repositories");

        assert!(
            source.contains("id > $1"),
            "repository reindex should paginate from the last indexed id"
        );
        assert!(
            !source.contains("OFFSET"),
            "repository reindex should not use OFFSET pagination on a live table"
        );
    }

    #[test]
    fn test_full_reindex_artifacts_scopes_download_count_aggregation_to_batch() {
        let source = function_source(meili_service_source(), "full_reindex_artifacts");

        assert!(
            source.contains("WHERE artifact_id = ANY($1)"),
            "download counts should be aggregated only for the current artifact batch"
        );
        assert!(
            !source.contains("LEFT JOIN ("),
            "artifact reindex should not use a full-table subquery JOIN for download counts"
        );
    }

    #[test]
    fn test_artifact_document_from_row_zero_download_count() {
        let now = Utc::now();
        let row = ArtifactRow {
            id: Uuid::new_v4(),
            name: "no-downloads".to_string(),
            path: "pkg/no-downloads".to_string(),
            version: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: 64,
            created_at: now,
            repository_id: Uuid::new_v4(),
            repository_key: "generic-local".to_string(),
            repository_name: "Generic".to_string(),
            format: "generic".to_string(),
        };
        let doc = artifact_document_from_row(row, 0);
        assert_eq!(doc.download_count, 0);
    }

    #[test]
    fn test_full_reindex_artifacts_errors_include_progress_context() {
        let source = function_source(meili_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("after {} documents"),
            "artifact reindex errors should include the count of documents indexed so far"
        );
    }

    #[test]
    fn test_full_reindex_repositories_errors_include_progress_context() {
        let source = function_source(meili_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("after {} documents"),
            "repository reindex errors should include the count of documents indexed so far"
        );
    }

    #[test]
    fn test_full_reindex_artifacts_logs_batch_progress() {
        let source = function_source(meili_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("Indexed artifact batch"),
            "artifact reindex should log progress after each batch"
        );
    }

    #[test]
    fn test_full_reindex_repositories_logs_batch_progress() {
        let source = function_source(meili_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("Indexed repository batch"),
            "repository reindex should log progress after each batch"
        );
    }

    #[test]
    fn test_full_reindex_artifacts_returns_count() {
        let source = function_source(meili_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("Result<usize>"),
            "full_reindex_artifacts should return Result<usize> with the count of indexed documents"
        );
    }

    #[test]
    fn test_full_reindex_repositories_returns_count() {
        let source = function_source(meili_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("Result<usize>"),
            "full_reindex_repositories should return Result<usize> with the count of indexed documents"
        );
    }

    #[test]
    fn test_full_reindex_logs_phase_completion() {
        let source = function_source(meili_service_source(), "full_reindex");
        assert!(
            source.contains("Artifact reindex phase complete"),
            "full_reindex should log when the artifact phase completes before starting repositories"
        );
    }

    #[test]
    fn test_artifact_row_to_document_mapping_preserves_all_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();

        let row = ArtifactRow {
            id,
            name: "lib".to_string(),
            path: "org/lib/1.0/lib-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            content_type: "application/java-archive".to_string(),
            size_bytes: 4096,
            created_at: now,
            repository_id: repo_id,
            repository_key: "maven-local".to_string(),
            repository_name: "Maven Local".to_string(),
            format: "maven".to_string(),
        };

        let doc = artifact_document_from_row(row, 5);

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.repository_id, repo_id.to_string());
        assert_eq!(doc.size_bytes, 4096);
        assert_eq!(doc.download_count, 5);
        assert_eq!(doc.created_at, now.timestamp());
    }

    #[test]
    fn test_repository_row_to_document_mapping_preserves_all_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let row = RepositoryRow {
            id,
            name: "NPM Local".to_string(),
            key: "npm-local".to_string(),
            description: Some("Local NPM".to_string()),
            format: "npm".to_string(),
            repo_type: "local".to_string(),
            is_public: false,
            created_at: now,
        };

        let doc = repository_document_from_row(row);

        assert_eq!(doc.id, id.to_string());
        assert!(!doc.is_public);
        assert_eq!(doc.description, Some("Local NPM".to_string()));
        assert_eq!(doc.created_at, now.timestamp());
    }

    // -----------------------------------------------------------------------
    // ArtifactDocument serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_document_serialization() {
        let doc = ArtifactDocument {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            name: "my-artifact".to_string(),
            path: "com/example/my-artifact/1.0.0/my-artifact-1.0.0.jar".to_string(),
            version: Some("1.0.0".to_string()),
            format: "maven".to_string(),
            repository_id: "repo-id-123".to_string(),
            repository_key: "maven-central".to_string(),
            repository_name: "Maven Central".to_string(),
            content_type: "application/java-archive".to_string(),
            size_bytes: 1024 * 1024,
            download_count: 42,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"name\":\"my-artifact\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"format\":\"maven\""));
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1048576"));
    }

    #[test]
    fn test_artifact_document_deserialization() {
        let json_val = json!({
            "id": "abc-123",
            "name": "pkg",
            "path": "pkg/1.0",
            "version": null,
            "format": "npm",
            "repository_id": "repo-1",
            "repository_key": "npm-local",
            "repository_name": "NPM Local",
            "content_type": "application/gzip",
            "size_bytes": 512,
            "download_count": 0,
            "created_at": 1700000000
        });

        let doc: ArtifactDocument = serde_json::from_value(json_val).unwrap();
        assert_eq!(doc.id, "abc-123");
        assert_eq!(doc.name, "pkg");
        assert!(doc.version.is_none());
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.size_bytes, 512);
        assert_eq!(doc.download_count, 0);
    }

    #[test]
    fn test_artifact_document_roundtrip() {
        let doc = ArtifactDocument {
            id: "test-id".to_string(),
            name: "test-name".to_string(),
            path: "test/path".to_string(),
            version: Some("2.0.0".to_string()),
            format: "docker".to_string(),
            repository_id: "repo".to_string(),
            repository_key: "docker-local".to_string(),
            repository_name: "Docker Local".to_string(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            size_bytes: 0,
            download_count: 100,
            created_at: 1234567890,
        };

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: ArtifactDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(doc.id, deserialized.id);
        assert_eq!(doc.name, deserialized.name);
        assert_eq!(doc.path, deserialized.path);
        assert_eq!(doc.version, deserialized.version);
        assert_eq!(doc.format, deserialized.format);
        assert_eq!(doc.repository_id, deserialized.repository_id);
        assert_eq!(doc.repository_key, deserialized.repository_key);
        assert_eq!(doc.repository_name, deserialized.repository_name);
        assert_eq!(doc.content_type, deserialized.content_type);
        assert_eq!(doc.size_bytes, deserialized.size_bytes);
        assert_eq!(doc.download_count, deserialized.download_count);
        assert_eq!(doc.created_at, deserialized.created_at);
    }

    #[test]
    fn test_artifact_document_clone() {
        let doc = ArtifactDocument {
            id: "id".to_string(),
            name: "name".to_string(),
            path: "path".to_string(),
            version: None,
            format: "generic".to_string(),
            repository_id: "repo".to_string(),
            repository_key: "key".to_string(),
            repository_name: "name".to_string(),
            content_type: "application/octet-stream".to_string(),
            size_bytes: 100,
            download_count: 0,
            created_at: 0,
        };
        let cloned = doc.clone();
        assert_eq!(doc.id, cloned.id);
        assert_eq!(doc.name, cloned.name);
    }

    // -----------------------------------------------------------------------
    // RepositoryDocument serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_document_serialization() {
        let doc = RepositoryDocument {
            id: "repo-id".to_string(),
            name: "My Repository".to_string(),
            key: "my-repo".to_string(),
            description: Some("A test repository".to_string()),
            format: "maven".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"name\":\"My Repository\""));
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"is_public\":true"));
        assert!(json.contains("\"format\":\"maven\""));
        assert!(json.contains("\"repo_type\":\"local\""));
    }

    #[test]
    fn test_repository_document_deserialization() {
        let json_val = json!({
            "id": "repo-1",
            "name": "NPM Repo",
            "key": "npm-local",
            "description": null,
            "format": "npm",
            "repo_type": "remote",
            "is_public": false,
            "created_at": 1700000000
        });

        let doc: RepositoryDocument = serde_json::from_value(json_val).unwrap();
        assert_eq!(doc.name, "NPM Repo");
        assert_eq!(doc.key, "npm-local");
        assert!(doc.description.is_none());
        assert!(!doc.is_public);
    }

    #[test]
    fn test_repository_document_roundtrip() {
        let doc = RepositoryDocument {
            id: "test".to_string(),
            name: "Test".to_string(),
            key: "test-key".to_string(),
            description: Some("desc".to_string()),
            format: "docker".to_string(),
            repo_type: "virtual".to_string(),
            is_public: false,
            created_at: 999,
        };
        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: RepositoryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc.id, deserialized.id);
        assert_eq!(doc.name, deserialized.name);
        assert_eq!(doc.key, deserialized.key);
        assert_eq!(doc.description, deserialized.description);
        assert_eq!(doc.format, deserialized.format);
        assert_eq!(doc.repo_type, deserialized.repo_type);
        assert_eq!(doc.is_public, deserialized.is_public);
        assert_eq!(doc.created_at, deserialized.created_at);
    }

    #[test]
    fn test_repository_document_clone() {
        let doc = RepositoryDocument {
            id: "id".to_string(),
            name: "name".to_string(),
            key: "key".to_string(),
            description: None,
            format: "pypi".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: 0,
        };
        let cloned = doc.clone();
        assert_eq!(doc.id, cloned.id);
        assert_eq!(doc.is_public, cloned.is_public);
    }

    // -----------------------------------------------------------------------
    // SearchResults serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_results_serialization_empty() {
        let results: SearchResults<ArtifactDocument> = SearchResults {
            hits: vec![],
            total_hits: 0,
            processing_time_ms: 5,
            query: "test".to_string(),
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"hits\":[]"));
        assert!(json.contains("\"total_hits\":0"));
        assert!(json.contains("\"processing_time_ms\":5"));
        assert!(json.contains("\"query\":\"test\""));
    }

    #[test]
    fn test_search_results_serialization_with_hits() {
        let doc = ArtifactDocument {
            id: "1".to_string(),
            name: "artifact1".to_string(),
            path: "a/b".to_string(),
            version: Some("1.0".to_string()),
            format: "npm".to_string(),
            repository_id: "r".to_string(),
            repository_key: "k".to_string(),
            repository_name: "n".to_string(),
            content_type: "application/gzip".to_string(),
            size_bytes: 100,
            download_count: 10,
            created_at: 0,
        };

        let results = SearchResults {
            hits: vec![doc],
            total_hits: 1,
            processing_time_ms: 12,
            query: "artifact".to_string(),
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"total_hits\":1"));
        assert!(json.contains("\"name\":\"artifact1\""));
    }

    #[test]
    fn test_search_results_clone() {
        let results: SearchResults<RepositoryDocument> = SearchResults {
            hits: vec![],
            total_hits: 0,
            processing_time_ms: 0,
            query: "q".to_string(),
        };
        let cloned = results.clone();
        assert_eq!(results.total_hits, cloned.total_hits);
        assert_eq!(results.query, cloned.query);
    }

    // -----------------------------------------------------------------------
    // ArtifactRow construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_row_to_document_conversion() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();

        let row = ArtifactRow {
            id,
            name: "my-lib".to_string(),
            path: "org/my-lib/1.0/my-lib-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            content_type: "application/java-archive".to_string(),
            size_bytes: 2048,
            created_at: now,
            repository_id: repo_id,
            repository_key: "maven-local".to_string(),
            repository_name: "Maven Local".to_string(),
            format: "maven".to_string(),
        };

        let doc = artifact_document_from_row(row, 7);

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.name, "my-lib");
        assert_eq!(doc.version, Some("1.0".to_string()));
        assert_eq!(doc.repository_key, "maven-local");
        assert_eq!(doc.download_count, 7);
        assert_eq!(doc.created_at, now.timestamp());
    }

    // -----------------------------------------------------------------------
    // RepositoryRow to document conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_row_to_document_conversion() {
        let now = Utc::now();
        let id = Uuid::new_v4();

        let row = RepositoryRow {
            id,
            name: "Docker Local".to_string(),
            key: "docker-local".to_string(),
            description: Some("Local docker repo".to_string()),
            format: "docker".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: now,
        };

        let doc = repository_document_from_row(row);

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.name, "Docker Local");
        assert_eq!(doc.key, "docker-local");
        assert_eq!(doc.description, Some("Local docker repo".to_string()));
        assert!(doc.is_public);
    }

    // -----------------------------------------------------------------------
    // build_artifact_batch tests
    // -----------------------------------------------------------------------

    fn make_artifact_row(id: Uuid) -> ArtifactRow {
        ArtifactRow {
            id,
            name: format!("artifact-{}", &id.to_string()[..8]),
            path: format!("pkg/{id}"),
            version: Some("1.0.0".to_string()),
            content_type: "application/octet-stream".to_string(),
            size_bytes: 256,
            created_at: Utc::now(),
            repository_id: Uuid::new_v4(),
            repository_key: "generic-local".to_string(),
            repository_name: "Generic".to_string(),
            format: "generic".to_string(),
        }
    }

    #[test]
    fn test_build_artifact_batch_empty() {
        let docs = build_artifact_batch(vec![], &HashMap::new());
        assert!(docs.is_empty());
    }

    #[test]
    fn test_build_artifact_batch_mixed_downloads() {
        let id_with = Uuid::new_v4();
        let id_without = Uuid::new_v4();
        let rows = vec![make_artifact_row(id_with), make_artifact_row(id_without)];

        let mut counts = HashMap::new();
        counts.insert(id_with, 42);

        let docs = build_artifact_batch(rows, &counts);
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].download_count, 42);
        assert_eq!(
            docs[1].download_count, 0,
            "missing download count defaults to 0"
        );
    }

    #[test]
    fn test_build_artifact_batch_all_have_downloads() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let rows = vec![
            make_artifact_row(id1),
            make_artifact_row(id2),
            make_artifact_row(id3),
        ];

        let mut counts = HashMap::new();
        counts.insert(id1, 10);
        counts.insert(id2, 20);
        counts.insert(id3, 30);

        let docs = build_artifact_batch(rows, &counts);
        assert_eq!(docs.len(), 3);
        assert_eq!(docs[0].download_count, 10);
        assert_eq!(docs[1].download_count, 20);
        assert_eq!(docs[2].download_count, 30);
    }

    // -----------------------------------------------------------------------
    // build_repository_batch tests
    // -----------------------------------------------------------------------

    fn make_repository_row(id: Uuid) -> RepositoryRow {
        RepositoryRow {
            id,
            name: format!("repo-{}", &id.to_string()[..8]),
            key: format!("repo-{}", &id.to_string()[..8]),
            description: None,
            format: "generic".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_build_repository_batch_empty() {
        let docs = build_repository_batch(vec![]);
        assert!(docs.is_empty());
    }

    #[test]
    fn test_build_repository_batch_multiple() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let rows = vec![make_repository_row(id1), make_repository_row(id2)];

        let docs = build_repository_batch(rows);
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].id, id1.to_string());
        assert_eq!(docs[1].id, id2.to_string());
    }
}
