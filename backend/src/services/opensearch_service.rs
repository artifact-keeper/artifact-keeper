//! OpenSearch integration service for full-text search indexing.
//!
//! Replaces the previous Meilisearch integration with OpenSearch 2.x,
//! providing the same public API surface (document types, search results,
//! reindex helpers) while taking advantage of OpenSearch features like
//! custom analyzers, multi-field mappings, and the `_bulk` API.

use chrono::{DateTime, Utc};
use opensearch::{
    auth::Credentials,
    cert::CertificateValidation,
    cluster::ClusterHealthParts,
    http::{
        request::JsonBody,
        transport::{SingleNodeConnectionPool, TransportBuilder},
    },
    indices::{IndicesCreateParts, IndicesExistsParts, IndicesRefreshParts},
    BulkParts, CountParts, DeleteParts, IndexParts, OpenSearch, SearchParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

use crate::error::{AppError, Result};

const ARTIFACTS_INDEX: &str = "artifacts";
const REPOSITORIES_INDEX: &str = "repositories";
const BATCH_SIZE: usize = 1000;

// ---------------------------------------------------------------------------
// Document types
// ---------------------------------------------------------------------------

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
    pub is_public: bool,
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

// ---------------------------------------------------------------------------
// OpenSearch service
// ---------------------------------------------------------------------------

/// OpenSearch service for indexing and searching artifacts and repositories.
pub struct OpenSearchService {
    client: OpenSearch,
}

impl std::fmt::Debug for OpenSearchService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSearchService")
            .field("client", &"<OpenSearch>")
            .finish()
    }
}

impl OpenSearchService {
    /// Create a new OpenSearchService connected to the given OpenSearch cluster.
    ///
    /// When `username` and `password` are provided the client authenticates
    /// with HTTP basic auth. Set `allow_invalid_certs` to `true` when running
    /// against a development cluster with self-signed certificates.
    pub fn new(
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        allow_invalid_certs: bool,
    ) -> Result<Self> {
        let parsed = Url::parse(url)
            .map_err(|e| AppError::Config(format!("Invalid OpenSearch URL '{}': {}", url, e)))?;

        let conn_pool = SingleNodeConnectionPool::new(parsed);
        let mut builder = TransportBuilder::new(conn_pool);

        if let (Some(u), Some(p)) = (username, password) {
            builder = builder.auth(Credentials::Basic(u.to_string(), p.to_string()));
        }

        if allow_invalid_certs {
            builder = builder.cert_validation(CertificateValidation::None);
        }

        let transport = builder.build().map_err(|e| {
            AppError::Config(format!("Failed to build OpenSearch transport: {}", e))
        })?;

        Ok(Self {
            client: OpenSearch::new(transport),
        })
    }

    /// Configure indexes with explicit mappings and custom analyzers.
    ///
    /// Creates the `artifacts` and `repositories` indexes if they do not
    /// already exist. Each index uses:
    /// - `path_hierarchy` tokenizer for hierarchical path fields
    /// - `edge_ngram` filter on the `name` field for prefix / typeahead queries
    /// - text + keyword multi-fields so the same field can be searched and filtered
    pub async fn configure_indexes(&self) -> Result<()> {
        self.ensure_index(ARTIFACTS_INDEX, Self::artifacts_index_body())
            .await?;
        self.ensure_index(REPOSITORIES_INDEX, Self::repositories_index_body())
            .await?;

        tracing::info!("OpenSearch indexes configured successfully");
        Ok(())
    }

    /// Index a single artifact document.
    pub async fn index_artifact(&self, doc: &ArtifactDocument) -> Result<()> {
        let body = serde_json::to_value(doc)
            .map_err(|e| AppError::Internal(format!("Failed to serialize artifact doc: {}", e)))?;

        let response = self
            .client
            .index(IndexParts::IndexId(ARTIFACTS_INDEX, &doc.id))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index artifact: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Failed to index artifact (HTTP {}): {}",
                status, text
            )));
        }
        Ok(())
    }

    /// Index a single repository document.
    pub async fn index_repository(&self, doc: &RepositoryDocument) -> Result<()> {
        let body = serde_json::to_value(doc).map_err(|e| {
            AppError::Internal(format!("Failed to serialize repository doc: {}", e))
        })?;

        let response = self
            .client
            .index(IndexParts::IndexId(REPOSITORIES_INDEX, &doc.id))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to index repository: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Failed to index repository (HTTP {}): {}",
                status, text
            )));
        }
        Ok(())
    }

    /// Remove an artifact from the search index.
    ///
    /// A 404 response is treated as success (the document was already gone).
    pub async fn remove_artifact(&self, artifact_id: &str) -> Result<()> {
        let response = self
            .client
            .delete(DeleteParts::IndexId(ARTIFACTS_INDEX, artifact_id))
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove artifact from index: {}", e))
            })?;

        let status = response.status_code().as_u16();
        if status != 200 && status != 404 {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Failed to remove artifact from index (HTTP {}): {}",
                status, text
            )));
        }
        Ok(())
    }

    /// Remove a repository from the search index.
    ///
    /// A 404 response is treated as success (the document was already gone).
    pub async fn remove_repository(&self, repo_id: &str) -> Result<()> {
        let response = self
            .client
            .delete(DeleteParts::IndexId(REPOSITORIES_INDEX, repo_id))
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to remove repository from index: {}", e))
            })?;

        let status = response.status_code().as_u16();
        if status != 200 && status != 404 {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Failed to remove repository from index (HTTP {}): {}",
                status, text
            )));
        }
        Ok(())
    }

    /// Search artifacts by query string with optional filters and sorting.
    ///
    /// The `filter` parameter accepts Meilisearch-style filter expressions
    /// (e.g. `format = maven AND repository_key = libs-release`) which are
    /// translated into OpenSearch bool/filter clauses via [`translate_filter`].
    ///
    /// The `sort` parameter accepts Meilisearch-style sort strings
    /// (e.g. `["created_at:desc", "name:asc"]`) which are translated into
    /// OpenSearch sort clauses via [`translate_sort`].
    pub async fn search_artifacts(
        &self,
        query: &str,
        filter: Option<&str>,
        sort: Option<&[&str]>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<ArtifactDocument>> {
        let mut must_clause = json!({
            "multi_match": {
                "query": query,
                "fields": ["name^3", "path^2", "version", "repository_key", "repository_name", "content_type"],
                "type": "best_fields",
                "fuzziness": "AUTO"
            }
        });

        // For empty queries, match everything
        if query.is_empty() {
            must_clause = json!({ "match_all": {} });
        }

        let filter_clauses = filter.map(translate_filter).unwrap_or_default();

        let mut body = json!({
            "query": {
                "bool": {
                    "must": [must_clause],
                    "filter": filter_clauses
                }
            },
            "from": offset,
            "size": limit,
            "track_total_hits": true
        });

        if let Some(sort_specs) = sort {
            let os_sort = translate_sort(sort_specs);
            if !os_sort.is_empty() {
                body["sort"] = Value::Array(os_sort);
            }
        }

        let response = self
            .client
            .search(SearchParts::Index(&[ARTIFACTS_INDEX]))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Artifact search failed: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Artifact search failed (HTTP {}): {}",
                status, text
            )));
        }

        let body: Value = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse artifact search response: {}", e))
        })?;

        parse_search_response(query, &body)
    }

    /// Search repositories by query string with optional filters.
    pub async fn search_repositories(
        &self,
        query: &str,
        filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<SearchResults<RepositoryDocument>> {
        let mut must_clause = json!({
            "multi_match": {
                "query": query,
                "fields": ["name^3", "key^2", "description", "format"],
                "type": "best_fields",
                "fuzziness": "AUTO"
            }
        });

        if query.is_empty() {
            must_clause = json!({ "match_all": {} });
        }

        let filter_clauses = filter.map(translate_filter).unwrap_or_default();

        let body = json!({
            "query": {
                "bool": {
                    "must": [must_clause],
                    "filter": filter_clauses
                }
            },
            "from": offset,
            "size": limit,
            "track_total_hits": true
        });

        let response = self
            .client
            .search(SearchParts::Index(&[REPOSITORIES_INDEX]))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Repository search failed: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Repository search failed (HTTP {}): {}",
                status, text
            )));
        }

        let body: Value = response.json().await.map_err(|e| {
            AppError::Internal(format!("Failed to parse repository search response: {}", e))
        })?;

        parse_search_response(query, &body)
    }

    /// Check if the artifacts index is empty (used to trigger initial reindex).
    ///
    /// An `index_not_found_exception` is treated as empty (the index has not
    /// been populated yet).
    pub async fn is_index_empty(&self) -> Result<bool> {
        let response = self
            .client
            .count(CountParts::Index(&[ARTIFACTS_INDEX]))
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status_code().as_u16();
                if status == 404 {
                    return Ok(true);
                }
                if !resp.status_code().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(AppError::Internal(format!(
                        "Failed to get index count (HTTP {}): {}",
                        status, text
                    )));
                }
                let body: Value = resp.json().await.map_err(|e| {
                    AppError::Internal(format!("Failed to parse count response: {}", e))
                })?;
                let count = body["count"].as_u64().unwrap_or(0);
                Ok(count == 0)
            }
            Err(e) => Err(AppError::Internal(format!(
                "Failed to get index stats: {}",
                e
            ))),
        }
    }

    /// Reindex all artifacts from the database into OpenSearch.
    ///
    /// Uses cursor-based pagination to avoid loading all rows into memory.
    /// Artifacts inserted concurrently during a reindex may be skipped;
    /// they are indexed individually via [`index_artifact`] on creation.
    ///
    /// Refresh is disabled for the duration of the bulk import and forced
    /// once at the end, which significantly improves indexing throughput.
    pub async fn full_reindex_artifacts(&self, db: &PgPool) -> Result<usize> {
        tracing::info!("Starting full artifact reindex");

        self.set_refresh_interval(ARTIFACTS_INDEX, "-1").await?;

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
                    r.format::text AS format,
                    r.is_public
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
            let batch_len = documents.len();

            self.bulk_index(ARTIFACTS_INDEX, &documents)
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to batch index artifacts (after {} documents, batch of {}): {}",
                        total, batch_len, e
                    ))
                })?;
            total += batch_len;

            tracing::info!(
                batch = documents.len(),
                total_so_far = total,
                "Indexed artifact batch"
            );
        }

        self.set_refresh_interval(ARTIFACTS_INDEX, "1s").await?;
        self.force_refresh(ARTIFACTS_INDEX).await?;

        tracing::info!("Artifact reindex complete: {} documents indexed", total);
        Ok(total)
    }

    /// Reindex all repositories from the database into OpenSearch.
    ///
    /// Uses cursor-based pagination to avoid loading all rows into memory.
    /// Repositories inserted concurrently during a reindex may be skipped;
    /// they are indexed individually via [`index_repository`] on creation.
    pub async fn full_reindex_repositories(&self, db: &PgPool) -> Result<usize> {
        tracing::info!("Starting full repository reindex");

        self.set_refresh_interval(REPOSITORIES_INDEX, "-1").await?;

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
            let batch_len = documents.len();

            self.bulk_index(REPOSITORIES_INDEX, &documents)
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to batch index repositories (after {} documents, batch of {}): {}",
                        total, batch_len, e
                    ))
                })?;
            total += batch_len;

            tracing::info!(
                batch = documents.len(),
                total_so_far = total,
                "Indexed repository batch"
            );
        }

        self.set_refresh_interval(REPOSITORIES_INDEX, "1s").await?;
        self.force_refresh(REPOSITORIES_INDEX).await?;

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

    /// Return the cluster health status: `"green"`, `"yellow"`, or `"red"`.
    pub async fn cluster_health(&self) -> Result<String> {
        let response = self
            .client
            .cluster()
            .health(ClusterHealthParts::None)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to get cluster health: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Cluster health check failed (HTTP {}): {}",
                status, text
            )));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse cluster health: {}", e)))?;

        let health = body["status"].as_str().unwrap_or("red").to_string();

        Ok(health)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Create an index if it does not already exist.
    async fn ensure_index(&self, name: &str, body: Value) -> Result<()> {
        let exists = self
            .client
            .indices()
            .exists(IndicesExistsParts::Index(&[name]))
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to check if index '{}' exists: {}", name, e))
            })?;

        if exists.status_code().is_success() {
            tracing::debug!("Index '{}' already exists, skipping creation", name);
            return Ok(());
        }

        let response = self
            .client
            .indices()
            .create(IndicesCreateParts::Index(name))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create index '{}': {}", name, e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Failed to create index '{}' (HTTP {}): {}",
                name, status, text
            )));
        }

        tracing::info!("Created OpenSearch index '{}'", name);
        Ok(())
    }

    /// Bulk-index a slice of serializable documents into the given index.
    ///
    /// Each document must have an `id` field used as the `_id`. The method
    /// builds an NDJSON body (action + source pairs) and sends it to the
    /// `_bulk` endpoint.
    async fn bulk_index<T: Serialize + HasId>(&self, index: &str, docs: &[T]) -> Result<()> {
        if docs.is_empty() {
            return Ok(());
        }

        let mut ndjson_body: Vec<JsonBody<Value>> = Vec::with_capacity(docs.len() * 2);
        for doc in docs {
            ndjson_body.push(json!({ "index": { "_index": index, "_id": doc.doc_id() } }).into());
            let source = serde_json::to_value(doc).map_err(|e| {
                AppError::Internal(format!("Failed to serialize document for bulk: {}", e))
            })?;
            ndjson_body.push(source.into());
        }

        let response = self
            .client
            .bulk(BulkParts::Index(index))
            .body(ndjson_body)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Bulk index request failed: {}", e)))?;

        let status = response.status_code();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Bulk index failed (HTTP {}): {}",
                status, text
            )));
        }

        // Check for per-item errors in the bulk response
        let body: Value = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse bulk response: {}", e)))?;

        if body["errors"].as_bool() == Some(true) {
            // Count failing items for the error message rather than dumping
            // the entire response, which can be very large.
            let failed = body["items"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter(|item| item["index"]["status"].as_u64().map_or(true, |s| s >= 400))
                        .count()
                })
                .unwrap_or(0);
            return Err(AppError::Internal(format!(
                "Bulk index had {} failed items out of {}",
                failed,
                docs.len()
            )));
        }

        Ok(())
    }

    /// Change the refresh interval for an index.
    ///
    /// Set to `"-1"` to disable automatic refreshing during bulk ingestion,
    /// then restore to `"1s"` (the OpenSearch default) afterward.
    async fn set_refresh_interval(&self, index: &str, interval: &str) -> Result<()> {
        let body = json!({
            "index": {
                "refresh_interval": interval
            }
        });

        let response = self
            .client
            .indices()
            .put_settings(opensearch::indices::IndicesPutSettingsParts::Index(&[
                index,
            ]))
            .body(body)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to set refresh_interval on '{}': {}",
                    index, e
                ))
            })?;

        if !response.status_code().is_success() {
            let text = response.text().await.unwrap_or_default();
            tracing::warn!(
                "Failed to set refresh_interval='{}' on index '{}': {}",
                interval,
                index,
                text
            );
        }

        Ok(())
    }

    /// Force a refresh of the index so all indexed documents become searchable.
    async fn force_refresh(&self, index: &str) -> Result<()> {
        let response = self
            .client
            .indices()
            .refresh(IndicesRefreshParts::Index(&[index]))
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to refresh index '{}': {}", index, e))
            })?;

        if !response.status_code().is_success() {
            let text = response.text().await.unwrap_or_default();
            tracing::warn!("Failed to refresh index '{}': {}", index, text);
        }

        Ok(())
    }

    /// Index body for the `artifacts` index.
    ///
    /// Custom analyzers:
    /// - `path_analyzer`: uses the `path_hierarchy` tokenizer so queries for
    ///   `com/example` match `com/example/lib/1.0/lib-1.0.jar`.
    /// - `name_ngram_analyzer`: uses an `edge_ngram` filter (min 2, max 20)
    ///   so typing `my-art` matches `my-artifact`.
    fn artifacts_index_body() -> Value {
        json!({
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "analysis": {
                    "tokenizer": {
                        "path_tokenizer": {
                            "type": "path_hierarchy"
                        }
                    },
                    "filter": {
                        "edge_ngram_filter": {
                            "type": "edge_ngram",
                            "min_gram": 2,
                            "max_gram": 20
                        }
                    },
                    "analyzer": {
                        "path_analyzer": {
                            "tokenizer": "path_tokenizer"
                        },
                        "name_ngram_analyzer": {
                            "tokenizer": "standard",
                            "filter": ["lowercase", "edge_ngram_filter"]
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    "id":              { "type": "keyword" },
                    "name": {
                        "type": "text",
                        "analyzer": "name_ngram_analyzer",
                        "search_analyzer": "standard",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "path": {
                        "type": "text",
                        "analyzer": "path_analyzer",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "version": {
                        "type": "text",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "format":          { "type": "keyword" },
                    "repository_id":   { "type": "keyword" },
                    "repository_key":  { "type": "keyword" },
                    "repository_name": {
                        "type": "text",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "content_type":    { "type": "keyword" },
                    "size_bytes":      { "type": "long" },
                    "download_count":  { "type": "long" },
                    "is_public":       { "type": "boolean" },
                    "created_at":      { "type": "long" }
                }
            }
        })
    }

    /// Index body for the `repositories` index.
    fn repositories_index_body() -> Value {
        json!({
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "analysis": {
                    "filter": {
                        "edge_ngram_filter": {
                            "type": "edge_ngram",
                            "min_gram": 2,
                            "max_gram": 20
                        }
                    },
                    "analyzer": {
                        "name_ngram_analyzer": {
                            "tokenizer": "standard",
                            "filter": ["lowercase", "edge_ngram_filter"]
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    "id":          { "type": "keyword" },
                    "name": {
                        "type": "text",
                        "analyzer": "name_ngram_analyzer",
                        "search_analyzer": "standard",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "key": {
                        "type": "text",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "description": { "type": "text" },
                    "format":      { "type": "keyword" },
                    "repo_type":   { "type": "keyword" },
                    "is_public":   { "type": "boolean" },
                    "created_at":  { "type": "long" }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Trait for extracting document IDs in bulk_index
// ---------------------------------------------------------------------------

trait HasId {
    fn doc_id(&self) -> &str;
}

impl HasId for ArtifactDocument {
    fn doc_id(&self) -> &str {
        &self.id
    }
}

impl HasId for RepositoryDocument {
    fn doc_id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// Internal row types for reindex queries
// ---------------------------------------------------------------------------

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
    is_public: bool,
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

// ---------------------------------------------------------------------------
// Batch builders and row-to-document converters
// ---------------------------------------------------------------------------

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
        is_public: row.is_public,
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

// ---------------------------------------------------------------------------
// Filter and sort translation
// ---------------------------------------------------------------------------

/// Translate a Meilisearch-style filter string into a vec of OpenSearch
/// bool filter clauses.
///
/// Supported operators: `=`, `!=`, `>`, `>=`, `<`, `<=`, `AND`.
/// Boolean values (`true`/`false`) and numeric values are handled.
///
/// Examples:
/// - `"format = maven"` -> `[{"term": {"format": "maven"}}]`
/// - `"format = maven AND repository_key = libs-release"` ->
///   `[{"term": {"format": "maven"}}, {"term": {"repository_key": "libs-release"}}]`
/// - `"size_bytes > 1024"` -> `[{"range": {"size_bytes": {"gt": 1024}}}]`
/// - `"is_public = true"` -> `[{"term": {"is_public": true}}]`
fn translate_filter(filter: &str) -> Vec<Value> {
    let mut clauses = Vec::new();

    // Split on AND (case-insensitive)
    let parts: Vec<&str> = filter.split(" AND ").collect();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some(clause) = parse_single_filter(part) {
            clauses.push(clause);
        }
    }

    clauses
}

/// Parse a single filter expression like `field = value` or `field > 42`.
fn parse_single_filter(expr: &str) -> Option<Value> {
    // Order matters: check two-char operators before single-char
    let operators = ["!=", ">=", "<=", "=", ">", "<"];

    for op in &operators {
        if let Some(pos) = expr.find(op) {
            let field = expr[..pos].trim();
            let value_str = expr[pos + op.len()..].trim();

            if field.is_empty() || value_str.is_empty() {
                continue;
            }

            // Strip surrounding quotes from value
            let value_str = value_str.trim_matches('"').trim_matches('\'');

            return Some(match *op {
                "=" => {
                    let val = parse_filter_value(value_str);
                    json!({ "term": { field: val } })
                }
                "!=" => {
                    let val = parse_filter_value(value_str);
                    json!({ "bool": { "must_not": [{ "term": { field: val } }] } })
                }
                ">" => {
                    let val = parse_filter_value(value_str);
                    json!({ "range": { field: { "gt": val } } })
                }
                ">=" => {
                    let val = parse_filter_value(value_str);
                    json!({ "range": { field: { "gte": val } } })
                }
                "<" => {
                    let val = parse_filter_value(value_str);
                    json!({ "range": { field: { "lt": val } } })
                }
                "<=" => {
                    let val = parse_filter_value(value_str);
                    json!({ "range": { field: { "lte": val } } })
                }
                _ => continue,
            });
        }
    }

    None
}

/// Parse a filter value string into a serde_json::Value, detecting booleans
/// and numbers.
fn parse_filter_value(s: &str) -> Value {
    match s {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => {
            if let Ok(n) = s.parse::<i64>() {
                Value::Number(n.into())
            } else if let Ok(n) = s.parse::<f64>() {
                serde_json::Number::from_f64(n)
                    .map(Value::Number)
                    .unwrap_or_else(|| Value::String(s.to_string()))
            } else {
                Value::String(s.to_string())
            }
        }
    }
}

/// Translate Meilisearch-style sort specs into OpenSearch sort clauses.
///
/// Input format: `["field:asc", "field:desc"]`
/// Output: `[{"field": {"order": "asc"}}, ...]`
///
/// For text fields with keyword sub-fields, the `.keyword` suffix is added
/// automatically.
fn translate_sort(specs: &[&str]) -> Vec<Value> {
    let text_fields_with_keyword = ["name", "version", "key", "repository_name"];

    specs
        .iter()
        .filter_map(|spec| {
            let parts: Vec<&str> = spec.splitn(2, ':').collect();
            if parts.is_empty() {
                return None;
            }
            let field = parts[0].trim();
            let order = parts.get(1).map(|s| s.trim()).unwrap_or("asc");

            let sort_field = if text_fields_with_keyword.contains(&field) {
                format!("{}.keyword", field)
            } else {
                field.to_string()
            };

            Some(json!({ sort_field: { "order": order } }))
        })
        .collect()
}

/// Parse an OpenSearch search response body into [`SearchResults`].
fn parse_search_response<T: for<'de> Deserialize<'de>>(
    query: &str,
    body: &Value,
) -> Result<SearchResults<T>> {
    let took = body["took"].as_u64().unwrap_or(0) as usize;
    let total_hits = body["hits"]["total"]["value"].as_u64().unwrap_or(0) as usize;

    let hits: Vec<T> = body["hits"]["hits"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|hit| serde_json::from_value::<T>(hit["_source"].clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(SearchResults {
        hits,
        total_hits,
        processing_time_ms: took,
        query: query.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    fn opensearch_service_source() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/services/opensearch_service.rs"
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
        let source = function_source(opensearch_service_source(), "full_reindex");
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
        let source = function_source(opensearch_service_source(), "new");
        assert!(
            source.contains("-> Result<Self>"),
            "OpenSearchService::new should return Result<Self>"
        );
    }

    #[test]
    fn test_new_with_invalid_url() {
        let result = OpenSearchService::new("not a url", None, None, false);
        assert!(result.is_err(), "Invalid URL should produce an error");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Invalid OpenSearch URL"),
            "Error should mention invalid URL: {}",
            err_msg
        );
    }

    #[test]
    fn test_new_with_valid_url() {
        let result = OpenSearchService::new("http://localhost:9200", None, None, false);
        assert!(result.is_ok(), "Valid URL should create a service");
    }

    #[test]
    fn test_new_with_credentials() {
        let result = OpenSearchService::new(
            "https://opensearch.example.com:9200",
            Some("admin"),
            Some("admin"),
            true,
        );
        assert!(
            result.is_ok(),
            "Should construct with username, password, and allow_invalid_certs"
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
        let page_size: i64 = BATCH_SIZE as i64;
        assert_eq!(page_size, 1000);
        assert!(page_size > 0);
    }

    #[test]
    fn test_full_reindex_artifacts_uses_cursor_pagination_without_offset() {
        let source = function_source(opensearch_service_source(), "full_reindex_artifacts");

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
        let source = function_source(opensearch_service_source(), "full_reindex_repositories");

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
        let source = function_source(opensearch_service_source(), "full_reindex_artifacts");

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
            is_public: false,
        };
        let doc = artifact_document_from_row(row, 0);
        assert_eq!(doc.download_count, 0);
        assert!(!doc.is_public);
    }

    #[test]
    fn test_full_reindex_artifacts_errors_include_progress_context() {
        let source = function_source(opensearch_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("after {} documents"),
            "artifact reindex errors should include the count of documents indexed so far"
        );
    }

    #[test]
    fn test_full_reindex_repositories_errors_include_progress_context() {
        let source = function_source(opensearch_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("after {} documents"),
            "repository reindex errors should include the count of documents indexed so far"
        );
    }

    #[test]
    fn test_full_reindex_artifacts_logs_batch_progress() {
        let source = function_source(opensearch_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("Indexed artifact batch"),
            "artifact reindex should log progress after each batch"
        );
    }

    #[test]
    fn test_full_reindex_repositories_logs_batch_progress() {
        let source = function_source(opensearch_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("Indexed repository batch"),
            "repository reindex should log progress after each batch"
        );
    }

    #[test]
    fn test_full_reindex_artifacts_returns_count() {
        let source = function_source(opensearch_service_source(), "full_reindex_artifacts");
        assert!(
            source.contains("Result<usize>"),
            "full_reindex_artifacts should return Result<usize>"
        );
    }

    #[test]
    fn test_full_reindex_repositories_returns_count() {
        let source = function_source(opensearch_service_source(), "full_reindex_repositories");
        assert!(
            source.contains("Result<usize>"),
            "full_reindex_repositories should return Result<usize>"
        );
    }

    #[test]
    fn test_full_reindex_logs_phase_completion() {
        let source = function_source(opensearch_service_source(), "full_reindex");
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
            is_public: true,
        };

        let doc = artifact_document_from_row(row, 5);

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.repository_id, repo_id.to_string());
        assert_eq!(doc.size_bytes, 4096);
        assert_eq!(doc.download_count, 5);
        assert!(doc.is_public);
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
            is_public: true,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"name\":\"my-artifact\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"format\":\"maven\""));
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1048576"));
        assert!(json.contains("\"is_public\":true"));
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
            "is_public": false,
            "created_at": 1700000000
        });

        let doc: ArtifactDocument = serde_json::from_value(json_val).unwrap();
        assert_eq!(doc.id, "abc-123");
        assert_eq!(doc.name, "pkg");
        assert!(doc.version.is_none());
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.size_bytes, 512);
        assert_eq!(doc.download_count, 0);
        assert!(!doc.is_public);
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
            is_public: true,
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
        assert_eq!(doc.is_public, deserialized.is_public);
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
            is_public: false,
            created_at: 0,
        };
        let cloned = doc.clone();
        assert_eq!(doc.id, cloned.id);
        assert_eq!(doc.name, cloned.name);
        assert_eq!(doc.is_public, cloned.is_public);
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
            is_public: true,
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
            is_public: true,
        };

        let doc = artifact_document_from_row(row, 7);

        assert_eq!(doc.id, id.to_string());
        assert_eq!(doc.name, "my-lib");
        assert_eq!(doc.version, Some("1.0".to_string()));
        assert_eq!(doc.repository_key, "maven-local");
        assert_eq!(doc.download_count, 7);
        assert!(doc.is_public);
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
            is_public: true,
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

    // -----------------------------------------------------------------------
    // Filter translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_translate_filter_simple_equality() {
        let clauses = translate_filter("format = maven");
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0], json!({ "term": { "format": "maven" } }));
    }

    #[test]
    fn test_translate_filter_compound_and() {
        let clauses = translate_filter("format = maven AND repository_key = libs-release");
        assert_eq!(clauses.len(), 2);
        assert_eq!(clauses[0], json!({ "term": { "format": "maven" } }));
        assert_eq!(
            clauses[1],
            json!({ "term": { "repository_key": "libs-release" } })
        );
    }

    #[test]
    fn test_translate_filter_inequality() {
        let clauses = translate_filter("format != docker");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            clauses[0],
            json!({ "bool": { "must_not": [{ "term": { "format": "docker" } }] } })
        );
    }

    #[test]
    fn test_translate_filter_range_gt() {
        let clauses = translate_filter("size_bytes > 1024");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            clauses[0],
            json!({ "range": { "size_bytes": { "gt": 1024 } } })
        );
    }

    #[test]
    fn test_translate_filter_range_gte() {
        let clauses = translate_filter("size_bytes >= 1024");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            clauses[0],
            json!({ "range": { "size_bytes": { "gte": 1024 } } })
        );
    }

    #[test]
    fn test_translate_filter_range_lt() {
        let clauses = translate_filter("created_at < 1700000000");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            clauses[0],
            json!({ "range": { "created_at": { "lt": 1700000000_i64 } } })
        );
    }

    #[test]
    fn test_translate_filter_range_lte() {
        let clauses = translate_filter("created_at <= 1700000000");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            clauses[0],
            json!({ "range": { "created_at": { "lte": 1700000000_i64 } } })
        );
    }

    #[test]
    fn test_translate_filter_boolean_value() {
        let clauses = translate_filter("is_public = true");
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0], json!({ "term": { "is_public": true } }));

        let clauses = translate_filter("is_public = false");
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0], json!({ "term": { "is_public": false } }));
    }

    #[test]
    fn test_translate_filter_empty_string() {
        let clauses = translate_filter("");
        assert!(clauses.is_empty());
    }

    // -----------------------------------------------------------------------
    // Sort translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_translate_sort_single_desc() {
        let sort = translate_sort(&["created_at:desc"]);
        assert_eq!(sort.len(), 1);
        assert_eq!(sort[0], json!({ "created_at": { "order": "desc" } }));
    }

    #[test]
    fn test_translate_sort_single_asc() {
        let sort = translate_sort(&["size_bytes:asc"]);
        assert_eq!(sort.len(), 1);
        assert_eq!(sort[0], json!({ "size_bytes": { "order": "asc" } }));
    }

    #[test]
    fn test_translate_sort_text_field_uses_keyword() {
        let sort = translate_sort(&["name:asc"]);
        assert_eq!(sort.len(), 1);
        assert_eq!(sort[0], json!({ "name.keyword": { "order": "asc" } }));
    }

    #[test]
    fn test_translate_sort_multiple() {
        let sort = translate_sort(&["name:desc", "created_at:asc"]);
        assert_eq!(sort.len(), 2);
        assert_eq!(sort[0], json!({ "name.keyword": { "order": "desc" } }));
        assert_eq!(sort[1], json!({ "created_at": { "order": "asc" } }));
    }

    #[test]
    fn test_translate_sort_no_order_defaults_to_asc() {
        let sort = translate_sort(&["download_count"]);
        assert_eq!(sort.len(), 1);
        assert_eq!(sort[0], json!({ "download_count": { "order": "asc" } }));
    }

    #[test]
    fn test_translate_sort_empty() {
        let sort = translate_sort(&[]);
        assert!(sort.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_search_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_search_response_empty_hits() {
        let body = json!({
            "took": 5,
            "hits": {
                "total": { "value": 0 },
                "hits": []
            }
        });

        let result: SearchResults<ArtifactDocument> = parse_search_response("test", &body).unwrap();
        assert_eq!(result.total_hits, 0);
        assert_eq!(result.processing_time_ms, 5);
        assert_eq!(result.query, "test");
        assert!(result.hits.is_empty());
    }

    #[test]
    fn test_parse_search_response_with_hits() {
        let body = json!({
            "took": 12,
            "hits": {
                "total": { "value": 1 },
                "hits": [
                    {
                        "_id": "abc",
                        "_source": {
                            "id": "abc",
                            "name": "my-repo",
                            "key": "my-repo",
                            "description": null,
                            "format": "npm",
                            "repo_type": "local",
                            "is_public": true,
                            "created_at": 1700000000
                        }
                    }
                ]
            }
        });

        let result: SearchResults<RepositoryDocument> =
            parse_search_response("npm", &body).unwrap();
        assert_eq!(result.total_hits, 1);
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].name, "my-repo");
    }

    // -----------------------------------------------------------------------
    // parse_filter_value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_filter_value_bool() {
        assert_eq!(parse_filter_value("true"), Value::Bool(true));
        assert_eq!(parse_filter_value("false"), Value::Bool(false));
    }

    #[test]
    fn test_parse_filter_value_integer() {
        assert_eq!(parse_filter_value("42"), json!(42));
        assert_eq!(parse_filter_value("0"), json!(0));
        assert_eq!(parse_filter_value("-1"), json!(-1));
    }

    #[test]
    fn test_parse_filter_value_string() {
        assert_eq!(parse_filter_value("maven"), json!("maven"));
        assert_eq!(parse_filter_value("libs-release"), json!("libs-release"));
    }

    // -----------------------------------------------------------------------
    // Index body validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifacts_index_body_has_path_hierarchy_tokenizer() {
        let body = OpenSearchService::artifacts_index_body();
        let tokenizer_type = body["settings"]["analysis"]["tokenizer"]["path_tokenizer"]["type"]
            .as_str()
            .unwrap();
        assert_eq!(tokenizer_type, "path_hierarchy");
    }

    #[test]
    fn test_artifacts_index_body_has_edge_ngram_filter() {
        let body = OpenSearchService::artifacts_index_body();
        let filter_type = body["settings"]["analysis"]["filter"]["edge_ngram_filter"]["type"]
            .as_str()
            .unwrap();
        assert_eq!(filter_type, "edge_ngram");
    }

    #[test]
    fn test_artifacts_index_body_has_is_public_mapping() {
        let body = OpenSearchService::artifacts_index_body();
        let is_public_type = body["mappings"]["properties"]["is_public"]["type"]
            .as_str()
            .unwrap();
        assert_eq!(is_public_type, "boolean");
    }

    #[test]
    fn test_repositories_index_body_has_name_ngram_analyzer() {
        let body = OpenSearchService::repositories_index_body();
        let analyzer = &body["settings"]["analysis"]["analyzer"]["name_ngram_analyzer"];
        assert_eq!(analyzer["tokenizer"].as_str().unwrap(), "standard");
        let filters = analyzer["filter"].as_array().unwrap();
        assert!(filters.contains(&json!("edge_ngram_filter")));
    }

    // -----------------------------------------------------------------------
    // HasId trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_document_has_id() {
        let doc = ArtifactDocument {
            id: "test-id-123".to_string(),
            name: "n".to_string(),
            path: "p".to_string(),
            version: None,
            format: "generic".to_string(),
            repository_id: "r".to_string(),
            repository_key: "k".to_string(),
            repository_name: "n".to_string(),
            content_type: "a".to_string(),
            size_bytes: 0,
            download_count: 0,
            is_public: false,
            created_at: 0,
        };
        assert_eq!(doc.doc_id(), "test-id-123");
    }

    #[test]
    fn test_repository_document_has_id() {
        let doc = RepositoryDocument {
            id: "repo-id-456".to_string(),
            name: "n".to_string(),
            key: "k".to_string(),
            description: None,
            format: "npm".to_string(),
            repo_type: "local".to_string(),
            is_public: false,
            created_at: 0,
        };
        assert_eq!(doc.doc_id(), "repo-id-456");
    }
}
