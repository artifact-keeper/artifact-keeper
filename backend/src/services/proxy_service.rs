//! Proxy service for remote/proxy repositories.
//!
//! Handles fetching artifacts from upstream repositories with caching support.
//! Implements cache TTL, ETag validation, and transparent proxying.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::storage_service::StorageService;

/// Default cache TTL in seconds (24 hours)
const DEFAULT_CACHE_TTL_SECS: i64 = 86400;

/// HTTP client timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 60;

/// Cache metadata for a proxied artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// When the artifact was cached
    pub cached_at: DateTime<Utc>,
    /// ETag from upstream (if available)
    pub upstream_etag: Option<String>,
    /// When the cache entry expires
    pub expires_at: DateTime<Utc>,
    /// Content type from upstream
    pub content_type: Option<String>,
    /// Size of the cached content
    pub size_bytes: i64,
    /// SHA-256 checksum of cached content
    pub checksum_sha256: String,
}

/// Proxy service for fetching and caching artifacts from upstream repositories
pub struct ProxyService {
    db: PgPool,
    storage: Arc<StorageService>,
    http_client: Client,
}

impl ProxyService {
    /// Create a new proxy service
    pub fn new(db: PgPool, storage: Arc<StorageService>) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent("artifact-keeper-proxy/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            db,
            storage,
            http_client,
        }
    }

    /// Fetch artifact from upstream if not cached or cache expired.
    /// Returns (content, content_type) tuple.
    pub async fn fetch_artifact(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        // Validate repository type
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        // Get upstream URL
        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        // Generate storage key for cached artifact
        let cache_key = Self::cache_storage_key(&repo.key, path);
        let metadata_key = Self::cache_metadata_key(&repo.key, path);

        // Check if we have a valid cached copy
        if let Some((content, content_type)) =
            self.get_cached_artifact(&cache_key, &metadata_key).await?
        {
            return Ok((content, content_type));
        }

        // Fetch from upstream
        let full_url = Self::build_upstream_url(upstream_url, path);
        let (content, content_type, etag) = self.fetch_from_upstream(&full_url).await?;

        // Cache the artifact
        let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
        self.cache_artifact(&cache_key, &metadata_key, &content, content_type.clone(), etag, cache_ttl)
            .await?;

        Ok((content, content_type))
    }

    /// Check if upstream has a newer version of the artifact.
    /// Returns true if upstream has newer content or cache is expired.
    pub async fn check_upstream(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<bool> {
        // Validate repository type
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let metadata_key = Self::cache_metadata_key(&repo.key, path);

        // Try to load existing cache metadata
        let metadata = match self.load_cache_metadata(&metadata_key).await? {
            Some(m) => m,
            None => return Ok(true), // No cache, definitely need to fetch
        };

        // Check if cache has expired
        if Utc::now() > metadata.expires_at {
            return Ok(true);
        }

        // If we have an ETag, do a conditional request
        if let Some(ref etag) = metadata.upstream_etag {
            let full_url = Self::build_upstream_url(upstream_url, path);
            return self.check_etag_changed(&full_url, etag).await;
        }

        // No ETag, rely on TTL - cache is still valid
        Ok(false)
    }

    /// Invalidate cached artifact
    pub async fn invalidate_cache(&self, repo: &Repository, path: &str) -> Result<()> {
        let cache_key = Self::cache_storage_key(&repo.key, path);
        let metadata_key = Self::cache_metadata_key(&repo.key, path);

        // Delete both content and metadata
        let _ = self.storage.delete(&cache_key).await;
        let _ = self.storage.delete(&metadata_key).await;

        Ok(())
    }

    /// Get cache TTL configuration for a repository.
    /// Returns TTL in seconds.
    async fn get_cache_ttl_for_repo(&self, repo_id: Uuid) -> i64 {
        // Try to get repository-specific TTL from config table
        // For now, use default TTL. This can be extended to read from
        // a repository_config table or the repository record itself.
        let result = sqlx::query_scalar!(
            r#"
            SELECT value FROM repository_config
            WHERE repository_id = $1 AND key = 'cache_ttl_secs'
            "#,
            repo_id
        )
        .fetch_optional(&self.db)
        .await;

        match result {
            Ok(Some(value)) => {
                if let Some(v) = value {
                    v.parse().unwrap_or(DEFAULT_CACHE_TTL_SECS)
                } else {
                    DEFAULT_CACHE_TTL_SECS
                }
            }
            _ => DEFAULT_CACHE_TTL_SECS,
        }
    }

    /// Build full upstream URL for an artifact path
    fn build_upstream_url(base_url: &str, path: &str) -> String {
        let base = base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{}/{}", base, path)
    }

    /// Generate storage key for cached artifact content
    fn cache_storage_key(repo_key: &str, path: &str) -> String {
        format!("proxy-cache/{}/{}", repo_key, path.trim_start_matches('/'))
    }

    /// Generate storage key for cache metadata
    fn cache_metadata_key(repo_key: &str, path: &str) -> String {
        format!(
            "proxy-cache/{}/{}.__metadata__.json",
            repo_key,
            path.trim_start_matches('/')
        )
    }

    /// Attempt to retrieve a cached artifact if valid
    async fn get_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Check if metadata exists
        let metadata = match self.load_cache_metadata(metadata_key).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Check if cache has expired
        if Utc::now() > metadata.expires_at {
            tracing::debug!("Cache expired for {}", cache_key);
            return Ok(None);
        }

        // Try to get cached content
        match self.storage.get(cache_key).await {
            Ok(content) => {
                // Verify checksum
                let actual_checksum = StorageService::calculate_hash(&content);
                if actual_checksum != metadata.checksum_sha256 {
                    tracing::warn!(
                        "Cache checksum mismatch for {}: expected {}, got {}",
                        cache_key,
                        metadata.checksum_sha256,
                        actual_checksum
                    );
                    return Ok(None);
                }

                tracing::debug!("Cache hit for {}", cache_key);
                Ok(Some((content, metadata.content_type)))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Load cache metadata from storage
    async fn load_cache_metadata(&self, metadata_key: &str) -> Result<Option<CacheMetadata>> {
        match self.storage.get(metadata_key).await {
            Ok(data) => {
                let metadata: CacheMetadata = serde_json::from_slice(&data)?;
                Ok(Some(metadata))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch artifact from upstream URL
    async fn fetch_from_upstream(
        &self,
        url: &str,
    ) -> Result<(Bytes, Option<String>, Option<String>)> {
        tracing::info!("Fetching artifact from upstream: {}", url);

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to fetch from upstream: {}", e)))?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(AppError::NotFound(format!(
                "Artifact not found at upstream: {}",
                url
            )));
        }

        if !status.is_success() {
            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status,
                url
            )));
        }

        // Extract headers before consuming response
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let content = response
            .bytes()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read upstream response: {}", e)))?;

        tracing::info!(
            "Fetched {} bytes from upstream (content_type: {:?}, etag: {:?})",
            content.len(),
            content_type,
            etag
        );

        Ok((content, content_type, etag))
    }

    /// Cache artifact content and metadata
    async fn cache_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
        content: &Bytes,
        content_type: Option<String>,
        etag: Option<String>,
        ttl_secs: i64,
    ) -> Result<()> {
        // Calculate checksum
        let checksum = StorageService::calculate_hash(content);

        // Create metadata
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: etag,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            content_type,
            size_bytes: content.len() as i64,
            checksum_sha256: checksum,
        };

        // Store content
        self.storage.put(cache_key, content.clone()).await?;

        // Store metadata
        let metadata_json = serde_json::to_vec(&metadata)?;
        self.storage
            .put(metadata_key, Bytes::from(metadata_json))
            .await?;

        tracing::debug!(
            "Cached artifact {} ({} bytes, expires at {})",
            cache_key,
            content.len(),
            metadata.expires_at
        );

        Ok(())
    }

    /// Check if upstream ETag has changed (returns true if changed/newer)
    async fn check_etag_changed(&self, url: &str, cached_etag: &str) -> Result<bool> {
        let response = self
            .http_client
            .head(url)
            .header(IF_NONE_MATCH, cached_etag)
            .send()
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to check upstream for changes: {}", e))
            })?;

        match response.status() {
            StatusCode::NOT_MODIFIED => {
                tracing::debug!("Upstream unchanged (304 Not Modified) for {}", url);
                Ok(false)
            }
            StatusCode::OK => {
                // Check if ETag in response differs
                let new_etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|v| v.to_str().ok());

                match new_etag {
                    Some(etag) if etag == cached_etag => {
                        tracing::debug!("Upstream ETag unchanged for {}", url);
                        Ok(false)
                    }
                    _ => {
                        tracing::debug!("Upstream has newer content for {}", url);
                        Ok(true)
                    }
                }
            }
            status => {
                tracing::warn!(
                    "Unexpected status {} checking upstream {}, assuming changed",
                    status,
                    url
                );
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upstream_url() {
        // Test basic URL building
        assert_eq!(
            ProxyService::build_upstream_url("https://repo.maven.apache.org/maven2", "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
            "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
        );

        // Test with trailing slash on base
        assert_eq!(
            ProxyService::build_upstream_url("https://registry.npmjs.org/", "express"),
            "https://registry.npmjs.org/express"
        );

        // Test with leading slash on path
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "/path/to/artifact"),
            "https://example.com/path/to/artifact"
        );
    }

    #[test]
    fn test_cache_storage_key() {
        assert_eq!(
            ProxyService::cache_storage_key("maven-central", "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
            "proxy-cache/maven-central/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
        );
    }

    #[test]
    fn test_cache_metadata_key() {
        assert_eq!(
            ProxyService::cache_metadata_key("npm-registry", "express"),
            "proxy-cache/npm-registry/express.__metadata__.json"
        );
    }

    #[test]
    fn test_cache_metadata_serialization() {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: Some("\"abc123\"".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 1024,
            checksum_sha256: "a".repeat(64),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.upstream_etag, parsed.upstream_etag);
        assert_eq!(metadata.size_bytes, parsed.size_bytes);
        assert_eq!(metadata.checksum_sha256, parsed.checksum_sha256);
    }
}
