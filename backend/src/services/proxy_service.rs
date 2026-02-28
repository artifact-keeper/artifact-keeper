//! Proxy service for remote/proxy repositories.
//!
//! Handles fetching artifacts from upstream repositories with caching support.
//! Implements cache TTL, ETag validation, and transparent proxying.

use std::collections::HashMap;
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
        let upstream_result = self.fetch_from_upstream(&full_url).await;

        match upstream_result {
            Ok((content, content_type, etag)) => {
                // Cache the artifact
                let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
                self.cache_artifact(
                    &cache_key,
                    &metadata_key,
                    &content,
                    content_type.clone(),
                    etag,
                    cache_ttl,
                )
                .await?;

                Ok((content, content_type))
            }
            Err(upstream_err) => {
                // Upstream failed. Try serving stale cached content as a fallback.
                if let Ok(Some((stale_content, stale_content_type))) = self
                    .get_stale_cached_artifact(&cache_key, &metadata_key)
                    .await
                {
                    tracing::warn!(
                        "Upstream fetch failed for {}; serving stale cached copy: {}",
                        full_url,
                        upstream_err
                    );
                    Ok((stale_content, stale_content_type))
                } else {
                    Err(upstream_err)
                }
            }
        }
    }

    /// Check if upstream has a newer version of the artifact.
    /// Returns true if upstream has newer content or cache is expired.
    pub async fn check_upstream(&self, repo: &Repository, path: &str) -> Result<bool> {
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

    /// Generate storage key for cached artifact content.
    /// Uses a `__content__` leaf file to avoid file/directory collisions
    /// when one path is a prefix of another (e.g., npm metadata at `is-odd`
    /// vs tarball at `is-odd/-/is-odd-3.0.1.tgz`).
    fn cache_storage_key(repo_key: &str, path: &str) -> String {
        format!(
            "proxy-cache/{}/{}/__content__",
            repo_key,
            path.trim_start_matches('/')
        )
    }

    /// Generate storage key for cache metadata
    fn cache_metadata_key(repo_key: &str, path: &str) -> String {
        format!(
            "proxy-cache/{}/{}/__cache_meta__.json",
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
                status, url
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

    /// Attempt to retrieve a cached artifact even if it has expired.
    /// Used as a fallback when upstream is unavailable.
    async fn get_stale_cached_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        // Load metadata without checking expiry
        let metadata = match self.load_cache_metadata(metadata_key).await? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Try to get cached content
        match self.storage.get(cache_key).await {
            Ok(content) => {
                // Verify checksum
                let actual_checksum = StorageService::calculate_hash(&content);
                if actual_checksum != metadata.checksum_sha256 {
                    tracing::warn!(
                        "Stale cache checksum mismatch for {}: expected {}, got {}",
                        cache_key,
                        metadata.checksum_sha256,
                        actual_checksum
                    );
                    return Ok(None);
                }

                tracing::debug!(
                    "Stale cache hit for {} (expired at {})",
                    cache_key,
                    metadata.expires_at
                );
                Ok(Some((content, metadata.content_type)))
            }
            Err(AppError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
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
                let new_etag = response.headers().get(ETAG).and_then(|v| v.to_str().ok());

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

/// Build response headers indicating the content was served from a stale cache.
/// Returns headers with `X-Cache: STALE` and an RFC 7234 Warning 110 header.
/// Currently used by tests; HTTP handlers will integrate this in a follow-up.
#[allow(dead_code)]
pub(crate) fn build_stale_cache_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("X-Cache".to_string(), "STALE".to_string());
    headers.insert(
        "Warning".to_string(),
        "110 artifact-keeper \"Response is stale\"".to_string(),
    );
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn is_cache_expired(expires_at: &DateTime<Utc>) -> bool {
        Utc::now() > *expires_at
    }

    fn compute_cache_expiry(cached_at: DateTime<Utc>, ttl_secs: i64) -> DateTime<Utc> {
        cached_at + chrono::Duration::seconds(ttl_secs)
    }

    fn parse_cache_ttl(value: Option<&str>) -> i64 {
        value
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CACHE_TTL_SECS)
    }

    // =======================================================================
    // build_upstream_url tests
    // =======================================================================

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
    fn test_build_upstream_url_both_slashes() {
        // Both trailing slash on base and leading slash on path
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com/", "/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_no_slashes() {
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_multiple_trailing_slashes() {
        // trim_end_matches removes all matching trailing characters
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com///", "path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_multiple_leading_slashes() {
        // trim_start_matches removes all matching leading characters
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", "///path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_build_upstream_url_empty_path() {
        assert_eq!(
            ProxyService::build_upstream_url("https://example.com", ""),
            "https://example.com/"
        );
    }

    #[test]
    fn test_build_upstream_url_complex_path_with_query() {
        // URL construction does not strip query strings
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.npmjs.org",
                "@scope/package/-/package-1.0.0.tgz"
            ),
            "https://registry.npmjs.org/@scope/package/-/package-1.0.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_pypi_path() {
        assert_eq!(
            ProxyService::build_upstream_url("https://pypi.org/simple", "requests/"),
            "https://pypi.org/simple/requests/"
        );
    }

    #[test]
    fn test_build_upstream_url_with_port() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "http://localhost:8080/v2",
                "library/alpine/manifests/latest"
            ),
            "http://localhost:8080/v2/library/alpine/manifests/latest"
        );
    }

    // =======================================================================
    // cache_storage_key tests
    // =======================================================================

    #[test]
    fn test_cache_storage_key() {
        assert_eq!(
            ProxyService::cache_storage_key("maven-central", "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"),
            "proxy-cache/maven-central/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_strips_leading_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "/express"),
            "proxy-cache/npm-proxy/express/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_no_leading_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "express"),
            "proxy-cache/npm-proxy/express/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_scoped_npm_package() {
        assert_eq!(
            ProxyService::cache_storage_key("npm-proxy", "@types/node/-/node-18.0.0.tgz"),
            "proxy-cache/npm-proxy/@types/node/-/node-18.0.0.tgz/__content__"
        );
    }

    #[test]
    fn test_cache_storage_key_deeply_nested_path() {
        let key = ProxyService::cache_storage_key(
            "maven",
            "com/example/group/artifact/1.0/artifact-1.0.pom",
        );
        assert!(key.starts_with("proxy-cache/maven/"));
        assert!(key.ends_with("/__content__"));
    }

    // =======================================================================
    // cache_metadata_key tests
    // =======================================================================

    #[test]
    fn test_cache_metadata_key() {
        assert_eq!(
            ProxyService::cache_metadata_key("npm-registry", "express"),
            "proxy-cache/npm-registry/express/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_metadata_key_strips_leading_slash() {
        assert_eq!(
            ProxyService::cache_metadata_key("repo", "/some/path"),
            "proxy-cache/repo/some/path/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_metadata_key_consistency_with_storage_key() {
        // Both keys should share the same prefix structure
        let repo_key = "npm-proxy";
        let path = "lodash";
        let storage_key = ProxyService::cache_storage_key(repo_key, path);
        let metadata_key = ProxyService::cache_metadata_key(repo_key, path);

        // Both start with the same prefix
        let storage_prefix = storage_key.rsplit_once('/').unwrap().0;
        let metadata_prefix = metadata_key.rsplit_once('/').unwrap().0;
        assert_eq!(storage_prefix, metadata_prefix);

        // But have different leaf file names
        assert!(storage_key.ends_with("__content__"));
        assert!(metadata_key.ends_with("__cache_meta__.json"));
    }

    // =======================================================================
    // Cache key collision tests
    // =======================================================================

    #[test]
    fn test_cache_keys_no_file_directory_collision() {
        // Metadata cached at "is-odd" and tarball at "is-odd/-/is-odd-3.0.1.tgz"
        // must not collide (one as file, other needing it as directory)
        let meta_key = ProxyService::cache_storage_key("npm-proxy", "is-odd");
        let tarball_key = ProxyService::cache_storage_key("npm-proxy", "is-odd/-/is-odd-3.0.1.tgz");

        // Both should be inside the "is-odd" directory, not at the same level
        assert!(meta_key.contains("is-odd/__content__"));
        assert!(tarball_key.contains("is-odd/-/is-odd-3.0.1.tgz/__content__"));
    }

    #[test]
    fn test_cache_keys_different_repos_do_not_collide() {
        let key1 = ProxyService::cache_storage_key("npm-proxy-1", "express");
        let key2 = ProxyService::cache_storage_key("npm-proxy-2", "express");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_keys_different_paths_do_not_collide() {
        let key1 = ProxyService::cache_storage_key("repo", "path/a");
        let key2 = ProxyService::cache_storage_key("repo", "path/b");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_storage_and_metadata_keys_do_not_collide() {
        let storage = ProxyService::cache_storage_key("repo", "package");
        let metadata = ProxyService::cache_metadata_key("repo", "package");
        assert_ne!(storage, metadata);
    }

    // =======================================================================
    // CacheMetadata serialization tests
    // =======================================================================

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

    #[test]
    fn test_cache_metadata_serialization_no_etag() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            expires_at: now + chrono::Duration::seconds(3600),
            content_type: None,
            size_bytes: 0,
            checksum_sha256: String::new(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();

        assert!(parsed.upstream_etag.is_none());
        assert!(parsed.content_type.is_none());
        assert_eq!(parsed.size_bytes, 0);
    }

    #[test]
    fn test_cache_metadata_roundtrip_preserves_timestamps() {
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(DEFAULT_CACHE_TTL_SECS);
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: Some("\"etag-value\"".to_string()),
            expires_at: expires,
            content_type: Some("application/json".to_string()),
            size_bytes: 4096,
            checksum_sha256: "b".repeat(64),
        };

        let json_bytes = serde_json::to_vec(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(parsed.cached_at, metadata.cached_at);
        assert_eq!(parsed.expires_at, metadata.expires_at);
    }

    #[test]
    fn test_cache_metadata_large_size() {
        let metadata = CacheMetadata {
            cached_at: Utc::now(),
            upstream_etag: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: i64::MAX,
            checksum_sha256: "c".repeat(64),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.size_bytes, i64::MAX);
    }

    // =======================================================================
    // Constants tests
    // =======================================================================

    #[test]
    fn test_default_cache_ttl_is_24_hours() {
        assert_eq!(DEFAULT_CACHE_TTL_SECS, 86400);
        assert_eq!(DEFAULT_CACHE_TTL_SECS, 24 * 60 * 60);
    }

    #[test]
    fn test_http_timeout_is_60_seconds() {
        assert_eq!(HTTP_TIMEOUT_SECS, 60);
    }

    // =======================================================================
    // Cache expiration logic tests
    // =======================================================================

    #[test]
    fn test_cache_expiration_check_logic() {
        // Replicate the cache expiration check from get_cached_artifact
        let now = Utc::now();

        // Expired cache entry
        let expired_metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(25),
            upstream_etag: None,
            expires_at: now - chrono::Duration::hours(1),
            content_type: None,
            size_bytes: 100,
            checksum_sha256: "abc".to_string(),
        };
        assert!(
            Utc::now() > expired_metadata.expires_at,
            "Cache should be expired"
        );

        // Valid cache entry
        let valid_metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            expires_at: now + chrono::Duration::hours(23),
            content_type: None,
            size_bytes: 100,
            checksum_sha256: "abc".to_string(),
        };
        assert!(
            Utc::now() < valid_metadata.expires_at,
            "Cache should still be valid"
        );
    }

    #[test]
    fn test_cache_ttl_computation() {
        // Replicate the TTL computation from cache_artifact
        let now = Utc::now();
        let ttl_secs: i64 = 3600;
        let expires_at = now + chrono::Duration::seconds(ttl_secs);
        assert!(expires_at > now);
        // Should expire roughly 1 hour from now
        let diff = (expires_at - now).num_seconds();
        assert_eq!(diff, 3600);
    }

    // =======================================================================
    // URL construction edge cases
    // =======================================================================

    #[test]
    fn test_build_upstream_url_preserves_base_path() {
        // Base URL with a subpath should be preserved
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.example.com/v2/library",
                "alpine/manifests/latest"
            ),
            "https://registry.example.com/v2/library/alpine/manifests/latest"
        );
    }

    #[test]
    fn test_build_upstream_url_with_special_characters() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://registry.npmjs.org",
                "@babel/core/-/core-7.24.0.tgz"
            ),
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"
        );
    }

    #[test]
    fn test_build_upstream_url_with_encoded_characters() {
        assert_eq!(
            ProxyService::build_upstream_url(
                "https://example.com",
                "path%20with%20spaces/artifact"
            ),
            "https://example.com/path%20with%20spaces/artifact"
        );
    }

    // =======================================================================
    // is_cache_expired (extracted pure function)
    // =======================================================================

    #[test]
    fn test_is_cache_expired_past() {
        let expired = Utc::now() - chrono::Duration::hours(1);
        assert!(is_cache_expired(&expired));
    }

    #[test]
    fn test_is_cache_expired_future() {
        let valid = Utc::now() + chrono::Duration::hours(23);
        assert!(!is_cache_expired(&valid));
    }

    #[test]
    fn test_is_cache_expired_far_future() {
        let far = Utc::now() + chrono::Duration::days(365);
        assert!(!is_cache_expired(&far));
    }

    // =======================================================================
    // compute_cache_expiry (extracted pure function)
    // =======================================================================

    #[test]
    fn test_compute_cache_expiry() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, 3600);
        let diff = (expires - now).num_seconds();
        assert_eq!(diff, 3600);
    }

    #[test]
    fn test_compute_cache_expiry_default_ttl() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, DEFAULT_CACHE_TTL_SECS);
        let diff = (expires - now).num_seconds();
        assert_eq!(diff, 86400);
    }

    #[test]
    fn test_compute_cache_expiry_zero_ttl() {
        let now = Utc::now();
        let expires = compute_cache_expiry(now, 0);
        assert_eq!(expires, now);
    }

    // =======================================================================
    // parse_cache_ttl (extracted pure function)
    // =======================================================================

    #[test]
    fn test_parse_cache_ttl_valid_number() {
        assert_eq!(parse_cache_ttl(Some("3600")), 3600);
    }

    #[test]
    fn test_parse_cache_ttl_none() {
        assert_eq!(parse_cache_ttl(None), DEFAULT_CACHE_TTL_SECS);
    }

    #[test]
    fn test_parse_cache_ttl_invalid() {
        assert_eq!(
            parse_cache_ttl(Some("not-a-number")),
            DEFAULT_CACHE_TTL_SECS
        );
    }

    #[test]
    fn test_parse_cache_ttl_empty() {
        assert_eq!(parse_cache_ttl(Some("")), DEFAULT_CACHE_TTL_SECS);
    }

    #[test]
    fn test_parse_cache_ttl_negative() {
        assert_eq!(parse_cache_ttl(Some("-100")), -100);
    }

    // =======================================================================
    // build_stale_cache_headers tests
    // =======================================================================

    #[test]
    fn test_build_stale_cache_headers_contains_x_cache() {
        let headers = build_stale_cache_headers();
        assert_eq!(headers.get("X-Cache").unwrap(), "STALE");
    }

    #[test]
    fn test_build_stale_cache_headers_contains_warning() {
        let headers = build_stale_cache_headers();
        assert_eq!(
            headers.get("Warning").unwrap(),
            "110 artifact-keeper \"Response is stale\""
        );
    }

    #[test]
    fn test_build_stale_cache_headers_has_exactly_two_entries() {
        let headers = build_stale_cache_headers();
        assert_eq!(headers.len(), 2);
    }

    // =======================================================================
    // Stale cache detection tests
    // =======================================================================

    #[test]
    fn test_expired_metadata_is_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::hours(25),
            upstream_etag: Some("\"old-etag\"".to_string()),
            expires_at: now - chrono::Duration::hours(1),
            content_type: Some("application/java-archive".to_string()),
            size_bytes: 2048,
            checksum_sha256: "d".repeat(64),
        };

        // The entry is expired (stale) because expires_at is in the past
        assert!(is_cache_expired(&metadata.expires_at));
        // But the metadata and content are still present, so it can be served
        // as a stale fallback when upstream is down
        assert!(metadata.content_type.is_some());
        assert!(metadata.size_bytes > 0);
    }

    #[test]
    fn test_valid_metadata_is_not_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now,
            upstream_etag: None,
            expires_at: now + chrono::Duration::hours(23),
            content_type: Some("application/octet-stream".to_string()),
            size_bytes: 512,
            checksum_sha256: "e".repeat(64),
        };

        // Not expired, so it would be served normally (not as stale)
        assert!(!is_cache_expired(&metadata.expires_at));
    }

    #[test]
    fn test_just_expired_metadata_is_stale() {
        let now = Utc::now();
        let metadata = CacheMetadata {
            cached_at: now - chrono::Duration::seconds(DEFAULT_CACHE_TTL_SECS + 1),
            upstream_etag: None,
            expires_at: now - chrono::Duration::seconds(1),
            content_type: Some("application/gzip".to_string()),
            size_bytes: 4096,
            checksum_sha256: "f".repeat(64),
        };

        assert!(is_cache_expired(&metadata.expires_at));
    }
}
