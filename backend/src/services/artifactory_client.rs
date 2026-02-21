//! Artifactory REST API client for migration.
//!
//! This module provides a client for interacting with JFrog Artifactory's REST API
//! to fetch repositories, artifacts, users, groups, and permissions for migration.

use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur when interacting with Artifactory
#[derive(Error, Debug)]
pub enum ArtifactoryError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Rate limited, retry after {retry_after:?} seconds")]
    RateLimited { retry_after: Option<u64> },

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Failed to parse response: {0}")]
    ParseError(#[from] serde_json::Error),
}

/// Authentication method for Artifactory
#[derive(Debug, Clone)]
pub enum ArtifactoryAuth {
    /// API token authentication
    ApiToken(String),
    /// Basic username/password authentication
    BasicAuth { username: String, password: String },
}

/// Retry configuration for exponential backoff
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay in milliseconds before first retry
    pub initial_delay_ms: u64,
    /// Maximum delay between retries in milliseconds
    pub max_delay_ms: u64,
    /// Multiplier for exponential backoff (e.g., 2.0 doubles delay each retry)
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Artifactory client configuration
#[derive(Debug, Clone)]
pub struct ArtifactoryClientConfig {
    /// Base URL of the Artifactory instance
    pub base_url: String,
    /// Authentication credentials
    pub auth: ArtifactoryAuth,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Delay between requests in milliseconds (for throttling)
    pub throttle_delay_ms: u64,
    /// Retry configuration for transient failures
    pub retry_config: RetryConfig,
}

impl Default for ArtifactoryClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth: ArtifactoryAuth::ApiToken(String::new()),
            timeout_secs: 30,
            max_concurrent: 4,
            throttle_delay_ms: 100,
            retry_config: RetryConfig::default(),
        }
    }
}

/// Artifactory REST API client
pub struct ArtifactoryClient {
    client: Client,
    config: ArtifactoryClientConfig,
}

// ============ API Response Types ============

#[derive(Debug, Deserialize)]
pub struct SystemVersionResponse {
    pub version: String,
    pub revision: Option<String>,
    pub addons: Option<Vec<String>>,
    pub license: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepositoryListItem {
    pub key: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    #[serde(rename = "packageType")]
    pub package_type: String,
    pub url: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepositoryConfig {
    pub key: String,
    pub rclass: String,
    #[serde(rename = "packageType")]
    pub package_type: String,
    pub description: Option<String>,
    pub notes: Option<String>,
    #[serde(rename = "includesPattern")]
    pub includes_pattern: Option<String>,
    #[serde(rename = "excludesPattern")]
    pub excludes_pattern: Option<String>,
    #[serde(rename = "repoLayoutRef")]
    pub repo_layout_ref: Option<String>,
    #[serde(rename = "handleReleases")]
    pub handle_releases: Option<bool>,
    #[serde(rename = "handleSnapshots")]
    pub handle_snapshots: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AqlQuery {
    pub query: String,
}

#[derive(Debug, Deserialize)]
pub struct AqlResponse {
    pub results: Vec<AqlResult>,
    pub range: AqlRange,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AqlResult {
    pub repo: String,
    pub path: String,
    pub name: String,
    pub size: Option<i64>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub sha256: Option<String>,
    pub actual_sha1: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AqlRange {
    pub start_pos: i64,
    pub end_pos: i64,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct StorageInfo {
    pub repo: String,
    pub path: String,
    pub created: Option<String>,
    #[serde(rename = "createdBy")]
    pub created_by: Option<String>,
    #[serde(rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(rename = "modifiedBy")]
    pub modified_by: Option<String>,
    #[serde(rename = "lastUpdated")]
    pub last_updated: Option<String>,
    #[serde(rename = "downloadUri")]
    pub download_uri: Option<String>,
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    pub size: Option<String>,
    pub checksums: Option<Checksums>,
    #[serde(rename = "originalChecksums")]
    pub original_checksums: Option<Checksums>,
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Checksums {
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PropertiesResponse {
    pub properties: Option<std::collections::HashMap<String, Vec<String>>>,
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserListItem {
    pub name: String,
    pub email: Option<String>,
    pub admin: Option<bool>,
    #[serde(rename = "profileUpdatable")]
    pub profile_updatable: Option<bool>,
    pub realm: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserDetails {
    pub name: String,
    pub email: Option<String>,
    pub admin: Option<bool>,
    #[serde(rename = "profileUpdatable")]
    pub profile_updatable: Option<bool>,
    #[serde(rename = "internalPasswordDisabled")]
    pub internal_password_disabled: Option<bool>,
    pub groups: Option<Vec<String>>,
    pub realm: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GroupListItem {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "autoJoin")]
    pub auto_join: Option<bool>,
    pub realm: Option<String>,
    #[serde(rename = "realmAttributes")]
    pub realm_attributes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionTarget {
    pub name: String,
    pub repo: Option<PermissionRepo>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionRepo {
    pub repositories: Option<Vec<String>>,
    pub actions: Option<PermissionActions>,
    #[serde(rename = "includePatterns")]
    pub include_patterns: Option<Vec<String>>,
    #[serde(rename = "excludePatterns")]
    pub exclude_patterns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionActions {
    pub users: Option<std::collections::HashMap<String, Vec<String>>>,
    pub groups: Option<std::collections::HashMap<String, Vec<String>>>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionsResponse {
    pub permissions: Vec<PermissionTarget>,
}

impl ArtifactoryClient {
    /// Create a new Artifactory client with the given configuration
    pub fn new(config: ArtifactoryClientConfig) -> Result<Self, ArtifactoryError> {
        // Enforce HTTPS unless explicitly opted out for local dev
        let allow_http = std::env::var("ALLOW_HTTP_INTEGRATIONS")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        if !allow_http && !config.base_url.starts_with("https://") {
            eprintln!(
                "[WARN] Artifactory base_url is not HTTPS. Set ALLOW_HTTP_INTEGRATIONS=1 for local dev."
            );
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .https_only(!allow_http)
            .build()?;

        Ok(Self { client, config })
    }

    /// Build an authenticated request
    fn auth_request(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.config.auth {
            ArtifactoryAuth::ApiToken(token) => builder.header("X-JFrog-Art-Api", token),
            ArtifactoryAuth::BasicAuth { username, password } => {
                builder.basic_auth(username, Some(password))
            }
        }
    }

    /// Make a GET request to the Artifactory API with retry logic
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ArtifactoryError> {
        self.request_with_retry(|| async {
            let url = format!("{}{}", self.config.base_url, path);
            let request = self.auth_request(self.client.get(&url));
            request.send().await
        })
        .await
    }

    /// Execute a request with retry logic and exponential backoff
    async fn request_with_retry<T, F, Fut>(&self, request_fn: F) -> Result<T, ArtifactoryError>
    where
        T: serde::de::DeserializeOwned,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let retry_config = &self.config.retry_config;
        let mut attempt = 0;
        let mut delay_ms = retry_config.initial_delay_ms;

        loop {
            // Apply throttle delay between requests
            if self.config.throttle_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.throttle_delay_ms)).await;
            }

            let result = request_fn().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    // Check for rate limiting
                    if status.as_u16() == 429 {
                        let retry_after = response
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok());

                        if attempt < retry_config.max_retries {
                            let wait_time = retry_after.map(|s| s * 1000).unwrap_or(delay_ms);
                            tracing::warn!(
                                "Rate limited, waiting {}ms before retry (attempt {}/{})",
                                wait_time,
                                attempt + 1,
                                retry_config.max_retries
                            );
                            tokio::time::sleep(Duration::from_millis(wait_time)).await;
                            attempt += 1;
                            delay_ms = std::cmp::min(
                                (delay_ms as f64 * retry_config.backoff_multiplier) as u64,
                                retry_config.max_delay_ms,
                            );
                            continue;
                        }
                        return Err(ArtifactoryError::RateLimited { retry_after });
                    }

                    // Check for retryable server errors (5xx)
                    if status.is_server_error() && attempt < retry_config.max_retries {
                        tracing::warn!(
                            "Server error {}, retrying in {}ms (attempt {}/{})",
                            status,
                            delay_ms,
                            attempt + 1,
                            retry_config.max_retries
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        attempt += 1;
                        delay_ms = std::cmp::min(
                            (delay_ms as f64 * retry_config.backoff_multiplier) as u64,
                            retry_config.max_delay_ms,
                        );
                        continue;
                    }

                    // Handle the response normally
                    return self.handle_response(response).await;
                }
                Err(e) => {
                    // Check for network/connection errors that are retryable
                    if (e.is_connect() || e.is_timeout()) && attempt < retry_config.max_retries {
                        tracing::warn!(
                            "Network error: {}, retrying in {}ms (attempt {}/{})",
                            e,
                            delay_ms,
                            attempt + 1,
                            retry_config.max_retries
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        attempt += 1;
                        delay_ms = std::cmp::min(
                            (delay_ms as f64 * retry_config.backoff_multiplier) as u64,
                            retry_config.max_delay_ms,
                        );
                        continue;
                    }
                    return Err(ArtifactoryError::HttpError(e));
                }
            }
        }
    }

    /// Make a POST request to the Artifactory API
    #[allow(dead_code)]
    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ArtifactoryError> {
        let url = format!("{}{}", self.config.base_url, path);
        let request = self.auth_request(self.client.post(&url)).json(body);

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Make a POST request with plain text body (for AQL)
    async fn post_text<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &str,
    ) -> Result<T, ArtifactoryError> {
        let url = format!("{}{}", self.config.base_url, path);
        let request = self
            .auth_request(self.client.post(&url))
            .header("Content-Type", "text/plain")
            .body(body.to_string());

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Handle the HTTP response
    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ArtifactoryError> {
        let status = response.status();

        if status.is_success() {
            let body = response.json::<T>().await?;
            Ok(body)
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ArtifactoryError::AuthError(format!(
                "Authentication failed with status {}",
                status
            )))
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound("Resource not found".into()))
        } else if status.as_u16() == 429 {
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            Err(ArtifactoryError::RateLimited { retry_after })
        } else {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".into());
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message,
            })
        }
    }

    // ============ API Methods ============

    /// Ping Artifactory to check if it's reachable
    pub async fn ping(&self) -> Result<bool, ArtifactoryError> {
        let url = format!("{}/api/system/ping", self.config.base_url);
        let request = self.auth_request(self.client.get(&url));

        let response = request.send().await?;
        Ok(response.status().is_success())
    }

    /// Get Artifactory system version information
    pub async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        self.get("/api/system/version").await
    }

    /// List all repositories
    pub async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        self.get("/api/repositories").await
    }

    /// Get repository configuration
    pub async fn get_repository(&self, key: &str) -> Result<RepositoryConfig, ArtifactoryError> {
        self.get(&format!("/api/repositories/{}", key)).await
    }

    /// Search for artifacts using AQL
    pub async fn search_aql(&self, query: &str) -> Result<AqlResponse, ArtifactoryError> {
        self.post_text("/api/search/aql", query).await
    }

    /// List artifacts in a repository with pagination
    pub async fn list_artifacts(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        let query = format!(
            r#"items.find({{"repo": "{}","type":"file"}}).include("repo", "path", "name", "size", "created", "modified", "sha256", "actual_sha1").offset({}).limit({})"#,
            repo_key, offset, limit
        );
        self.search_aql(&query).await
    }

    /// List artifacts in a repository with date range filtering
    pub async fn list_artifacts_with_date_filter(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
        modified_after: Option<&str>,
        modified_before: Option<&str>,
    ) -> Result<AqlResponse, ArtifactoryError> {
        let mut conditions = vec![format!(r#""repo": "{}""#, repo_key)];

        if let Some(after) = modified_after {
            conditions.push(format!(r#""modified": {{"$gt": "{}"}}"#, after));
        }

        if let Some(before) = modified_before {
            conditions.push(format!(r#""modified": {{"$lt": "{}"}}"#, before));
        }

        let query = format!(
            r#"items.find({{{},"type":"file"}}).include("repo", "path", "name", "size", "created", "modified", "sha256", "actual_sha1").offset({}).limit({})"#,
            conditions.join(", "),
            offset,
            limit
        );
        self.search_aql(&query).await
    }

    /// List artifacts modified since a specific date (for incremental migration)
    pub async fn list_modified_artifacts(
        &self,
        repo_key: &str,
        since: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        self.list_artifacts_with_date_filter(repo_key, offset, limit, Some(since), None)
            .await
    }

    /// Get artifact storage info (metadata, checksums)
    pub async fn get_storage_info(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<StorageInfo, ArtifactoryError> {
        self.get(&format!("/api/storage/{}/{}", repo_key, path))
            .await
    }

    /// Get artifact properties
    pub async fn get_properties(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError> {
        self.get(&format!("/api/storage/{}/{}?properties", repo_key, path))
            .await
    }

    /// Download artifact as bytes (streaming)
    pub async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        let url = format!("{}/{}/{}", self.config.base_url, repo_key, path);
        let request = self.auth_request(self.client.get(&url));

        let response = request.send().await?;
        let status = response.status();

        if status.is_success() {
            Ok(response.bytes().await?)
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound(format!(
                "Artifact not found: {}/{}",
                repo_key, path
            )))
        } else {
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message: "Failed to download artifact".into(),
            })
        }
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<UserListItem>, ArtifactoryError> {
        self.get("/api/security/users").await
    }

    /// Get user details
    pub async fn get_user(&self, username: &str) -> Result<UserDetails, ArtifactoryError> {
        self.get(&format!("/api/security/users/{}", username)).await
    }

    /// List all groups
    pub async fn list_groups(&self) -> Result<Vec<GroupListItem>, ArtifactoryError> {
        self.get("/api/security/groups").await
    }

    /// List all permission targets (v2 API)
    pub async fn list_permissions(&self) -> Result<PermissionsResponse, ArtifactoryError> {
        self.get("/api/v2/security/permissions").await
    }
}

// Implement SourceRegistry trait for migration compatibility
#[async_trait::async_trait]
impl crate::services::source_registry::SourceRegistry for ArtifactoryClient {
    async fn ping(&self) -> Result<bool, ArtifactoryError> {
        self.ping().await
    }

    async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        self.get_version().await
    }

    async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        self.list_repositories().await
    }

    async fn list_artifacts(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        self.list_artifacts(repo_key, offset, limit).await
    }

    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        self.download_artifact(repo_key, path).await
    }

    async fn get_properties(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError> {
        self.get_properties(repo_key, path).await
    }

    fn source_type(&self) -> &'static str {
        "artifactory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ArtifactoryClientConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.throttle_delay_ms, 100);
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_config_default_base_url_is_empty() {
        let config = ArtifactoryClientConfig::default();
        assert!(config.base_url.is_empty());
    }

    #[test]
    fn test_config_default_auth_is_api_token() {
        let config = ArtifactoryClientConfig::default();
        assert!(matches!(config.auth, ArtifactoryAuth::ApiToken(_)));
    }

    #[test]
    fn test_client_creation_with_api_token() {
        let config = ArtifactoryClientConfig {
            base_url: "https://artifactory.example.com".to_string(),
            auth: ArtifactoryAuth::ApiToken("test-token".to_string()),
            ..Default::default()
        };
        let client = ArtifactoryClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_creation_with_basic_auth() {
        let config = ArtifactoryClientConfig {
            base_url: "https://artifactory.example.com".to_string(),
            auth: ArtifactoryAuth::BasicAuth {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            ..Default::default()
        };
        let client = ArtifactoryClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_repository_list_item_deserialization() {
        let json = r#"{
            "key": "libs-release",
            "type": "LOCAL",
            "packageType": "maven",
            "url": "https://example.com/libs-release",
            "description": "Release repository"
        }"#;
        let item: RepositoryListItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.key, "libs-release");
        assert_eq!(item.repo_type, "LOCAL");
        assert_eq!(item.package_type, "maven");
        assert_eq!(
            item.url,
            Some("https://example.com/libs-release".to_string())
        );
        assert_eq!(item.description, Some("Release repository".to_string()));
    }

    #[test]
    fn test_repository_list_item_minimal() {
        let json = r#"{
            "key": "repo",
            "type": "REMOTE",
            "packageType": "npm"
        }"#;
        let item: RepositoryListItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.key, "repo");
        assert!(item.url.is_none());
        assert!(item.description.is_none());
    }

    #[test]
    fn test_repository_config_deserialization() {
        let json = r#"{
            "key": "libs-release",
            "rclass": "local",
            "packageType": "maven",
            "description": "Release repo",
            "notes": "Some notes",
            "includesPattern": "**/*",
            "excludesPattern": "",
            "repoLayoutRef": "maven-2-default",
            "handleReleases": true,
            "handleSnapshots": false
        }"#;
        let config: RepositoryConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.key, "libs-release");
        assert_eq!(config.rclass, "local");
        assert_eq!(config.package_type, "maven");
        assert_eq!(config.handle_releases, Some(true));
        assert_eq!(config.handle_snapshots, Some(false));
        assert_eq!(config.repo_layout_ref, Some("maven-2-default".to_string()));
    }

    #[test]
    fn test_repository_config_minimal() {
        let json = r#"{
            "key": "simple-repo",
            "rclass": "local",
            "packageType": "generic"
        }"#;
        let config: RepositoryConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.key, "simple-repo");
        assert!(config.description.is_none());
        assert!(config.notes.is_none());
        assert!(config.handle_releases.is_none());
    }

    #[test]
    fn test_aql_result_deserialization() {
        let json = r#"{
            "repo": "libs-release",
            "path": "com/example",
            "name": "artifact-1.0.jar",
            "size": 1024,
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-02T00:00:00.000Z",
            "sha256": "abc123def456",
            "actual_sha1": "sha1hash"
        }"#;
        let result: AqlResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.repo, "libs-release");
        assert_eq!(result.path, "com/example");
        assert_eq!(result.name, "artifact-1.0.jar");
        assert_eq!(result.size, Some(1024));
        assert_eq!(result.sha256, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_aql_result_minimal() {
        let json = r#"{
            "repo": "repo",
            "path": ".",
            "name": "file.txt"
        }"#;
        let result: AqlResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.repo, "repo");
        assert!(result.size.is_none());
        assert!(result.sha256.is_none());
        assert!(result.actual_sha1.is_none());
        assert!(result.created.is_none());
        assert!(result.modified.is_none());
    }

    #[test]
    fn test_aql_response_deserialization() {
        let json = r#"{
            "results": [
                {
                    "repo": "libs-release",
                    "path": "com/example",
                    "name": "artifact.jar"
                }
            ],
            "range": {
                "start_pos": 0,
                "end_pos": 1,
                "total": 1
            }
        }"#;
        let response: AqlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.range.start_pos, 0);
        assert_eq!(response.range.end_pos, 1);
        assert_eq!(response.range.total, 1);
    }

    #[test]
    fn test_storage_info_deserialization() {
        let json = r#"{
            "repo": "libs-release",
            "path": "/com/example/artifact-1.0.jar",
            "created": "2024-01-01T00:00:00.000Z",
            "createdBy": "admin",
            "lastModified": "2024-01-02T00:00:00.000Z",
            "modifiedBy": "admin",
            "lastUpdated": "2024-01-02T00:00:00.000Z",
            "downloadUri": "https://example.com/libs-release/com/example/artifact-1.0.jar",
            "mimeType": "application/java-archive",
            "size": "1024",
            "checksums": {
                "sha1": "sha1value",
                "md5": "md5value",
                "sha256": "sha256value"
            },
            "originalChecksums": {
                "sha1": "sha1value"
            },
            "uri": "https://example.com/api/storage/libs-release/com/example/artifact-1.0.jar"
        }"#;
        let info: StorageInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.repo, "libs-release");
        assert_eq!(info.created_by, Some("admin".to_string()));
        assert_eq!(info.size, Some("1024".to_string()));
        assert!(info.checksums.is_some());
        let checksums = info.checksums.unwrap();
        assert_eq!(checksums.sha256, Some("sha256value".to_string()));
    }

    #[test]
    fn test_user_details_deserialization() {
        let json = r#"{
            "name": "admin",
            "email": "admin@example.com",
            "admin": true,
            "profileUpdatable": true,
            "internalPasswordDisabled": false,
            "groups": ["readers", "deployers"],
            "realm": "internal"
        }"#;
        let user: UserDetails = serde_json::from_str(json).unwrap();
        assert_eq!(user.name, "admin");
        assert_eq!(user.email, Some("admin@example.com".to_string()));
        assert_eq!(user.admin, Some(true));
        assert_eq!(
            user.groups,
            Some(vec!["readers".to_string(), "deployers".to_string()])
        );
    }

    #[test]
    fn test_user_list_item_deserialization() {
        let json = r#"{
            "name": "john",
            "email": "john@example.com",
            "admin": false,
            "profileUpdatable": true,
            "realm": "ldap"
        }"#;
        let item: UserListItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.name, "john");
        assert_eq!(item.realm, Some("ldap".to_string()));
    }

    #[test]
    fn test_group_list_item_deserialization() {
        let json = r#"{
            "name": "developers",
            "description": "Dev team",
            "autoJoin": false,
            "realm": "internal",
            "realmAttributes": ""
        }"#;
        let group: GroupListItem = serde_json::from_str(json).unwrap();
        assert_eq!(group.name, "developers");
        assert_eq!(group.description, Some("Dev team".to_string()));
        assert_eq!(group.auto_join, Some(false));
    }

    #[test]
    fn test_permission_target_deserialization() {
        let json = r#"{
            "name": "read-all",
            "repo": {
                "repositories": ["libs-release", "libs-snapshot"],
                "actions": {
                    "users": {"admin": ["read", "write", "deploy"]},
                    "groups": {"readers": ["read"]}
                },
                "includePatterns": ["**"],
                "excludePatterns": []
            }
        }"#;
        let perm: PermissionTarget = serde_json::from_str(json).unwrap();
        assert_eq!(perm.name, "read-all");
        assert!(perm.repo.is_some());
        let repo = perm.repo.unwrap();
        assert_eq!(
            repo.repositories,
            Some(vec![
                "libs-release".to_string(),
                "libs-snapshot".to_string()
            ])
        );
        let actions = repo.actions.unwrap();
        assert!(actions.users.is_some());
        assert!(actions.groups.is_some());
    }

    #[test]
    fn test_properties_response_deserialization() {
        let json = r#"{
            "properties": {
                "build.name": ["my-build"],
                "build.number": ["42"]
            },
            "uri": "https://example.com/api/storage/repo/artifact?properties"
        }"#;
        let props: PropertiesResponse = serde_json::from_str(json).unwrap();
        assert!(props.properties.is_some());
        let properties = props.properties.unwrap();
        assert_eq!(
            properties.get("build.name").unwrap(),
            &vec!["my-build".to_string()]
        );
    }

    #[test]
    fn test_properties_response_empty() {
        let json = r#"{}"#;
        let props: PropertiesResponse = serde_json::from_str(json).unwrap();
        assert!(props.properties.is_none());
        assert!(props.uri.is_none());
    }

    #[test]
    fn test_system_version_response_deserialization() {
        let json = r#"{
            "version": "7.55.10",
            "revision": "75510900",
            "addons": ["build", "license"],
            "license": "Enterprise"
        }"#;
        let version: SystemVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(version.version, "7.55.10");
        assert_eq!(version.revision, Some("75510900".to_string()));
        assert_eq!(
            version.addons,
            Some(vec!["build".to_string(), "license".to_string()])
        );
        assert_eq!(version.license, Some("Enterprise".to_string()));
    }

    #[test]
    fn test_system_version_response_minimal() {
        let json = r#"{"version": "7.0.0"}"#;
        let version: SystemVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(version.version, "7.0.0");
        assert!(version.revision.is_none());
        assert!(version.addons.is_none());
        assert!(version.license.is_none());
    }

    #[test]
    fn test_checksums_deserialization() {
        let json = r#"{
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }"#;
        let checksums: Checksums = serde_json::from_str(json).unwrap();
        assert!(checksums.sha1.is_some());
        assert!(checksums.md5.is_some());
        assert!(checksums.sha256.is_some());
    }

    #[test]
    fn test_checksums_partial() {
        let json = r#"{"sha256": "abc123"}"#;
        let checksums: Checksums = serde_json::from_str(json).unwrap();
        assert_eq!(checksums.sha256, Some("abc123".to_string()));
        assert!(checksums.sha1.is_none());
        assert!(checksums.md5.is_none());
    }

    #[test]
    fn test_artifactory_error_display() {
        let err = ArtifactoryError::NotFound("repo/file.jar".to_string());
        assert_eq!(format!("{}", err), "Resource not found: repo/file.jar");

        let err = ArtifactoryError::AuthError("Invalid token".to_string());
        assert_eq!(format!("{}", err), "Authentication failed: Invalid token");

        let err = ArtifactoryError::RateLimited {
            retry_after: Some(30),
        };
        assert!(format!("{}", err).contains("30"));

        let err = ArtifactoryError::ApiError {
            status: 500,
            message: "Internal Server Error".to_string(),
        };
        assert!(format!("{}", err).contains("500"));
        assert!(format!("{}", err).contains("Internal Server Error"));
    }

    #[test]
    fn test_aql_query_serialization() {
        let query = AqlQuery {
            query: r#"items.find({"repo":"libs-release"})"#.to_string(),
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("items.find"));
    }

    #[test]
    fn test_source_type_returns_artifactory() {
        let config = ArtifactoryClientConfig {
            base_url: "https://example.com".to_string(),
            auth: ArtifactoryAuth::ApiToken("token".to_string()),
            ..Default::default()
        };
        let client = ArtifactoryClient::new(config).unwrap();
        use crate::services::source_registry::SourceRegistry;
        assert_eq!(client.source_type(), "artifactory");
    }
}
