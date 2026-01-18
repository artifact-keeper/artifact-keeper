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

#[derive(Debug, Deserialize)]
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
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
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
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ArtifactoryError> {
        self.request_with_retry(|| async {
            let url = format!("{}{}", self.config.base_url, path);
            let request = self.auth_request(self.client.get(&url));
            request.send().await
        })
        .await
    }

    /// Execute a request with retry logic and exponential backoff
    async fn request_with_retry<T, F, Fut>(
        &self,
        request_fn: F,
    ) -> Result<T, ArtifactoryError>
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
                            let wait_time = retry_after
                                .map(|s| s * 1000)
                                .unwrap_or(delay_ms);
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
                    if e.is_connect() || e.is_timeout() {
                        if attempt < retry_config.max_retries {
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
                    }
                    return Err(ArtifactoryError::HttpError(e));
                }
            }
        }
    }

    /// Make a POST request to the Artifactory API
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
            let message = response.text().await.unwrap_or_else(|_| "Unknown error".into());
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
            r#"items.find({{"repo": "{}"}}).include("repo", "path", "name", "size", "created", "modified", "sha256", "actual_sha1").sort({{"$asc": ["path", "name"]}}).offset({}).limit({})"#,
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
            r#"items.find({{{}}}).include("repo", "path", "name", "size", "created", "modified", "sha256", "actual_sha1").sort({{"$asc": ["path", "name"]}}).offset({}).limit({})"#,
            conditions.join(", "), offset, limit
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
        self.list_artifacts_with_date_filter(repo_key, offset, limit, Some(since), None).await
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
}
