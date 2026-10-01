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
    /// How long a read may stall with no bytes arriving (#3926). Not a
    /// deadline for the whole request: it restarts on every chunk, so a
    /// multi-GiB download survives as long as bytes keep flowing, while a dead
    /// connection is still cut off. Before #3926 this was a *total* request
    /// timeout, which failed every artifact whose transfer took longer than
    /// 30 s with "error decoding response body".
    pub timeout_secs: u64,
    /// How long to wait for the TCP/TLS connection itself.
    pub connect_timeout_secs: u64,
    /// Ceiling on a whole request (connect, headers and body) for the callers
    /// that buffer the body: the JSON API calls and `download_artifact`.
    /// `read_timeout` alone does not bound them, since a source dribbling one
    /// byte per read restarts it forever. The streaming download that the
    /// migration worker uses carries no such ceiling, so a large artifact is
    /// never cut off mid-transfer. `0` disables the ceiling.
    pub buffered_timeout_secs: u64,
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
            timeout_secs: migration_timeout_secs_from_env(
                MIGRATION_SOURCE_READ_TIMEOUT_ENV,
                DEFAULT_READ_TIMEOUT_SECS,
            ),
            connect_timeout_secs: migration_timeout_secs_from_env(
                MIGRATION_SOURCE_CONNECT_TIMEOUT_ENV,
                DEFAULT_CONNECT_TIMEOUT_SECS,
            ),
            buffered_timeout_secs: migration_timeout_secs_from_env(
                MIGRATION_SOURCE_BUFFERED_TIMEOUT_ENV,
                DEFAULT_BUFFERED_TIMEOUT_SECS,
            ),
            max_concurrent: 4,
            throttle_delay_ms: 100,
            retry_config: RetryConfig::default(),
        }
    }
}

/// Default read-idle timeout for migration source clients (#3926).
pub(crate) const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;
/// Default connect timeout for migration source clients (#3926).
pub(crate) const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default whole-request ceiling for buffered source requests (#3926).
pub(crate) const DEFAULT_BUFFERED_TIMEOUT_SECS: u64 = 300;

/// Env override for the migration source clients' read-idle timeout (seconds).
pub(crate) const MIGRATION_SOURCE_READ_TIMEOUT_ENV: &str = "MIGRATION_SOURCE_READ_TIMEOUT_SECS";
/// Env override for the migration source clients' connect timeout (seconds).
pub(crate) const MIGRATION_SOURCE_CONNECT_TIMEOUT_ENV: &str =
    "MIGRATION_SOURCE_CONNECT_TIMEOUT_SECS";
/// Env override for the buffered-request ceiling (seconds, `0` disables).
pub(crate) const MIGRATION_SOURCE_BUFFERED_TIMEOUT_ENV: &str =
    "MIGRATION_SOURCE_BUFFERED_TIMEOUT_SECS";

/// Read a migration source timeout from `name`, falling back to `default`
/// when it is unset or not a non-negative integer. A read-idle or connect
/// timeout of `0` would make every request fail instantly, so for those the
/// caller-supplied default also replaces `0`; the buffered ceiling keeps `0`
/// as its documented "disabled" value.
pub(crate) fn migration_timeout_secs_from_env(name: &str, default: u64) -> u64 {
    parse_timeout_secs(std::env::var(name).ok().as_deref(), name, default)
}

fn parse_timeout_secs(raw: Option<&str>, name: &str, default: u64) -> u64 {
    let Some(raw) = raw else {
        return default;
    };
    match raw.trim().parse::<u64>() {
        Ok(0) if name != MIGRATION_SOURCE_BUFFERED_TIMEOUT_ENV => {
            tracing::warn!(
                env = name,
                default,
                "ignoring a zero timeout override: it would fail every request; using the default"
            );
            default
        }
        Ok(secs) => secs,
        Err(_) => {
            tracing::warn!(
                env = name,
                value = raw,
                "ignoring non-numeric timeout override"
            );
            default
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

#[derive(Debug, Default, Deserialize)]
pub struct RepositoryListItem {
    pub key: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    #[serde(rename = "packageType")]
    pub package_type: String,
    pub url: Option<String>,
    pub description: Option<String>,
    /// For virtual/group repositories: the ordered list of *source-side* member
    /// repository keys (Nexus `group.memberNames`, Artifactory virtual
    /// `repositories`). Empty for local/remote repos and for sources that do not
    /// report membership. These are source names that must be correlated to the
    /// migrated Artifact Keeper repositories before a virtual repo can be wired
    /// up (issue #2783).
    #[serde(default)]
    pub members: Vec<String>,
    /// For remote/proxy repositories: the upstream URL the source proxies. This
    /// is distinct from `url` (which for Nexus is the repo's own browse URL).
    /// It is threaded into the migrated Artifact Keeper repo's `upstream_url`
    /// column; a remote repo migrated without it is rejected by the
    /// `check_upstream_url` constraint (issue #2822). Populated best-effort from
    /// the Artifactory remote-config `url` / Nexus `proxy.remoteUrl`.
    #[serde(default)]
    pub upstream_url: Option<String>,
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

/// Decide whether an Artifactory-supplied `downloadUri` is safe to follow
/// (#1423). The storage-API `downloadUri` is attacker-influenceable, so it must
/// pass the same outbound SSRF policy (`validate_outbound_url`) as any other
/// upstream URL before we issue a request to it. Factored out as a free
/// function so the guard is unit-testable without a live HTTP client.
/// Candidate ping endpoints for an Artifactory deployment, in probe order
/// (#2847).
///
/// `{base}/api/system/ping` is the classic Artifactory REST ping, correct
/// when `base_url` carries the `/artifactory` context (the self-hosted
/// default) or when the deployment routes the Artifactory service at the
/// root. Instances fronted by the JFrog Platform unified router (JFrog
/// Cloud, or self-hosted platform installs) 404 that path and expose the
/// Access service's ping at `{platform_root}/access/api/v1/system/ping`
/// instead — the Access service lives at the platform root, so a trailing
/// `/artifactory` context is stripped for that candidate.
fn ping_candidate_urls(base_url: &str) -> Vec<String> {
    let base = base_url.trim_end_matches('/');
    let platform_root = base.strip_suffix("/artifactory").unwrap_or(base);
    let mut candidates = vec![format!("{}/api/system/ping", base)];
    for url in [
        format!("{}/access/api/v1/system/ping", platform_root),
        format!("{}/access/api/v1/system/ping", base),
    ] {
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    }
    candidates
}

fn download_uri_is_safe_to_follow(download_uri: &str) -> bool {
    crate::api::validation::validate_outbound_url(download_uri, "Artifactory downloadUri").is_ok()
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

        let client = Self::build_http_client(&config, allow_http)?;
        Ok(Self { client, config })
    }

    /// Build the reqwest client. A `.timeout()` here would be a *total*
    /// deadline covering the body, which killed every download that took
    /// longer than it (#3926). Bound the connect and per-read phases instead:
    /// a slow download survives, a dead one does not. The buffered callers add
    /// their own whole-request ceiling per request (`buffered_timeout`).
    fn build_http_client(
        config: &ArtifactoryClientConfig,
        allow_http: bool,
    ) -> Result<Client, ArtifactoryError> {
        Ok(crate::services::http_client::base_client_builder()
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .read_timeout(Duration::from_secs(config.timeout_secs))
            .https_only(!allow_http)
            .build()?)
    }

    /// Whole-request ceiling for the callers that buffer the response body,
    /// or `None` when `buffered_timeout_secs` is `0` (disabled).
    fn buffered_timeout(&self) -> Option<Duration> {
        match self.config.buffered_timeout_secs {
            0 => None,
            secs => Some(Duration::from_secs(secs)),
        }
    }

    /// Apply the buffered ceiling to a request that will be read to the end.
    fn buffered(&self, builder: RequestBuilder) -> RequestBuilder {
        match self.buffered_timeout() {
            Some(total) => builder.timeout(total),
            None => builder,
        }
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
            let request = self.buffered(self.auth_request(self.client.get(&url)));
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
        let request = self
            .buffered(self.auth_request(self.client.post(&url)))
            .json(body);

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
            .buffered(self.auth_request(self.client.post(&url)))
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

    /// Ping Artifactory to check if it's reachable (#2847).
    ///
    /// Probes each shape from [`ping_candidate_urls`] in order and reports
    /// reachable on the first success. Deployments fronted by the JFrog
    /// Platform router 404 the classic `/api/system/ping` and only answer the
    /// Access service's `/access/api/v1/system/ping`, so a single-endpoint
    /// probe wrongly reported those instances as unreachable.
    pub async fn ping(&self) -> Result<bool, ArtifactoryError> {
        let mut last_err: Option<ArtifactoryError> = None;
        for url in ping_candidate_urls(&self.config.base_url) {
            // The whole-request ceiling, so a connection test cannot be held
            // open indefinitely by a source that answers one byte at a time.
            let request = self.buffered(self.auth_request(self.client.get(&url)));
            match request.send().await {
                Ok(response) if response.status().is_success() => return Ok(true),
                // Non-success: this deployment does not answer this ping
                // shape; try the next candidate.
                Ok(_) => {}
                Err(e) => last_err = Some(ArtifactoryError::HttpError(e)),
            }
        }
        match last_err {
            // The host answered every candidate, just never successfully —
            // same `Ok(false)` the old single-endpoint probe reported.
            None => Ok(false),
            // At least one candidate failed at the transport level and none
            // succeeded: surface the error, as before.
            Some(e) => Err(e),
        }
    }

    /// Get Artifactory system version information
    pub async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        self.get("/api/system/version").await
    }

    /// List all repositories
    pub async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        let mut items: Vec<RepositoryListItem> = self.get("/api/repositories").await?;
        // Artifactory's `/api/repositories` reports a remote repo's configured
        // upstream in the `url` field. Capture it as `upstream_url` so remote
        // repos migrate with a non-NULL upstream; otherwise Artifact Keeper's
        // `check_upstream_url` constraint rejects the created repo (issue #2822).
        for item in items.iter_mut() {
            if item.repo_type.eq_ignore_ascii_case("remote") {
                item.upstream_url = item.url.clone();
            }
        }
        Ok(items)
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

    /// List artifacts in a repository with date range filtering.
    ///
    /// Named `_impl` to avoid name-shadowing with the
    /// `SourceRegistry::list_artifacts_with_date_filter` trait method this
    /// type also implements. The trait impl below explicitly delegates
    /// to this inherent function; if both were named identically the
    /// trait method would recursively call itself.
    pub async fn list_artifacts_with_date_filter_impl(
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
        self.list_artifacts_with_date_filter_impl(repo_key, offset, limit, Some(since), None)
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

    /// `buffered` applies the whole-request ceiling: `true` for a caller that
    /// reads the body into memory, `false` for the streaming download, which
    /// must be allowed to take as long as a large artifact needs (#3926).
    async fn download_response_with_fallback(
        &self,
        repo_key: &str,
        path: &str,
        buffered: bool,
    ) -> Result<reqwest::Response, ArtifactoryError> {
        let with_ceiling = |builder: RequestBuilder| {
            if buffered {
                self.buffered(builder)
            } else {
                builder
            }
        };
        let raw_url = format!("{}/{}/{}", self.config.base_url, repo_key, path);
        let request = with_ceiling(self.auth_request(self.client.get(&raw_url)));
        let response = request.send().await?;

        if response.status().as_u16() != 404 {
            return Ok(response);
        }

        let storage_info = match self.get_storage_info(repo_key, path).await {
            Ok(info) => info,
            Err(_) => return Ok(response),
        };

        let Some(download_uri) = storage_info.download_uri else {
            return Ok(response);
        };

        if download_uri == raw_url {
            return Ok(response);
        }

        // #1423: `download_uri` comes from the upstream Artifactory storage API
        // response, which is attacker-influenceable (a hostile or compromised
        // source instance can point it anywhere). It must pass the outbound
        // SSRF policy before we issue a request to it. The `download_uri ==
        // raw_url` check above is a migration-specific constraint, NOT an SSRF
        // guard: any differing path or port (e.g. the cloud-metadata endpoint
        // `http://169.254.169.254/...`) sails past it. The shared client's
        // redirect policy only screens redirect *hops*, not this initial
        // connection. On rejection, fall back to the original 404 response.
        if !download_uri_is_safe_to_follow(&download_uri) {
            tracing::warn!(
                repo = %repo_key,
                path = %path,
                download_uri = %download_uri,
                "Rejecting Artifactory downloadUri: failed outbound SSRF validation"
            );
            return Ok(response);
        }

        // #1420: host-allowlist (defense in depth on top of the SSRF policy
        // above): only send authenticated requests to a host that matches the
        // configured Artifactory base_url, so a malicious or misconfigured
        // source cannot return an attacker-controlled downloadUri that
        // exfiltrates our credentials to a foreign host. On mismatch, log and
        // surface the original 404 instead of issuing the request.
        if !fallback_host_matches(&self.config.base_url, &download_uri) {
            tracing::warn!(
                repo = %repo_key,
                path = %path,
                base_url = %self.config.base_url,
                download_uri = %download_uri,
                "Refusing to follow Artifactory downloadUri to a foreign host; returning original 404"
            );
            return Ok(response);
        }

        tracing::debug!(
            repo = %repo_key,
            path = %path,
            download_uri = %download_uri,
            "Direct artifact download returned 404; retrying with Artifactory storage downloadUri"
        );

        let fallback_request = with_ceiling(self.auth_request(self.client.get(download_uri)));
        fallback_request
            .send()
            .await
            .map_err(ArtifactoryError::from)
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

    /// Download artifact and buffer the full body into memory.
    ///
    /// Prefer `download_artifact_stream` for migrations: this method holds
    /// the entire artifact in memory at once and OOMs on multi-GB artifacts
    /// (issue #1422). It is kept for callers that genuinely need the bytes
    /// in memory (small fixtures, tests).
    #[allow(clippy::disallowed_methods)] // clippy allow is fn-scoped (tail expr); the exempt call is marked inline below (#1608)
    pub async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        let response = self
            .download_response_with_fallback(repo_key, path, true)
            .await?;
        let status = response.status();

        if status.is_success() {
            Ok(response.bytes().await?) // STREAMING-EXEMPT: capped-metadata read (upstream index/advisory/packument, not an artifact blob); bounded response buffered; tracked under #1608
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

    /// Download artifact as a chunked byte stream.
    ///
    /// Returns chunks from `reqwest::Response::bytes_stream()` so callers
    /// can spill straight to disk without ever buffering the full payload.
    /// This is the path used by `migration_worker::transfer_artifact` to
    /// keep memory bounded to one chunk regardless of artifact size
    /// (issue #1422).
    pub async fn download_artifact_stream(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<bytes::Bytes, ArtifactoryError>>,
        ArtifactoryError,
    > {
        use futures::StreamExt;

        let response = self
            .download_response_with_fallback(repo_key, path, false)
            .await?;
        let status = response.status();

        if status.is_success() {
            let stream = response
                .bytes_stream()
                .map(|res| res.map_err(ArtifactoryError::from));
            Ok(Box::pin(stream))
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

    fn origin_base_url(&self) -> Option<String> {
        let url = self.config.base_url.trim();
        (!url.is_empty()).then(|| url.to_string())
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

    async fn list_artifacts_with_date_filter(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
        modified_after: Option<&str>,
        modified_before: Option<&str>,
    ) -> Result<AqlResponse, ArtifactoryError> {
        // Explicitly call the inherent `_impl` method to avoid recursing
        // into this trait method via method-resolution shadowing.
        ArtifactoryClient::list_artifacts_with_date_filter_impl(
            self,
            repo_key,
            offset,
            limit,
            modified_after,
            modified_before,
        )
        .await
    }

    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        self.download_artifact(repo_key, path).await
    }

    async fn download_artifact_stream(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<crate::services::source_registry::ArtifactByteStream, ArtifactoryError> {
        self.download_artifact_stream(repo_key, path).await
    }

    async fn download_oci_content_stream(
        &self,
        repo_key: &str,
        image: &str,
        digest: &str,
        kind: crate::services::source_registry::OciContentKind,
    ) -> Result<crate::services::source_registry::ArtifactByteStream, ArtifactoryError> {
        // Artifactory exposes each Docker repository through its Docker
        // Registry v2 REST API at `api/docker/<repo>/v2/<image>/{blobs|manifests}/<digest>`.
        // `download_artifact_stream` joins `<base>/<repo>/<path>`, so pass the
        // API prefix as the repo segment and the image-relative remainder as
        // the path. In practice the migration enumerates Artifactory blobs and
        // child manifests as their own items, so the referenced-content walker
        // dedups them and never calls this — it exists for correctness if the
        // enumeration ever misses a referenced digest.
        crate::services::source_registry::validate_oci_content_ref(image, digest)?;
        let api_repo = format!("api/docker/{}/v2", repo_key);
        let path = format!("{}/{}/{}", image, kind.path_segment(), digest);
        self.download_artifact_stream(&api_repo, &path).await
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

/// SSRF host-allowlist predicate for the Artifactory downloadUri fallback.
///
/// Returns `true` only when both URLs parse and resolve to the same host
/// (case-insensitive, exact match — no suffix matching). Mismatched hosts,
/// missing hosts, and unparseable URLs all return `false` so the caller
/// surfaces the original 404 instead of leaking auth headers to an
/// attacker-controlled or misconfigured endpoint.
pub(crate) fn fallback_host_matches(base_url: &str, download_uri: &str) -> bool {
    let base_host = reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let fallback_host = reqwest::Url::parse(download_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    matches!(
        (base_host.as_deref(), fallback_host.as_deref()),
        (Some(b), Some(f)) if b == f
    )
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_download_uri_ssrf_guard_rejects_dangerous_targets() {
        // #1423 regression: a malicious/compromised upstream Artifactory can put
        // an internal or metadata address in the storage-API `downloadUri`. The
        // guard must refuse to follow it. These targets are hard-blocked
        // regardless of the private-IP allowlist toggle, so the assertions are
        // deterministic and require no network/DNS.
        assert!(
            !download_uri_is_safe_to_follow("http://169.254.169.254/latest/meta-data/"),
            "cloud-metadata link-local IP must be rejected"
        );
        assert!(
            !download_uri_is_safe_to_follow("http://metadata.google.internal/computeMetadata/v1/"),
            "cloud-metadata hostname must be rejected"
        );
        assert!(
            !download_uri_is_safe_to_follow("http://127.0.0.1:8081/artifactory/x/a.jar"),
            "loopback must be rejected"
        );
        assert!(
            !download_uri_is_safe_to_follow("file:///etc/passwd"),
            "non-http(s) scheme must be rejected"
        );
        // A normal public upstream URL is still followed (no DNS lookup happens
        // for a non-literal host, so this is offline-deterministic too).
        assert!(
            download_uri_is_safe_to_follow("https://repo.example.com/artifactory/libs/a-1.0.jar"),
            "a public upstream downloadUri must still be allowed"
        );
    }

    #[test]
    fn test_config_default() {
        let config = ArtifactoryClientConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.buffered_timeout_secs, 300);
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.throttle_delay_ms, 100);
    }

    // -----------------------------------------------------------------------
    // Large-artifact timeouts (#3926)
    // -----------------------------------------------------------------------

    #[test]
    fn test_timeout_override_parsing_3926() {
        let read = MIGRATION_SOURCE_READ_TIMEOUT_ENV;
        let buffered = MIGRATION_SOURCE_BUFFERED_TIMEOUT_ENV;
        assert_eq!(parse_timeout_secs(None, read, 30), 30);
        assert_eq!(parse_timeout_secs(Some("120"), read, 30), 120);
        assert_eq!(parse_timeout_secs(Some(" 45 "), read, 30), 45);
        assert_eq!(parse_timeout_secs(Some("soon"), read, 30), 30);
        // A zero read/connect timeout would fail every request instantly.
        assert_eq!(parse_timeout_secs(Some("0"), read, 30), 30);
        // The buffered ceiling keeps 0 as "disabled".
        assert_eq!(parse_timeout_secs(Some("0"), buffered, 300), 0);
    }

    /// A client built through the real builder (connect + read-idle timeouts,
    /// no total deadline), with plain HTTP allowed for the local test server,
    /// and no retries so a failure surfaces immediately.
    fn timeout_client(
        base_url: String,
        read_timeout_secs: u64,
        buffered_timeout_secs: u64,
    ) -> ArtifactoryClient {
        let config = ArtifactoryClientConfig {
            base_url,
            timeout_secs: read_timeout_secs,
            connect_timeout_secs: 5,
            buffered_timeout_secs,
            throttle_delay_ms: 0,
            retry_config: RetryConfig {
                max_retries: 0,
                initial_delay_ms: 1,
                max_delay_ms: 5,
                backoff_multiplier: 2.0,
            },
            ..Default::default()
        };
        let client = ArtifactoryClient::build_http_client(&config, true).unwrap();
        ArtifactoryClient { client, config }
    }

    /// Serve one HTTP response whose body arrives in `chunks` pieces spaced
    /// `gap` apart: a source that is slow in total but never idle for long,
    /// i.e. a large artifact on a modest link. Returns the base URL.
    async fn spawn_trickling_server(chunks: usize, gap: Duration) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            // Drain the request head; its content is irrelevant here.
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {chunks}\r\nConnection: close\r\n\r\n"
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            for _ in 0..chunks {
                tokio::time::sleep(gap).await;
                // The client may already have given up (the timeout tests).
                if sock.write_all(b"x").await.is_err() || sock.flush().await.is_err() {
                    break;
                }
            }
        });
        format!("http://{addr}")
    }

    /// #3926: the streaming download must not carry a total deadline. The body
    /// here takes ~2.4 s to arrive while no single read waits more than 0.4 s;
    /// with a 1 s timeout the pre-#3926 client (`.timeout(timeout_secs)`, a
    /// whole-request deadline) aborted it mid-body with "error decoding
    /// response body". A read-idle timeout lets it finish.
    #[tokio::test]
    async fn test_streaming_download_outlives_the_read_timeout_3926() {
        use futures::StreamExt;

        let base = spawn_trickling_server(6, Duration::from_millis(400)).await;
        let client = timeout_client(base, 1, 1);
        let started = std::time::Instant::now();
        let mut stream = client
            .download_artifact_stream("repo", "big.bin")
            .await
            .expect("headers arrive immediately");
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.expect("a slow-but-alive body must not be cut off"));
        }
        assert_eq!(body, b"xxxxxx");
        assert!(
            started.elapsed() > Duration::from_secs(2),
            "the test body must take longer than the timeouts it exercises"
        );
    }

    /// The buffered path keeps a whole-request ceiling, so a source that
    /// dribbles bytes cannot hold a buffered caller forever.
    #[tokio::test]
    async fn test_buffered_download_is_bounded_by_the_total_ceiling_3926() {
        let base = spawn_trickling_server(6, Duration::from_millis(400)).await;
        let client = timeout_client(base, 1, 1);
        let started = std::time::Instant::now();
        let err = client
            .download_artifact("repo", "big.bin")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ArtifactoryError::HttpError(e) if e.is_timeout()),
            "expected the buffered path to hit its ceiling, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the ceiling did not bound the request: {:?}",
            started.elapsed()
        );
    }

    /// A stalled source (headers sent, then silence) is still cut off by the
    /// read-idle timeout on the streaming path: no unbounded waits.
    #[tokio::test]
    async fn test_streaming_download_stalled_source_times_out_3926() {
        use futures::StreamExt;

        // One byte after 3 s: longer than the 1 s read-idle timeout.
        let base = spawn_trickling_server(1, Duration::from_secs(3)).await;
        let client = timeout_client(base, 1, 0);
        let started = std::time::Instant::now();
        let mut stream = client
            .download_artifact_stream("repo", "stuck.bin")
            .await
            .expect("headers arrive immediately");
        let mut saw_error = false;
        while let Some(chunk) = stream.next().await {
            if chunk.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error, "a stalled body must surface an error");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the read-idle timeout did not fire: {:?}",
            started.elapsed()
        );
    }

    // -----------------------------------------------------------------------
    // Ping endpoint fallback (#2847)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ping_candidates_classic_first_then_access() {
        assert_eq!(
            ping_candidate_urls("https://repo.example.com"),
            vec![
                "https://repo.example.com/api/system/ping".to_string(),
                "https://repo.example.com/access/api/v1/system/ping".to_string(),
            ]
        );
    }

    #[test]
    fn test_ping_candidates_strip_artifactory_context_for_access() {
        // The Access service lives at the PLATFORM root, not under the
        // `/artifactory` context; both spellings are probed.
        assert_eq!(
            ping_candidate_urls("https://repo.example.com/artifactory/"),
            vec![
                "https://repo.example.com/artifactory/api/system/ping".to_string(),
                "https://repo.example.com/access/api/v1/system/ping".to_string(),
                "https://repo.example.com/artifactory/access/api/v1/system/ping".to_string(),
            ]
        );
    }

    /// Build a client over a plain reqwest client (no `https_only`) so
    /// wiremock's HTTP listener is reachable without env toggles.
    fn test_client(base_url: String) -> ArtifactoryClient {
        ArtifactoryClient {
            client: reqwest::Client::new(),
            config: ArtifactoryClientConfig {
                base_url,
                ..Default::default()
            },
        }
    }

    /// A JFrog Platform deployment 404s the classic `/api/system/ping` and
    /// answers only the Access service's ping (#2847). The probe must fall
    /// through and report reachable.
    #[tokio::test]
    async fn test_ping_falls_back_to_access_service_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/system/ping"))
            .respond_with(ResponseTemplate::new(404).set_body_string("404 page not found"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/access/api/v1/system/ping"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&server)
            .await;

        let client = test_client(server.uri());
        assert!(
            client.ping().await.expect("ping must not error"),
            "ping must fall back to /access/api/v1/system/ping and succeed"
        );
    }

    /// A reachable host that answers no ping shape is `Ok(false)`, exactly as
    /// the old single-endpoint probe reported.
    #[tokio::test]
    async fn test_ping_false_when_no_shape_answers() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = test_client(server.uri());
        assert!(!client.ping().await.expect("ping must not error"));
    }

    /// The classic endpoint still wins on deployments that serve it — no
    /// second request is made.
    #[tokio::test]
    async fn test_ping_classic_endpoint_short_circuits() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/system/ping"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(server.uri());
        assert!(client.ping().await.expect("ping must not error"));
        let hits = server.received_requests().await.unwrap_or_default().len();
        assert_eq!(hits, 1, "a successful classic ping must short-circuit");
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

    // -----------------------------------------------------------------------
    // SSRF host-allowlist for download_response_with_fallback
    //
    // The helper decides whether a downloadUri returned by Artifactory can be
    // followed with our auth headers. It now lives at module scope and is
    // called from `download_response_with_fallback`, so these tests exercise
    // the production predicate directly.
    // -----------------------------------------------------------------------

    #[test]
    fn test_fallback_host_matches_same_host_same_scheme() {
        assert!(fallback_host_matches(
            "https://artifactory.example.com",
            "https://artifactory.example.com/artifactory/api/storage/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_matches_case_insensitive() {
        assert!(fallback_host_matches(
            "https://ArtiFactory.Example.com",
            "https://artifactory.example.COM/api/storage/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_foreign_host() {
        assert!(!fallback_host_matches(
            "https://artifactory.example.com",
            "https://attacker.example.net/exfil"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_invalid_uri() {
        assert!(!fallback_host_matches(
            "https://artifactory.example.com",
            "not a url"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_subdomain_swap() {
        // Strict equality, not suffix matching: subdomain swaps must fail.
        assert!(!fallback_host_matches(
            "https://artifactory.example.com",
            "https://evil.artifactory.example.com/exfil"
        ));
    }

    #[test]
    fn test_fallback_host_matches_same_host_different_scheme() {
        // Host is what we gate on; scheme is irrelevant to the SSRF rule.
        // A downgrade to http on the same host is still an in-allowlist host
        // (TLS posture is a separate concern handled by the HTTP client).
        assert!(fallback_host_matches(
            "https://artifactory.example.com",
            "http://artifactory.example.com/api/storage/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_matches_same_host_with_explicit_port() {
        // An explicit port (e.g. 8081) on the same host name still matches:
        // we compare host strings, not host:port authority.
        assert!(fallback_host_matches(
            "https://artifactory.example.com",
            "https://artifactory.example.com:8081/api/storage/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_empty_base_url() {
        // Empty / unparseable base must not authorize any downloadUri.
        assert!(!fallback_host_matches(
            "",
            "https://artifactory.example.com/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_relative_download_uri() {
        // Some Artifactory deployments return a path-only downloadUri. We
        // can't safely follow it from this helper (no host to compare), so
        // it must be rejected.
        assert!(!fallback_host_matches(
            "https://artifactory.example.com",
            "/artifactory/api/storage/foo/bar.jar"
        ));
    }

    #[test]
    fn test_fallback_host_rejects_host_with_trailing_dot() {
        // Strict equality: "example.com." (FQDN) is NOT equal to
        // "example.com" as a host string. Treat as a foreign host.
        assert!(!fallback_host_matches(
            "https://artifactory.example.com",
            "https://artifactory.example.com./api/storage/foo/bar.jar"
        ));
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
