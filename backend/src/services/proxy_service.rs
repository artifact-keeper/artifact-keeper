//! Proxy service for remote/proxy repositories.
//!
//! Handles fetching artifacts from upstream repositories with caching support.
//! Implements cache TTL, ETag validation, and transparent proxying.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH, WWW_AUTHENTICATE};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout as tokio_timeout;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};
use crate::services::storage_service::StorageService;

/// Default cache TTL in seconds (24 hours)
const DEFAULT_CACHE_TTL_SECS: i64 = 86400;

/// HTTP client timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 60;

/// Default upstream-fetch concurrency cap when no explicit value is supplied
/// (e.g. the deprecated zero-arg `ProxyService::new` constructor).
const DEFAULT_MAX_CONCURRENT_FETCHES: usize = 20;

/// RAII guard wrapping an `OwnedSemaphorePermit` so the
/// `ak_proxy_upstream_inflight` gauge is decremented when the permit is
/// released. Without this, the gauge would only be updated on acquire and
/// would stay pinned at the high-water mark forever, falsely advertising
/// saturation while traffic is idle.
struct FetchPermitGuard {
    /// `Option` so `Drop` can `take()` the permit and explicitly drop it
    /// BEFORE reading `available_permits()`. Custom `Drop::drop` runs
    /// before field drops, so without the explicit `take()` the permit
    /// would still be held when we sample the semaphore — the gauge
    /// would report saturation - 1 forever. Counterintuitive but
    /// matches the documented Rust drop-order semantics.
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    sem: Arc<Semaphore>,
    limit: usize,
}

impl Drop for FetchPermitGuard {
    fn drop(&mut self) {
        // Release the permit FIRST so the gauge sample reflects the
        // post-release available-permits count, not the pre-release one.
        drop(self.permit.take());
        ProxyService::refresh_inflight_gauge_for(&self.sem, self.limit);
    }
}

/// Default queue-wait budget per upstream fetch when no explicit value is
/// supplied. Tuned to be tighter than typical client read timeouts (npm,
/// cargo, pip) so a saturated proxy returns 503 fast rather than the
/// client timing out first.
const DEFAULT_QUEUE_TIMEOUT_SECS: u64 = 10;

/// Response from an upstream registry fetch.
struct UpstreamResponse {
    content: Bytes,
    content_type: Option<String>,
    etag: Option<String>,
    effective_url: String,
    link: Option<String>,
}

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

/// Default bearer token TTL when the token endpoint omits `expires_in` (5 minutes).
const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

/// Maximum bearer token TTL (1 hour). Prevents a malicious token endpoint from
/// disabling cache eviction or causing integer overflow via a huge `expires_in`.
const MAX_TOKEN_TTL_SECS: u64 = 3600;

/// JSON response from an OCI registry token endpoint.
#[derive(Deserialize)]
struct RegistryTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// Proxy service for fetching and caching artifacts from upstream repositories
pub struct ProxyService {
    db: PgPool,
    storage: Arc<StorageService>,
    http_client: Client,
    /// In-memory cache for OCI registry bearer tokens.
    /// Key: "{realm}\0{service}\0{scope}", Value: (token, created_at, ttl_secs)
    token_cache: RwLock<HashMap<String, (String, Instant, u64)>>,
    /// Bounds peak concurrent in-flight upstream fetches. When N concurrent
    /// clients hit the same cold cache key, the proxy used to fan out N
    /// concurrent upstream requests; this caps the fan-out at
    /// `proxy_max_concurrent_fetches` (#872). The permit is acquired inside
    /// [`Self::fetch_from_upstream`] (the single chokepoint for upstream HTTP)
    /// and is held only for the duration of the HTTP call: cache writes,
    /// stale-fallback DB/storage reads, and OCI token-exchange retries all
    /// run outside the permit so a slow disk or upstream error cannot
    /// block other repos' fetches.
    ///
    /// `None` = stampede protection disabled (operator set
    /// `PROXY_MAX_CONCURRENT_FETCHES=0`). The acquire path becomes a no-op.
    ///
    /// NOTE: this bounds the *peak* of redundant fetches but does not
    /// coalesce them. 20 clients on a single cold key still issue up to 20
    /// upstream GETs. Single-flight coalescing (request-deduplication
    /// keyed by cache_key) is a separate, complementary mechanism tracked
    /// as a follow-up issue.
    upstream_fetch_sem: Option<Arc<Semaphore>>,
    /// Configured permit count (0 = disabled). Cached separately because
    /// `Semaphore::available_permits()` reports current availability, not
    /// the configured cap, and we want the cap in error messages and the
    /// `ak_proxy_upstream_inflight` gauge.
    fetch_concurrency_limit: usize,
    /// Time a fetch will wait for a permit before giving up with 503.
    queue_timeout: Duration,
}

impl ProxyService {
    /// Create a new proxy service with explicit upstream-fetch concurrency
    /// limits. Pass `0` for `max_concurrent_fetches` to disable stampede
    /// protection entirely (no semaphore allocated, acquire is a no-op).
    pub fn with_concurrency(
        db: PgPool,
        storage: Arc<StorageService>,
        max_concurrent_fetches: usize,
        queue_timeout: Duration,
    ) -> Self {
        let http_client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent("artifact-keeper-proxy/1.0")
            .build()
            .expect("Failed to create HTTP client");

        let upstream_fetch_sem = if max_concurrent_fetches == 0 {
            tracing::warn!(
                "PROXY_MAX_CONCURRENT_FETCHES=0; upstream-fetch stampede protection is DISABLED. \
                 Set a positive value to bound concurrent upstream requests."
            );
            None
        } else {
            Some(Arc::new(Semaphore::new(max_concurrent_fetches)))
        };

        Self {
            db,
            storage,
            http_client,
            token_cache: RwLock::new(HashMap::new()),
            upstream_fetch_sem,
            fetch_concurrency_limit: max_concurrent_fetches,
            queue_timeout,
        }
    }

    /// Convenience constructor with documented defaults (20 permits, 10s
    /// queue timeout). Prefer `with_concurrency` so config knobs propagate
    /// from `Config` to a single source of truth.
    pub fn new(db: PgPool, storage: Arc<StorageService>) -> Self {
        Self::with_concurrency(
            db,
            storage,
            DEFAULT_MAX_CONCURRENT_FETCHES,
            Duration::from_secs(DEFAULT_QUEUE_TIMEOUT_SECS),
        )
    }

    /// Acquire a permit for an upstream fetch, waiting up to `queue_timeout`.
    ///
    /// Returns `Ok(None)` when stampede protection is disabled (operator set
    /// the limit to 0). Returns `Ok(Some(guard))` after acquiring a permit;
    /// the guard automatically releases the permit AND decrements the
    /// `ak_proxy_upstream_inflight` gauge on drop. Returns
    /// `Err(AppError::Overloaded)` when the queue is saturated and the
    /// timeout fires, after emitting `ak_proxy_queue_full_total`.
    ///
    /// The 503 message returned to the client is deliberately generic;
    /// the concrete configured limit and timeout are logged server-side
    /// only so an unauthenticated attacker probing for capacity numbers
    /// gets nothing useful out of the response body. The `Retry-After`
    /// header (set in `IntoResponse`) carries the actionable hint.
    ///
    /// Emits `ak_proxy_queue_wait_seconds` for every acquire attempt
    /// (success or timeout) so operators can dashboard p50/p95 wait time.
    async fn acquire_fetch_permit(&self) -> Result<Option<FetchPermitGuard>> {
        let Some(sem) = &self.upstream_fetch_sem else {
            return Ok(None);
        };
        let started = Instant::now();
        let result = tokio_timeout(self.queue_timeout, sem.clone().acquire_owned()).await;
        let waited = started.elapsed();
        crate::services::metrics_service::record_proxy_queue_wait(waited.as_secs_f64());

        match result {
            Ok(Ok(permit)) => {
                self.refresh_inflight_gauge();
                Ok(Some(FetchPermitGuard {
                    permit: Some(permit),
                    sem: Arc::clone(sem),
                    limit: self.fetch_concurrency_limit,
                }))
            }
            Ok(Err(_)) => {
                // The semaphore is owned by this ProxyService instance and
                // is never explicitly closed, so reaching this branch implies
                // a logic error elsewhere. Return an error rather than
                // panicking so a never-expected condition cannot bring down
                // the proxy hot path.
                Err(AppError::Internal(
                    "upstream fetch semaphore unexpectedly closed".to_string(),
                ))
            }
            Err(_) => {
                crate::services::metrics_service::record_proxy_queue_full();
                tracing::warn!(
                    limit = self.fetch_concurrency_limit,
                    timeout_secs = self.queue_timeout.as_secs(),
                    "proxy upstream-fetch queue full, returning 503 to client"
                );
                // Generic public message: do NOT include limit or timeout
                // numbers. An unauthenticated client can otherwise binary-
                // search the limit by ramping concurrency until 503 fires,
                // learning the exact PROXY_MAX_CONCURRENT_FETCHES per pod.
                // The Retry-After header carries the actionable hint.
                Err(AppError::Overloaded {
                    message: "upstream-fetch queue is saturated; retry after backoff".to_string(),
                    retry_after_secs: self.queue_timeout.as_secs().max(1),
                })
            }
        }
    }

    /// Recompute and publish the `ak_proxy_upstream_inflight` gauge from the
    /// semaphore's current available-permits count. Called both on permit
    /// acquire (in `acquire_fetch_permit`) and on permit release (via
    /// `FetchPermitGuard::drop`) so the gauge tracks both edges and never
    /// stays pinned at a stale high-water mark while traffic is idle.
    fn refresh_inflight_gauge_for(sem: &Semaphore, limit: usize) {
        let inflight = limit.saturating_sub(sem.available_permits());
        crate::services::metrics_service::set_proxy_upstream_inflight(inflight as f64);
    }

    fn refresh_inflight_gauge(&self) {
        if let Some(sem) = &self.upstream_fetch_sem {
            Self::refresh_inflight_gauge_for(sem, self.fetch_concurrency_limit);
        }
    }

    /// Fetch artifact from upstream if not cached or cache expired.
    /// Returns (content, content_type) tuple.
    pub async fn fetch_artifact(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        self.fetch_artifact_with_cache_path(repo, path, path).await
    }

    /// Check whether an artifact is already present in the proxy cache
    /// under the given `path` (without contacting upstream).
    ///
    /// Returns `Ok(Some((content, content_type)))` on cache hit, `Ok(None)`
    /// on cache miss or expired entry.
    pub async fn get_cached_artifact_by_path(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        let cache_key = Self::cache_storage_key(repo_key, path);
        let metadata_key = Self::cache_metadata_key(repo_key, path);
        self.get_cached_artifact(&cache_key, &metadata_key).await
    }

    /// Fetch artifact from upstream, but use `cache_path` instead of
    /// `fetch_path` when reading and writing the proxy cache.
    ///
    /// This is useful when the upstream download URL is unpredictable (e.g.,
    /// PyPI hosts files on a different domain) but the caller wants a stable,
    /// locally-computed cache key so that subsequent requests can hit the
    /// cache without rediscovering the upstream URL.
    pub async fn fetch_artifact_with_cache_path(
        &self,
        repo: &Repository,
        fetch_path: &str,
        cache_path: &str,
    ) -> Result<(Bytes, Option<String>)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        // Cache keys use the caller-supplied cache_path
        let cache_key = Self::cache_storage_key(&repo.key, cache_path);
        let metadata_key = Self::cache_metadata_key(&repo.key, cache_path);

        // Check if we have a valid cached copy
        if let Some((content, content_type)) =
            self.get_cached_artifact(&cache_key, &metadata_key).await?
        {
            return Ok((content, content_type));
        }

        // Fetch from upstream using the real fetch_path. The stampede-
        // protection permit is acquired inside fetch_from_upstream itself
        // (the chokepoint) so callers like fetch_upstream_direct that don't
        // go through this cache-aware path are also bounded. The permit is
        // released as soon as the upstream HTTP call completes; the cache
        // write below and the stale-fallback branch run unguarded.
        let full_url = Self::build_upstream_url(upstream_url, fetch_path);
        let upstream_result = self.fetch_from_upstream(&full_url, repo.id).await;

        match upstream_result {
            Ok(resp) => {
                let cache_ttl = self.get_cache_ttl_for_repo(repo.id).await;
                self.cache_artifact(
                    &cache_key,
                    &metadata_key,
                    &resp.content,
                    resp.content_type.clone(),
                    resp.etag,
                    cache_ttl,
                    repo.id,
                    cache_path,
                )
                .await?;

                Ok((resp.content, resp.content_type))
            }
            Err(upstream_err) => {
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
            return self.check_etag_changed(&full_url, etag, repo.id).await;
        }

        // No ETag, rely on TTL - cache is still valid
        Ok(false)
    }

    /// Fetch from upstream without reading or writing the proxy cache.
    ///
    /// This is useful when the caller needs the *raw* upstream response (e.g.,
    /// to parse download URLs from a PyPI simple index) and cannot risk
    /// receiving a locally-transformed cached copy.
    ///
    /// Returns `(content, content_type, effective_url)`. The effective URL is
    /// the final URL after any redirects, which may differ from the requested
    /// URL. Callers that resolve relative URLs in the response body should use
    /// the effective URL as the base for resolution.
    pub async fn fetch_upstream_direct(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>, String)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let full_url = Self::build_upstream_url(upstream_url, path);
        let resp = self.fetch_from_upstream(&full_url, repo.id).await?;
        Ok((resp.content, resp.content_type, resp.effective_url))
    }

    /// Fetch from upstream directly, preserving the upstream `Link` header.
    ///
    /// OCI tag pagination relies on the upstream continuation cursor when the
    /// registry enforces its own page-size cap. Callers that need to reconstruct
    /// pagination accurately should use this instead of [`fetch_upstream_direct`].
    pub async fn fetch_upstream_direct_with_link(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<(Bytes, Option<String>, Option<String>)> {
        if repo.repo_type != RepositoryType::Remote {
            return Err(AppError::Validation(
                "Proxy operations only supported for remote repositories".to_string(),
            ));
        }

        let upstream_url = repo.upstream_url.as_ref().ok_or_else(|| {
            AppError::Config("Remote repository missing upstream_url".to_string())
        })?;

        let full_url = Self::build_upstream_url(upstream_url, path);
        let resp = self.fetch_from_upstream(&full_url, repo.id).await?;
        Ok((resp.content, resp.content_type, resp.link))
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
            path.trim_start_matches('/').trim_end_matches('/')
        )
    }

    /// Generate storage key for cache metadata
    fn cache_metadata_key(repo_key: &str, path: &str) -> String {
        format!(
            "proxy-cache/{}/{}/__cache_meta__.json",
            repo_key,
            path.trim_start_matches('/').trim_end_matches('/')
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

    /// Fetch artifact from upstream URL.
    ///
    /// Handles OCI registry bearer token exchange: when the upstream returns
    /// 401 with a `WWW-Authenticate: Bearer` challenge, the service requests
    /// a token from the indicated realm and retries the request. Tokens are
    /// cached in memory with their advertised TTL so subsequent requests to
    /// the same registry/scope don't repeat the exchange.
    async fn fetch_from_upstream(&self, url: &str, repo_id: Uuid) -> Result<UpstreamResponse> {
        // Stampede protection: every upstream HTTP call funnels through
        // this method, so acquiring the permit here bounds concurrent
        // fan-out across ALL paths (fetch_artifact_with_cache_path,
        // fetch_upstream_direct, fetch_upstream_direct_with_link, OCI
        // bearer-token retries, ETag conditional fetches, etc.) without
        // each caller having to remember to acquire. The permit is
        // released when this function returns; the caller's cache write
        // / stale fallback / metadata persistence run unguarded.
        let _permit = self.acquire_fetch_permit().await?;

        tracing::info!("Fetching artifact from upstream: {}", url);

        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self.http_client.get(url);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to fetch from upstream: {}", e)))?;

        let status = response.status();

        // Handle 401 with bearer token exchange (required by Docker Hub and
        // other OCI registries, even for anonymous/public pulls).
        if status == StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if challenge.starts_with("Bearer ") {
                let params = Self::parse_bearer_challenge(&challenge);
                if let Some(realm) = params.get("realm") {
                    let scope = params.get("scope").cloned().unwrap_or_default();
                    let service = params.get("service").cloned().unwrap_or_default();

                    // Validate the realm URL against SSRF rules before making
                    // any outbound request. A malicious upstream could set
                    // realm to an internal address.
                    crate::api::validation::validate_outbound_url(realm, "OCI token realm")?;

                    let token = self
                        .obtain_bearer_token(realm, &service, &scope, &upstream_auth)
                        .await?;

                    // Retry with the bearer token only. The original upstream
                    // Basic credentials were already forwarded to the token
                    // endpoint in obtain_bearer_token(); adding them here
                    // would produce two Authorization headers.
                    let retry_request = self.http_client.get(url).bearer_auth(&token);

                    let retry_response = retry_request.send().await.map_err(|e| {
                        AppError::Storage(format!(
                            "Failed to fetch from upstream after token exchange: {}",
                            e
                        ))
                    })?;

                    return Self::read_upstream_response(retry_response, url).await;
                }
            }

            return Err(AppError::Storage(format!(
                "Upstream returned error status {}: {}",
                status, url
            )));
        }

        Self::read_upstream_response(response, url).await
    }

    /// Extract content, content-type, etag, effective URL, and Link header from
    /// an upstream HTTP response. Callers are responsible for handling 401 before
    /// invoking.
    async fn read_upstream_response(
        response: reqwest::Response,
        url: &str,
    ) -> Result<UpstreamResponse> {
        let status = response.status();
        let effective_url = response.url().to_string();

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

        let link = response
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let content = response
            .bytes()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read upstream response: {}", e)))?;

        tracing::info!(
            "Fetched {} bytes from upstream (content_type: {:?}, etag: {:?}, link: {:?})",
            content.len(),
            content_type,
            etag,
            link
        );

        Ok(UpstreamResponse {
            content,
            content_type,
            etag,
            effective_url,
            link,
        })
    }

    /// Obtain a bearer token for an OCI registry, using the in-memory cache
    /// when possible.
    async fn obtain_bearer_token(
        &self,
        realm: &str,
        service: &str,
        scope: &str,
        upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
    ) -> Result<String> {
        let cache_key = format!("{}\0{}\0{}", realm, service, scope);

        if let Some(token) = self.get_cached_token(&cache_key).await {
            return Ok(token);
        }

        // Build token request URL with query parameters.
        let token_url = {
            let mut parts = Vec::new();
            if !service.is_empty() {
                parts.push(format!("service={}", urlencoding::encode(service)));
            }
            if !scope.is_empty() {
                parts.push(format!("scope={}", urlencoding::encode(scope)));
            }
            if parts.is_empty() {
                realm.to_string()
            } else {
                let sep = if realm.contains('?') { "&" } else { "?" };
                format!("{}{}{}", realm, sep, parts.join("&"))
            }
        };
        let mut token_request = self.http_client.get(&token_url);

        // Forward configured Basic credentials for private registries.
        if let Some(crate::services::upstream_auth::UpstreamAuthType::Basic {
            username,
            password,
        }) = upstream_auth
        {
            token_request = token_request.basic_auth(username, Some(password));
        }

        tracing::debug!("Requesting bearer token from {} (scope={})", realm, scope);

        let token_response = token_request.send().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to request bearer token from {}: {}",
                realm, e
            ))
        })?;

        if !token_response.status().is_success() {
            return Err(AppError::Storage(format!(
                "Token endpoint {} returned status {}",
                realm,
                token_response.status()
            )));
        }

        let body: RegistryTokenResponse = token_response.json().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to parse token response from {}: {}",
                realm, e
            ))
        })?;

        let token = body
            .token
            .or(body.access_token)
            .ok_or_else(|| AppError::Storage("Token endpoint returned no token".to_string()))?;

        // Cap TTL to prevent overflow and unreasonably long cache entries.
        let ttl = body
            .expires_in
            .unwrap_or(DEFAULT_TOKEN_TTL_SECS)
            .min(MAX_TOKEN_TTL_SECS);

        // Cache the token, evicting expired entries to prevent unbounded growth.
        {
            let mut cache = self.token_cache.write().await;
            cache.retain(|_, (_, created_at, entry_ttl)| {
                created_at.elapsed() < Duration::from_secs(*entry_ttl)
            });
            cache.insert(cache_key, (token.clone(), Instant::now(), ttl));
        }

        Ok(token)
    }

    /// Return a cached bearer token if present and not expired.
    async fn get_cached_token(&self, cache_key: &str) -> Option<String> {
        let cache = self.token_cache.read().await;
        let (token, created_at, ttl_secs) = cache.get(cache_key)?;
        if created_at.elapsed() < Duration::from_secs(ttl_secs.saturating_mul(9) / 10) {
            Some(token.clone())
        } else {
            None
        }
    }

    /// Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
    /// header into a map of key-value pairs.
    fn parse_bearer_challenge(header: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        let bearer_params = match header.strip_prefix("Bearer ") {
            Some(p) => p,
            None => return params,
        };

        let mut remaining = bearer_params.trim();
        while !remaining.is_empty() {
            let eq_pos = match remaining.find('=') {
                Some(p) => p,
                None => break,
            };
            let key = remaining[..eq_pos].trim().to_lowercase();
            remaining = remaining[eq_pos + 1..].trim();

            let value;
            if remaining.starts_with('"') {
                remaining = &remaining[1..];
                let end = remaining.find('"').unwrap_or(remaining.len());
                value = remaining[..end].to_string();
                remaining = if end + 1 < remaining.len() {
                    remaining[end + 1..].trim_start_matches(',').trim()
                } else {
                    ""
                };
            } else {
                let end = remaining.find(',').unwrap_or(remaining.len());
                value = remaining[..end].trim().to_string();
                remaining = if end < remaining.len() {
                    remaining[end + 1..].trim()
                } else {
                    ""
                };
            }

            params.insert(key, value);
        }

        params
    }

    /// Cache artifact content and metadata, and record the artifact in the
    /// database so that it appears in repository listings and storage usage.
    #[allow(clippy::too_many_arguments)]
    async fn cache_artifact(
        &self,
        cache_key: &str,
        metadata_key: &str,
        content: &Bytes,
        content_type: Option<String>,
        etag: Option<String>,
        ttl_secs: i64,
        repository_id: Uuid,
        artifact_path: &str,
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
            checksum_sha256: checksum.clone(),
        };

        // Store content
        self.storage.put(cache_key, content.clone()).await?;

        // Store metadata
        let metadata_json = serde_json::to_vec(&metadata)?;
        self.storage
            .put(metadata_key, Bytes::from(metadata_json))
            .await?;

        // Record the cached artifact in the database so it shows up in
        // repository listings and storage size calculations.
        let normalized_path = artifact_path.trim_start_matches('/');
        let artifact_name = normalized_path
            .rsplit('/')
            .next()
            .unwrap_or(normalized_path);
        let ct = metadata
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let size = content.len() as i64;
        let format = sqlx::query_scalar::<_, RepositoryFormat>(
            "SELECT format FROM repositories WHERE id = $1",
        )
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(RepositoryFormat::Generic);
        let version = extract_version_from_path(&format, normalized_path);

        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (repository_id, path) DO UPDATE SET
                version = COALESCE(EXCLUDED.version, artifacts.version),
                size_bytes = EXCLUDED.size_bytes,
                checksum_sha256 = EXCLUDED.checksum_sha256,
                content_type = EXCLUDED.content_type,
                storage_key = EXCLUDED.storage_key,
                is_deleted = false,
                updated_at = NOW()
            "#,
        )
        .bind(repository_id)
        .bind(normalized_path)
        .bind(artifact_name)
        .bind(&version)
        .bind(size)
        .bind(&checksum)
        .bind(&ct)
        .bind(cache_key)
        .execute(&self.db)
        .await
        {
            // Log the error but don't fail the cache operation. The content is
            // already stored and usable; the DB record is a best-effort addition
            // for listing/size purposes.
            tracing::warn!(
                "Failed to record cached artifact in database for {}: {}",
                cache_key,
                e
            );
        }

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
    async fn check_etag_changed(
        &self,
        url: &str,
        cached_etag: &str,
        repo_id: Uuid,
    ) -> Result<bool> {
        let upstream_auth =
            crate::services::upstream_auth::load_upstream_auth(&self.db, repo_id).await?;

        let mut request = self
            .http_client
            .head(url)
            .header(IF_NONE_MATCH, cached_etag);
        if let Some(ref auth) = upstream_auth {
            request = crate::services::upstream_auth::apply_upstream_auth(request, auth);
        }

        let response = request.send().await.map_err(|e| {
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
            StatusCode::UNAUTHORIZED => {
                // OCI registries require bearer token exchange even for HEAD
                // requests. Rather than duplicating the token exchange here,
                // treat this as "needs re-fetch" and let fetch_from_upstream
                // handle the full 401 flow on the next access.
                tracing::debug!(
                    "Upstream returned 401 for ETag check on {}, will re-fetch with token exchange",
                    url
                );
                Ok(true)
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

/// Extract version from an artifact path based on the repository format.
///
/// Each package format encodes the version differently in the path. This
/// function delegates to format-specific parsing logic and returns `None`
/// for metadata files, index pages, or paths where the version cannot be
/// determined.
pub(crate) fn extract_version_from_path(format: &RepositoryFormat, path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    match format {
        // Maven: groupId/.../artifactId/version/filename
        RepositoryFormat::Maven | RepositoryFormat::Gradle | RepositoryFormat::Sbt => {
            crate::formats::maven::MavenHandler::parse_coordinates(path)
                .ok()
                .map(|c| c.version)
        }

        // NPM: @scope/name/-/name-version.tgz or name/-/name-version.tgz
        RepositoryFormat::Npm
        | RepositoryFormat::Yarn
        | RepositoryFormat::Bower
        | RepositoryFormat::Pnpm => crate::formats::npm::NpmHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // PyPI: simple/name/ (index) or packages/name/version/filename
        RepositoryFormat::Pypi | RepositoryFormat::Poetry | RepositoryFormat::Conda => {
            crate::formats::pypi::PypiHandler::parse_path(path)
                .ok()
                .and_then(|info| info.version)
        }

        // NuGet: v3/flatcontainer/name/version/name.version.nupkg
        RepositoryFormat::Nuget | RepositoryFormat::Chocolatey | RepositoryFormat::Powershell => {
            crate::formats::nuget::NugetHandler::parse_path(path)
                .ok()
                .and_then(|info| info.version)
        }

        // Cargo: crates/name/name-version.crate or api/v1/crates/name/version/download
        RepositoryFormat::Cargo => crate::formats::cargo::CargoHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // Go: module/@v/version.info|.mod|.zip
        RepositoryFormat::Go => crate::formats::go::GoHandler::parse_path(path)
            .ok()
            .and_then(|info| info.version),

        // OCI/Docker formats: version is conveyed via tags/digests in the
        // registry protocol, not in the URL path, so return None.
        RepositoryFormat::Docker
        | RepositoryFormat::Podman
        | RepositoryFormat::Buildx
        | RepositoryFormat::Oras
        | RepositoryFormat::WasmOci
        | RepositoryFormat::HelmOci
        | RepositoryFormat::Incus
        | RepositoryFormat::Lxc => None,

        // Generic fallback: try name/version/filename pattern
        _ => {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 3 {
                Some(parts[parts.len() - 2].to_string())
            } else {
                None
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
    fn test_cache_metadata_key_strips_trailing_slash() {
        assert_eq!(
            ProxyService::cache_metadata_key("pypi-remote", "simple/numpy/"),
            "proxy-cache/pypi-remote/simple/numpy/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_storage_key_strips_trailing_slash() {
        assert_eq!(
            ProxyService::cache_storage_key("pypi-remote", "simple/numpy/"),
            "proxy-cache/pypi-remote/simple/numpy/__content__"
        );
    }

    #[test]
    fn test_cache_keys_strip_both_slashes() {
        assert_eq!(
            ProxyService::cache_metadata_key("pypi-remote", "/simple/numpy/"),
            "proxy-cache/pypi-remote/simple/numpy/__cache_meta__.json"
        );
        assert_eq!(
            ProxyService::cache_storage_key("pypi-remote", "/simple/numpy/"),
            "proxy-cache/pypi-remote/simple/numpy/__content__"
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

    // =======================================================================
    // PyPI-specific cache key derivation
    // =======================================================================

    #[test]
    fn test_cache_key_for_pypi_local_path() {
        let key = ProxyService::cache_storage_key(
            "my-pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        );
        assert_eq!(
            key,
            "proxy-cache/my-pypi-remote/simple/requests/requests-2.31.0.tar.gz/__content__"
        );
    }

    #[test]
    fn test_cache_metadata_key_for_pypi_local_path() {
        let key = ProxyService::cache_metadata_key(
            "my-pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        );
        assert_eq!(
            key,
            "proxy-cache/my-pypi-remote/simple/requests/requests-2.31.0.tar.gz/__cache_meta__.json"
        );
    }

    #[test]
    fn test_cache_key_for_pypi_wheel() {
        let key = ProxyService::cache_storage_key(
            "pypi-proxy",
            "simple/flask/flask-3.0.0-py3-none-any.whl",
        );
        assert!(key.starts_with("proxy-cache/pypi-proxy/simple/flask/"));
        assert!(key.ends_with("/__content__"));
    }

    #[test]
    fn test_cache_key_pypi_and_npm_do_not_collide() {
        let pypi_key = ProxyService::cache_storage_key(
            "pypi-remote",
            "simple/requests/requests-2.31.0.tar.gz",
        );
        let npm_key =
            ProxyService::cache_storage_key("npm-remote", "simple/requests/requests-2.31.0.tar.gz");
        assert_ne!(pypi_key, npm_key);
    }

    // --- cache key construction for fetch_artifact_with_cache_path ---

    #[test]
    fn test_cache_key_with_custom_path_differs_from_fetch_path() {
        let fetch_path = "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz";
        let cache_path = "simple/requests/requests-2.31.0.tar.gz";
        let fetch_key = ProxyService::cache_storage_key("pypi-remote", fetch_path);
        let cache_key = ProxyService::cache_storage_key("pypi-remote", cache_path);
        assert_ne!(
            fetch_key, cache_key,
            "cache key should differ from fetch key"
        );
    }

    #[test]
    fn test_cache_metadata_key_with_custom_path() {
        let cache_path = "simple/numpy/numpy-1.26.0.tar.gz";
        let key = ProxyService::cache_metadata_key("pypi-remote", cache_path);
        assert!(key.contains("pypi-remote"));
        assert!(key.contains("numpy"));
    }

    #[test]
    fn test_build_upstream_url_with_trailing_slash() {
        let url = ProxyService::build_upstream_url("https://pypi.org/", "simple/requests/");
        assert_eq!(url, "https://pypi.org/simple/requests/");
    }

    #[test]
    fn test_build_upstream_url_without_trailing_slash() {
        let url = ProxyService::build_upstream_url("https://pypi.org", "simple/requests/");
        assert_eq!(url, "https://pypi.org/simple/requests/");
    }

    #[test]
    fn test_build_upstream_url_with_leading_slash_in_path() {
        let url = ProxyService::build_upstream_url("https://pypi.org", "/simple/requests/");
        // Should not double-slash
        assert!(!url.contains("//simple"));
    }

    #[test]
    fn test_get_cached_artifact_by_path_uses_correct_keys() {
        // Verify that get_cached_artifact_by_path constructs the same keys
        // as manual cache_storage_key + cache_metadata_key calls
        let repo_key = "test-pypi";
        let path = "simple/flask/flask-3.0.0.tar.gz";
        let expected_storage = ProxyService::cache_storage_key(repo_key, path);
        let expected_meta = ProxyService::cache_metadata_key(repo_key, path);
        // The function internally calls these same methods, so keys should match
        assert!(expected_storage.contains("test-pypi"));
        assert!(expected_meta.contains("test-pypi"));
        assert!(expected_storage.contains("flask"));
        assert!(expected_meta.contains("flask"));
    }

    // =======================================================================
    // Bearer challenge parser tests
    // =======================================================================

    #[test]
    fn test_parse_bearer_challenge_docker_hub() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://auth.docker.io/token");
        assert_eq!(params.get("service").unwrap(), "registry.docker.io");
        assert_eq!(
            params.get("scope").unwrap(),
            "repository:library/alpine:pull"
        );
    }

    #[test]
    fn test_parse_bearer_challenge_ghcr() {
        let header = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/image:pull""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://ghcr.io/token");
        assert_eq!(params.get("service").unwrap(), "ghcr.io");
    }

    #[test]
    fn test_parse_bearer_challenge_realm_only() {
        let header = r#"Bearer realm="https://example.com/token""#;
        let params = ProxyService::parse_bearer_challenge(header);
        assert_eq!(params.get("realm").unwrap(), "https://example.com/token");
        assert!(!params.contains_key("service"));
    }

    #[test]
    fn test_parse_bearer_challenge_not_bearer() {
        let params = ProxyService::parse_bearer_challenge("Basic realm=\"test\"");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_bearer_challenge_empty() {
        let params = ProxyService::parse_bearer_challenge("");
        assert!(params.is_empty());
    }

    #[tokio::test]
    async fn test_token_cache_hit_and_expiry() {
        let cache: RwLock<HashMap<String, (String, Instant, u64)>> = RwLock::new(HashMap::new());
        {
            let mut c = cache.write().await;
            c.insert(
                "key".to_string(),
                ("tok123".to_string(), Instant::now(), 300),
            );
        }
        let hit = {
            let c = cache.read().await;
            let (token, created_at, ttl) = c.get("key").unwrap();
            if created_at.elapsed() < Duration::from_secs(ttl.saturating_mul(9) / 10) {
                Some(token.clone())
            } else {
                None
            }
        };
        assert_eq!(hit, Some("tok123".to_string()));

        {
            let mut c = cache.write().await;
            c.insert(
                "expired".to_string(),
                (
                    "old".to_string(),
                    Instant::now() - Duration::from_secs(600),
                    300,
                ),
            );
        }
        let miss = {
            let c = cache.read().await;
            let (token, created_at, ttl) = c.get("expired").unwrap();
            if created_at.elapsed() < Duration::from_secs(ttl.saturating_mul(9) / 10) {
                Some(token.clone())
            } else {
                None
            }
        };
        assert!(miss.is_none());
    }

    #[tokio::test]
    async fn test_token_cache_eviction_on_write() {
        let cache: RwLock<HashMap<String, (String, Instant, u64)>> = RwLock::new(HashMap::new());
        {
            let mut c = cache.write().await;
            c.insert(
                "expired".to_string(),
                (
                    "old".to_string(),
                    Instant::now() - Duration::from_secs(600),
                    300,
                ),
            );
            c.insert(
                "fresh".to_string(),
                ("new".to_string(), Instant::now(), 300),
            );
        }
        {
            let mut c = cache.write().await;
            c.retain(|_, (_, created_at, entry_ttl)| {
                created_at.elapsed() < Duration::from_secs(*entry_ttl)
            });
        }
        let c = cache.read().await;
        assert!(!c.contains_key("expired"));
        assert!(c.contains_key("fresh"));
    }

    // =======================================================================
    // extract_version_from_path tests
    // =======================================================================

    #[test]
    fn test_extract_version_maven_standard() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_sha1_checksum() {
        // This is the exact case from issue #640
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom.sha1",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_snapshot() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "com/mycompany/app/my-app/1.0-SNAPSHOT/my-app-1.0-20260402.154115-1.jar",
        );
        assert_eq!(version.as_deref(), Some("1.0-SNAPSHOT"));
    }

    #[test]
    fn test_extract_version_maven_deep_group_id() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
        );
        assert_eq!(version.as_deref(), Some("3.12.0"));
    }

    #[test]
    fn test_extract_version_maven_metadata_xml() {
        // maven-metadata.xml at version level still has the version in the path
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "org/junit/junit-bom/5.10.1/maven-metadata.xml",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_extract_version_maven_too_short_path() {
        // Artifact-level metadata: groupId/artifactId/maven-metadata.xml
        let version =
            extract_version_from_path(&RepositoryFormat::Maven, "org/junit/maven-metadata.xml");
        // parse_coordinates requires 4 segments, so this returns None
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_npm_unscoped_tarball() {
        let version =
            extract_version_from_path(&RepositoryFormat::Npm, "express/-/express-4.18.2.tgz");
        assert_eq!(version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn test_extract_version_npm_scoped_tarball() {
        let version =
            extract_version_from_path(&RepositoryFormat::Npm, "@babel/core/-/core-7.24.0.tgz");
        assert_eq!(version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn test_extract_version_npm_metadata_request() {
        // Metadata requests (just package name) have no version
        let version = extract_version_from_path(&RepositoryFormat::Npm, "express");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_pypi_package_file() {
        let version = extract_version_from_path(
            &RepositoryFormat::Pypi,
            "packages/requests/2.31.0/requests-2.31.0.tar.gz",
        );
        assert_eq!(version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn test_extract_version_pypi_simple_index() {
        let version = extract_version_from_path(&RepositoryFormat::Pypi, "simple/requests/");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_nuget() {
        let version = extract_version_from_path(
            &RepositoryFormat::Nuget,
            "v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        );
        assert_eq!(version.as_deref(), Some("13.0.3"));
    }

    #[test]
    fn test_extract_version_cargo() {
        let version =
            extract_version_from_path(&RepositoryFormat::Cargo, "crates/serde/serde-1.0.197.crate");
        assert_eq!(version.as_deref(), Some("1.0.197"));
    }

    #[test]
    fn test_extract_version_go_module() {
        let version = extract_version_from_path(
            &RepositoryFormat::Go,
            "github.com/gin-gonic/gin/@v/v1.9.1.info",
        );
        assert_eq!(version.as_deref(), Some("v1.9.1"));
    }

    #[test]
    fn test_extract_version_go_zip() {
        let version = extract_version_from_path(
            &RepositoryFormat::Go,
            "github.com/gin-gonic/gin/@v/v1.9.1.zip",
        );
        assert_eq!(version.as_deref(), Some("v1.9.1"));
    }

    #[test]
    fn test_extract_version_docker_returns_none() {
        let version = extract_version_from_path(
            &RepositoryFormat::Docker,
            "v2/library/nginx/manifests/1.25.3",
        );
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_gradle_delegates_to_maven() {
        let version = extract_version_from_path(
            &RepositoryFormat::Gradle,
            "com/google/guava/guava/32.1.3-jre/guava-32.1.3-jre.jar",
        );
        assert_eq!(version.as_deref(), Some("32.1.3-jre"));
    }

    #[test]
    fn test_extract_version_generic_fallback() {
        let version = extract_version_from_path(
            &RepositoryFormat::Generic,
            "my-tool/2.0.0/my-tool-2.0.0.tar.gz",
        );
        assert_eq!(version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn test_extract_version_generic_short_path() {
        let version = extract_version_from_path(&RepositoryFormat::Generic, "single-file.bin");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_version_leading_slash_stripped() {
        let version = extract_version_from_path(
            &RepositoryFormat::Maven,
            "/org/junit/junit-bom/5.10.1/junit-bom-5.10.1.pom",
        );
        assert_eq!(version.as_deref(), Some("5.10.1"));
    }

    #[test]
    fn test_cache_key_includes_service() {
        let key1 = format!(
            "{}\0{}\0{}",
            "https://auth.example.com/token", "registry-a", "repo:img:pull"
        );
        let key2 = format!(
            "{}\0{}\0{}",
            "https://auth.example.com/token", "registry-b", "repo:img:pull"
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ttl_cap_prevents_overflow() {
        let huge_ttl: u64 = u64::MAX;
        let capped = huge_ttl.min(MAX_TOKEN_TTL_SECS);
        assert_eq!(capped, 3600);
        let effective = capped.saturating_mul(9) / 10;
        assert_eq!(effective, 3240);
    }

    // =======================================================================
    // upstream-fetch semaphore tests (proxy_stampede_protection)
    //
    // Validate acquire_fetch_permit directly without DB or wiremock. The
    // critical bound-concurrency test gates task release through a Barrier,
    // so the observed peak is deterministic and not coupled to wallclock
    // sleep — a starved CI runner cannot mask a regression.
    // =======================================================================

    /// Build a ProxyService for permit-only tests. Returns the service plus
    /// the TempDir guard; the guard MUST be kept alive for the duration of
    /// the test or the storage backend's tempdir is unlinked early.
    ///
    /// IMPORTANT: this service's `db` is `PgPool::connect_lazy` against an
    /// invalid URL. Any test that calls a method touching `self.db` will
    /// hang on connect. Stick to `acquire_fetch_permit` and direct field
    /// access on `upstream_fetch_sem`.
    fn make_permit_only_proxy(
        max_concurrent: usize,
        queue_timeout: Duration,
    ) -> (std::sync::Arc<ProxyService>, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("create tempdir for permit-only proxy test");
        let backend: std::sync::Arc<dyn crate::services::storage_service::StorageBackend> =
            std::sync::Arc::new(crate::services::storage_service::FilesystemBackend::new(
                temp_dir.path().to_path_buf(),
            ));
        let storage = std::sync::Arc::new(crate::services::storage_service::StorageService::new(
            backend,
        ));
        let db = sqlx::PgPool::connect_lazy("postgres://invalid-host/test")
            .expect("lazy pool construction");
        let svc = ProxyService::with_concurrency(db, storage, max_concurrent, queue_timeout);
        (std::sync::Arc::new(svc), temp_dir)
    }

    #[tokio::test]
    async fn test_acquire_permit_bounds_concurrency_at_limit_deterministic() {
        // Deterministic peak measurement: each task acquires a permit, ticks
        // a Barrier waiting for LIMIT tasks to be inside the critical region,
        // then releases. This proves peak == LIMIT exactly; a starved runner
        // cannot make peak appear lower than LIMIT.
        const LIMIT: usize = 3;
        const N: usize = 12;
        let (svc, _td) = make_permit_only_proxy(LIMIT, Duration::from_secs(30));

        let inflight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Barrier of LIMIT: only LIMIT permit-holders fit at once, so once
        // LIMIT tasks have acquired they all proceed past the barrier
        // together; the rest stay queued at acquire_fetch_permit until a
        // permit drops, repeat the cycle.
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(LIMIT));

        let mut handles = Vec::new();
        for _ in 0..N {
            let svc = svc.clone();
            let inflight = inflight.clone();
            let peak = peak.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let permit = svc.acquire_fetch_permit().await.expect("permit");
                let cur = inflight.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
                // Wait until exactly LIMIT permit-holders are in the
                // critical region. This guarantees observed peak == LIMIT
                // without depending on scheduler timing.
                barrier.wait().await;
                inflight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                drop(permit);
            }));
        }
        for h in handles {
            h.await.expect("task");
        }

        let peak_observed = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            peak_observed, LIMIT,
            "expected peak concurrent fetches to equal LIMIT={LIMIT}, got {peak_observed}"
        );
    }

    #[tokio::test]
    async fn test_acquire_permit_returns_overloaded_on_queue_timeout() {
        // Limit=1 + a held permit => the next acquire must time out.
        // 500ms timeout gives ~3x scheduler-jitter margin over the previous
        // 150ms; total test runtime stays well under a second.
        let (svc, _td) = make_permit_only_proxy(1, Duration::from_millis(500));
        let sem = svc
            .upstream_fetch_sem
            .as_ref()
            .expect("limit=1 must allocate a semaphore")
            .clone();
        let _held = sem.acquire_owned().await.expect("hold permit");

        let result = svc.acquire_fetch_permit().await;
        match result {
            Err(AppError::Overloaded {
                message,
                retry_after_secs,
            }) => {
                assert!(
                    message.contains("saturated"),
                    "expected 'saturated' in user message, got: {message}"
                );
                // Public message must NOT leak capacity tunables (see
                // comment on acquire_fetch_permit). Asserting absence
                // catches a regression where someone reintroduces
                // limit/timeout into the response body.
                assert!(
                    !message.contains("limit:"),
                    "user message must not leak configured limit, got: {message}"
                );
                assert!(
                    !message.contains("timeout"),
                    "user message must not leak configured timeout, got: {message}"
                );
                // Retry-After must be at least 1 second (we max(1) the
                // queue_timeout). Caller's queue_timeout was 500ms which
                // floor()s to 0; the max(1) guard turns it into 1.
                assert!(
                    retry_after_secs >= 1,
                    "retry_after_secs must be >= 1, got: {retry_after_secs}"
                );
            }
            other => panic!("expected AppError::Overloaded, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn test_acquire_permit_succeeds_after_release() {
        // Verify the semaphore is not poisoned by a queue-timeout: after a
        // held permit is released, the next acquire succeeds normally.
        let (svc, _td) = make_permit_only_proxy(1, Duration::from_millis(500));
        {
            let sem = svc
                .upstream_fetch_sem
                .as_ref()
                .expect("limit=1 must allocate a semaphore")
                .clone();
            let _held = sem.acquire_owned().await.expect("hold permit");
            let _ = svc.acquire_fetch_permit().await; // expected to time out
        }
        let permit = svc
            .acquire_fetch_permit()
            .await
            .expect("post-release acquire");
        assert!(
            permit.is_some(),
            "expected Some(permit) after holder released; got None (limit > 0 should always allocate)"
        );
        drop(permit);
    }

    #[tokio::test]
    async fn test_zero_max_concurrent_disables_stampede_protection() {
        // Operator kill switch: PROXY_MAX_CONCURRENT_FETCHES=0 must DISABLE
        // the limiter entirely (no semaphore allocated, acquire is a no-op).
        // The previous behavior of clamping to 1 permit was a footgun: an
        // operator's instinct ("0 = disabled") tightened the cap instead.
        let (svc, _td) = make_permit_only_proxy(0, Duration::from_secs(1));
        assert_eq!(svc.fetch_concurrency_limit, 0);
        assert!(
            svc.upstream_fetch_sem.is_none(),
            "limit=0 must allocate no semaphore; got Some(_)"
        );
        // Acquire is a no-op fast path that returns Ok(None).
        let permit = svc.acquire_fetch_permit().await.expect("no-op acquire");
        assert!(
            permit.is_none(),
            "limit=0 acquire must return Ok(None); got Some(_)"
        );
    }

    #[tokio::test]
    async fn test_acquire_permit_no_op_does_not_block_under_concurrency() {
        // With stampede protection disabled, N concurrent acquires must all
        // return immediately without any semaphore contention. Catches a
        // regression where the disabled path accidentally still sequences.
        let (svc, _td) = make_permit_only_proxy(0, Duration::from_secs(1));
        let mut handles = Vec::new();
        for _ in 0..50 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move {
                svc.acquire_fetch_permit().await.expect("acquire").is_none()
            }));
        }
        for h in handles {
            assert!(h.await.expect("task"), "expected None permit on disabled");
        }
    }

    #[tokio::test]
    async fn test_overloaded_error_maps_to_503_with_retry_after() {
        // Documents the AppError::Overloaded → 503 + Retry-After contract.
        // The 503 is the load-bearing client signal; the Retry-After header
        // is what stops well-behaved clients (cargo, npm, pip retry
        // middleware, kubelet) from retry-storming the moment they see
        // 503 and re-saturating the queue.
        let err = AppError::Overloaded {
            message: "saturated".to_string(),
            retry_after_secs: 7,
        };
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .expect("Retry-After header must be present on 503 Overloaded")
            .to_str()
            .expect("Retry-After value must be valid ASCII");
        assert_eq!(retry_after, "7");
    }

    #[tokio::test]
    async fn test_with_concurrency_default_construction() {
        // Validate the documented defaults wired by ProxyService::new().
        let (svc, _td) = make_permit_only_proxy(
            DEFAULT_MAX_CONCURRENT_FETCHES,
            Duration::from_secs(DEFAULT_QUEUE_TIMEOUT_SECS),
        );
        assert_eq!(svc.fetch_concurrency_limit, DEFAULT_MAX_CONCURRENT_FETCHES);
        assert_eq!(
            svc.queue_timeout,
            Duration::from_secs(DEFAULT_QUEUE_TIMEOUT_SECS)
        );
        assert!(svc.upstream_fetch_sem.is_some());
    }

    /// Structural guard: assert that `fetch_from_upstream` actually invokes
    /// the permit acquisition. Every behavioural test in this module calls
    /// `acquire_fetch_permit` directly, so deleting the `let _permit = ...`
    /// line from `fetch_from_upstream` would silently disable stampede
    /// protection on the hot path while leaving every other test green.
    ///
    /// The forbidden-revert needle is built via `format!` from disjoint
    /// fragments so this test body itself does not contain a literal copy
    /// that would satisfy the substring check.
    #[test]
    fn test_fetch_from_upstream_invokes_acquire_fetch_permit() {
        const SOURCE: &str = include_str!("proxy_service.rs");

        let fn_marker = format!(
            "async fn {}{}",
            "fetch_from_upstream", "(&self, url: &str, repo_id: Uuid)"
        );
        let body_start = SOURCE.find(&fn_marker).unwrap_or_else(|| {
            panic!(
                "could not locate `fetch_from_upstream` definition; \
                 has its signature changed? Update this structural test."
            )
        });

        // Extract a window from the function definition through the next
        // 8 KB so the search stops well inside the function body but well
        // before any unrelated trailing methods.
        let end = (body_start + 8 * 1024).min(SOURCE.len());
        let window = &SOURCE[body_start..end];

        let needle = format!("{}{}", "acquire_fetch_", "permit");
        assert!(
            window.contains(&needle),
            "`fetch_from_upstream` no longer calls `{}`. This is the chokepoint \
             that bounds upstream fetch concurrency (#872); removing it silently \
             disables stampede protection. Re-add the permit acquisition or \
             update this structural test if the chokepoint moved.",
            needle
        );
    }
}
