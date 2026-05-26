//! API module - HTTP handlers and middleware.

pub mod download_response;
pub mod dto;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod validation;

use crate::config::Config;
use crate::services::artifact_service::ArtifactService;
use crate::services::dependency_track_service::DependencyTrackService;
use crate::services::event_bus::EventBus;
use crate::services::opensearch_service::OpenSearchService;
use crate::services::permission_service::PermissionService;
use crate::services::plugin_registry::PluginRegistry;
use crate::services::proxy_service::ProxyService;
use crate::services::quality_check_service::QualityCheckService;
use crate::services::repository_service::RepositoryService;
use crate::services::scanner_service::ScannerService;
use crate::services::smtp_service::SmtpService;
use crate::services::wasm_plugin_service::WasmPluginService;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};
use bytes::Bytes;
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Repository info cache — shared between repo_visibility_middleware and
// format-handler resolvers to eliminate duplicate DB lookups per request.
// ---------------------------------------------------------------------------

/// How long a cached repository record is considered fresh.
/// Repository metadata (visibility, type, upstream URL) rarely changes, so
/// 60 seconds is a safe balance between performance and propagation speed.
pub const REPO_CACHE_TTL_SECS: u64 = 60;

/// Cached repository metadata populated by the repo-visibility middleware
/// and reused by format-handler resolvers to avoid a second DB round-trip.
#[derive(Clone, Debug)]
pub struct CachedRepo {
    pub id: Uuid,
    pub format: String,
    pub repo_type: String,
    pub upstream_url: Option<String>,
    pub storage_path: String,
    pub storage_backend: String,
    pub is_public: bool,
    /// The `index_upstream_url` config value (cargo-specific; `None` for
    /// other formats or when not configured).
    pub index_upstream_url: Option<String>,
}

/// Thread-safe in-process cache for `CachedRepo` entries, keyed by repo key.
pub type RepoCache = Arc<RwLock<HashMap<String, (CachedRepo, Instant)>>>;

/// Thread-safe in-process cache for rendered cargo sparse-index entries.
/// Key: `"{repo_key}:{crate_name_lowercase}"`. Value: raw response bytes + insertion time.
pub type IndexCache = Arc<RwLock<HashMap<String, (Bytes, Instant)>>>;

/// Thread-safe in-process cache for signed APT Release artifacts
/// (`InRelease` and `Release.gpg`). Key: hex-encoded SHA-256 of
/// `(unsigned Release content || signing key fingerprint)`. Value: the
/// armored signed bytes.
///
/// OpenPGP signing of the Release file is CPU-bound (multi-millisecond per
/// hit on RSA-4096) and `apt update` requests both InRelease and Release.gpg
/// on every refresh. Caching by content hash means the signature is reused
/// across requests until the underlying Release content actually changes,
/// at which point the cache key naturally rotates. The `(repo_key,
/// distribution) -> set of cache keys` reverse index lets the change-detect
/// path purge stale entries when an upstream Release flip is detected
/// (mirroring how sibling Packages caches are invalidated for #1147).
pub type SignedReleaseCache = Arc<RwLock<HashMap<String, Bytes>>>;

/// Reverse index from (repo_key, distribution) to the set of cache keys
/// installed under that scope. Lets the change-detect path drop just the
/// signed-Release entries that belong to the changed distribution without
/// scanning the entire cache.
pub type SignedReleaseCacheIndex = Arc<RwLock<HashMap<(String, String), Vec<String>>>>;

/// Soft cap on the signed-Release cache. Each distribution typically holds
/// at most two entries (InRelease + Release.gpg) per active fingerprint, so
/// 1024 is comfortably above the working-set size for a busy registry while
/// still bounding worst-case memory if the cache ever grows pathologically.
pub const SIGNED_RELEASE_CACHE_MAX_ENTRIES: usize = 1024;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub storage: Arc<dyn StorageBackend>,
    pub storage_registry: Arc<StorageRegistry>,
    pub plugin_registry: Option<Arc<PluginRegistry>>,
    pub wasm_plugin_service: Option<Arc<WasmPluginService>>,
    pub scanner_service: Option<Arc<ScannerService>>,
    pub search_service: Option<Arc<OpenSearchService>>,
    pub dependency_track: Option<Arc<DependencyTrackService>>,
    pub quality_check_service: Option<Arc<QualityCheckService>>,
    pub permission_service: Arc<PermissionService>,
    pub proxy_service: Option<Arc<ProxyService>>,
    pub smtp_service: Option<Arc<SmtpService>>,
    pub metrics_handle: Option<Arc<PrometheusHandle>>,
    /// When true, most API endpoints return 403 until the admin changes the default password.
    pub setup_required: Arc<AtomicBool>,
    pub event_bus: Arc<EventBus>,
    /// Short-lived in-process cache of repository metadata, shared between
    /// the repo-visibility middleware and format-handler resolvers.
    pub repo_cache: RepoCache,
    /// In-process cache of rendered cargo sparse-index entries, keyed by
    /// `"{repo_key}:{crate_name_lowercase}"`. Eliminates storage I/O and
    /// SHA-256 re-verification on every warm index request.
    pub index_cache: IndexCache,
    /// In-process cache of signed APT `InRelease` / `Release.gpg` payloads,
    /// keyed by `SHA-256(unsigned Release || key fingerprint)`. Avoids
    /// re-signing on every `apt update` poll (#1236).
    pub signed_release_cache: SignedReleaseCache,
    /// Reverse index for `signed_release_cache` so the change-detect path
    /// can evict just the entries belonging to a specific
    /// `(repo_key, distribution)` when the underlying Release flips.
    pub signed_release_cache_index: SignedReleaseCacheIndex,
    /// Concurrency cap for bcrypt-bound auth work (login, password verify,
    /// API token verify). `None` when `auth_max_concurrency == 0`, in which
    /// case auth runs without a process-wide cap (legacy behaviour).
    ///
    /// See `config::auth_max_concurrency` for rationale: bcrypt-cost-12 is
    /// CPU-bound (~100-300 ms / verify), so without a fast-fail shed every
    /// extra concurrent login starves the blocking-thread pool and the rest
    /// of the API degrades along with it (#991, #1088).
    pub auth_semaphore: Option<Arc<Semaphore>>,
}

/// Build an auth-concurrency semaphore from a config value, or `None` when
/// the operator has disabled the cap by setting `auth_max_concurrency = 0`.
fn build_auth_semaphore(max: usize) -> Option<Arc<Semaphore>> {
    if max == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(max)))
    }
}

impl AppState {
    pub fn new(
        config: Config,
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        storage_registry: Arc<StorageRegistry>,
    ) -> Self {
        let permission_service = Arc::new(PermissionService::new(db.clone()));
        let auth_semaphore = build_auth_semaphore(config.auth_max_concurrency);
        // Install the process-wide cap that `AuthService::verify_password` /
        // `hash_password` consult on every bcrypt-bound call. Idempotent —
        // the first AppState wins, which keeps multi-AppState test setups
        // deterministic.
        crate::services::auth_service::install_global_auth_semaphore(auth_semaphore.clone());
        if config.auth_max_concurrency == 0 {
            tracing::warn!(
                "AUTH_MAX_CONCURRENCY=0: bcrypt-bound auth runs without a process-wide cap. \
                 Under sustained load this can saturate the blocking-thread pool and starve \
                 the API (#991, #1088). Production deployments should leave this unset."
            );
        }
        Self {
            config,
            db,
            storage,
            storage_registry,
            plugin_registry: None,
            wasm_plugin_service: None,
            scanner_service: None,
            quality_check_service: None,
            search_service: None,
            dependency_track: None,
            permission_service,
            proxy_service: None,
            smtp_service: None,
            metrics_handle: None,
            setup_required: Arc::new(AtomicBool::new(false)),
            event_bus: Arc::new(EventBus::new(1024)),
            repo_cache: Arc::new(RwLock::new(HashMap::new())),
            index_cache: Arc::new(RwLock::new(HashMap::new())),
            signed_release_cache: Arc::new(RwLock::new(HashMap::new())),
            signed_release_cache_index: Arc::new(RwLock::new(HashMap::new())),
            auth_semaphore,
        }
    }

    /// Create state with WASM plugin support
    pub fn with_wasm_plugins(
        config: Config,
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        storage_registry: Arc<StorageRegistry>,
        plugin_registry: Arc<PluginRegistry>,
        wasm_plugin_service: Arc<WasmPluginService>,
    ) -> Self {
        let permission_service = Arc::new(PermissionService::new(db.clone()));
        let auth_semaphore = build_auth_semaphore(config.auth_max_concurrency);
        crate::services::auth_service::install_global_auth_semaphore(auth_semaphore.clone());
        if config.auth_max_concurrency == 0 {
            tracing::warn!(
                "AUTH_MAX_CONCURRENCY=0: bcrypt-bound auth runs without a process-wide cap"
            );
        }
        Self {
            config,
            db,
            storage,
            storage_registry,
            plugin_registry: Some(plugin_registry),
            wasm_plugin_service: Some(wasm_plugin_service),
            scanner_service: None,
            quality_check_service: None,
            search_service: None,
            dependency_track: None,
            permission_service,
            proxy_service: None,
            smtp_service: None,
            metrics_handle: None,
            setup_required: Arc::new(AtomicBool::new(false)),
            event_bus: Arc::new(EventBus::new(1024)),
            repo_cache: Arc::new(RwLock::new(HashMap::new())),
            index_cache: Arc::new(RwLock::new(HashMap::new())),
            signed_release_cache: Arc::new(RwLock::new(HashMap::new())),
            signed_release_cache_index: Arc::new(RwLock::new(HashMap::new())),
            auth_semaphore,
        }
    }

    /// Get the storage backend for a given repository.
    ///
    /// Delegates to the `StorageRegistry` which handles filesystem backends
    /// (creating a per-repo directory instance) and cloud backends (returning
    /// the shared instance).
    pub fn storage_for_repo(
        &self,
        location: &StorageLocation,
    ) -> crate::error::Result<Arc<dyn StorageBackend>> {
        self.storage_registry.backend_for(location)
    }

    /// Convenience for handlers that return `Result<..., Response>`.
    /// Resolves storage and maps errors to a 500 plain-text response.
    #[allow(clippy::result_large_err)]
    pub fn storage_for_repo_or_500(
        &self,
        location: &StorageLocation,
    ) -> Result<Arc<dyn StorageBackend>, Response> {
        self.storage_for_repo(location).map_err(|e| {
            tracing::error!("Storage backend resolution failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage operation failed",
            )
                .into_response()
        })
    }

    /// Set the scanner service for security scanning.
    pub fn set_scanner_service(&mut self, scanner_service: Arc<ScannerService>) {
        self.scanner_service = Some(scanner_service);
    }

    /// Set the quality check service for health scoring and quality gates.
    pub fn set_quality_check_service(&mut self, qc_service: Arc<QualityCheckService>) {
        self.quality_check_service = Some(qc_service);
    }

    /// Set the OpenSearch service for search indexing.
    pub fn set_search_service(&mut self, search_service: Arc<OpenSearchService>) {
        self.search_service = Some(search_service);
    }

    /// Set the Dependency-Track service for security analysis.
    pub fn set_dependency_track(&mut self, dt: Arc<DependencyTrackService>) {
        self.dependency_track = Some(dt);
    }

    /// Set the proxy service for remote repository proxying.
    pub fn set_proxy_service(&mut self, proxy_service: Arc<ProxyService>) {
        self.proxy_service = Some(proxy_service);
    }

    /// Set the SMTP service for email delivery.
    pub fn set_smtp_service(&mut self, smtp_service: Arc<SmtpService>) {
        self.smtp_service = Some(smtp_service);
    }

    /// Set the Prometheus metrics handle for rendering /metrics output.
    pub fn set_metrics_handle(&mut self, handle: PrometheusHandle) {
        self.metrics_handle = Some(Arc::new(handle));
    }

    /// Create an ArtifactService with the shared search and scanner services.
    pub fn create_artifact_service(&self, storage: Arc<dyn StorageBackend>) -> ArtifactService {
        let mut svc =
            ArtifactService::new_with_search(self.db.clone(), storage, self.search_service.clone());
        if let Some(ref scanner) = self.scanner_service {
            svc.set_scanner_service(scanner.clone());
        }
        if let Some(ref qc) = self.quality_check_service {
            svc.set_quality_check_service(qc.clone());
        }
        svc
    }

    /// Create a RepositoryService with the shared search service.
    pub fn create_repository_service(&self) -> RepositoryService {
        RepositoryService::new_with_search(self.db.clone(), self.search_service.clone())
    }

    /// Try to claim a slot for a bcrypt-bound auth operation.
    ///
    /// **Deprecated as a per-handler call site**: handlers should NOT acquire
    /// this manually. The cap is now enforced inside
    /// [`crate::services::auth_service::AuthService::verify_password`] and
    /// `hash_password`, so every bcrypt entry point (login, validate_api_token,
    /// basic-auth fallback, SSO post-auth, password change) shares the same
    /// shed boundary. Holding a permit in the handler and another inside
    /// `verify_password` would double-count slots and cause spurious 503s.
    ///
    /// Kept as a thin wrapper for diagnostics / external observers that want
    /// to probe the same `auth_semaphore` used internally.
    pub fn try_acquire_auth_permit(
        &self,
    ) -> crate::error::Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        match self.auth_semaphore.as_ref() {
            None => Ok(None),
            Some(sem) => match sem.clone().try_acquire_owned() {
                Ok(permit) => Ok(Some(permit)),
                Err(_) => Err(crate::error::AppError::ServiceUnavailable(
                    "Authentication service is at capacity, retry shortly".to_string(),
                )),
            },
        }
    }
}

pub type SharedState = Arc<AppState>;

/// Redact sensitive query-string parameters from a URI path for safe logging.
///
/// Parameters named `token`, `key`, `api_key`, `password`, or `secret`
/// (case-insensitive) have their values replaced with `[REDACTED]`.
pub fn redact_sensitive_params(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => {
            let redacted: String = q
                .split('&')
                .map(|pair| {
                    if let Some((key, _)) = pair.split_once('=') {
                        let k = key.to_lowercase();
                        if k == "token"
                            || k == "key"
                            || k == "api_key"
                            || k == "password"
                            || k == "secret"
                        {
                            return format!("{}=[REDACTED]", key);
                        }
                    }
                    pair.to_string()
                })
                .collect::<Vec<_>>()
                .join("&");
            format!("{}?{}", path, redacted)
        }
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cached_repo() -> CachedRepo {
        CachedRepo {
            id: Uuid::nil(),
            format: "cargo".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            storage_path: "/data/repos/my-repo".to_string(),
            storage_backend: "filesystem".to_string(),
            is_public: true,
            index_upstream_url: None,
        }
    }

    #[test]
    fn test_cached_repo_clone() {
        let original = make_cached_repo();
        let cloned = original.clone();
        assert_eq!(cloned.id, original.id);
        assert_eq!(cloned.format, original.format);
        assert_eq!(cloned.is_public, original.is_public);
        assert_eq!(cloned.storage_path, original.storage_path);
    }

    #[test]
    fn test_cached_repo_debug() {
        let repo = make_cached_repo();
        let debug = format!("{:?}", repo);
        assert!(debug.contains("cargo"));
        assert!(debug.contains("hosted"));
    }

    #[test]
    fn test_cached_repo_with_upstream() {
        let repo = CachedRepo {
            upstream_url: Some("https://crates.io".to_string()),
            index_upstream_url: Some("https://index.crates.io".to_string()),
            ..make_cached_repo()
        };
        assert_eq!(repo.upstream_url.as_deref(), Some("https://crates.io"));
        assert_eq!(
            repo.index_upstream_url.as_deref(),
            Some("https://index.crates.io")
        );
    }

    #[test]
    fn test_repo_cache_ttl_constant() {
        assert_eq!(REPO_CACHE_TTL_SECS, 60);
    }

    #[tokio::test]
    async fn test_repo_cache_insert_and_lookup() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let repo = make_cached_repo();
        cache
            .write()
            .await
            .insert("my-repo".to_string(), (repo.clone(), Instant::now()));

        let guard = cache.read().await;
        let (entry, at) = guard.get("my-repo").unwrap();
        assert_eq!(entry.id, repo.id);
        assert!(at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
    }

    #[tokio::test]
    async fn test_repo_cache_eviction_on_write() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let repo = make_cached_repo();

        // Insert an entry with a backdated timestamp (simulate expiry).
        let expired_at = Instant::now() - std::time::Duration::from_secs(REPO_CACHE_TTL_SECS + 1);
        cache
            .write()
            .await
            .insert("stale".to_string(), (repo.clone(), expired_at));

        // Insert a fresh entry and run eviction.
        {
            let mut w = cache.write().await;
            w.retain(|_, (_, at)| at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
            w.insert("fresh".to_string(), (repo, Instant::now()));
        }

        let guard = cache.read().await;
        assert!(
            guard.get("stale").is_none(),
            "stale entry should be evicted"
        );
        assert!(guard.get("fresh").is_some(), "fresh entry should remain");
    }

    #[tokio::test]
    async fn test_repo_cache_miss_returns_none() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let guard = cache.read().await;
        assert!(guard.get("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_index_cache_type_construction() {
        let cache: IndexCache = Arc::new(RwLock::new(HashMap::new()));
        assert!(cache.read().await.is_empty());
    }

    #[test]
    fn test_cached_repo_private_visibility() {
        let repo = CachedRepo {
            is_public: false,
            ..make_cached_repo()
        };
        assert!(!repo.is_public);
    }

    #[tokio::test]
    async fn test_repo_cache_invalidation_by_key_removal() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let repo = make_cached_repo();
        cache
            .write()
            .await
            .insert("my-remote".to_string(), (repo, Instant::now()));
        assert!(cache.read().await.contains_key("my-remote"));

        // Simulate cache invalidation on repo update: remove the key.
        cache.write().await.remove("my-remote");
        assert!(
            !cache.read().await.contains_key("my-remote"),
            "entry should be removed after invalidation"
        );
    }

    #[tokio::test]
    async fn test_repo_cache_invalidation_preserves_other_entries() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let repo = make_cached_repo();
        cache
            .write()
            .await
            .insert("repo-a".to_string(), (repo.clone(), Instant::now()));
        cache
            .write()
            .await
            .insert("repo-b".to_string(), (repo, Instant::now()));

        // Invalidate only repo-a.
        cache.write().await.remove("repo-a");
        assert!(!cache.read().await.contains_key("repo-a"));
        assert!(
            cache.read().await.contains_key("repo-b"),
            "other entries should remain after targeted invalidation"
        );
    }

    #[tokio::test]
    async fn test_repo_cache_visibility_toggle() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let private_repo = CachedRepo {
            is_public: false,
            ..make_cached_repo()
        };
        cache
            .write()
            .await
            .insert("my-cache".to_string(), (private_repo, Instant::now()));

        // Verify it's private.
        {
            let guard = cache.read().await;
            let (entry, _) = guard.get("my-cache").unwrap();
            assert!(!entry.is_public);
        }

        // Simulate update: remove old entry, insert updated one.
        cache.write().await.remove("my-cache");
        let public_repo = CachedRepo {
            is_public: true,
            ..make_cached_repo()
        };
        cache
            .write()
            .await
            .insert("my-cache".to_string(), (public_repo, Instant::now()));

        // Verify the change is visible immediately.
        {
            let guard = cache.read().await;
            let (entry, _) = guard.get("my-cache").unwrap();
            assert!(
                entry.is_public,
                "cache should reflect the updated visibility immediately"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Concurrent access exercise (ak-2q98): with tokio::sync::RwLock the
    // cache supports concurrent reads/writes from many tasks without
    // blocking the runtime, regardless of which order they arrive in.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_repo_cache_concurrent_access() {
        let cache: RepoCache = Arc::new(RwLock::new(HashMap::new()));
        let mut handles = Vec::new();
        for i in 0..32 {
            let c = cache.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("repo-{}", i % 8);
                let repo = CachedRepo {
                    id: Uuid::new_v4(),
                    format: "cargo".to_string(),
                    repo_type: "hosted".to_string(),
                    upstream_url: None,
                    storage_path: format!("/data/{}", key),
                    storage_backend: "filesystem".to_string(),
                    is_public: i % 2 == 0,
                    index_upstream_url: None,
                };
                c.write().await.insert(key.clone(), (repo, Instant::now()));
                // Hold a read guard briefly to interleave readers + writers.
                let read = c.read().await;
                assert!(read.contains_key(&key));
            }));
        }
        for h in handles {
            h.await.expect("task panicked");
        }
        let guard = cache.read().await;
        // 8 distinct keys after 32 inserts.
        assert_eq!(guard.len(), 8);
    }

    // -- redact_sensitive_params --

    #[test]
    fn test_redact_no_query_string() {
        let result = redact_sensitive_params("/api/v1/artifacts", None);
        assert_eq!(result, "/api/v1/artifacts");
    }

    #[test]
    fn test_redact_normal_params_unchanged() {
        let result = redact_sensitive_params("/api/v1/search", Some("q=nginx&page=1"));
        assert_eq!(result, "/api/v1/search?q=nginx&page=1");
    }

    #[test]
    fn test_redact_token_param() {
        let result = redact_sensitive_params("/api/v1/download", Some("token=abc123&file=lib.tar"));
        assert_eq!(result, "/api/v1/download?token=[REDACTED]&file=lib.tar");
    }

    #[test]
    fn test_redact_api_key_param() {
        let result = redact_sensitive_params("/hook", Some("api_key=secret_val&event=push"));
        assert_eq!(result, "/hook?api_key=[REDACTED]&event=push");
    }

    #[test]
    fn test_redact_password_param() {
        let result = redact_sensitive_params("/login", Some("user=admin&password=hunter2"));
        assert_eq!(result, "/login?user=admin&password=[REDACTED]");
    }

    #[test]
    fn test_redact_secret_param() {
        let result = redact_sensitive_params("/webhook", Some("secret=s3cr3t&id=42"));
        assert_eq!(result, "/webhook?secret=[REDACTED]&id=42");
    }

    #[test]
    fn test_redact_key_param() {
        let result = redact_sensitive_params("/auth", Some("key=mykey"));
        assert_eq!(result, "/auth?key=[REDACTED]");
    }

    #[test]
    fn test_redact_mixed_case_param() {
        // The lowercase comparison should catch "Token" and "API_KEY"
        let result = redact_sensitive_params("/api", Some("Token=x&API_KEY=y&name=z"));
        assert_eq!(result, "/api?Token=[REDACTED]&API_KEY=[REDACTED]&name=z");
    }

    #[test]
    fn test_redact_multiple_sensitive_params() {
        let result =
            redact_sensitive_params("/endpoint", Some("token=a&password=b&secret=c&key=d"));
        assert_eq!(
            result,
            "/endpoint?token=[REDACTED]&password=[REDACTED]&secret=[REDACTED]&key=[REDACTED]"
        );
    }

    // -----------------------------------------------------------------------
    // Auth-concurrency semaphore (perf bundle #991/#1088)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_auth_semaphore_zero_disables_cap() {
        assert!(build_auth_semaphore(0).is_none());
    }

    #[test]
    fn test_build_auth_semaphore_positive_returns_some() {
        let sem = build_auth_semaphore(4).expect("expected a semaphore");
        // A fresh semaphore should have all permits available.
        assert_eq!(sem.available_permits(), 4);
    }

    #[test]
    fn test_auth_semaphore_sheds_when_saturated() {
        let sem = build_auth_semaphore(2).expect("expected a semaphore");
        let _p1 = sem.clone().try_acquire_owned().expect("permit 1");
        let _p2 = sem.clone().try_acquire_owned().expect("permit 2");
        // Third concurrent acquire must fail fast (the saturation signal that
        // surfaces as 503 ServiceUnavailable in `try_acquire_auth_permit`).
        assert!(sem.clone().try_acquire_owned().is_err());
    }

    #[test]
    fn test_auth_semaphore_releases_on_permit_drop() {
        let sem = build_auth_semaphore(1).expect("expected a semaphore");
        {
            let _p = sem.clone().try_acquire_owned().expect("permit");
            assert!(sem.clone().try_acquire_owned().is_err());
        }
        // Permit returned to the pool after drop, the next acquire must succeed.
        assert!(sem.clone().try_acquire_owned().is_ok());
    }
}
