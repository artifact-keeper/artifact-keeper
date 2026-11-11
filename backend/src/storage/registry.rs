//! Storage registry for per-repository backend routing.
//!
//! Maps backend names to initialized `StorageBackend` instances and provides
//! lookup by `StorageLocation`. The `"filesystem"` backend is handled specially:
//! each call to `backend_for` creates a new `FilesystemStorage` rooted at the
//! location's path, so every repository gets its own directory tree.

use std::collections::HashMap;
use std::sync::Arc;

use super::StorageBackend;
use crate::error::{AppError, Result};
use crate::storage::filesystem::FilesystemStorage;

/// A resolved storage location carrying the backend name and base path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLocation {
    /// Backend identifier (e.g. "filesystem", "s3-primary", "gcs-archive").
    pub backend: String,
    /// Base path or prefix within the backend.
    pub path: String,
}

/// Registry of available storage backends.
///
/// Holds a map of named backends (S3, GCS, Azure, etc.) and a default backend
/// name. Filesystem backends are created on-the-fly from the location path
/// rather than stored in the map, so they do not need upfront registration.
pub struct StorageRegistry {
    backends: HashMap<String, Arc<dyn StorageBackend>>,
    default_backend: String,
    /// Global filesystem storage root (`STORAGE_PATH`), when known.
    ///
    /// Filesystem locations are rooted at the *repository's* directory
    /// (`<STORAGE_PATH>/<repo_key>`), while the proxy cache writes through a
    /// handle rooted at `<STORAGE_PATH>` itself. Handing the global root to
    /// each `FilesystemStorage` lets reserved bucket-root namespaces resolve
    /// to the same file through both handles (#3368) — the filesystem
    /// counterpart of the `S3_PREFIX` split.
    filesystem_bucket_root: Option<std::path::PathBuf>,
    /// Backends that were *configured* but failed to initialize at startup and
    /// were skipped, keyed by backend name and carrying the configuration
    /// error that caused the skip (#4530).
    ///
    /// This is deliberately distinct from a backend that was never configured:
    /// an absent name means "not set up on this deployment", while a name here
    /// means "the operator asked for this backend and its configuration is
    /// broken". Repositories whose `storage_backend` is one of these would
    /// otherwise fail every request with a generic 500 `STORAGE_ERROR` naming
    /// nothing; recording the reason lets [`Self::backend_for`] answer a 503
    /// that names the backend and the configuration error instead.
    skipped_backends: HashMap<String, String>,
}

impl StorageRegistry {
    /// Create a new registry with the given named backends and default.
    ///
    /// Filesystem locations get no global root, so reserved bucket-root
    /// namespaces resolve against the location path exactly as before. Use
    /// [`Self::with_filesystem_bucket_root`] to supply `STORAGE_PATH`.
    pub fn new(
        backends: HashMap<String, Arc<dyn StorageBackend>>,
        default_backend: String,
    ) -> Self {
        Self {
            backends,
            default_backend,
            filesystem_bucket_root: None,
            skipped_backends: HashMap::new(),
        }
    }

    /// Anchor reserved bucket-root namespaces on filesystem locations at
    /// `root` (the configured `STORAGE_PATH`) rather than at each
    /// repository's own directory (#3368).
    pub fn with_filesystem_bucket_root(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.filesystem_bucket_root = Some(root.into());
        self
    }

    /// The global filesystem storage root (`STORAGE_PATH`), when one was
    /// supplied via [`Self::with_filesystem_bucket_root`].
    pub fn filesystem_bucket_root(&self) -> Option<&std::path::Path> {
        self.filesystem_bucket_root.as_deref()
    }

    /// Record that `name` was configured but could not be initialized at
    /// startup, with `error` the configuration error that caused the skip
    /// (#4530).
    ///
    /// The registry has no way to construct the failed backend, so this is
    /// how the startup skip becomes visible to the request path
    /// ([`Self::backend_for`] answers 503 naming it) and to `/health`
    /// ([`Self::skipped_backends`] reports it as degraded) rather than being
    /// a single WARN nobody reads.
    pub fn record_skipped_backend(&mut self, name: impl Into<String>, error: impl Into<String>) {
        self.skipped_backends.insert(name.into(), error.into());
    }

    /// The backends that were configured but skipped at startup, with the
    /// configuration error for each (#4530).
    pub fn skipped_backends(&self) -> &HashMap<String, String> {
        &self.skipped_backends
    }

    /// Resolve a `StorageLocation` to a concrete backend instance.
    ///
    /// For `"filesystem"` locations a fresh `FilesystemStorage` is created using
    /// the location's path. All other backend names are looked up in the
    /// registry's map of shared instances.
    ///
    /// A backend that was configured but skipped at startup (#4530) answers a
    /// [`AppError::ServiceUnavailable`] naming the backend (the configuration
    /// error itself stays on `/health` and in the log), so a repository on it
    /// fails with a 503 that says why instead of a generic 500 `STORAGE_ERROR`. An unknown name that was
    /// never configured stays a [`AppError::Storage`].
    pub fn backend_for(&self, location: &StorageLocation) -> Result<Arc<dyn StorageBackend>> {
        if location.backend == "filesystem" {
            let fs = FilesystemStorage::new(&location.path);
            return Ok(Arc::new(match &self.filesystem_bucket_root {
                Some(root) => fs.with_bucket_root(root),
                None => fs,
            }));
        }

        if self.skipped_backends.contains_key(&location.backend) {
            // The configuration error itself is NOT in this message: it goes to
            // every client of the repository, anonymous ones included, and can
            // name internal endpoints. Operators read it on `/health` and in
            // the startup ERROR log.
            return Err(AppError::ServiceUnavailable(format!(
                "storage backend '{}' is unavailable: it was configured but skipped at startup \
                 because of a configuration error",
                location.backend
            )));
        }

        self.backends
            .get(&location.backend)
            .cloned()
            .ok_or_else(|| {
                AppError::Storage(format!(
                    "storage backend '{}' is not registered",
                    location.backend
                ))
            })
    }

    /// Check whether a backend name is available.
    ///
    /// `"filesystem"` is always considered available because it does not require
    /// pre-registration. Other names are checked against the registry map.
    pub fn is_available(&self, backend: &str) -> bool {
        if backend == "filesystem" {
            return true;
        }
        self.backends.contains_key(backend)
    }

    /// Return the name of the default backend.
    pub fn default_backend(&self) -> &str {
        &self.default_backend
    }
}

/// Whether a storage backend gives each repository a physically isolated key
/// space.
///
/// Only `"filesystem"` does: [`StorageRegistry::backend_for`] roots a fresh
/// [`FilesystemStorage`] at the repository's `storage_path`, so every repository
/// gets its own directory tree. Cloud backends (S3/GCS/Azure) resolve to a
/// single shared instance and share one flat object namespace, so a bare
/// `{format}/{coords}` key on cloud is not provably owned by the requesting
/// repository. Callers use this to gate row-bypass reads (which are only sound
/// where the backend physically isolates repositories).
pub fn backend_is_repo_isolated(backend: &str) -> bool {
    backend == "filesystem"
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::StatusCode;
    use bytes::Bytes;

    /// Minimal mock backend for testing registry lookups.
    struct MockBackend {
        name: String,
    }

    impl MockBackend {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for MockBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> Result<Bytes> {
            Ok(Bytes::from(self.name.clone()))
        }

        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }

        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }

        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, Result<Bytes>>,
        ) -> Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn make_registry() -> StorageRegistry {
        let mut backends: HashMap<String, Arc<dyn StorageBackend>> = HashMap::new();
        backends.insert(
            "s3-primary".to_string(),
            Arc::new(MockBackend::new("s3-primary")),
        );
        backends.insert(
            "gcs-archive".to_string(),
            Arc::new(MockBackend::new("gcs-archive")),
        );
        StorageRegistry::new(backends, "s3-primary".to_string())
    }

    /// #3368 on the FILESYSTEM backend — the default one.
    ///
    /// The two handles differ by ROOT rather than by key prefix, but the
    /// consequence is identical:
    ///
    /// * the proxy cache writes through `FilesystemBackend::new(STORAGE_PATH)`
    ///   (`StorageService::from_config`), so the object lands at
    ///   `<STORAGE_PATH>/proxy-cache/...`;
    /// * an `artifacts` row is read through `backend_for(location)`, and
    ///   `repositories.rs` sets `location.path` to
    ///   `<STORAGE_PATH>/<repo_key>`, so the read looked at
    ///   `<STORAGE_PATH>/<repo_key>/proxy-cache/...`.
    ///
    /// Both `key_to_path` implementations are a bare `root.join(key)` for a
    /// hierarchical key, so the read was a structurally guaranteed miss with
    /// the file present on disk — the same failure the prefixed-S3 half
    /// produces, on the default backend and with no `S3_PREFIX` involved.
    ///
    /// FAILS ON MAIN: the read resolves under the repository directory.
    #[tokio::test]
    async fn test_filesystem_proxy_cache_key_is_read_at_the_global_root_3368() {
        let root = tempfile::tempdir().expect("tempdir");
        let repo_key = "pypi-remote";
        let cache_key = "proxy-cache/pypi-remote/simple/six/six-1.17.0.whl/__content__";
        let body = Bytes::from_static(b"wheel-bytes");

        // The proxy cache's own handle: rooted at STORAGE_PATH.
        let cache_handle = FilesystemStorage::new(root.path());
        cache_handle
            .put(cache_key, body.clone())
            .await
            .expect("cache write");

        // The artifact handle the `artifacts`-row read paths resolve.
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string())
            .with_filesystem_bucket_root(root.path());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: root.path().join(repo_key).to_string_lossy().into_owned(),
        };
        let artifact_handle = registry.backend_for(&location).expect("resolve backend");

        let read = artifact_handle.get(cache_key).await;
        assert!(
            read.is_ok(),
            "#3368: the artifacts-row read must address the object the proxy cache wrote; \
             it resolved under <STORAGE_PATH>/{repo_key}/ instead of the global root"
        );
        assert_eq!(read.unwrap(), body, "and it must be the same bytes");

        // Negative control: ordinary artifact bytes stay isolated per
        // repository. Anchoring the reserved namespaces must not collapse the
        // per-repo directory tree, or one repository could read another's
        // objects by guessing a flat key.
        let hosted_key = "pypi/six/1.17.0/six-1.17.0.whl";
        artifact_handle
            .put(hosted_key, Bytes::from_static(b"hosted"))
            .await
            .expect("hosted write");
        assert!(
            root.path().join(repo_key).join(hosted_key).exists(),
            "hosted artifact bytes must stay under the repository directory"
        );
        assert!(
            !root.path().join(hosted_key).exists(),
            "hosted artifact bytes must NOT leak to the global root"
        );
        assert!(
            cache_handle.get(hosted_key).await.is_err(),
            "the global-root handle must not see another repository's hosted bytes"
        );

        // The OTHER direction, asserted because it is a deliberate design
        // consequence rather than an oversight: within the reserved
        // namespaces the isolation boundary is no longer the repository. A
        // handle rooted at a DIFFERENT repository resolves the same
        // `proxy-cache/...` key to the same object — that is the whole point,
        // since the writer (the proxy cache) and the reader (an `artifacts`
        // row on some repository) are rooted differently by construction.
        //
        // What keeps that safe is that no caller can put a
        // `proxy-cache/`-prefixed `storage_key` on an `artifacts` row through
        // any API: every format composes hosted keys as `<format>/...`, and
        // the cache keys are derived server-side from `(repo_key, path)`. The
        // boundary is therefore "who can write such a row", not "which
        // repository is asking". Pinned here so a future change that starts
        // accepting a caller-supplied storage key has to confront it.
        let other_location = StorageLocation {
            backend: "filesystem".to_string(),
            path: root
                .path()
                .join("some-other-repo")
                .to_string_lossy()
                .into_owned(),
        };
        let other_handle = registry
            .backend_for(&other_location)
            .expect("resolve backend");
        assert_eq!(
            other_handle.get(cache_key).await.ok(),
            Some(body),
            "a proxy-cache key resolves to one shared object regardless of which repository's \
             handle asks; the reserved namespace is deliberately not repo-scoped"
        );
    }

    /// #3368 hardening: the root and the path tail must be derived from the
    /// SAME string.
    ///
    /// `key_to_path` builds the tail from the sanitized key (only
    /// `Component::Normal` survives), so deciding the root from the raw key
    /// let spellings that sanitize identically land in different places —
    /// `proxy-cache/r/x` at the global root but `/proxy-cache/r/x` and
    /// `../proxy-cache/r/x` under the repository directory. One logical
    /// object, two physical locations: a miniature of the divergence this
    /// anchoring removes.
    ///
    /// Not reachable through any caller today (`validate_cache_path` trims a
    /// leading `/` and rejects dot segments), so this pins the property rather
    /// than fixing a live bug.
    #[tokio::test]
    async fn test_filesystem_root_is_decided_from_the_sanitized_key_3368() {
        let root = tempfile::tempdir().expect("tempdir");
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string())
            .with_filesystem_bucket_root(root.path());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: root.path().join("repoA").to_string_lossy().into_owned(),
        };
        let handle = registry.backend_for(&location).expect("resolve backend");

        // All three sanitize to `proxy-cache/repoB/x/__content__`, so all three
        // must address the one object at the global root.
        let canonical = "proxy-cache/repoB/x/__content__";
        handle
            .put(canonical, Bytes::from_static(b"cache"))
            .await
            .expect("write");
        for spelling in [
            canonical,
            "/proxy-cache/repoB/x/__content__",
            "../proxy-cache/repoB/x/__content__",
        ] {
            assert_eq!(
                handle.get(spelling).await.ok(),
                Some(Bytes::from_static(b"cache")),
                "{spelling} sanitizes to the canonical key and must resolve to the same object"
            );
        }
        assert!(
            root.path().join(canonical).exists(),
            "and that object lives at the global root"
        );
        assert!(
            !root.path().join("repoA").join(canonical).exists(),
            "not a second copy under the repository directory"
        );
    }

    /// Without a global root the registry keeps its historical single-root
    /// behaviour, so the standalone constructions (and any caller that does
    /// not know `STORAGE_PATH`) are unchanged.
    #[tokio::test]
    async fn test_filesystem_without_a_global_root_is_unchanged_3368() {
        let root = tempfile::tempdir().expect("tempdir");
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: root.path().join("repo").to_string_lossy().into_owned(),
        };
        let handle = registry.backend_for(&location).expect("resolve backend");
        let cache_key = "proxy-cache/repo/p/__content__";
        handle
            .put(cache_key, Bytes::from_static(b"x"))
            .await
            .expect("write");
        assert!(
            root.path().join("repo").join(cache_key).exists(),
            "with no global root configured the key stays under the location path"
        );
    }

    // -- StorageLocation tests ------------------------------------------------

    #[test]
    fn test_storage_location_debug() {
        let loc = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/data/artifacts".to_string(),
        };
        let debug = format!("{:?}", loc);
        assert!(debug.contains("filesystem"));
        assert!(debug.contains("/data/artifacts"));
    }

    #[test]
    fn test_storage_location_clone() {
        let loc = StorageLocation {
            backend: "s3-primary".to_string(),
            path: "repo/maven-central".to_string(),
        };
        let cloned = loc.clone();
        assert_eq!(cloned.backend, loc.backend);
        assert_eq!(cloned.path, loc.path);
    }

    // -- StorageRegistry::new -------------------------------------------------

    #[test]
    fn test_new_stores_default_backend() {
        let registry = make_registry();
        assert_eq!(registry.default_backend(), "s3-primary");
    }

    #[test]
    fn test_new_with_empty_backends() {
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string());
        assert_eq!(registry.default_backend(), "filesystem");
    }

    // -- StorageRegistry::backend_for -----------------------------------------

    #[tokio::test]
    async fn test_backend_for_filesystem_creates_new_instance() {
        let registry = make_registry();
        let loc = StorageLocation {
            backend: "filesystem".to_string(),
            path: "/tmp/test-artifacts".to_string(),
        };

        let backend = registry.backend_for(&loc).unwrap();
        // Verify it behaves like a real backend (will fail on missing key,
        // proving it was constructed).
        let result = backend.get("nonexistent-key12").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_backend_for_registered_backend() {
        let registry = make_registry();
        let loc = StorageLocation {
            backend: "s3-primary".to_string(),
            path: "repo/maven".to_string(),
        };

        let backend = registry.backend_for(&loc).unwrap();
        // MockBackend returns its name from get()
        let data = backend.get("any-key").await.unwrap();
        assert_eq!(data, Bytes::from("s3-primary"));
    }

    #[test]
    fn test_backend_for_unknown_returns_error() {
        let registry = make_registry();
        let loc = StorageLocation {
            backend: "nonexistent-backend".to_string(),
            path: "some/path".to_string(),
        };

        let result = registry.backend_for(&loc);
        assert!(result.is_err());
        let msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected error"),
        };
        assert!(msg.contains("nonexistent-backend"));
    }

    // -- #4530: a skipped-at-startup backend must answer 503, not 500 --------

    /// Read the HTTP status and JSON `code` from a `backend_for` error without
    /// depending on `AppError`'s private mapping, exactly as a client sees
    /// them. Consumes the error, so it does not need `AppError: Clone`.
    #[allow(clippy::disallowed_methods)] // STREAMING-EXEMPT: test reads a small, bounded error body
    async fn status_and_code_of(result: Result<Arc<dyn StorageBackend>>) -> (StatusCode, String) {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;
        let err = match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        };
        let response = err.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (
            status,
            json["code"].as_str().unwrap_or_default().to_string(),
        )
    }

    /// A backend that was configured but skipped at startup resolves to a
    /// `ServiceUnavailable` (503) whose message names the backend AND the
    /// configuration error — instead of the generic 500 `STORAGE_ERROR` an
    /// unregistered name produces. This is the request-path half of #4530:
    /// a repository on a skipped secondary backend must say why.
    #[tokio::test]
    async fn test_backend_for_skipped_backend_is_service_unavailable_4530() {
        let mut registry = make_registry();
        registry.record_skipped_backend(
            "s3",
            "Configuration error: S3_PUBLIC_ENDPOINT=\"ftp://s3.example.com/sub\" is invalid: \
             the scheme must be http or https",
        );

        let loc = StorageLocation {
            backend: "s3".to_string(),
            path: "repo/w5b-s3".to_string(),
        };
        let result = registry.backend_for(&loc);
        assert!(result.is_err(), "a skipped backend must not resolve");

        // Inspect the message before the assertion consumes the error.
        let msg = match &result {
            Ok(_) => unreachable!(),
            Err(e) => e.to_string(),
        };
        assert!(msg.contains("s3"), "message must name the backend: {msg}");
        assert!(
            msg.contains("skipped at startup"),
            "message must say the backend was skipped: {msg}"
        );
        assert!(
            !msg.contains("S3_PUBLIC_ENDPOINT") && !msg.contains("s3.example.com"),
            "the client-facing message must not carry the configuration error: {msg}"
        );

        assert_eq!(
            status_and_code_of(result).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE".to_string()
            ),
            "a skipped backend must be a 503, not a 500 STORAGE_ERROR (#4530)"
        );
    }

    /// The negative control: a name that was NEVER configured still resolves
    /// to the plain `Storage` error (500), because it is not a startup skip.
    /// Only a *configured but broken* backend becomes a 503.
    #[tokio::test]
    async fn test_backend_for_never_configured_backend_still_storage_error_4530() {
        let registry = make_registry();
        let loc = StorageLocation {
            backend: "azure".to_string(),
            path: "repo/x".to_string(),
        };
        let result = registry.backend_for(&loc);
        assert!(result.is_err(), "an unregistered backend must not resolve");

        assert_eq!(
            status_and_code_of(result).await,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORAGE_ERROR".to_string()
            ),
            "a backend that was never configured must keep its historic 500 mapping"
        );
    }

    /// The skipped set is reported (for `/health`) with the error attached, and
    /// a registered backend is unaffected by another name being skipped.
    #[test]
    fn test_skipped_backends_reports_names_and_errors_4530() {
        let mut registry = make_registry();
        assert!(
            registry.skipped_backends().is_empty(),
            "a healthy registry reports no skipped backends"
        );

        registry.record_skipped_backend("s3", "S3_PUBLIC_ENDPOINT is invalid");
        registry.record_skipped_backend("gcs", "GCS_PROJECT_ID not set");

        let skipped = registry.skipped_backends();
        assert_eq!(skipped.len(), 2);
        assert_eq!(
            skipped.get("s3").map(String::as_str),
            Some("S3_PUBLIC_ENDPOINT is invalid")
        );
        assert_eq!(
            skipped.get("gcs").map(String::as_str),
            Some("GCS_PROJECT_ID not set")
        );

        // A *registered* backend still resolves even when a sibling is skipped.
        let loc = StorageLocation {
            backend: "s3-primary".to_string(),
            path: "repo/maven".to_string(),
        };
        assert!(
            registry.backend_for(&loc).is_ok(),
            "skipping one backend must not break a registered sibling"
        );
    }

    /// A later `record_skipped_backend` for the same name replaces the earlier
    /// error, so a redirect/retry at startup cannot leave two reasons to fight.
    #[test]
    fn test_record_skipped_backend_replaces_a_previous_reason_4530() {
        let mut registry = make_registry();
        registry.record_skipped_backend("s3", "first reason");
        registry.record_skipped_backend("s3", "second reason");
        assert_eq!(registry.skipped_backends().len(), 1);
        assert_eq!(
            registry.skipped_backends().get("s3").map(String::as_str),
            Some("second reason")
        );
    }

    #[tokio::test]
    async fn test_backend_for_second_registered_backend() {
        let registry = make_registry();
        let loc = StorageLocation {
            backend: "gcs-archive".to_string(),
            path: "archive/old".to_string(),
        };

        let backend = registry.backend_for(&loc).unwrap();
        let data = backend.get("any-key").await.unwrap();
        assert_eq!(data, Bytes::from("gcs-archive"));
    }

    // -- StorageRegistry::is_available ----------------------------------------

    #[test]
    fn test_is_available_filesystem_always_true() {
        let registry = make_registry();
        assert!(registry.is_available("filesystem"));
    }

    #[test]
    fn test_is_available_registered_backend() {
        let registry = make_registry();
        assert!(registry.is_available("s3-primary"));
        assert!(registry.is_available("gcs-archive"));
    }

    #[test]
    fn test_is_available_unknown_backend() {
        let registry = make_registry();
        assert!(!registry.is_available("azure-blob"));
        assert!(!registry.is_available(""));
    }

    #[test]
    fn test_is_available_filesystem_even_with_empty_registry() {
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string());
        assert!(registry.is_available("filesystem"));
    }

    // -- StorageRegistry::default_backend -------------------------------------

    #[test]
    fn test_default_backend_returns_configured_name() {
        let registry = make_registry();
        assert_eq!(registry.default_backend(), "s3-primary");
    }

    #[test]
    fn test_default_backend_can_be_filesystem() {
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string());
        assert_eq!(registry.default_backend(), "filesystem");
    }

    // -- backend_is_repo_isolated (#2504) -------------------------------------

    #[test]
    fn test_backend_is_repo_isolated_only_filesystem() {
        // Only filesystem physically isolates each repository's key space; every
        // cloud backend shares one flat namespace, so row-bypass reads must not
        // trust the key's implicit ownership there.
        assert!(backend_is_repo_isolated("filesystem"));
        for cloud in ["s3-primary", "gcs-archive", "azure-blob", "s3", "gcs", ""] {
            assert!(
                !backend_is_repo_isolated(cloud),
                "cloud backend {cloud:?} must NOT be treated as repo-isolated"
            );
        }
    }

    // -- #1054: registry / primary-storage coincidence ------------------------
    //
    // `is_cache_fresh` reads via `state.storage` (the global primary backend
    // built in `main.rs`); the presigned redirect signs against
    // `state.storage_for_repo(default_location)` which goes through this
    // registry's `backend_for`. The fast-path / slow-path coincidence relied
    // on by the proxy fix in #1018 requires those two code paths to resolve
    // to the same backend. The contract isn't enforced anywhere, so a future
    // change that adds wrapping/caching in `backend_for` could silently
    // break it. Pin the contract here.

    #[tokio::test]
    async fn test_backend_for_default_cloud_returns_same_arc_as_primary() {
        // Cloud backends (S3, GCS, Azure) are stored as shared `Arc`s in the
        // registry map. `backend_for(default_location)` must return that
        // same `Arc` (`Arc::ptr_eq`), not a wrapped or re-instantiated one,
        // or the freshness probe and the redirect target would point at
        // different backend objects.
        let primary: Arc<dyn StorageBackend> = Arc::new(MockBackend::new("s3-primary"));
        let mut backends: HashMap<String, Arc<dyn StorageBackend>> = HashMap::new();
        backends.insert("s3-primary".to_string(), primary.clone());
        let registry = StorageRegistry::new(backends, "s3-primary".to_string());

        let default_location = StorageLocation {
            backend: registry.default_backend().to_string(),
            path: "default-path".to_string(),
        };
        let resolved = registry.backend_for(&default_location).unwrap();

        assert!(
            Arc::ptr_eq(&primary, &resolved),
            "default cloud backend must be the SAME Arc instance as the \
             primary registered backend, not a wrapped or re-instantiated \
             one (#1054)"
        );
    }

    #[tokio::test]
    async fn test_backend_for_default_filesystem_writes_and_reads_coincide() {
        // Filesystem backends are constructed fresh per `backend_for` call
        // (see the `if location.backend == "filesystem"` early return), so
        // `Arc::ptr_eq` is not the right invariant. The behavior contract
        // is that two `FilesystemStorage` instances pointing at the same
        // path observe each other's writes. Pin that.
        use crate::storage::filesystem::FilesystemStorage;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let primary: Arc<dyn StorageBackend> = Arc::new(FilesystemStorage::new(&path));
        let registry = StorageRegistry::new(HashMap::new(), "filesystem".to_string());
        let resolved = registry
            .backend_for(&StorageLocation {
                backend: "filesystem".to_string(),
                path: path.clone(),
            })
            .unwrap();

        // Write via primary (the freshness-probe path), read via resolved
        // (the redirect path). They must observe the same bytes.
        primary
            .put("coincide-key", Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let bytes = resolved.get("coincide-key").await.unwrap();
        assert_eq!(bytes, Bytes::from_static(b"hello"));
    }
}
