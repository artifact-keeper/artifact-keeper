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
#[derive(Debug, Clone)]
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
        }
    }

    /// Anchor reserved bucket-root namespaces on filesystem locations at
    /// `root` (the configured `STORAGE_PATH`) rather than at each
    /// repository's own directory (#3368).
    pub fn with_filesystem_bucket_root(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.filesystem_bucket_root = Some(root.into());
        self
    }

    /// Resolve a `StorageLocation` to a concrete backend instance.
    ///
    /// For `"filesystem"` locations a fresh `FilesystemStorage` is created using
    /// the location's path. All other backend names are looked up in the
    /// registry's map of shared instances.
    pub fn backend_for(&self, location: &StorageLocation) -> Result<Arc<dyn StorageBackend>> {
        if location.backend == "filesystem" {
            let fs = FilesystemStorage::new(&location.path);
            return Ok(Arc::new(match &self.filesystem_bucket_root {
                Some(root) => fs.with_bucket_root(root),
                None => fs,
            }));
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
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
