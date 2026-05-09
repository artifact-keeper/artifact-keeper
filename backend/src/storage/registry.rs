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
}

impl StorageRegistry {
    /// Create a new registry with the given named backends and default.
    pub fn new(
        backends: HashMap<String, Arc<dyn StorageBackend>>,
        default_backend: String,
    ) -> Self {
        Self {
            backends,
            default_backend,
        }
    }

    /// Resolve a `StorageLocation` to a concrete backend instance.
    ///
    /// For `"filesystem"` locations a fresh `FilesystemStorage` is created using
    /// the location's path. All other backend names are looked up in the
    /// registry's map of shared instances.
    pub fn backend_for(&self, location: &StorageLocation) -> Result<Arc<dyn StorageBackend>> {
        if location.backend == "filesystem" {
            return Ok(Arc::new(FilesystemStorage::new(&location.path)));
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
