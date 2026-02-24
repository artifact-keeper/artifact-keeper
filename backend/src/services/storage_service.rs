//! Storage service - facade over storage backends.
//!
//! Supports filesystem and S3-compatible storage with CAS pattern.

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::config::Config;
use crate::error::{AppError, Result};

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store content and return the storage key
    async fn put(&self, key: &str, content: Bytes) -> Result<()>;

    /// Retrieve content by key
    async fn get(&self, key: &str) -> Result<Bytes>;

    /// Check if content exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Delete content by key
    async fn delete(&self, key: &str) -> Result<()>;

    /// List keys with optional prefix
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>>;

    /// Copy content from one key to another
    async fn copy(&self, source: &str, dest: &str) -> Result<()>;

    /// Get content size without fetching full content
    async fn size(&self, key: &str) -> Result<u64>;
}

/// Filesystem storage backend
pub struct FilesystemBackend {
    base_path: PathBuf,
}

impl FilesystemBackend {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        // Sanitize the key to prevent path traversal.
        // Remove any ".." components and leading "/" to ensure the
        // resolved path stays under self.base_path.
        let sanitized: PathBuf = std::path::Path::new(key)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        self.base_path.join(sanitized)
    }
}

#[async_trait]
impl StorageBackend for FilesystemBackend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let path = self.key_to_path(key);

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write atomically via temp file
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&content).await?;
        file.sync_all().await?;
        drop(file);

        // Rename to final location
        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.key_to_path(key);
        let content = fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(e.to_string())
            }
        })?;
        Ok(Bytes::from(content))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_path = match prefix {
            Some(p) => self.key_to_path(p),
            None => self.base_path.clone(),
        };

        let mut keys = Vec::new();
        let mut stack = vec![search_path];

        while let Some(current) = stack.pop() {
            if !current.exists() {
                continue;
            }

            let mut entries = fs::read_dir(&current).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(relative) = path.strip_prefix(&self.base_path) {
                    keys.push(relative.to_string_lossy().to_string());
                }
            }
        }

        Ok(keys)
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_path = self.key_to_path(source);
        let dest_path = self.key_to_path(dest);

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::copy(&source_path, &dest_path).await?;
        Ok(())
    }

    async fn size(&self, key: &str) -> Result<u64> {
        let path = self.key_to_path(key);
        let metadata = fs::metadata(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(e.to_string())
            }
        })?;
        Ok(metadata.len())
    }
}

/// S3 storage backend (wrapper for integration with StorageService)
pub struct S3BackendWrapper {
    inner: crate::storage::s3::S3Backend,
}

impl S3BackendWrapper {
    pub async fn from_config(config: &Config) -> crate::error::Result<Self> {
        let s3_config = crate::storage::s3::S3Config::new(
            config.s3_bucket.clone().unwrap_or_default(),
            config
                .s3_region
                .clone()
                .unwrap_or_else(|| "us-east-1".to_string()),
            config.s3_endpoint.clone(),
            None, // No prefix by default
        );
        let inner = crate::storage::s3::S3Backend::new(s3_config).await?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl StorageBackend for S3BackendWrapper {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        crate::storage::StorageBackend::put(&self.inner, key, content).await
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        crate::storage::StorageBackend::get(&self.inner, key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        crate::storage::StorageBackend::exists(&self.inner, key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        crate::storage::StorageBackend::delete(&self.inner, key).await
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        self.inner.copy(source, dest).await
    }

    async fn size(&self, key: &str) -> Result<u64> {
        self.inner.size(key).await
    }
}

/// Storage service facade
pub struct StorageService {
    backend: Arc<dyn StorageBackend>,
}

impl StorageService {
    /// Create storage service from config
    pub async fn from_config(config: &Config) -> Result<Self> {
        let backend: Arc<dyn StorageBackend> = match config.storage_backend.as_str() {
            "filesystem" => {
                let path = PathBuf::from(&config.storage_path);
                fs::create_dir_all(&path).await?;
                Arc::new(FilesystemBackend::new(path))
            }
            "s3" => {
                let s3_backend = S3BackendWrapper::from_config(config).await?;
                Arc::new(s3_backend)
            }
            other => {
                return Err(AppError::Config(format!(
                    "Unknown storage backend: {}",
                    other
                )))
            }
        };

        Ok(Self { backend })
    }

    /// Create with a specific backend (for testing)
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    /// Calculate SHA-256 hash of content
    pub fn calculate_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Generate CAS key from hash
    pub fn cas_key(hash: &str) -> String {
        // Split hash into directories for better filesystem performance
        // e.g., "abc123..." -> "cas/ab/c1/abc123..."
        format!("cas/{}/{}/{}", &hash[0..2], &hash[2..4], hash)
    }

    /// Store content with CAS (content-addressable storage)
    pub async fn put_cas(&self, content: Bytes) -> Result<String> {
        let hash = Self::calculate_hash(&content);
        let key = Self::cas_key(&hash);

        // Only write if doesn't exist (deduplication)
        if !self.backend.exists(&key).await? {
            self.backend.put(&key, content).await?;
        }

        Ok(hash)
    }

    /// Get content by CAS hash
    pub async fn get_cas(&self, hash: &str) -> Result<Bytes> {
        let key = Self::cas_key(hash);
        self.backend.get(&key).await
    }

    /// Check if CAS content exists
    pub async fn exists_cas(&self, hash: &str) -> Result<bool> {
        let key = Self::cas_key(hash);
        self.backend.exists(&key).await
    }

    /// Store content at arbitrary path (for non-CAS use)
    pub async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        self.backend.put(key, content).await
    }

    /// Get content from arbitrary path
    pub async fn get(&self, key: &str) -> Result<Bytes> {
        self.backend.get(key).await
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> Result<bool> {
        self.backend.exists(key).await
    }

    /// Delete content
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    /// List keys with optional prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        self.backend.list(prefix).await
    }

    /// Copy content
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        self.backend.copy(source, dest).await
    }

    /// Get content size
    pub async fn size(&self, key: &str) -> Result<u64> {
        self.backend.size(key).await
    }

    /// Get underlying backend for direct access
    pub fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_storage() -> (StorageService, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend: Arc<dyn StorageBackend> =
            Arc::new(FilesystemBackend::new(temp_dir.path().to_path_buf()));
        (StorageService::new(backend), temp_dir)
    }

    #[tokio::test]
    async fn test_put_get() {
        let (storage, _temp) = create_test_storage();

        let content = Bytes::from("test content");
        storage.put("test/file.txt", content.clone()).await.unwrap();

        let retrieved = storage.get("test/file.txt").await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_cas_deduplication() {
        let (storage, _temp) = create_test_storage();

        let content = Bytes::from("duplicate content");
        let hash1 = storage.put_cas(content.clone()).await.unwrap();
        let hash2 = storage.put_cas(content.clone()).await.unwrap();

        // Same content should produce same hash
        assert_eq!(hash1, hash2);

        // Should be able to retrieve by hash
        let retrieved = storage.get_cas(&hash1).await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_exists() {
        let (storage, _temp) = create_test_storage();

        assert!(!storage.exists("nonexistent").await.unwrap());

        storage
            .put("exists.txt", Bytes::from("data"))
            .await
            .unwrap();
        assert!(storage.exists("exists.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage();

        storage
            .put("to_delete.txt", Bytes::from("data"))
            .await
            .unwrap();
        assert!(storage.exists("to_delete.txt").await.unwrap());

        storage.delete("to_delete.txt").await.unwrap();
        assert!(!storage.exists("to_delete.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let (storage, _temp) = create_test_storage();

        storage
            .put("dir/file1.txt", Bytes::from("1"))
            .await
            .unwrap();
        storage
            .put("dir/file2.txt", Bytes::from("2"))
            .await
            .unwrap();
        storage
            .put("other/file3.txt", Bytes::from("3"))
            .await
            .unwrap();

        let all_keys = storage.list(None).await.unwrap();
        assert_eq!(all_keys.len(), 3);

        let dir_keys = storage.list(Some("dir")).await.unwrap();
        assert_eq!(dir_keys.len(), 2);
    }

    #[test]
    fn test_calculate_hash_empty() {
        let hash = StorageService::calculate_hash(b"");
        // SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_calculate_hash_deterministic() {
        let content = b"hello world";
        let hash1 = StorageService::calculate_hash(content);
        let hash2 = StorageService::calculate_hash(content);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_calculate_hash_different_content() {
        let hash1 = StorageService::calculate_hash(b"foo");
        let hash2 = StorageService::calculate_hash(b"bar");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_calculate_hash_known_value() {
        // SHA-256 of "test" is well-known
        let hash = StorageService::calculate_hash(b"test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_cas_key_format() {
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = StorageService::cas_key(hash);
        assert_eq!(
            key,
            "cas/ab/cd/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn test_cas_key_splits_first_four_chars() {
        let hash = "1234abcdef567890";
        let key = StorageService::cas_key(hash);
        assert!(key.starts_with("cas/12/34/"));
        assert!(key.ends_with(hash));
    }

    #[test]
    fn test_cas_key_different_hashes_different_keys() {
        let key1 = StorageService::cas_key(
            "aabbccddee112233445566778899aabbccddee112233445566778899aabbccdd",
        );
        let key2 = StorageService::cas_key(
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_filesystem_backend_key_to_path() {
        let backend = FilesystemBackend::new(PathBuf::from("/data/storage"));
        let path = backend.key_to_path("repos/maven/artifact.jar");
        assert_eq!(
            path,
            PathBuf::from("/data/storage/repos/maven/artifact.jar")
        );
    }

    #[test]
    fn test_filesystem_backend_key_to_path_nested() {
        let backend = FilesystemBackend::new(PathBuf::from("/tmp/test"));
        let path = backend.key_to_path("a/b/c/d/e.txt");
        assert_eq!(path, PathBuf::from("/tmp/test/a/b/c/d/e.txt"));
    }

    #[test]
    fn test_filesystem_backend_key_to_path_simple() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("file.bin");
        assert_eq!(path, PathBuf::from("/storage/file.bin"));
    }

    #[tokio::test]
    async fn test_copy() {
        let (storage, _temp) = create_test_storage();

        let content = Bytes::from("copy me");
        storage.put("source.txt", content.clone()).await.unwrap();
        storage.copy("source.txt", "dest.txt").await.unwrap();

        let retrieved = storage.get("dest.txt").await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_size() {
        let (storage, _temp) = create_test_storage();

        let content = Bytes::from("12345");
        storage.put("sized.txt", content).await.unwrap();

        let size = storage.size("sized.txt").await.unwrap();
        assert_eq!(size, 5);
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_error() {
        let (storage, _temp) = create_test_storage();

        let result = storage.get("does_not_exist.txt").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_succeeds() {
        let (storage, _temp) = create_test_storage();

        // Deleting a non-existent key should succeed silently
        let result = storage.delete("nonexistent.txt").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cas_roundtrip() {
        let (storage, _temp) = create_test_storage();

        let content = Bytes::from("cas roundtrip test");
        let hash = storage.put_cas(content.clone()).await.unwrap();

        // Verify hash matches expected
        let expected_hash = StorageService::calculate_hash(&content);
        assert_eq!(hash, expected_hash);

        // Verify existence
        assert!(storage.exists_cas(&hash).await.unwrap());

        // Verify retrieval
        let retrieved = storage.get_cas(&hash).await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_cas_nonexistent_hash() {
        let (storage, _temp) = create_test_storage();

        let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!storage.exists_cas(fake_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_overwrite_key() {
        let (storage, _temp) = create_test_storage();

        storage
            .put("overwrite.txt", Bytes::from("first"))
            .await
            .unwrap();
        storage
            .put("overwrite.txt", Bytes::from("second"))
            .await
            .unwrap();

        let content = storage.get("overwrite.txt").await.unwrap();
        assert_eq!(content, Bytes::from("second"));
    }

    #[tokio::test]
    async fn test_list_empty_dir() {
        let (storage, _temp) = create_test_storage();

        let keys = storage.list(None).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_list_nonexistent_prefix() {
        let (storage, _temp) = create_test_storage();

        let keys = storage.list(Some("nonexistent_prefix")).await.unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_storage_service_backend_accessor() {
        let temp_dir = TempDir::new().unwrap();
        let backend: Arc<dyn StorageBackend> =
            Arc::new(FilesystemBackend::new(temp_dir.path().to_path_buf()));
        let storage = StorageService::new(backend);

        // Ensure backend() returns a clone of the backend arc
        let _backend_ref = storage.backend();
    }

    // -----------------------------------------------------------------------
    // Path traversal protection in key_to_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_key_to_path_normal_key() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("maven/com/example/artifact.jar");
        assert_eq!(
            path,
            PathBuf::from("/storage/maven/com/example/artifact.jar")
        );
    }

    #[test]
    fn test_key_to_path_strips_dotdot() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("maven/../../etc/passwd");
        // ".." components are filtered out, only normal components remain
        assert_eq!(path, PathBuf::from("/storage/maven/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_strips_leading_slash() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("/etc/shadow");
        // Leading "/" (RootDir component) is filtered out
        assert_eq!(path, PathBuf::from("/storage/etc/shadow"));
    }

    #[test]
    fn test_key_to_path_strips_pure_traversal() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("../../../etc/passwd");
        assert_eq!(path, PathBuf::from("/storage/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_preserves_nested_dirs() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("npm/@scope/package/-/package-1.0.0.tgz");
        assert_eq!(
            path,
            PathBuf::from("/storage/npm/@scope/package/-/package-1.0.0.tgz")
        );
    }

    #[test]
    fn test_key_to_path_empty_key() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("");
        assert_eq!(path, PathBuf::from("/storage"));
    }

    #[tokio::test]
    async fn test_put_get_with_traversal_key_stays_inside_storage() {
        let temp_dir = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(temp_dir.path().to_path_buf());

        // Attempt to write with a traversal key
        backend
            .put("../../escape.txt", Bytes::from("should stay inside"))
            .await
            .unwrap();

        // The file should be stored inside the temp dir, not outside
        let path = backend.key_to_path("../../escape.txt");
        assert!(path.starts_with(temp_dir.path()));

        // And we can read it back via the same key
        let content = backend.get("../../escape.txt").await.unwrap();
        assert_eq!(content, Bytes::from("should stay inside"));
    }
}
