//! Storage service - facade over storage backends.
//!
//! Supports filesystem and S3-compatible storage with CAS pattern.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};

/// Result of a streaming put operation. Returned by [`StorageBackend::put_stream`]
/// / [`StorageService::put_stream`] so callers can verify the bytes-written count
/// and the SHA-256 the storage layer observed (used by proxy caching to set the
/// cache metadata sidecar without buffering the full body first; #895).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutStreamResult {
    /// Hex-encoded SHA-256 over the streamed bytes.
    pub checksum_sha256: String,
    /// Total number of bytes the stream produced.
    pub bytes_written: u64,
}

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store content and return the storage key
    async fn put(&self, key: &str, content: Bytes) -> Result<()>;

    /// Retrieve content by key
    async fn get(&self, key: &str) -> Result<Bytes>;

    /// Check if content exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Return the storage backend's opaque ETag for `key`, or `Ok(None)`
    /// when the backend has no ETag concept (filesystem) or the object is
    /// missing. Used by the proxy cache fast-path revalidation (#1051) to
    /// detect tampering before signing a presigned URL. Default
    /// implementation returns `Ok(None)` so legacy mock backends keep
    /// compiling and the fast path simply skips revalidation, matching
    /// pre-#1051 behavior for filesystem and test backends.
    async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        let _ = key;
        Ok(None)
    }

    /// Delete content by key
    async fn delete(&self, key: &str) -> Result<()>;

    /// Whether this backend can issue presigned download URLs. Default `false`
    /// so filesystem and test backends opt out. The S3/GCS wrappers forward
    /// to the inner backend, making presign capability type-enforced on the
    /// single backend handle (#1555) instead of a side-channel field.
    fn supports_redirect(&self) -> bool {
        false
    }

    /// Get a presigned URL for direct download, or `Ok(None)` when the backend
    /// does not support presigning. Default returns `None`; the S3/GCS wrappers
    /// forward to the inner backend. Proxy-cache presigns go through this so the
    /// signed key matches the no-prefix cache layout (#1555).
    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: std::time::Duration,
    ) -> Result<Option<crate::storage::PresignedUrl>> {
        let _ = (key, expires_in);
        Ok(None)
    }

    /// List keys with optional prefix
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>>;

    /// Copy content from one key to another
    async fn copy(&self, source: &str, dest: &str) -> Result<()>;

    /// Get content size without fetching full content
    async fn size(&self, key: &str) -> Result<u64>;

    /// Retrieve content as a byte stream instead of buffering the full
    /// object in memory. Default implementation wraps `get()` in a
    /// single-item stream; backends should override to actually stream
    /// from the underlying store (filesystem `read_buf` loop, S3 ranged
    /// GET, etc.). Used by the proxy cache fast path to serve large
    /// cached artifacts without OOM on 1 GiB-limited pods (#895 / #737).
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let content = self.get(key).await?;
        Ok(Box::pin(futures::stream::once(async move { Ok(content) })))
    }

    /// Store content from a byte stream and return the observed SHA-256
    /// plus byte count. Default implementation buffers into memory and
    /// delegates to `put()`; backends should override to actually stream
    /// into the underlying store. Used by the proxy cache slow path to
    /// tee an upstream response simultaneously to client + storage
    /// without buffering the full body (#895 / #737).
    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        use futures::StreamExt;

        let mut hasher = Sha256::new();
        let mut buf = Vec::new();
        let mut total: u64 = 0;

        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            total += chunk.len() as u64;
            buf.extend_from_slice(&chunk);
        }

        self.put(key, Bytes::from(buf)).await?;
        Ok(PutStreamResult {
            checksum_sha256: format!("{:x}", hasher.finalize()),
            bytes_written: total,
        })
    }
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

    fn temp_write_path(&self, path: &std::path::Path) -> Result<PathBuf> {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                AppError::Storage(format!(
                    "Cannot derive temporary storage path for {}",
                    path.display()
                ))
            })?;

        Ok(path.with_file_name(format!(".{}.{}.tmp", file_name, Uuid::new_v4().simple())))
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

        // Write atomically via a unique temp file so concurrent same-key writes
        // do not stomp each other's staging path before rename.
        let temp_path = self.temp_write_path(&path)?;
        let mut file = fs::File::create(&temp_path).await?;
        if let Err(e) = file.write_all(&content).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::Storage(e.to_string()));
        }
        file.sync_all().await?;
        drop(file);

        // Rename to final location
        if let Err(e) = fs::rename(&temp_path, &path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::Storage(e.to_string()));
        }

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

    /// Stream file contents in 64 KiB chunks instead of buffering the whole
    /// file into memory. Used by the proxy cache fast path on large
    /// artifacts (`.deb`, container blobs) so a 1 GiB pod can serve
    /// 800 MiB cached objects without OOM (#895).
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        use tokio::io::AsyncReadExt;

        let path = self.key_to_path(key);
        let file = fs::File::open(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(e.to_string())
            }
        })?;

        // 64 KiB matches the page-aligned chunk size most HTTP clients
        // and S3 SDKs use on the read side; tuning higher risks doubling
        // the working set when many concurrent streams are in flight,
        // tuning lower defeats kernel readahead.
        const CHUNK: usize = 64 * 1024;
        let stream = async_stream::try_stream! {
            let mut file = file;
            loop {
                let mut buf = vec![0u8; CHUNK];
                let n = file
                    .read(&mut buf)
                    .await
                    .map_err(|e| AppError::Storage(format!("filesystem stream read: {}", e)))?;
                if n == 0 {
                    break;
                }
                buf.truncate(n);
                yield Bytes::from(buf);
            }
        };
        Ok(Box::pin(stream))
    }

    /// Write a stream to the filesystem atomically via a temp file +
    /// rename, hashing chunks as they arrive. Used by the proxy cache
    /// slow path so an upstream response can be tee'd to the client
    /// AND to the local cache without buffering the full body (#895).
    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        use futures::StreamExt;

        let path = self.key_to_path(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let temp_path = self.temp_write_path(&path)?;
        let mut file = fs::File::create(&temp_path).await?;

        let mut hasher = Sha256::new();
        let mut total: u64 = 0;

        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(b) => b,
                Err(e) => {
                    // Best-effort temp-file cleanup. If the rename has not
                    // happened the partial bytes never reach the final
                    // path; we just drop the tmp file. Ignore the cleanup
                    // result since the original stream error is the one
                    // the caller cares about.
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(e);
                }
            };
            hasher.update(&chunk);
            total += chunk.len() as u64;
            if let Err(e) = file.write_all(&chunk).await {
                let _ = fs::remove_file(&temp_path).await;
                return Err(AppError::Storage(format!("filesystem stream write: {}", e)));
            }
        }
        file.sync_all().await?;
        drop(file);
        if let Err(e) = fs::rename(&temp_path, &path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::Storage(e.to_string()));
        }

        Ok(PutStreamResult {
            checksum_sha256: format!("{:x}", hasher.finalize()),
            bytes_written: total,
        })
    }
}

/// Generate a StorageBackend wrapper that delegates to an inner backend.
///
/// Forwards the core `crate::storage::StorageBackend` methods
/// (put/get/exists/delete), the extended methods (list/copy/size), and the
/// presign capability (supports_redirect/get_presigned_url, #1555) to the
/// inner type — so the facade handle is presign-capable when the inner is.
macro_rules! impl_storage_wrapper {
    ($wrapper:ident, $inner_ty:ty) => {
        #[async_trait]
        impl StorageBackend for $wrapper {
            async fn put(&self, key: &str, content: Bytes) -> Result<()> {
                crate::storage::StorageBackend::put(self.inner.as_ref(), key, content).await
            }
            async fn get(&self, key: &str) -> Result<Bytes> {
                crate::storage::StorageBackend::get(self.inner.as_ref(), key).await
            }
            async fn exists(&self, key: &str) -> Result<bool> {
                crate::storage::StorageBackend::exists(self.inner.as_ref(), key).await
            }
            async fn head_etag(&self, key: &str) -> Result<Option<String>> {
                crate::storage::StorageBackend::head_etag(self.inner.as_ref(), key).await
            }
            async fn delete(&self, key: &str) -> Result<()> {
                crate::storage::StorageBackend::delete(self.inner.as_ref(), key).await
            }
            // Presign capability forwarded from the inner backend (#1555) so a
            // single facade handle carries it — no parallel side-channel field.
            fn supports_redirect(&self) -> bool {
                crate::storage::StorageBackend::supports_redirect(self.inner.as_ref())
            }
            async fn get_presigned_url(
                &self,
                key: &str,
                expires_in: std::time::Duration,
            ) -> Result<Option<crate::storage::PresignedUrl>> {
                crate::storage::StorageBackend::get_presigned_url(
                    self.inner.as_ref(),
                    key,
                    expires_in,
                )
                .await
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
            // Streaming methods (#895): forward to the inner backend's
            // streaming impls so we pick up S3 ranged GETs, GCS chunked
            // reads, etc., without buffering through this wrapper.
            async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
                crate::storage::StorageBackend::get_stream(self.inner.as_ref(), key).await
            }
            async fn put_stream(
                &self,
                key: &str,
                stream: BoxStream<'static, Result<Bytes>>,
            ) -> Result<PutStreamResult> {
                let inner_result =
                    crate::storage::StorageBackend::put_stream(self.inner.as_ref(), key, stream)
                        .await?;
                // The two PutStreamResult types are structurally identical
                // (sha256 hex + byte count); translate at the boundary.
                Ok(PutStreamResult {
                    checksum_sha256: inner_result.checksum_sha256,
                    bytes_written: inner_result.bytes_written,
                })
            }
        }
    };
}

/// S3 storage backend (wrapper for integration with StorageService).
///
/// Forwards the facade `StorageBackend` trait — including `supports_redirect`
/// and `get_presigned_url` — to the inner S3 backend, so the single facade
/// handle carries presign capability (built with `prefix = None` for the
/// proxy cache; #1555).
pub struct S3BackendWrapper {
    inner: Arc<crate::storage::s3::S3Backend>,
}

impl_storage_wrapper!(S3BackendWrapper, crate::storage::s3::S3Backend);

/// GCS storage backend (wrapper for integration with StorageService).
///
/// Thin wrapper that delegates the `StorageBackend` trait to the inner
/// `crate::storage` trait and the extra `list`/`copy`/`size` methods to
/// `GcsBackend`'s inherent methods.
pub struct GcsBackendWrapper {
    inner: Arc<crate::storage::gcs::GcsBackend>,
}

impl_storage_wrapper!(GcsBackendWrapper, crate::storage::gcs::GcsBackend);

/// Storage service facade
pub struct StorageService {
    /// Single backend handle. Presign capability is type-enforced on this
    /// facade trait (`supports_redirect` / `get_presigned_url`), forwarded by
    /// `impl_storage_wrapper!` from the inner S3/GCS backend (#1555). No
    /// parallel side-channel field, so no call site can silently get a
    /// non-presigning handle.
    ///
    /// For S3 the inner backend is built with `prefix = None` so the signed
    /// key matches the no-prefix layout the proxy cache writes.
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
                // Build the proxy-cache S3 backend from the SAME env-derived
                // config the primary storage uses (redirect_downloads, presign
                // creds, CloudFront, path_format, TLS, pool tuning), then force
                // the key prefix to None. Proxy-cache content lives at the
                // bucket root (`proxy-cache/...`), not under S3_PREFIX, so the
                // signed key must carry no prefix. Reusing from_env() (instead
                // of S3Config::new, which hardcodes redirect_downloads=false and
                // no presign creds) is what makes presigning actually fire on
                // this handle (#1555).
                let mut s3_config = crate::storage::s3::S3Config::from_env()?;
                s3_config.prefix = None;
                let inner = Arc::new(crate::storage::s3::S3Backend::new(s3_config).await?);
                Arc::new(S3BackendWrapper { inner })
            }
            "gcs" => {
                let gcs_config = crate::storage::gcs::GcsConfig::from_env()?;
                let inner = Arc::new(crate::storage::gcs::GcsBackend::new(gcs_config).await?);
                Arc::new(GcsBackendWrapper { inner })
            }
            // TODO(#1555): Azure has no arm here. main.rs builds an Azure
            // primary backend, but this facade has no AzureBackendWrapper
            // (the `impl_storage_wrapper!` macro forwards inherent
            // list/copy/size, which AzureBackend does not yet expose). An
            // Azure deployment therefore errors loudly below rather than
            // silently losing presign capability. Wire up a wrapper +
            // no-prefix presign handle (mirroring the s3/gcs arms) before
            // enabling Azure for the proxy cache.
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

    /// Return the backend's opaque ETag for `key`. Used by the proxy
    /// cache fast-path revalidation (#1051). See
    /// [`StorageBackend::head_etag`] for the per-backend contract.
    pub async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        self.backend.head_etag(key).await
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

    /// Stream content out instead of buffering the full body. Used by
    /// proxy cache fast-path serves of large artifacts (#895).
    pub async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        self.backend.get_stream(key).await
    }

    /// Write a stream into the backend, returning the SHA-256 and byte count
    /// observed without buffering the body. Used by the proxy cache slow
    /// path to tee an upstream response simultaneously to the client and
    /// to the local cache (#895).
    pub async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        self.backend.put_stream(key, stream).await
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

    #[test]
    fn test_filesystem_backend_temp_write_path_is_unique() {
        let backend = FilesystemBackend::new(PathBuf::from("/storage"));
        let path = backend.key_to_path("proxy-cache/repo/pkg/__content__");

        let first = backend.temp_write_path(&path).expect("temp path");
        let second = backend.temp_write_path(&path).expect("temp path");

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert_eq!(second.parent(), path.parent());
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

    // -----------------------------------------------------------------------
    // StorageService::from_config() backend selection
    // -----------------------------------------------------------------------

    // Serialize env-var tests to avoid cross-test interference.
    // Uses tokio::sync::Mutex so the guard can be held across .await points
    // without triggering clippy::await_holding_lock.
    static GCS_ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

    fn gcs_env_lock() -> &'static tokio::sync::Mutex<()> {
        GCS_ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn minimal_config(storage_backend: &str) -> crate::config::Config {
        crate::config::Config {
            storage_backend: storage_backend.to_string(),
            ..crate::config::Config::test_config()
        }
    }

    #[tokio::test]
    async fn test_storage_service_from_config_rejects_unknown_backend() {
        let config = minimal_config("bogus");
        let result = StorageService::from_config(&config).await;
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("bogus"),
            "Error should mention the unknown backend name, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_gcs_backend_wrapper_from_config_fields() {
        let _guard = gcs_env_lock().lock().await;
        std::env::set_var("GCS_BUCKET", "wrapper-test-bucket");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");
        std::env::remove_var("GCS_PROJECT_ID");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");

        let gcs_config = crate::storage::gcs::GcsConfig::from_env();
        let result = match gcs_config {
            Ok(cfg) => crate::storage::gcs::GcsBackend::new(cfg).await,
            Err(e) => Err(e),
        };
        std::env::remove_var("GCS_BUCKET");

        assert!(
            result.is_ok(),
            "GcsBackend should construct without error in ADC mode"
        );
        let inner = Arc::new(result.unwrap());
        let wrapper = GcsBackendWrapper {
            inner: Arc::clone(&inner),
        };
        assert_eq!(wrapper.inner.bucket(), "wrapper-test-bucket");
    }

    #[tokio::test]
    async fn test_storage_service_from_config_gcs_arm_reached() {
        let _guard = gcs_env_lock().lock().await;
        std::env::set_var("GCS_BUCKET", "service-test-bucket");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");
        std::env::remove_var("GCS_PROJECT_ID");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");

        let config = minimal_config("gcs");
        let result = StorageService::from_config(&config).await;
        std::env::remove_var("GCS_BUCKET");

        assert!(
            result.is_ok(),
            "StorageService::from_config should succeed with storage_backend=gcs"
        );
    }

    // ── presigned URL support tests (via crate::storage::StorageBackend) ──

    use crate::storage::{PresignedUrl, PresignedUrlSource};

    /// A mock backend implementing `crate::storage::StorageBackend` with
    /// presigned URL support.
    struct MockPresignedInner;

    #[async_trait]
    impl crate::storage::StorageBackend for MockPresignedInner {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Ok(Bytes::from_static(b"mock"))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        fn supports_redirect(&self) -> bool {
            true
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: std::time::Duration,
        ) -> Result<Option<PresignedUrl>> {
            Ok(Some(PresignedUrl {
                url: format!("https://mock.example.com/{}", key),
                expires_in,
                source: PresignedUrlSource::S3,
            }))
        }
    }

    #[test]
    fn test_filesystem_storage_does_not_support_redirect() {
        let backend = crate::storage::filesystem::FilesystemStorage::new("/tmp/test-artifacts");
        assert!(!crate::storage::StorageBackend::supports_redirect(&backend));
    }

    #[tokio::test]
    async fn test_filesystem_storage_presigned_url_returns_none() {
        let backend = crate::storage::filesystem::FilesystemStorage::new("/tmp/test-artifacts");
        let result = crate::storage::StorageBackend::get_presigned_url(
            &backend,
            "test-key",
            std::time::Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(result.is_none());
    }

    // ── facade-trait presign defaults (#1555) ──────────────────────────────
    // The redirect fast path is gated on the FACADE trait
    // (`storage_service::StorageBackend`) methods, not the inner
    // `crate::storage::StorageBackend`. The facade `FilesystemBackend` does
    // NOT override `supports_redirect`/`get_presigned_url`, so it inherits the
    // `false`/`None` defaults — which is exactly what makes a filesystem (or
    // any non-presigning) deployment fall through to streaming instead of
    // emitting a 302. These tests pin that default on the facade handle.

    #[test]
    fn test_facade_filesystem_does_not_support_redirect() {
        let backend = FilesystemBackend::new(std::path::PathBuf::from("/tmp/test-artifacts"));
        // Through the FACADE trait specifically (the one the redirect path uses).
        assert!(
            !StorageBackend::supports_redirect(&backend),
            "filesystem facade must report no redirect support so the proxy \
             cache path falls through to streaming (#1555)"
        );
    }

    #[tokio::test]
    async fn test_facade_filesystem_presigned_url_returns_none() {
        let backend = FilesystemBackend::new(std::path::PathBuf::from("/tmp/test-artifacts"));
        let result = StorageBackend::get_presigned_url(
            &backend,
            "proxy-cache/repo/pkg/__content__",
            std::time::Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(
            result.is_none(),
            "filesystem facade must never presign — forces the streaming fallback (#1555)"
        );
    }

    #[tokio::test]
    async fn test_storage_service_backend_handle_is_non_presigning_on_filesystem() {
        // `cache_storage_backend()` returns `StorageService::backend()`. On a
        // filesystem-backed service that handle must report no redirect support
        // and yield no presigned URL, so `try_proxy_cache_redirect` returns
        // None and the caller streams. This is the core non-regression
        // guarantee for non-S3 deployments (the rig) (#1555).
        let (storage, _temp) = create_test_storage();
        let handle = storage.backend();
        assert!(
            !handle.supports_redirect(),
            "filesystem StorageService backend handle must not support redirect"
        );
        let presigned = handle
            .get_presigned_url(
                "proxy-cache/repo/pkg/__content__",
                std::time::Duration::from_secs(300),
            )
            .await
            .unwrap();
        assert!(
            presigned.is_none(),
            "filesystem StorageService backend handle must not presign"
        );
    }

    #[test]
    fn test_mock_presigned_inner_supports_redirect() {
        let backend = MockPresignedInner;
        assert!(crate::storage::StorageBackend::supports_redirect(&backend));
    }

    #[tokio::test]
    async fn test_mock_presigned_inner_returns_url() {
        let backend = MockPresignedInner;
        let result = crate::storage::StorageBackend::get_presigned_url(
            &backend,
            "test-key",
            std::time::Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(result.is_some());
        let presigned = result.unwrap();
        assert!(presigned.url.contains("test-key"));
        assert_eq!(presigned.source, PresignedUrlSource::S3);
    }

    // -----------------------------------------------------------------------
    // #895 streaming primitives — FilesystemBackend put_stream / get_stream
    //
    // The trait defaults buffer the body; the real OOM relief only kicks in
    // when the FilesystemBackend overrides actually stream from disk + write
    // in chunks. These tests exercise that override.
    // -----------------------------------------------------------------------

    use futures::stream::StreamExt as _StreamExt;

    #[tokio::test]
    async fn test_filesystem_put_stream_round_trip_through_get_stream() {
        let tmp = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(tmp.path().to_path_buf());

        let payload = Bytes::from_static(b"streaming hello world");
        let upload_stream: BoxStream<'static, Result<Bytes>> =
            Box::pin(futures::stream::iter(vec![Ok(payload.clone())]));

        let put_result = backend
            .put_stream("k1", upload_stream)
            .await
            .expect("put_stream must succeed");
        assert_eq!(put_result.bytes_written, payload.len() as u64);
        // SHA-256 is a 64-char lowercase hex string; verify shape rather
        // than the literal value to keep the test independent of payload
        // changes. Empty + known values are covered by other tests.
        assert_eq!(put_result.checksum_sha256.len(), 64);
        assert!(put_result
            .checksum_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Round-trip read via streaming
        let mut read_stream = backend
            .get_stream("k1")
            .await
            .expect("get_stream must succeed");
        let mut received: Vec<u8> = Vec::new();
        while let Some(chunk) = read_stream.next().await {
            received.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(received, payload.as_ref());
    }

    #[tokio::test]
    async fn test_filesystem_put_stream_multi_chunk_streams_to_disk() {
        let tmp = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(tmp.path().to_path_buf());

        let chunks: Vec<&[u8]> = vec![b"alpha-", b"beta-", b"gamma"];
        let total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let upload: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(
            chunks
                .iter()
                .map(|c| Ok(Bytes::from_static(c)))
                .collect::<Vec<_>>(),
        ));

        let result = backend.put_stream("k-multi", upload).await.unwrap();
        assert_eq!(result.bytes_written, total);

        // Read back end-to-end and confirm reassembled content.
        let mut stream = backend.get_stream("k-multi").await.unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"alpha-beta-gamma");
    }

    #[tokio::test]
    async fn test_filesystem_put_stream_cleans_temp_on_stream_error() {
        let tmp = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(tmp.path().to_path_buf());

        // A stream that yields one chunk then an error.
        let upload: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![
            Ok(Bytes::from_static(b"partial")),
            Err(AppError::Storage(
                "simulated mid-stream failure".to_string(),
            )),
        ]));

        let err = backend
            .put_stream("k-fail", upload)
            .await
            .expect_err("stream error must propagate from put_stream");
        match err {
            AppError::Storage(_) => {}
            other => panic!("expected Storage error, got {:?}", other),
        }

        // The final key must not exist (atomic rename never ran).
        let exists = backend.exists("k-fail").await.unwrap();
        assert!(
            !exists,
            "atomic temp file must NOT promote to final key on stream error"
        );
    }

    #[tokio::test]
    async fn test_filesystem_get_stream_missing_key_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(tmp.path().to_path_buf());

        match backend.get_stream("nope").await {
            Ok(_) => panic!("missing key must error, not yield empty stream"),
            Err(AppError::NotFound(_)) => {}
            Err(other) => panic!(
                "missing key must map to AppError::NotFound (cache-miss \
                 contract from #1016 / #1089); got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_filesystem_put_stream_empty_stream_writes_empty_file() {
        let tmp = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(tmp.path().to_path_buf());

        let empty: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![]));
        let result = backend.put_stream("k-empty", empty).await.unwrap();
        assert_eq!(result.bytes_written, 0);
        // SHA-256 of empty input is well-known:
        assert_eq!(
            result.checksum_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // The key exists and reads back as 0 bytes via streaming.
        let mut stream = backend.get_stream("k-empty").await.unwrap();
        let mut bytes_seen: u64 = 0;
        while let Some(chunk) = stream.next().await {
            bytes_seen += chunk.unwrap().len() as u64;
        }
        assert_eq!(bytes_seen, 0);
    }

    #[tokio::test]
    async fn test_storage_service_put_stream_get_stream_delegate_to_backend() {
        // StorageService is the facade ProxyService uses; verify the
        // pub get_stream / put_stream methods round-trip through the
        // underlying backend rather than silently no-op'ing.
        let tmp = TempDir::new().unwrap();
        let backend: Arc<dyn StorageBackend> =
            Arc::new(FilesystemBackend::new(tmp.path().to_path_buf()));
        let service = StorageService::new(backend);

        let upload: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(vec![Ok(
            Bytes::from_static(b"via facade"),
        )]));
        let put_result = service.put_stream("facade-key", upload).await.unwrap();
        assert_eq!(put_result.bytes_written, 10);

        let mut stream = service.get_stream("facade-key").await.unwrap();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(buf, b"via facade");
    }

    #[tokio::test]
    async fn test_put_stream_result_equality_and_clone() {
        let r1 = PutStreamResult {
            checksum_sha256: "abc".to_string(),
            bytes_written: 42,
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
        let r3 = PutStreamResult {
            checksum_sha256: "def".to_string(),
            bytes_written: 42,
        };
        assert_ne!(r1, r3);
    }
}
