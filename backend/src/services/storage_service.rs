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
        self.base_path.join(key)
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

/// S3-compatible storage backend
#[cfg(feature = "s3")]
pub struct S3Backend {
    client: aws_sdk_s3::Client,
    bucket: String,
}

#[cfg(feature = "s3")]
impl S3Backend {
    pub async fn new(bucket: String, region: Option<String>, endpoint: Option<String>) -> Result<Self> {
        let mut config_loader = aws_config::from_env();

        if let Some(region) = region {
            config_loader = config_loader.region(aws_sdk_s3::config::Region::new(region));
        }

        let config = config_loader.load().await;

        let mut s3_config = aws_sdk_s3::config::Builder::from(&config);
        if let Some(endpoint) = endpoint {
            s3_config = s3_config.endpoint_url(endpoint).force_path_style(true);
        }

        let client = aws_sdk_s3::Client::from_conf(s3_config.build());

        Ok(Self { client, bucket })
    }
}

#[cfg(feature = "s3")]
#[async_trait]
impl StorageBackend for S3Backend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(content.into())
            .send()
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("NoSuchKey") {
                    AppError::NotFound(format!("Storage key not found: {}", key))
                } else {
                    AppError::Storage(msg)
                }
            })?;

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?
            .into_bytes();

        Ok(bytes)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self.client.head_object().bucket(&self.bucket).key(key).send().await {
            Ok(_) => Ok(true),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NotFound") || msg.contains("NoSuchKey") {
                    Ok(false)
                } else {
                    Err(AppError::Storage(msg))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self.client.list_objects_v2().bucket(&self.bucket);

            if let Some(p) = prefix {
                request = request.prefix(p);
            }

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| AppError::Storage(e.to_string()))?;

            if let Some(contents) = response.contents {
                for obj in contents {
                    if let Some(key) = obj.key {
                        keys.push(key);
                    }
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(keys)
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .copy_source(format!("{}/{}", self.bucket, source))
            .key(dest)
            .send()
            .await
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn size(&self, key: &str) -> Result<u64> {
        let response = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("NotFound") || msg.contains("NoSuchKey") {
                    AppError::NotFound(format!("Storage key not found: {}", key))
                } else {
                    AppError::Storage(msg)
                }
            })?;

        Ok(response.content_length.unwrap_or(0) as u64)
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
            #[cfg(feature = "s3")]
            "s3" => {
                let bucket = config
                    .s3_bucket
                    .clone()
                    .ok_or_else(|| AppError::Config("S3_BUCKET required for S3 backend".into()))?;
                Arc::new(
                    S3Backend::new(bucket, config.s3_region.clone(), config.s3_endpoint.clone())
                        .await?,
                )
            }
            #[cfg(not(feature = "s3"))]
            "s3" => {
                return Err(AppError::Config(
                    "S3 backend not available - compile with 's3' feature".into(),
                ))
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

    async fn create_test_storage() -> (StorageService, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = Arc::new(FilesystemBackend::new(temp_dir.path().to_path_buf()));
        (StorageService::new(backend), temp_dir)
    }

    #[tokio::test]
    async fn test_put_get() {
        let (storage, _temp) = create_test_storage().await;

        let content = Bytes::from("test content");
        storage.put("test/file.txt", content.clone()).await.unwrap();

        let retrieved = storage.get("test/file.txt").await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_cas_deduplication() {
        let (storage, _temp) = create_test_storage().await;

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
        let (storage, _temp) = create_test_storage().await;

        assert!(!storage.exists("nonexistent").await.unwrap());

        storage.put("exists.txt", Bytes::from("data")).await.unwrap();
        assert!(storage.exists("exists.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage().await;

        storage.put("to_delete.txt", Bytes::from("data")).await.unwrap();
        assert!(storage.exists("to_delete.txt").await.unwrap());

        storage.delete("to_delete.txt").await.unwrap();
        assert!(!storage.exists("to_delete.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let (storage, _temp) = create_test_storage().await;

        storage.put("dir/file1.txt", Bytes::from("1")).await.unwrap();
        storage.put("dir/file2.txt", Bytes::from("2")).await.unwrap();
        storage.put("other/file3.txt", Bytes::from("3")).await.unwrap();

        let all_keys = storage.list(None).await.unwrap();
        assert_eq!(all_keys.len(), 3);

        let dir_keys = storage.list(Some("dir")).await.unwrap();
        assert_eq!(dir_keys.len(), 2);
    }
}
