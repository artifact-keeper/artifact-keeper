//! Filesystem storage backend.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::StorageBackend;
use crate::error::{AppError, Result};

/// Filesystem-based storage backend
pub struct FilesystemStorage {
    base_path: PathBuf,
}

impl FilesystemStorage {
    /// Create new filesystem storage
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Get full path for a key (using first 2 chars as subdirectory for distribution)
    fn key_to_path(&self, key: &str) -> PathBuf {
        let prefix = &key[..2.min(key.len())];
        self.base_path.join(prefix).join(key)
    }
}

#[async_trait]
impl StorageBackend for FilesystemStorage {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let path = self.key_to_path(key);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write content
        let mut file = fs::File::create(&path).await?;
        file.write_all(&content).await?;
        file.sync_all().await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.key_to_path(key);
        let content = fs::read(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read {}: {}", key, e)))?;
        Ok(Bytes::from(content))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);
        fs::remove_file(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to delete {}: {}", key, e)))?;
        Ok(())
    }
}
