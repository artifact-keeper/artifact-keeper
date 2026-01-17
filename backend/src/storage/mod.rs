//! Storage backends.

pub mod filesystem;
pub mod s3;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Result;

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store content with the given key (CAS pattern - key is typically SHA-256)
    async fn put(&self, key: &str, content: Bytes) -> Result<()>;

    /// Retrieve content by key
    async fn get(&self, key: &str) -> Result<Bytes>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Delete content by key
    async fn delete(&self, key: &str) -> Result<()>;
}
