//! Storage backends.

pub mod filesystem;
pub mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use std::time::Duration;

use crate::error::Result;

/// Result of a presigned URL request
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    /// The presigned URL for direct access
    pub url: String,
    /// When the URL expires
    pub expires_in: Duration,
    /// Source type (s3, cloudfront, etc.)
    pub source: PresignedUrlSource,
}

/// Source of the presigned URL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresignedUrlSource {
    /// Direct S3 presigned URL
    S3,
    /// CloudFront signed URL
    CloudFront,
}

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

    /// Check if this backend supports redirect downloads via presigned URLs
    fn supports_redirect(&self) -> bool {
        false
    }

    /// Get a presigned URL for direct download (if supported)
    ///
    /// Returns `Ok(Some(url))` if presigned URLs are supported and enabled,
    /// `Ok(None)` if not supported or disabled, or an error if generation fails.
    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        let _ = (key, expires_in); // Suppress unused warnings
        Ok(None)
    }
}
