//! Storage backends.

pub mod azure;
pub mod filesystem;
pub mod gcs;
pub mod path_format;
pub mod registry;
pub mod s3;

pub use path_format::StoragePathFormat;
pub use registry::{StorageLocation, StorageRegistry};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::Duration;

use crate::error::Result;

/// Result of a streaming put operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutStreamResult {
    /// SHA-256 checksum computed incrementally during the write.
    pub checksum_sha256: String,
    /// Total bytes written.
    pub bytes_written: u64,
}

/// Result of a presigned URL request
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    /// The presigned URL for direct access
    pub url: String,
    /// When the URL expires
    pub expires_in: Duration,
    /// Source type (s3, cloudfront, azure, gcs)
    pub source: PresignedUrlSource,
}

/// Source of the presigned URL
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresignedUrlSource {
    /// Direct S3 presigned URL
    S3,
    /// CloudFront signed URL
    CloudFront,
    /// Azure Blob Storage SAS URL
    Azure,
    /// Google Cloud Storage signed URL
    Gcs,
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

    /// Store content from a file. Default reads the whole file into memory;
    /// backends should override for streaming support.
    async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<()> {
        let content = tokio::fs::read(path).await?;
        self.put(key, content.into()).await
    }

    /// Retrieve content as a byte stream instead of loading the full object
    /// into memory. The default implementation wraps `get()` in a single-item
    /// stream.
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let content = self.get(key).await?;
        Ok(Box::pin(futures::stream::once(async { Ok(content) })))
    }

    /// Store content from a byte stream, computing a SHA-256 checksum
    /// incrementally as data arrives. The default implementation collects
    /// the stream into memory and delegates to `put()`.
    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        use futures::StreamExt;
        use sha2::{Digest, Sha256};

        tracing::debug!(key, "put_stream falling back to in-memory buffering");

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

    /// Perform a lightweight connectivity probe against the storage backend.
    ///
    /// Returns `Ok(())` if the backend is reachable and authenticated.
    /// The default implementation always succeeds; cloud backends (S3, GCS,
    /// Azure) override this with a real API call.
    async fn health_check(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presigned_url_source_s3() {
        let source = PresignedUrlSource::S3;
        assert_eq!(source, PresignedUrlSource::S3);
        assert_ne!(source, PresignedUrlSource::CloudFront);
    }

    #[test]
    fn test_presigned_url_source_cloudfront() {
        let source = PresignedUrlSource::CloudFront;
        assert_eq!(source, PresignedUrlSource::CloudFront);
    }

    #[test]
    fn test_presigned_url_source_azure() {
        let source = PresignedUrlSource::Azure;
        assert_eq!(source, PresignedUrlSource::Azure);
    }

    #[test]
    fn test_presigned_url_source_gcs() {
        let source = PresignedUrlSource::Gcs;
        assert_eq!(source, PresignedUrlSource::Gcs);
    }

    #[test]
    fn test_presigned_url_source_equality() {
        assert_ne!(PresignedUrlSource::S3, PresignedUrlSource::Azure);
        assert_ne!(PresignedUrlSource::CloudFront, PresignedUrlSource::Gcs);
        assert_ne!(PresignedUrlSource::Azure, PresignedUrlSource::Gcs);
    }

    #[test]
    fn test_presigned_url_source_copy() {
        let source = PresignedUrlSource::S3;
        let copied = source;
        assert_eq!(source, copied);
    }

    #[test]
    fn test_presigned_url_construction() {
        let url = PresignedUrl {
            url: "https://s3.amazonaws.com/bucket/key?signature=abc".to_string(),
            expires_in: Duration::from_secs(3600),
            source: PresignedUrlSource::S3,
        };

        assert_eq!(url.url, "https://s3.amazonaws.com/bucket/key?signature=abc");
        assert_eq!(url.expires_in, Duration::from_secs(3600));
        assert_eq!(url.source, PresignedUrlSource::S3);
    }

    #[test]
    fn test_presigned_url_clone() {
        let url = PresignedUrl {
            url: "https://example.com/artifact".to_string(),
            expires_in: Duration::from_secs(600),
            source: PresignedUrlSource::Azure,
        };
        let cloned = url.clone();
        assert_eq!(url.url, cloned.url);
        assert_eq!(url.expires_in, cloned.expires_in);
        assert_eq!(url.source, cloned.source);
    }

    #[test]
    fn test_presigned_url_debug() {
        let url = PresignedUrl {
            url: "https://example.com".to_string(),
            expires_in: Duration::from_secs(60),
            source: PresignedUrlSource::Gcs,
        };
        let debug_str = format!("{:?}", url);
        assert!(debug_str.contains("PresignedUrl"));
        assert!(debug_str.contains("Gcs"));
    }

    /// A minimal StorageBackend implementation for testing default methods
    struct TestBackend;

    #[async_trait]
    impl StorageBackend for TestBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Ok(Bytes::from_static(b"test"))
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_default_supports_redirect() {
        let backend = TestBackend;
        assert!(!backend.supports_redirect());
    }

    #[tokio::test]
    async fn test_default_get_presigned_url() {
        let backend = TestBackend;
        let result = backend
            .get_presigned_url("test-key", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_presigned_url_source_debug() {
        let debug_str = format!("{:?}", PresignedUrlSource::S3);
        assert_eq!(debug_str, "S3");
        let debug_str = format!("{:?}", PresignedUrlSource::CloudFront);
        assert_eq!(debug_str, "CloudFront");
    }

    #[test]
    fn test_put_stream_result_construction() {
        let result = PutStreamResult {
            checksum_sha256: "abc123".to_string(),
            bytes_written: 1024,
        };
        assert_eq!(result.checksum_sha256, "abc123");
        assert_eq!(result.bytes_written, 1024);
    }

    #[test]
    fn test_put_stream_result_clone() {
        let result = PutStreamResult {
            checksum_sha256: "def456".to_string(),
            bytes_written: 512,
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_put_stream_result_debug() {
        let result = PutStreamResult {
            checksum_sha256: "abc".to_string(),
            bytes_written: 0,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("PutStreamResult"));
        assert!(debug_str.contains("abc"));
    }

    #[tokio::test]
    async fn test_default_get_stream() {
        use futures::StreamExt;

        let backend = TestBackend;
        let mut stream = backend.get_stream("any-key").await.unwrap();

        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"test");
    }

    #[tokio::test]
    async fn test_default_put_stream() {
        let backend = TestBackend;
        let data = Bytes::from_static(b"hello world");
        let stream = Box::pin(futures::stream::once(async { Ok(data) }))
            as BoxStream<'static, Result<Bytes>>;

        let result = backend.put_stream("test-key", stream).await.unwrap();
        assert_eq!(result.bytes_written, 11);
        // SHA-256 of "hello world"
        assert_eq!(
            result.checksum_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_default_put_stream_multi_chunk() {
        let backend = TestBackend;
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let stream = Box::pin(futures::stream::iter(chunks)) as BoxStream<'static, Result<Bytes>>;

        let result = backend.put_stream("test-key", stream).await.unwrap();
        assert_eq!(result.bytes_written, 11);
        // Same content as above, so same hash
        assert_eq!(
            result.checksum_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_default_put_stream_empty() {
        let backend = TestBackend;
        let stream = Box::pin(futures::stream::empty()) as BoxStream<'static, Result<Bytes>>;

        let result = backend.put_stream("test-key", stream).await.unwrap();
        assert_eq!(result.bytes_written, 0);
        // SHA-256 of empty input
        assert_eq!(
            result.checksum_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
