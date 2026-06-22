//! Storage backends.

pub mod azure;
pub mod filesystem;
pub mod gcs;
pub mod keys;
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

/// Build an inclusive HTTP `Range` header (`bytes=START-END`) for a download
/// window, validating that the requested length is non-zero and that
/// `offset + length` does not overflow `u64`.
///
/// Shared by the GCS and Azure backends, both of which issue ranged GETs with
/// the same inclusive byte-range semantics.
pub(crate) fn download_range_header(offset: u64, length: usize) -> Result<String> {
    use crate::error::AppError;

    if length == 0 {
        return Err(AppError::Storage(
            "Requested range length must be greater than zero".to_string(),
        ));
    }

    let length = u64::try_from(length).map_err(|_| {
        AppError::Storage(format!(
            "Requested range length {} does not fit in u64",
            length
        ))
    })?;
    let end_exclusive = offset.checked_add(length).ok_or_else(|| {
        AppError::Storage(format!(
            "Requested range offset {} length {} overflows u64",
            offset, length
        ))
    })?;
    let end_inclusive = end_exclusive - 1;

    Ok(format!("bytes={offset}-{end_inclusive}"))
}

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

    /// Return the storage backend's opaque ETag for `key` if the backend
    /// supports per-object ETags (S3, GCS, Azure). Returns `Ok(None)` when
    /// the backend has no concept of an ETag (filesystem) or when the
    /// object exists but the backend did not surface an ETag header.
    /// Returns an error only on transport/auth failures; a missing object
    /// is reported as `Ok(None)` so callers can distinguish "no ETag to
    /// revalidate against" from "backend is broken".
    ///
    /// Used by the proxy cache fast path (#1051) to detect cache-entry
    /// tampering or backend-side replacement before signing a presigned
    /// URL: we pin the storage ETag at cache-write time into the metadata
    /// sidecar, then re-HEAD on each fast-path hit and compare. A mismatch
    /// forces a fall-through to the slow path which recomputes the SHA-256
    /// and self-heals the cache.
    async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        let _ = key; // Suppress unused warning for default impl
        Ok(None)
    }

    /// Delete content by key
    async fn delete(&self, key: &str) -> Result<()>;

    /// Copy content between keys within the same backend.
    ///
    /// Backends with server-side copy support should override this. The
    /// default routes through `get_stream()` + `put_stream()` so backends that
    /// implement streaming but not native copy do not need to buffer the source
    /// object in memory. Large-object backends must override `put_stream()`;
    /// the default `put_stream()` remains a compatibility fallback for simple
    /// in-memory implementations.
    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let stream = self.get_stream(source).await?;
        self.put_stream(dest, stream).await.map(|_| ())
    }

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

    /// Store content from a file.
    ///
    /// Default implementation opens the file and delegates to `put_stream`,
    /// so backends that override `put_stream` (filesystem, S3, GCS) get
    /// memory-bounded `put_file` for free. The buffer reader uses a
    /// fixed-size chunk (256 KiB) so peak memory stays O(chunk_size)
    /// regardless of file size. This is the path the migration worker
    /// (#1422) uses to upload artifacts that have been spilled to disk,
    /// where loading the whole file (10 GB+ Maven JARs) into memory would
    /// OOM the host.
    async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<()> {
        use tokio::io::BufReader;
        use tokio_util::io::ReaderStream;

        let file = tokio::fs::File::open(path).await?;
        // 256 KiB matches `STREAM_CHUNK_SIZE` in the filesystem backend so the
        // chunk granularity is consistent across read/write paths.
        let reader = BufReader::with_capacity(256 * 1024, file);
        let stream = ReaderStream::with_capacity(reader, 256 * 1024);
        let mapped = futures::StreamExt::map(stream, |r| {
            r.map_err(|e| crate::error::AppError::Storage(format!("Read error: {}", e)))
        });
        self.put_stream(key, Box::pin(mapped)).await.map(|_| ())
    }

    /// Retrieve content as a byte stream instead of loading the full object
    /// into memory. The default implementation wraps `get()` in a single-item
    /// stream.
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let content = self.get(key).await?;
        Ok(Box::pin(futures::stream::once(async { Ok(content) })))
    }

    /// Retrieve a byte range from an object.
    ///
    /// Backends with native random/ranged reads should override this method
    /// so large-object consumers do not have to re-download and discard bytes
    /// for every chunk. The default implementation remains correct for
    /// backends without native ranges by streaming once and collecting only
    /// the requested window.
    async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
        use futures::StreamExt;

        if length == 0 {
            return Ok(Bytes::new());
        }

        let mut stream = self.get_stream(key).await?;
        let mut consumed = 0u64;
        let mut remaining = length;
        let mut out = Vec::with_capacity(length);

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let chunk_len = chunk.len() as u64;
            let chunk_end = consumed.saturating_add(chunk_len);

            if chunk_end <= offset {
                consumed = chunk_end;
                continue;
            }

            let start = offset.saturating_sub(consumed) as usize;
            let available = &chunk[start..];
            let take = available.len().min(remaining);
            out.extend_from_slice(&available[..take]);
            remaining -= take;

            if remaining == 0 {
                break;
            }

            consumed = chunk_end;
        }

        Ok(Bytes::from(out))
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
    async fn test_default_copy_reads_source_and_writes_dest() {
        use std::sync::{Arc, Mutex};

        struct CopyBackend {
            writes: Arc<Mutex<Vec<(String, Bytes)>>>,
        }

        #[async_trait]
        impl StorageBackend for CopyBackend {
            async fn put(&self, key: &str, content: Bytes) -> Result<()> {
                self.writes.lock().unwrap().push((key.to_string(), content));
                Ok(())
            }

            async fn get(&self, key: &str) -> Result<Bytes> {
                assert_eq!(key, "source-key");
                Ok(Bytes::from_static(b"copied bytes"))
            }

            // `copy` routes through get_stream/put_stream only; these are never
            // touched by this test, so fail loudly if that ever changes.
            async fn exists(&self, _key: &str) -> Result<bool> {
                unreachable!("copy default path must not call exists")
            }

            async fn delete(&self, _key: &str) -> Result<()> {
                unreachable!("copy default path must not call delete")
            }
        }

        let writes = Arc::new(Mutex::new(Vec::new()));
        let backend = CopyBackend {
            writes: writes.clone(),
        };

        backend.copy("source-key", "dest-key").await.unwrap();

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "dest-key");
        assert_eq!(writes[0].1, Bytes::from_static(b"copied bytes"));
    }

    #[tokio::test]
    async fn test_default_get_range_slices_streamed_bytes() {
        let backend = TestBackend;

        let range = backend.get_range("any-key", 1, 2).await.unwrap();

        assert_eq!(range, Bytes::from_static(b"es"));
    }

    #[tokio::test]
    async fn test_default_get_range_zero_length() {
        let backend = TestBackend;

        let range = backend.get_range("any-key", 2, 0).await.unwrap();

        assert!(range.is_empty());
    }

    #[test]
    fn test_download_range_header_is_inclusive() {
        // offset 1024, length 4096 -> bytes=1024-5119 (inclusive end).
        assert_eq!(
            download_range_header(1_024, 4_096).unwrap(),
            "bytes=1024-5119"
        );
        assert_eq!(download_range_header(0, 1).unwrap(), "bytes=0-0");
    }

    #[test]
    fn test_download_range_header_rejects_zero_length() {
        let err = download_range_header(0, 0).unwrap_err();
        assert!(
            err.to_string().contains("greater than zero"),
            "error should explain zero length: {err}"
        );
    }

    #[test]
    fn test_download_range_header_rejects_overflow() {
        let err = download_range_header(u64::MAX - 1, 4).unwrap_err();
        assert!(
            err.to_string().contains("overflows u64"),
            "error should explain overflow: {err}"
        );
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

    // -------------------------------------------------------------------
    // PR #1512 review fix: `put_file` default impl must not buffer the
    // whole file into memory. Previously it called
    // `tokio::fs::read(path).await?` which loaded 10 GB Maven artifacts
    // into a single `Bytes` on cloud backends inheriting the default,
    // OOM'ing the host even though the upstream download had been
    // streamed to disk.
    // -------------------------------------------------------------------

    /// Records the maximum single chunk size delivered to `put_stream` so
    /// callers can assert peak memory is bounded to O(chunk_size).
    struct ChunkRecordingBackend {
        max_chunk: std::sync::Mutex<usize>,
        total_bytes: std::sync::Mutex<u64>,
    }

    #[async_trait]
    impl StorageBackend for ChunkRecordingBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }
        // Note: we deliberately do NOT override `put_file`. The whole
        // point of this test is to exercise the trait default and prove
        // it doesn't buffer.
        async fn put_stream(
            &self,
            _key: &str,
            stream: BoxStream<'static, Result<Bytes>>,
        ) -> Result<PutStreamResult> {
            use futures::StreamExt;
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            tokio::pin!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                let len = chunk.len();
                {
                    let mut max = self.max_chunk.lock().unwrap();
                    if len > *max {
                        *max = len;
                    }
                }
                hasher.update(&chunk);
                total += len as u64;
            }
            *self.total_bytes.lock().unwrap() = total;
            Ok(PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total,
            })
        }
    }

    /// Regression test for the #1512 review blocker. A 4 MiB temp file
    /// must be uploaded via `put_file` -> `put_stream` (the new default)
    /// without any single chunk exceeding the 256 KiB streaming size.
    /// Pre-fix, the default `put_file` did `tokio::fs::read(path)` and
    /// passed a single 4 MiB chunk through `put`, scaling linearly with
    /// file size and OOMing on multi-GB artifacts.
    #[tokio::test]
    async fn test_default_put_file_chunks_through_put_stream() {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;

        // Write 4 MiB of pseudo-random bytes to a temp file. We hash the
        // same buffer locally so we can cross-check the streaming digest.
        const FILE_SIZE: usize = 4 * 1024 * 1024;
        const CHUNK_SIZE: usize = 256 * 1024;

        let temp = tempfile::NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();

        // Deterministic non-zero payload so a "all zeroes" mock doesn't
        // hide a bug; LCG is fine here.
        let mut data = Vec::with_capacity(FILE_SIZE);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..FILE_SIZE {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.push((x >> 24) as u8);
        }

        {
            let mut file = tokio::fs::File::create(&temp_path).await.unwrap();
            file.write_all(&data).await.unwrap();
            file.flush().await.unwrap();
        }

        let backend = ChunkRecordingBackend {
            max_chunk: std::sync::Mutex::new(0),
            total_bytes: std::sync::Mutex::new(0),
        };

        backend.put_file("any-key", &temp_path).await.unwrap();

        let max = *backend.max_chunk.lock().unwrap();
        let total = *backend.total_bytes.lock().unwrap();

        // The whole file made it through.
        assert_eq!(total as usize, FILE_SIZE);
        // Critically: no single chunk handed to `put_stream` exceeded the
        // configured streaming chunk size. This is the memory-bound
        // invariant the PR claims; before the fix this would equal
        // FILE_SIZE (the whole body in one `Bytes`).
        assert!(
            max <= CHUNK_SIZE,
            "max chunk {} exceeded streaming chunk size {} -- default put_file is not chunking",
            max,
            CHUNK_SIZE
        );

        // And the streaming digest matches a one-shot hash of the same
        // bytes. This is the chunked-vs-buffered parity guarantee.
        let expected_sha256 = format!("{:x}", Sha256::digest(&data));
        // (no public way to recover the digest from `put_file`'s ()-return,
        // so re-call put_stream over the same data to compare.)
        let stream = Box::pin(futures::stream::iter(
            data.chunks(CHUNK_SIZE)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        )) as BoxStream<'static, Result<Bytes>>;
        let direct = backend.put_stream("any-key", stream).await.unwrap();
        assert_eq!(direct.checksum_sha256, expected_sha256);
    }

    /// Sanity check: when a backend DOES override `put_file` (filesystem
    /// does this for performance), the override wins over the default and
    /// `put_stream` is not invoked. The chunk recorder above would not
    /// observe any traffic in that case.
    #[tokio::test]
    async fn test_put_file_override_skips_put_stream() {
        struct OverridingBackend {
            put_file_called: std::sync::Mutex<bool>,
            put_stream_called: std::sync::Mutex<bool>,
        }

        #[async_trait]
        impl StorageBackend for OverridingBackend {
            // Only put_file/put_stream are relevant to this test; the basic CRUD
            // methods must never be hit on the put_file override path.
            async fn put(&self, _key: &str, _content: Bytes) -> Result<()> {
                unreachable!("put_file override path must not call put")
            }
            async fn get(&self, _key: &str) -> Result<Bytes> {
                unreachable!("put_file override path must not call get")
            }
            async fn exists(&self, _key: &str) -> Result<bool> {
                unreachable!("put_file override path must not call exists")
            }
            async fn delete(&self, _key: &str) -> Result<()> {
                unreachable!("put_file override path must not call delete")
            }
            async fn put_file(&self, _key: &str, _path: &std::path::Path) -> Result<()> {
                *self.put_file_called.lock().unwrap() = true;
                Ok(())
            }
            async fn put_stream(
                &self,
                _key: &str,
                _stream: BoxStream<'static, Result<Bytes>>,
            ) -> Result<PutStreamResult> {
                *self.put_stream_called.lock().unwrap() = true;
                Ok(PutStreamResult {
                    checksum_sha256: String::new(),
                    bytes_written: 0,
                })
            }
        }

        let backend = OverridingBackend {
            put_file_called: std::sync::Mutex::new(false),
            put_stream_called: std::sync::Mutex::new(false),
        };
        let temp = tempfile::NamedTempFile::new().unwrap();
        backend.put_file("k", temp.path()).await.unwrap();

        assert!(*backend.put_file_called.lock().unwrap());
        assert!(!*backend.put_stream_called.lock().unwrap());
    }
}
