//! Filesystem storage backend.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use super::{PutStreamResult, StorageBackend};
use crate::error::{AppError, Result};

/// Chunk size for streaming reads (256 KB).
const STREAM_CHUNK_SIZE: usize = 256 * 1024;

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

    /// Get full path for a key (using first 2 chars as subdirectory for distribution).
    ///
    /// Keys are sanitized to prevent path traversal: only normal path components
    /// are kept, stripping `..`, `/`, and other special components.
    fn key_to_path(&self, key: &str) -> PathBuf {
        let sanitized: PathBuf = std::path::Path::new(key)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        let sanitized_str = sanitized.to_string_lossy();
        let prefix = &sanitized_str[..2.min(sanitized_str.len())];
        self.base_path.join(prefix).join(&sanitized)
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

    async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<()> {
        let dest = self.key_to_path(key);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::copy(path, &dest)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to copy file to {}: {}", key, e)))?;
        Ok(())
    }

    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let path = self.key_to_path(key);
        let file = fs::File::open(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to open {}: {}", key, e)))?;

        let reader = BufReader::new(file);
        let stream = ReaderStream::with_capacity(reader, STREAM_CHUNK_SIZE);

        // Map tokio io errors to our Result type
        let mapped = stream
            .map(|result| result.map_err(|e| AppError::Storage(format!("Read error: {}", e))));

        Ok(Box::pin(mapped))
    }

    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        let dest = self.key_to_path(key);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write to a temp file in the same directory so rename is atomic
        // (same filesystem guarantees atomic rename on POSIX).
        let mut temp_name = dest.as_os_str().to_os_string();
        temp_name.push(format!(".tmp.{}", Uuid::new_v4()));
        let temp_path = PathBuf::from(temp_name);
        let mut file = fs::File::create(&temp_path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to create temp file: {}", e)))?;

        let mut hasher = Sha256::new();
        let mut total: u64 = 0;

        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(data) => {
                    hasher.update(&data);
                    total += data.len() as u64;
                    if let Err(e) = file.write_all(&data).await {
                        let _ = fs::remove_file(&temp_path).await;
                        return Err(AppError::Storage(format!("Write error: {}", e)));
                    }
                }
                Err(e) => {
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(e);
                }
            }
        }

        // Flush and sync to disk before renaming
        if let Err(e) = file.sync_all().await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::Storage(format!("Sync error: {}", e)));
        }
        drop(file);

        // Atomic rename
        if let Err(e) = fs::rename(&temp_path, &dest).await {
            // Best-effort cleanup; the temp file may already be gone
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::Storage(format!("Rename error: {}", e)));
        }

        Ok(PutStreamResult {
            checksum_sha256: format!("{:x}", hasher.finalize()),
            bytes_written: total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_filesystem_storage() {
        let storage = FilesystemStorage::new("/tmp/test-storage");
        assert_eq!(storage.base_path, PathBuf::from("/tmp/test-storage"));
    }

    #[test]
    fn test_new_from_pathbuf() {
        let path = PathBuf::from("/var/data/artifacts");
        let storage = FilesystemStorage::new(path.clone());
        assert_eq!(storage.base_path, path);
    }

    #[test]
    fn test_key_to_path_normal_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("abcdef1234567890");
        // First 2 chars = "ab", used as subdirectory
        assert_eq!(path, PathBuf::from("/data/ab/abcdef1234567890"));
    }

    #[test]
    fn test_key_to_path_sha256_hash() {
        let storage = FilesystemStorage::new("/storage");
        let key = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let path = storage.key_to_path(key);
        assert_eq!(path, PathBuf::from(format!("/storage/91/{}", key)));
    }

    #[test]
    fn test_key_to_path_short_key() {
        let storage = FilesystemStorage::new("/data");
        // Key shorter than 2 chars: uses entire key as prefix
        let path = storage.key_to_path("a");
        assert_eq!(path, PathBuf::from("/data/a/a"));
    }

    #[test]
    fn test_key_to_path_two_char_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("ab");
        assert_eq!(path, PathBuf::from("/data/ab/ab"));
    }

    #[test]
    fn test_key_to_path_distributes_across_dirs() {
        let storage = FilesystemStorage::new("/data");
        let path1 = storage.key_to_path("aa1234");
        let path2 = storage.key_to_path("bb5678");
        // Different prefix subdirectories
        assert_ne!(path1.parent().unwrap(), path2.parent().unwrap());
    }

    #[test]
    fn test_key_to_path_same_prefix_same_dir() {
        let storage = FilesystemStorage::new("/data");
        let path1 = storage.key_to_path("ab1111");
        let path2 = storage.key_to_path("ab2222");
        // Same prefix = same subdirectory
        assert_eq!(path1.parent().unwrap(), path2.parent().unwrap());
    }

    #[test]
    fn test_key_to_path_traversal_dot_dot() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("../../etc/passwd");
        // "../" components are stripped; only "etc" and "passwd" remain
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/et/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_absolute_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("/etc/passwd");
        // Leading "/" (RootDir component) is stripped; result stays inside base
        assert!(path.starts_with("/data"));
        assert_eq!(path, PathBuf::from("/data/et/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_mixed_traversal() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("maven/../../../etc/passwd");
        // ".." components stripped, only Normal components kept
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/ma/maven/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_empty_key() {
        let storage = FilesystemStorage::new("/data");
        // Empty key should not panic
        let path = storage.key_to_path("");
        // Sanitized string is empty, prefix is empty, result is base_path joined with empties
        assert!(path.starts_with("/data"));
    }

    #[test]
    fn test_key_to_path_only_dots() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("../..");
        // All components are ParentDir, all stripped
        assert!(path.starts_with("/data"));
    }

    #[test]
    fn test_key_to_path_current_dir_traversal() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("./secret/../passwords");
        // "." and ".." are stripped, only "secret" and "passwords" remain
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/se/secret/passwords"));
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let content = Bytes::from_static(b"hello world");

        storage.put(key, content.clone()).await.unwrap();

        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn test_exists() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        assert!(!storage.exists(key).await.unwrap());

        storage.put(key, Bytes::from_static(b"data")).await.unwrap();
        assert!(storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        storage.put(key, Bytes::from_static(b"data")).await.unwrap();
        assert!(storage.exists(key).await.unwrap());

        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let result = storage.get("nonexistent-key1234").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let result = storage.delete("nonexistent-key1234").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_overwrites_existing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        storage
            .put(key, Bytes::from_static(b"original"))
            .await
            .unwrap();
        storage
            .put(key, Bytes::from_static(b"updated"))
            .await
            .unwrap();

        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(retrieved, Bytes::from_static(b"updated"));
    }

    // --- get_stream tests ---

    #[tokio::test]
    async fn test_get_stream_returns_correct_content() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let content = Bytes::from_static(b"streaming content here");
        storage.put(key, content.clone()).await.unwrap();

        let mut stream = storage.get_stream(key).await.unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, content.as_ref());
    }

    #[tokio::test]
    async fn test_get_stream_large_file_produces_multiple_chunks() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        // Create content larger than STREAM_CHUNK_SIZE (256 KB)
        let size = STREAM_CHUNK_SIZE * 3 + 100;
        let content = Bytes::from(vec![0xABu8; size]);
        storage.put(key, content.clone()).await.unwrap();

        let mut stream = storage.get_stream(key).await.unwrap();
        let mut chunk_count = 0u64;
        let mut total_bytes = 0usize;
        while let Some(chunk) = stream.next().await {
            let data = chunk.unwrap();
            total_bytes += data.len();
            chunk_count += 1;
        }
        assert_eq!(total_bytes, size);
        // Multiple chunks expected for a file > STREAM_CHUNK_SIZE
        assert!(
            chunk_count > 1,
            "expected multiple chunks, got {}",
            chunk_count
        );
    }

    #[tokio::test]
    async fn test_get_stream_nonexistent_key_returns_error() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let result = storage.get_stream("nonexistent-key1234").await;
        assert!(result.is_err());
    }

    // --- put_stream tests ---

    #[tokio::test]
    async fn test_put_stream_writes_correct_content() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"chunk1-")),
            Ok(Bytes::from_static(b"chunk2-")),
            Ok(Bytes::from_static(b"chunk3")),
        ];
        let stream = Box::pin(futures::stream::iter(chunks)) as BoxStream<'static, Result<Bytes>>;

        let result = storage.put_stream(key, stream).await.unwrap();
        assert_eq!(result.bytes_written, 20);

        // Verify content was written correctly
        let retrieved = storage.get(key).await.unwrap();
        assert_eq!(retrieved.as_ref(), b"chunk1-chunk2-chunk3");
    }

    #[tokio::test]
    async fn test_put_stream_computes_correct_sha256() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let data = Bytes::from_static(b"hello world");
        let stream = Box::pin(futures::stream::once(async { Ok(data) }))
            as BoxStream<'static, Result<Bytes>>;

        let result = storage.put_stream(key, stream).await.unwrap();
        assert_eq!(
            result.checksum_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_put_stream_atomic_rename_no_temp_file_left() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let data = Bytes::from_static(b"test data");
        let stream = Box::pin(futures::stream::once(async { Ok(data) }))
            as BoxStream<'static, Result<Bytes>>;

        storage.put_stream(key, stream).await.unwrap();

        // Walk the storage directory and verify no .tmp files remain
        let mut entries = fs::read_dir(temp_dir.path()).await.unwrap();
        let mut tmp_files = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            collect_tmp_files(entry.path(), &mut tmp_files).await;
        }
        assert!(
            tmp_files.is_empty(),
            "temp files should be cleaned up after put_stream, found: {:?}",
            tmp_files
        );
    }

    /// Recursively collect .tmp files under a path.
    async fn collect_tmp_files(path: PathBuf, out: &mut Vec<PathBuf>) {
        if path.is_dir() {
            let mut entries = fs::read_dir(&path).await.unwrap();
            while let Some(entry) = entries.next_entry().await.unwrap() {
                Box::pin(collect_tmp_files(entry.path(), out)).await;
            }
        } else if path
            .file_name()
            .map(|n| n.to_string_lossy().contains(".tmp."))
            .unwrap_or(false)
        {
            out.push(path);
        }
    }

    #[tokio::test]
    async fn test_put_stream_cleans_temp_on_stream_error() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"good data")),
            Err(AppError::Storage("simulated stream error".into())),
        ];
        let stream = Box::pin(futures::stream::iter(chunks)) as BoxStream<'static, Result<Bytes>>;

        let result = storage.put_stream(key, stream).await;
        assert!(result.is_err());

        // Verify no temp files or final files remain
        let mut tmp_files = Vec::new();
        let mut entries = fs::read_dir(temp_dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            collect_tmp_files(entry.path(), &mut tmp_files).await;
        }
        assert!(
            tmp_files.is_empty(),
            "temp files should be cleaned up on error, found: {:?}",
            tmp_files
        );

        // The final file should not exist either
        assert!(!storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_put_stream_empty_stream() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let stream = Box::pin(futures::stream::empty()) as BoxStream<'static, Result<Bytes>>;

        let result = storage.put_stream(key, stream).await.unwrap();
        assert_eq!(result.bytes_written, 0);
        // SHA-256 of empty input
        assert_eq!(
            result.checksum_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Verify the file exists and is empty
        let content = storage.get(key).await.unwrap();
        assert!(content.is_empty());
    }

    #[tokio::test]
    async fn test_put_stream_roundtrip_with_get_stream() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "abcdef1234567890";
        let original = b"roundtrip content for streaming test";
        let data = Bytes::from_static(original);
        let stream = Box::pin(futures::stream::once(async { Ok(data) }))
            as BoxStream<'static, Result<Bytes>>;

        let put_result = storage.put_stream(key, stream).await.unwrap();
        assert_eq!(put_result.bytes_written, original.len() as u64);

        // Read back via get_stream and verify
        let mut read_stream = storage.get_stream(key).await.unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = read_stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, original);
    }
}
