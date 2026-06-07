//! Filesystem storage backend.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use super::{PutStreamResult, StorageBackend};
use crate::error::{AppError, Result};

/// Chunk size for streaming reads (256 KB).
const STREAM_CHUNK_SIZE: usize = 256 * 1024;

#[cfg(unix)]
async fn sync_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to open parent directory {} for sync: {}",
                parent.display(),
                e
            ))
        })?;
        dir.sync_all().await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to sync parent directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn temp_path_for_dest(dest: &Path, id: Uuid) -> Result<PathBuf> {
    let parent = dest.parent().ok_or_else(|| {
        AppError::Storage(format!(
            "Destination path {} has no parent directory",
            dest.display()
        ))
    })?;
    Ok(parent.join(format!(".tmp.{id}")))
}

async fn remove_temp_file_best_effort(path: &Path, context: &'static str) {
    if let Err(e) = fs::remove_file(path).await {
        tracing::warn!(
            path = %path.display(),
            context,
            error = %e,
            "Failed to remove filesystem storage temp file"
        );
    }
}

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

    /// Get full path for a key.
    ///
    /// Keys are sanitized to prevent path traversal: only normal path components
    /// are kept, stripping `..`, `/`, and other special components.
    ///
    /// Two layouts are supported, selected by whether the key already encodes
    /// a directory hierarchy:
    ///
    /// * **Hierarchical keys** (containing `/`, e.g. `proxy-cache/repo/path/__content__`,
    ///   `maven/org/example/.../file.jar`): written under `base_path` verbatim.
    ///   The key's own path segments provide directory distribution, and adding a
    ///   2-char shard prefix on top of that produced the bug behind #1073, where
    ///   `put_stream` (via `StorageService::FilesystemBackend`) and `get` (via this
    ///   backend) ended up writing to and reading from different directories for
    ///   the same proxy-cache key.
    /// * **Flat keys** (no `/`, e.g. a bare sha256 hash `916f0027...`): written
    ///   under a 2-char prefix subdirectory so a single directory does not accumulate
    ///   millions of entries. This is the original behaviour and is preserved for
    ///   the legacy hash-key callers.
    fn key_to_path(&self, key: &str) -> PathBuf {
        let sanitized: PathBuf = std::path::Path::new(key)
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        let sanitized_str = sanitized.to_string_lossy();

        // Hierarchical keys (the key contains its own `/` separators) already
        // distribute themselves across directories. Skip the shard prefix so
        // path-style keys land where every other call site expects them.
        // See #1073: proxy-cache writes went to `<base>/proxy-cache/...` while
        // reads looked under `<base>/pr/proxy-cache/...`.
        if sanitized.components().count() > 1 {
            return self.base_path.join(&sanitized);
        }

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

        // Write to a unique temp file in the same directory, then atomically
        // rename into place (same filesystem => atomic rename on POSIX). The
        // previous implementation wrote directly to `path` via
        // `File::create` + `write_all`, which is NOT atomic: under a
        // cold-cache proxy stampede, N concurrent writers target the SAME
        // cache file and race on truncate/write, and a reader interleaving
        // with a sibling writer's truncate can observe a torn or
        // transiently-missing file. Writing to a per-writer temp path and
        // renaming gives each writer an isolated file and makes the visible
        // `path` flip atomically from old bytes to new bytes, never to a
        // partial/empty state. This closes the B6 stampede 502 leak at the
        // storage layer (the proxy-service call site additionally treats a
        // cache-write failure as best-effort).
        let mut temp_name = path.as_os_str().to_os_string();
        temp_name.push(format!(".tmp.{}", Uuid::new_v4()));
        let temp_path = PathBuf::from(temp_name);

        let mut file = fs::File::create(&temp_path).await?;
        if let Err(e) = file.write_all(&content).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e.into());
        }
        if let Err(e) = file.sync_all().await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e.into());
        }
        drop(file);

        if let Err(e) = fs::rename(&temp_path, &path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(e.into());
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let path = self.key_to_path(key);
        let content = fs::read(&path).await.map_err(|e| {
            // #1016: missing keys MUST map to AppError::NotFound so callers
            // that branch on cache-miss (proxy_service::get_cached_artifact,
            // OCI blob lookups, etc.) treat ENOENT as "not present" rather
            // than as a 500-class storage failure. The S3 backend already
            // distinguishes NotFound; the filesystem backend was
            // historically lumping every io::Error into AppError::Storage,
            // which surfaced as "Internal server error / os error 2" on
            // cached-package re-downloads.
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(format!("Failed to read {}: {}", key, e))
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
        fs::remove_file(&path).await.map_err(|e| {
            // Same #1016 contract for delete: ENOENT → NotFound so callers
            // (artifact deletion, cache eviction) can handle "already gone"
            // as idempotent rather than as a hard failure.
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(format!("Failed to delete {}: {}", key, e))
            }
        })?;
        Ok(())
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_path = self.key_to_path(source);
        let dest_path = self.key_to_path(dest);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let temp_path = temp_path_for_dest(&dest_path, Uuid::new_v4())?;

        if let Err(e) = fs::copy(&source_path, &temp_path).await {
            remove_temp_file_best_effort(&temp_path, "filesystem copy failed").await;
            return Err(if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", source))
            } else {
                AppError::Storage(format!("Failed to copy {} to {}: {}", source, dest, e))
            });
        }

        let file = match fs::OpenOptions::new().read(true).open(&temp_path).await {
            Ok(file) => file,
            Err(e) => {
                remove_temp_file_best_effort(&temp_path, "filesystem copy temp open failed").await;
                return Err(AppError::Storage(format!(
                    "Failed to open copied temp file for {}: {}",
                    dest, e
                )));
            }
        };
        if let Err(e) = file.sync_all().await {
            remove_temp_file_best_effort(&temp_path, "filesystem copy temp sync failed").await;
            return Err(AppError::Storage(format!(
                "Failed to sync copied temp file for {}: {}",
                dest, e
            )));
        }
        drop(file);

        if let Err(e) = fs::rename(&temp_path, &dest_path).await {
            remove_temp_file_best_effort(&temp_path, "filesystem copy temp promote failed").await;
            return Err(AppError::Storage(format!(
                "Failed to promote copied temp file to {}: {}",
                dest, e
            )));
        }
        sync_parent_directory(&dest_path).await?;
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
        let file = fs::File::open(&path).await.map_err(|e| {
            // #1016: a missing key MUST map to AppError::NotFound so callers
            // (e.g. maven_proxy sibling fall-through, local hydration retry)
            // see a 404, not a 500. Mirror the buffered `get`/`get_range`
            // mapping; anything that is not a NotFound stays a Storage error.
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(format!("Failed to open {}: {}", key, e))
            }
        })?;

        let reader = BufReader::new(file);
        let stream = ReaderStream::with_capacity(reader, STREAM_CHUNK_SIZE);

        // Map tokio io errors to our Result type
        let mapped = stream
            .map(|result| result.map_err(|e| AppError::Storage(format!("Read error: {}", e))));

        Ok(Box::pin(mapped))
    }

    async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let path = self.key_to_path(key);
        let mut file = fs::File::open(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(format!("Failed to open {}: {}", key, e))
            }
        })?;

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| AppError::Storage(format!("Failed to seek {}: {}", key, e)))?;

        let mut remaining = length;
        let mut out = Vec::with_capacity(length);

        while remaining > 0 {
            let mut buf = vec![0u8; remaining.min(STREAM_CHUNK_SIZE)];
            let read = file
                .read(&mut buf)
                .await
                .map_err(|e| AppError::Storage(format!("Failed to read {}: {}", key, e)))?;
            if read == 0 {
                break;
            }
            buf.truncate(read);
            out.extend_from_slice(&buf);
            remaining -= read;
        }

        Ok(Bytes::from(out))
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
        let temp_path = temp_path_for_dest(&dest, Uuid::new_v4())?;
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
                        remove_temp_file_best_effort(&temp_path, "filesystem stream write failed")
                            .await;
                        return Err(AppError::Storage(format!("Write error: {}", e)));
                    }
                }
                Err(e) => {
                    remove_temp_file_best_effort(&temp_path, "filesystem stream read failed").await;
                    return Err(e);
                }
            }
        }

        // Flush and sync to disk before renaming
        if let Err(e) = file.sync_all().await {
            remove_temp_file_best_effort(&temp_path, "filesystem stream sync failed").await;
            return Err(AppError::Storage(format!("Sync error: {}", e)));
        }
        drop(file);

        // Atomic rename
        if let Err(e) = fs::rename(&temp_path, &dest).await {
            remove_temp_file_best_effort(&temp_path, "filesystem stream promote failed").await;
            return Err(AppError::Storage(format!("Rename error: {}", e)));
        }
        sync_parent_directory(&dest).await?;

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
    fn test_temp_path_for_dest_uses_short_sibling_name() {
        let dest = PathBuf::from(format!("/data/aa/{}", "a".repeat(240)));
        let temp = temp_path_for_dest(&dest, Uuid::nil()).expect("temp path");

        assert_eq!(temp.parent(), dest.parent());
        let file_name = temp
            .file_name()
            .and_then(|name| name.to_str())
            .expect("temp file name");
        assert_eq!(file_name, ".tmp.00000000-0000-0000-0000-000000000000");
        assert!(file_name.len() < 64);
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
        // "../" components are stripped; only "etc" and "passwd" remain.
        // Multi-segment hierarchical key, so no shard prefix is added.
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_absolute_key() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("/etc/passwd");
        // Leading "/" (RootDir component) is stripped; result stays inside base.
        // Multi-segment hierarchical key, so no shard prefix is added.
        assert!(path.starts_with("/data"));
        assert_eq!(path, PathBuf::from("/data/etc/passwd"));
    }

    #[test]
    fn test_key_to_path_mixed_traversal() {
        let storage = FilesystemStorage::new("/data");
        let path = storage.key_to_path("maven/../../../etc/passwd");
        // ".." components stripped, only Normal components kept.
        // Multi-segment hierarchical key, so no shard prefix is added.
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/maven/etc/passwd"));
    }

    // #1073: proxy-cache keys must not be sharded. They already carry a
    // hierarchical layout (`proxy-cache/<repo>/<path>/__content__`) that the
    // proxy_service writer in `services::storage_service::FilesystemBackend`
    // honors verbatim. Sharding under the first 2 chars made `get` look in
    // `<base>/pr/proxy-cache/...` while the file was at `<base>/proxy-cache/...`.
    #[test]
    fn test_key_to_path_proxy_cache_key_not_sharded() {
        let storage = FilesystemStorage::new("/data/storage");
        let key = "proxy-cache/docker-hub-remote/v2/library/nginx/manifests/latest/__content__";
        let path = storage.key_to_path(key);
        assert_eq!(
            path,
            PathBuf::from(
                "/data/storage/proxy-cache/docker-hub-remote/v2/library/nginx/manifests/latest/__content__"
            )
        );
    }

    #[test]
    fn test_key_to_path_proxy_cache_meta_not_sharded() {
        let storage = FilesystemStorage::new("/data/storage");
        let key = "proxy-cache/pypi-remote/simple/flask/__cache_meta__.json";
        let path = storage.key_to_path(key);
        assert_eq!(
            path,
            PathBuf::from("/data/storage/proxy-cache/pypi-remote/simple/flask/__cache_meta__.json")
        );
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
        // "." and ".." are stripped, only "secret" and "passwords" remain.
        // Multi-segment hierarchical key, so no shard prefix is added.
        assert!(path.starts_with("/data"));
        assert!(!path.to_string_lossy().contains(".."));
        assert_eq!(path, PathBuf::from("/data/secret/passwords"));
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
    async fn test_get_range_reads_requested_window() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "range-key";
        storage
            .put(key, Bytes::from_static(b"abcdefghijklmnopqrstuvwxyz"))
            .await
            .unwrap();

        let range = storage.get_range(key, 5, 8).await.unwrap();

        assert_eq!(range, Bytes::from_static(b"fghijklm"));
    }

    #[tokio::test]
    async fn test_get_range_past_eof_returns_empty() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "short-range-key";
        storage.put(key, Bytes::from_static(b"abc")).await.unwrap();

        let range = storage.get_range(key, 10, 4).await.unwrap();

        assert!(range.is_empty());
    }

    #[tokio::test]
    async fn test_get_range_zero_length_returns_empty_without_opening() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        // Zero length short-circuits before touching the filesystem, so even a
        // missing key returns empty rather than NotFound.
        let range = storage.get_range("never-written", 0, 0).await.unwrap();

        assert!(range.is_empty());
    }

    #[tokio::test]
    async fn test_get_range_missing_key_returns_not_found() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let err = storage.get_range("does-not-exist", 0, 4).await.unwrap_err();

        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    /// B6 (stampede 502 leak, storage half): `put` writes via a temp file +
    /// atomic rename so concurrent writers to the SAME key never observe a
    /// torn / transiently-missing file. Before the fix, `put` did
    /// `File::create(&dest) + write_all`, which truncated `dest` in place and
    /// let a reader interleave with a sibling writer's truncate. This test
    /// fires many concurrent writers + readers at one key and asserts every
    /// `put` succeeds, no `.tmp.` files leak, and the final read returns a
    /// complete (non-empty) body.
    #[tokio::test]
    async fn test_concurrent_put_same_key_is_atomic() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = std::sync::Arc::new(FilesystemStorage::new(temp_dir.path()));
        let key = "proxy-cache/stampede-repo/simple/pkg/__content__";
        let content = Bytes::from(vec![b'x'; 4096]);

        let mut handles = Vec::new();
        for _ in 0..24 {
            let s = storage.clone();
            let c = content.clone();
            handles.push(tokio::spawn(async move {
                // Each writer writes the same body; the read may race a
                // concurrent rename but must never see a partial file.
                s.put(key, c).await
            }));
        }
        for h in handles {
            // Every put must succeed (no ENOENT from the create_dir_all /
            // File::create race the old non-atomic path exhibited).
            h.await.unwrap().expect("concurrent put must not fail");
        }

        let got = storage.get(key).await.expect("final read must succeed");
        assert_eq!(got.len(), content.len(), "body must be complete, not torn");

        // No leftover temp files.
        let mut leftovers = Vec::new();
        let mut entries = fs::read_dir(temp_dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            collect_tmp_files(entry.path(), &mut leftovers).await;
        }
        assert!(
            leftovers.is_empty(),
            "atomic put must not leave .tmp. files: {leftovers:?}"
        );
    }

    // #1073 regression: a proxy-cache key written by the un-sharded writer
    // (`services::storage_service::FilesystemBackend`) must be readable by
    // this backend's `get`. Before the fix, this backend sharded the key
    // under the first 2 chars and looked in `<base>/pr/proxy-cache/...`,
    // missing the file that lived at `<base>/proxy-cache/...`.
    #[tokio::test]
    async fn test_proxy_cache_key_readable_at_unsharded_path() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        // Simulate what the proxy writer puts on disk: file at
        // `<base>/proxy-cache/<repo>/<path>/__content__` with no shard prefix.
        let key = "proxy-cache/docker-hub-remote/v2/library/nginx/manifests/latest/__content__";
        let on_disk = temp_dir
            .path()
            .join("proxy-cache/docker-hub-remote/v2/library/nginx/manifests/latest/__content__");
        tokio::fs::create_dir_all(on_disk.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&on_disk, b"manifest body").await.unwrap();

        // Reader path must resolve to the same on-disk location.
        let bytes = storage.get(key).await.expect("get must find file");
        assert_eq!(bytes.as_ref(), b"manifest body");
    }

    // #1073 regression: roundtrip via this backend's own put/get for a
    // proxy-cache key. With sharding still enabled this previously wrote to
    // `<base>/pr/proxy-cache/...` (matching the get path), but the bug was
    // that the *writer* in `services::storage_service::FilesystemBackend`
    // didn't shard. Today both paths land at `<base>/proxy-cache/...`.
    #[tokio::test]
    async fn test_proxy_cache_key_roundtrip_unsharded() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        let key = "proxy-cache/pypi-remote/simple/flask/__content__";
        storage
            .put(key, Bytes::from_static(b"index html"))
            .await
            .unwrap();

        let expected_path = temp_dir
            .path()
            .join("proxy-cache/pypi-remote/simple/flask/__content__");
        assert!(
            expected_path.exists(),
            "proxy-cache key must land at unsharded path; expected {} to exist",
            expected_path.display()
        );

        let bytes = storage.get(key).await.unwrap();
        assert_eq!(bytes.as_ref(), b"index html");
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
    async fn test_copy_copies_content_to_destination_key() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        storage
            .put("source/object", Bytes::from_static(b"copy me"))
            .await
            .unwrap();

        storage
            .copy("source/object", "dest/nested/object")
            .await
            .unwrap();

        assert_eq!(
            storage.get("source/object").await.unwrap(),
            Bytes::from_static(b"copy me")
        );
        assert_eq!(
            storage.get("dest/nested/object").await.unwrap(),
            Bytes::from_static(b"copy me")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_copy_replaces_existing_destination_by_rename() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        storage
            .put("source/object", Bytes::from_static(b"new content"))
            .await
            .unwrap();
        storage
            .put("dest/object", Bytes::from_static(b"old content"))
            .await
            .unwrap();
        let dest_path = storage.key_to_path("dest/object");
        let before_ino = tokio::fs::metadata(&dest_path).await.unwrap().ino();

        storage.copy("source/object", "dest/object").await.unwrap();

        let after_ino = tokio::fs::metadata(&dest_path).await.unwrap().ino();
        assert_ne!(
	            before_ino, after_ino,
	            "copy should replace the destination with a temp-file rename instead of rewriting it in place"
	        );
        assert_eq!(
            storage.get("dest/object").await.unwrap(),
            Bytes::from_static(b"new content")
        );
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

    /// #1016 contract (streaming half): a missing key passed to `get_stream`
    /// MUST surface as `AppError::NotFound`, exactly like the buffered `get`
    /// and `get_range`. Callers such as `maven_proxy.rs` sibling fall-through
    /// and the local hydration retry distinguish NotFound (→ 404 / coordinated
    /// retry) from a real I/O error (→ 500); lumping a missing file into
    /// `AppError::Storage` would turn a legitimate 404 into a 500. This test
    /// guards the regression introduced when the local download path migrated
    /// to streaming (PR #1393 / #1608 download invariant).
    #[tokio::test]
    async fn test_get_stream_missing_key_returns_not_found() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = FilesystemStorage::new(temp_dir.path());

        // The Ok arm holds a BoxStream (not Debug), so match rather than
        // `unwrap_err` to extract the error.
        let err = match storage.get_stream("does-not-exist-stream").await {
            Ok(_) => panic!("expected an error for a missing key"),
            Err(e) => e,
        };

        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound for a missing key, got {err:?}"
        );
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

    // -----------------------------------------------------------------------
    // #1016 / #1089 regression tests
    //
    // The filesystem backend previously mapped every io::Error from
    // `fs::read` and `fs::remove_file` into `AppError::Storage`, including
    // `ErrorKind::NotFound` (ENOENT / "os error 2"). Callers that branched
    // on `AppError::NotFound` for cache-miss handling (notably
    // `proxy_service::get_cached_artifact`) would never match, so a
    // missing proxy cache key surfaced as a 500 with "os error 2" rather
    // than as a cache miss that re-fetched from upstream. The S3 backend
    // had the right behaviour for years; the filesystem one drifted.
    // -----------------------------------------------------------------------

    use tempfile::TempDir;

    #[tokio::test]
    async fn test_get_missing_key_returns_not_found_not_storage_error() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path());
        let err = storage.get("does-not-exist-xyz").await.unwrap_err();
        match err {
            AppError::NotFound(_) => {}
            other => panic!(
                "missing key must map to AppError::NotFound (closes #1016 / \
                 #1089); got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_get_missing_key_message_mentions_key() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path());
        let key = "proxy-cache/debian/pool/main/p/php/php_7.4.deb/__content__";
        let err = storage.get(key).await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains(key),
            "NotFound error must include the missing key for log correlation; got {:?}",
            msg
        );
    }

    #[tokio::test]
    async fn test_delete_missing_key_returns_not_found_not_storage_error() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path());
        let err = storage.delete("never-existed").await.unwrap_err();
        match err {
            AppError::NotFound(_) => {}
            other => panic!(
                "delete of missing key must map to AppError::NotFound so \
                 cache eviction can treat 'already gone' as idempotent; \
                 got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_get_existing_key_round_trips() {
        // Sanity / non-regression for the happy path of the modified
        // map_err closure. A successful read must still return Ok(Bytes).
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path());
        storage
            .put("existing-key", Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let bytes = storage.get("existing-key").await.unwrap();
        assert_eq!(bytes, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn test_get_then_delete_then_get_yields_not_found() {
        // Full lifecycle: a put + get works, delete succeeds, second
        // get returns NotFound. This is the exact sequence
        // proxy_service::get_cached_artifact relies on to treat a
        // cache-miss after an eviction as a real miss rather than a
        // 500-class storage failure.
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path());
        storage
            .put("lifecycle-key", Bytes::from_static(b"data"))
            .await
            .unwrap();
        assert_eq!(
            storage.get("lifecycle-key").await.unwrap(),
            Bytes::from_static(b"data")
        );
        storage.delete("lifecycle-key").await.unwrap();
        match storage.get("lifecycle-key").await.unwrap_err() {
            AppError::NotFound(_) => {}
            other => panic!("post-delete get must be NotFound, got {:?}", other),
        }
    }
}
