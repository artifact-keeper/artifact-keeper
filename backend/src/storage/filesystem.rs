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
}
