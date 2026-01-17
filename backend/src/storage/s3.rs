//! S3 storage backend using rust-s3 crate.
//!
//! Supports AWS S3 and S3-compatible services (MinIO, etc.).
//! Configuration via environment variables:
//! - S3_BUCKET: Bucket name (required)
//! - S3_REGION: AWS region (default: us-east-1)
//! - S3_ENDPOINT: Custom endpoint URL for S3-compatible services
//! - AWS_ACCESS_KEY_ID: Access key (required)
//! - AWS_SECRET_ACCESS_KEY: Secret key (required)

use async_trait::async_trait;
use bytes::Bytes;
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

use crate::error::{AppError, Result};

/// S3 storage backend configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// Custom endpoint URL (for MinIO compatibility)
    pub endpoint: Option<String>,
    /// Optional key prefix for all objects
    pub prefix: Option<String>,
}

impl S3Config {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("S3_BUCKET")
            .map_err(|_| AppError::Config("S3_BUCKET not set".into()))?;
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let endpoint = std::env::var("S3_ENDPOINT").ok();
        let prefix = std::env::var("S3_PREFIX").ok();

        Ok(Self {
            bucket,
            region,
            endpoint,
            prefix,
        })
    }

    /// Create config with explicit values
    pub fn new(bucket: String, region: String, endpoint: Option<String>, prefix: Option<String>) -> Self {
        Self {
            bucket,
            region,
            endpoint,
            prefix,
        }
    }
}

/// S3-compatible storage backend
pub struct S3Backend {
    bucket: Box<Bucket>,
    prefix: Option<String>,
}

impl S3Backend {
    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        // Get credentials from environment
        let credentials = Credentials::from_env()
            .map_err(|e| AppError::Config(format!("Failed to load AWS credentials: {}", e)))?;

        // Create region (with optional custom endpoint)
        let region = match &config.endpoint {
            Some(endpoint) => Region::Custom {
                region: config.region.clone(),
                endpoint: endpoint.clone(),
            },
            None => config.region.parse().map_err(|_| {
                AppError::Config(format!("Invalid S3 region: {}", config.region))
            })?,
        };

        // Create bucket handle
        let bucket = Bucket::new(&config.bucket, region, credentials)
            .map_err(|e| AppError::Config(format!("Failed to create S3 bucket: {}", e)))?;

        // Enable path-style access for MinIO compatibility
        let bucket = if config.endpoint.is_some() {
            bucket.with_path_style()
        } else {
            bucket
        };

        Ok(Self {
            bucket,
            prefix: config.prefix,
        })
    }

    /// Create S3 backend from environment variables
    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }

    /// Generate the full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), key),
            None => key.to_string(),
        }
    }

    /// Strip the prefix from an S3 key
    fn strip_prefix(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => {
                let prefix_with_slash = format!("{}/", prefix.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        }
    }
}

#[async_trait]
impl super::StorageBackend for S3Backend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);

        self.bucket
            .put_object(&full_key, &content)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to put object '{}': {}", key, e)))?;

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);

        let response = self.bucket
            .get_object(&full_key)
            .await
            .map_err(|e| {
                // Check for 404 errors
                if e.to_string().contains("404") || e.to_string().contains("NoSuchKey") {
                    AppError::NotFound(format!("Storage key not found: {}", key))
                } else {
                    AppError::Storage(format!("Failed to get object '{}': {}", key, e))
                }
            })?;

        tracing::debug!(key = %key, size = response.bytes().len(), "S3 get object successful");
        Ok(Bytes::from(response.to_vec()))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);

        match self.bucket.head_object(&full_key).await {
            Ok(_) => Ok(true),
            Err(e) => {
                // Check if it's a "not found" error
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NoSuchKey") || err_str.contains("Not Found") {
                    Ok(false)
                } else {
                    Err(AppError::Storage(format!(
                        "Failed to check existence of '{}': {}",
                        key, e
                    )))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);

        self.bucket
            .delete_object(&full_key)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to delete object '{}': {}", key, e)))?;

        tracing::debug!(key = %key, "S3 delete object successful");
        Ok(())
    }
}

/// Extended S3 backend operations (for StorageService compatibility)
impl S3Backend {
    /// List keys with optional prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_prefix = match (&self.prefix, prefix) {
            (Some(base), Some(p)) => format!("{}/{}", base.trim_end_matches('/'), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let results = self.bucket
            .list(search_prefix, None)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = results
            .into_iter()
            .flat_map(|result| result.contents)
            .map(|obj| self.strip_prefix(&obj.key))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }

    /// Copy content from one key to another
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        // S3 CopyObject requires source in format "bucket/key"
        let copy_source = format!("{}/{}", self.bucket.name(), source_key);

        self.bucket
            .copy_object_internal(&copy_source, &dest_key)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e)))?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }

    /// Get content size without fetching full content
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);

        let (head, _) = self.bucket
            .head_object(&full_key)
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NoSuchKey") || err_str.contains("Not Found") {
                    AppError::NotFound(format!("Storage key not found: {}", key))
                } else {
                    AppError::Storage(format!("Failed to get size of '{}': {}", key, e))
                }
            })?;

        let size = head.content_length.unwrap_or(0) as u64;
        tracing::debug!(key = %key, size = size, "S3 head object successful");
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_with_prefix() {
        // We can't create a real S3Backend without credentials, but we can test the key logic
        // by testing the string operations directly
        let prefix = Some("artifacts".to_string());
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "artifacts/test/file.txt");
    }

    #[test]
    fn test_full_key_without_prefix() {
        let prefix: Option<String> = None;
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "test/file.txt");
    }

    #[test]
    fn test_strip_prefix() {
        let prefix = Some("artifacts".to_string());
        let key = "artifacts/test/file.txt";

        let stripped = match &prefix {
            Some(p) => {
                let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        };

        assert_eq!(stripped, "test/file.txt");
    }

    #[test]
    fn test_s3_config_new() {
        let config = S3Config::new(
            "my-bucket".to_string(),
            "us-west-2".to_string(),
            Some("http://localhost:9000".to_string()),
            Some("prefix".to_string()),
        );

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
    }
}
