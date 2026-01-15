//! S3 storage backend.

use async_trait::async_trait;
use aws_sdk_s3::Client;
use bytes::Bytes;

use super::StorageBackend;
use crate::error::{AppError, Result};

/// S3-based storage backend
pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: Option<String>,
}

impl S3Storage {
    /// Create new S3 storage
    pub fn new(client: Client, bucket: String, prefix: Option<String>) -> Self {
        Self {
            client,
            bucket,
            prefix,
        }
    }

    /// Get full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(p) => format!("{}/{}", p, key),
            None => key.to_string(),
        }
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .body(content.into())
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("S3 put failed: {}", e)))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("S3 get failed: {}", e)))?;

        let body = response
            .body
            .collect()
            .await
            .map_err(|e| AppError::Storage(format!("S3 read body failed: {}", e)))?;

        Ok(body.into_bytes())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Assume not found on error
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("S3 delete failed: {}", e)))?;

        Ok(())
    }
}
