//! Artifact service.
//!
//! Handles artifact upload, download, checksum calculation, and storage.

use std::sync::Arc;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::services::repository_service::RepositoryService;
use crate::storage::StorageBackend;

/// Artifact service
pub struct ArtifactService {
    db: PgPool,
    storage: Arc<dyn StorageBackend>,
    repo_service: RepositoryService,
}

impl ArtifactService {
    /// Create a new artifact service
    pub fn new(db: PgPool, storage: Arc<dyn StorageBackend>) -> Self {
        let repo_service = RepositoryService::new(db.clone());
        Self {
            db,
            storage,
            repo_service,
        }
    }

    /// Calculate SHA-256 checksum of data
    pub fn calculate_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Generate content-addressable storage key from checksum
    fn storage_key_from_checksum(checksum: &str) -> String {
        // Use first 4 chars for directory sharding: ab/cd/abcd...
        format!("{}/{}/{}", &checksum[..2], &checksum[2..4], checksum)
    }

    /// Upload an artifact
    pub async fn upload(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: Option<&str>,
        content_type: &str,
        data: Bytes,
        uploaded_by: Option<Uuid>,
    ) -> Result<Artifact> {
        let size_bytes = data.len() as i64;

        // Check quota
        if !self.repo_service.check_quota(repository_id, size_bytes).await? {
            return Err(AppError::QuotaExceeded(
                "Repository storage quota exceeded".to_string(),
            ));
        }

        // Calculate checksum
        let checksum_sha256 = Self::calculate_sha256(&data);
        let storage_key = Self::storage_key_from_checksum(&checksum_sha256);

        // Check if artifact with same path already exists
        let existing = sqlx::query!(
            "SELECT id, version FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            repository_id,
            path
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(existing) = existing {
            // For immutable artifacts, reject if version matches
            if existing.version == version.map(String::from) {
                return Err(AppError::Conflict(
                    "Artifact version already exists and is immutable".to_string(),
                ));
            }
        }

        // Check if content already exists (deduplication)
        let content_exists = self.storage.exists(&storage_key).await?;

        if !content_exists {
            // Store the actual content
            self.storage.put(&storage_key, data).await?;
        }

        // Create artifact record
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (repository_id, path) DO UPDATE SET
                version = EXCLUDED.version,
                size_bytes = EXCLUDED.size_bytes,
                checksum_sha256 = EXCLUDED.checksum_sha256,
                content_type = EXCLUDED.content_type,
                storage_key = EXCLUDED.storage_key,
                uploaded_by = EXCLUDED.uploaded_by,
                updated_at = NOW()
            RETURNING
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            "#,
            repository_id,
            path,
            name,
            version,
            size_bytes,
            checksum_sha256,
            content_type,
            storage_key,
            uploaded_by
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(artifact)
    }

    /// Download an artifact
    pub async fn download(
        &self,
        repository_id: Uuid,
        path: &str,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<&str>,
    ) -> Result<(Artifact, Bytes)> {
        // Find artifact
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE repository_id = $1 AND path = $2 AND is_deleted = false
            "#,
            repository_id,
            path
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        // Get content from storage
        let content = self.storage.get(&artifact.storage_key).await?;

        // Record download statistics
        sqlx::query!(
            r#"
            INSERT INTO download_statistics (artifact_id, user_id, ip_address, user_agent)
            VALUES ($1, $2, $3, $4)
            "#,
            artifact.id,
            user_id,
            ip_address.as_deref(),
            user_agent
        )
        .execute(&self.db)
        .await
        .ok(); // Ignore stats errors

        Ok((artifact, content))
    }

    /// Get artifact by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<Artifact> {
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND is_deleted = false
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        Ok(artifact)
    }

    /// List artifacts in a repository with pagination
    pub async fn list(
        &self,
        repository_id: Uuid,
        path_prefix: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Artifact>, i64)> {
        let prefix_pattern = path_prefix.map(|p| format!("{}%", p));

        let artifacts = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE repository_id = $1
              AND is_deleted = false
              AND ($2::text IS NULL OR path LIKE $2)
            ORDER BY path
            OFFSET $3
            LIMIT $4
            "#,
            repository_id,
            prefix_pattern,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM artifacts
            WHERE repository_id = $1
              AND is_deleted = false
              AND ($2::text IS NULL OR path LIKE $2)
            "#,
            repository_id,
            prefix_pattern
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((artifacts, total))
    }

    /// Soft-delete an artifact
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE artifacts SET is_deleted = true, updated_at = NOW() WHERE id = $1",
            id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Artifact not found".to_string()));
        }

        Ok(())
    }

    /// Get or create artifact metadata
    pub async fn get_metadata(&self, artifact_id: Uuid) -> Result<Option<ArtifactMetadata>> {
        let metadata = sqlx::query_as!(
            ArtifactMetadata,
            r#"
            SELECT id, artifact_id, format, metadata, properties
            FROM artifact_metadata
            WHERE artifact_id = $1
            "#,
            artifact_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(metadata)
    }

    /// Set artifact metadata
    pub async fn set_metadata(
        &self,
        artifact_id: Uuid,
        format: &str,
        metadata: serde_json::Value,
        properties: serde_json::Value,
    ) -> Result<ArtifactMetadata> {
        let meta = sqlx::query_as!(
            ArtifactMetadata,
            r#"
            INSERT INTO artifact_metadata (artifact_id, format, metadata, properties)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (artifact_id) DO UPDATE SET
                format = EXCLUDED.format,
                metadata = EXCLUDED.metadata,
                properties = EXCLUDED.properties
            RETURNING id, artifact_id, format, metadata, properties
            "#,
            artifact_id,
            format,
            metadata,
            properties
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(meta)
    }

    /// Search artifacts by name
    pub async fn search(
        &self,
        query: &str,
        repository_ids: Option<Vec<Uuid>>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Artifact>, i64)> {
        let artifacts = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE is_deleted = false
              AND name ILIKE $1
              AND ($2::uuid[] IS NULL OR repository_id = ANY($2))
            ORDER BY name
            OFFSET $3
            LIMIT $4
            "#,
            format!("%{}%", query),
            repository_ids.as_deref(),
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM artifacts
            WHERE is_deleted = false
              AND name ILIKE $1
              AND ($2::uuid[] IS NULL OR repository_id = ANY($2))
            "#,
            format!("%{}%", query),
            repository_ids.as_deref()
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((artifacts, total))
    }

    /// Find artifact by checksum (for deduplication)
    pub async fn find_by_checksum(&self, checksum: &str) -> Result<Option<Artifact>> {
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                created_at, updated_at
            FROM artifacts
            WHERE checksum_sha256 = $1 AND is_deleted = false
            LIMIT 1
            "#,
            checksum
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(artifact)
    }

    /// Get download statistics for an artifact
    pub async fn get_download_stats(&self, artifact_id: Uuid) -> Result<i64> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM download_statistics WHERE artifact_id = $1"#,
            artifact_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let data = b"test data";
        let hash = ArtifactService::calculate_sha256(data);
        assert_eq!(hash.len(), 64);
        // Known SHA-256 of "test data"
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_storage_key_from_checksum() {
        let checksum = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let key = ArtifactService::storage_key_from_checksum(checksum);
        assert_eq!(
            key,
            "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }
}
