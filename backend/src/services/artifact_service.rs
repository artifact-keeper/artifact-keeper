//! Artifact service.
//!
//! Handles artifact upload, download, checksum calculation, and storage.

use std::sync::Arc;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::services::meili_service::{ArtifactDocument, MeiliService};
use crate::services::plugin_service::{ArtifactInfo, PluginEventType, PluginService};
use crate::services::repository_service::RepositoryService;
use crate::services::scanner_service::ScannerService;
use crate::storage::StorageBackend;

/// Artifact service
pub struct ArtifactService {
    db: PgPool,
    storage: Arc<dyn StorageBackend>,
    repo_service: RepositoryService,
    plugin_service: Option<Arc<PluginService>>,
    scanner_service: Option<Arc<ScannerService>>,
    meili_service: Option<Arc<MeiliService>>,
}

impl ArtifactService {
    /// Create a new artifact service
    pub fn new(db: PgPool, storage: Arc<dyn StorageBackend>) -> Self {
        let repo_service = RepositoryService::new(db.clone());
        Self {
            db,
            storage,
            repo_service,
            plugin_service: None,
            scanner_service: None,
            meili_service: None,
        }
    }

    /// Create a new artifact service with Meilisearch indexing support.
    pub fn new_with_meili(
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        meili_service: Option<Arc<MeiliService>>,
    ) -> Self {
        let repo_service = RepositoryService::new(db.clone());
        Self {
            db,
            storage,
            repo_service,
            plugin_service: None,
            scanner_service: None,
            meili_service,
        }
    }

    /// Create a new artifact service with plugin support.
    pub fn with_plugins(
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        plugin_service: Arc<PluginService>,
    ) -> Self {
        let repo_service = RepositoryService::new(db.clone());
        Self {
            db,
            storage,
            repo_service,
            plugin_service: Some(plugin_service),
            scanner_service: None,
            meili_service: None,
        }
    }

    /// Set the plugin service for hook triggering.
    pub fn set_plugin_service(&mut self, plugin_service: Arc<PluginService>) {
        self.plugin_service = Some(plugin_service);
    }

    /// Set the scanner service for scan-on-upload.
    pub fn set_scanner_service(&mut self, scanner_service: Arc<ScannerService>) {
        self.scanner_service = Some(scanner_service);
    }

    /// Set the Meilisearch service for search indexing.
    pub fn set_meili_service(&mut self, meili_service: Arc<MeiliService>) {
        self.meili_service = Some(meili_service);
    }

    /// Trigger a plugin hook, logging but not failing if plugin service is unavailable.
    async fn trigger_hook(
        &self,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) -> Result<()> {
        if let Some(ref plugin_service) = self.plugin_service {
            plugin_service.trigger_hooks(event, artifact_info).await
        } else {
            Ok(())
        }
    }

    /// Trigger a plugin hook, logging errors but not blocking operations.
    /// Used for "after" events where we don't want to fail the main operation.
    async fn trigger_hook_non_blocking(
        &self,
        event: PluginEventType,
        artifact_info: &ArtifactInfo,
    ) {
        if let Some(ref plugin_service) = self.plugin_service {
            if let Err(e) = plugin_service.trigger_hooks(event, artifact_info).await {
                warn!("Plugin hook {:?} failed (non-blocking): {}", event, e);
            }
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
    #[allow(clippy::too_many_arguments)]
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
        if !self
            .repo_service
            .check_quota(repository_id, size_bytes)
            .await?
        {
            return Err(AppError::QuotaExceeded(
                "Repository storage quota exceeded".to_string(),
            ));
        }

        // Calculate checksum
        let checksum_sha256 = Self::calculate_sha256(&data);
        let storage_key = Self::storage_key_from_checksum(&checksum_sha256);

        // Build artifact info for plugin hooks (before artifact is created)
        let pre_artifact_info = ArtifactInfo {
            id: Uuid::nil(), // Will be set after creation
            repository_id,
            path: path.to_string(),
            name: name.to_string(),
            version: version.map(String::from),
            size_bytes,
            checksum_sha256: checksum_sha256.clone(),
            content_type: content_type.to_string(),
            uploaded_by,
        };

        // Trigger BeforeUpload hooks - validators can reject the upload
        self.trigger_hook(PluginEventType::BeforeUpload, &pre_artifact_info)
            .await?;

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

        // Trigger AfterUpload hooks (non-blocking - don't fail upload if hooks fail)
        let artifact_info = ArtifactInfo::from(&artifact);
        self.trigger_hook_non_blocking(PluginEventType::AfterUpload, &artifact_info)
            .await;

        // Trigger scan-on-upload if scanner service is configured
        if let Some(ref scanner) = self.scanner_service {
            let scanner = scanner.clone();
            let artifact_id = artifact.id;
            let repo_id = artifact.repository_id;
            let db = self.db.clone();
            tokio::spawn(async move {
                // Check if scan_on_upload is enabled for this repository
                let should_scan = sqlx::query_scalar!(
                    "SELECT scan_on_upload FROM scan_configs WHERE repository_id = $1 AND scan_enabled = true",
                    repo_id
                )
                .fetch_optional(&db)
                .await
                .ok()
                .flatten()
                .unwrap_or(false);

                if should_scan {
                    if let Err(e) = scanner.scan_artifact(artifact_id).await {
                        tracing::warn!("Auto-scan failed for artifact {}: {}", artifact_id, e);
                    }
                }
            });
        }

        // Index artifact in Meilisearch (non-blocking)
        if let Some(ref meili) = self.meili_service {
            let meili = meili.clone();
            let db = self.db.clone();
            let artifact_id = artifact.id;
            let artifact_name = artifact.name.clone();
            let artifact_path = artifact.path.clone();
            let artifact_version = artifact.version.clone();
            let artifact_content_type = artifact.content_type.clone();
            let artifact_size = artifact.size_bytes;
            let artifact_created = artifact.created_at;
            let repo_id = artifact.repository_id;
            tokio::spawn(async move {
                // Fetch repository info for the document
                let repo_info = sqlx::query_as::<_, (String, String, String)>(
                    "SELECT key, name, format::text FROM repositories WHERE id = $1",
                )
                .bind(repo_id)
                .fetch_optional(&db)
                .await;

                match repo_info {
                    Ok(Some((repo_key, repo_name, format))) => {
                        let doc = ArtifactDocument {
                            id: artifact_id.to_string(),
                            name: artifact_name,
                            path: artifact_path,
                            version: artifact_version,
                            format,
                            repository_id: repo_id.to_string(),
                            repository_key: repo_key,
                            repository_name: repo_name,
                            content_type: artifact_content_type,
                            size_bytes: artifact_size,
                            download_count: 0,
                            created_at: artifact_created.timestamp(),
                        };
                        if let Err(e) = meili.index_artifact(&doc).await {
                            tracing::warn!(
                                "Failed to index artifact {} in Meilisearch: {}",
                                artifact_id,
                                e
                            );
                        }
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "Repository {} not found when indexing artifact {}",
                            repo_id,
                            artifact_id
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to fetch repository for Meilisearch indexing: {}",
                            e
                        );
                    }
                }
            });
        }

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

        // Trigger BeforeDownload hooks - validators can reject the download
        let artifact_info = ArtifactInfo::from(&artifact);
        self.trigger_hook(PluginEventType::BeforeDownload, &artifact_info)
            .await?;

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

        // Trigger AfterDownload hooks (non-blocking)
        self.trigger_hook_non_blocking(PluginEventType::AfterDownload, &artifact_info)
            .await;

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
        // Get artifact info for plugin hooks
        let artifact = self.get_by_id(id).await?;
        let artifact_info = ArtifactInfo::from(&artifact);

        // Trigger BeforeDelete hooks - validators can reject the deletion
        self.trigger_hook(PluginEventType::BeforeDelete, &artifact_info)
            .await?;

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

        // Trigger AfterDelete hooks (non-blocking)
        self.trigger_hook_non_blocking(PluginEventType::AfterDelete, &artifact_info)
            .await;

        // Remove artifact from Meilisearch index (non-blocking)
        if let Some(ref meili) = self.meili_service {
            let meili = meili.clone();
            let artifact_id_str = id.to_string();
            tokio::spawn(async move {
                if let Err(e) = meili.remove_artifact(&artifact_id_str).await {
                    tracing::warn!(
                        "Failed to remove artifact {} from Meilisearch: {}",
                        artifact_id_str,
                        e
                    );
                }
            });
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
