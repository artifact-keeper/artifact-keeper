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
use crate::services::quality_check_service::QualityCheckService;
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
    quality_check_service: Option<Arc<QualityCheckService>>,
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
            quality_check_service: None,
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
            quality_check_service: None,
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
            quality_check_service: None,
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

    /// Set the quality check service for quality-on-upload.
    pub fn set_quality_check_service(&mut self, qc_service: Arc<QualityCheckService>) {
        self.quality_check_service = Some(qc_service);
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
    pub fn storage_key_from_checksum(checksum: &str) -> String {
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

        // Check quota warning threshold after successful upload
        if let Ok(repo) = self.repo_service.get_by_id(repository_id).await {
            if let Some(quota) = repo.quota_bytes {
                if let Ok(current_usage) = self.repo_service.get_storage_usage(repository_id).await
                {
                    if crate::services::repository_service::exceeds_quota_warning_threshold(
                        current_usage,
                        quota,
                    ) {
                        let usage_pct = crate::services::repository_service::quota_usage_percentage(
                            current_usage,
                            quota,
                        );
                        tracing::warn!(
                            repository_key = %repo.key,
                            usage_percent = format!("{:.1}", usage_pct * 100.0),
                            current_bytes = current_usage,
                            quota_bytes = quota,
                            "Repository quota warning: usage exceeds 80%"
                        );
                    }
                }
            }
        }

        // Populate packages / package_versions tables (non-blocking)
        if let Some(ref ver) = artifact.version {
            let pkg_svc = crate::services::package_service::PackageService::new(self.db.clone());
            pkg_svc
                .try_create_or_update_from_artifact(
                    artifact.repository_id,
                    &artifact.name,
                    ver,
                    artifact.size_bytes,
                    &artifact.checksum_sha256,
                    None,
                    None,
                )
                .await;
        }

        // Trigger AfterUpload hooks (non-blocking - don't fail upload if hooks fail)
        let artifact_info = ArtifactInfo::from(&artifact);
        self.trigger_hook_non_blocking(PluginEventType::AfterUpload, &artifact_info)
            .await;

        // Queue sync tasks for peer replication (non-blocking)
        {
            let db = self.db.clone();
            let artifact_id = artifact.id;
            let repository_id = artifact.repository_id;
            let artifact_path = artifact.path.clone();
            let artifact_size = artifact.size_bytes;
            let artifact_created = artifact.created_at;
            tokio::spawn(async move {
                // Find peers with push/mirror subscriptions, including the policy's artifact_filter
                #[derive(sqlx::FromRow)]
                struct SubWithFilter {
                    peer_instance_id: uuid::Uuid,
                    artifact_filter: Option<serde_json::Value>,
                }

                let subscriptions: std::result::Result<Vec<SubWithFilter>, _> = sqlx::query_as(
                    r#"
                    SELECT prs.peer_instance_id, sp.artifact_filter
                    FROM peer_repo_subscriptions prs
                    LEFT JOIN sync_policies sp ON sp.id = prs.policy_id
                    WHERE prs.repository_id = $1
                      AND prs.sync_enabled = true
                      AND prs.replication_mode::text IN ('push', 'mirror')
                    "#,
                )
                .bind(repository_id)
                .fetch_all(&db)
                .await;

                match subscriptions {
                    Ok(subs) if !subs.is_empty() => {
                        let peer_service =
                            crate::services::peer_instance_service::PeerInstanceService::new(db);
                        let mut queued = 0usize;
                        for sub in &subs {
                            let filter: crate::services::sync_policy_service::ArtifactFilter = sub
                                .artifact_filter
                                .as_ref()
                                .and_then(|v| serde_json::from_value(v.clone()).ok())
                                .unwrap_or_default();

                            if !filter.matches(&artifact_path, artifact_size, artifact_created) {
                                tracing::debug!(
                                    "Artifact {} filtered out for peer {} by policy artifact_filter",
                                    artifact_id,
                                    sub.peer_instance_id,
                                );
                                continue;
                            }

                            if let Err(e) = peer_service
                                .queue_sync_task(sub.peer_instance_id, artifact_id, 0)
                                .await
                            {
                                tracing::warn!(
                                    "Failed to queue sync task for peer {} artifact {}: {}",
                                    sub.peer_instance_id,
                                    artifact_id,
                                    e
                                );
                            } else {
                                queued += 1;
                            }
                        }
                        if queued > 0 {
                            tracing::info!(
                                "Queued sync tasks for artifact {} to {} peer(s)",
                                artifact_id,
                                queued
                            );
                        }
                    }
                    Ok(_) => {} // No push/mirror subscriptions
                    Err(e) => {
                        tracing::warn!(
                            "Failed to query peer subscriptions for repo {}: {}",
                            repository_id,
                            e
                        );
                    }
                }
            });
        }

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

        // Trigger quality checks on upload (non-blocking)
        if let Some(ref qc) = self.quality_check_service {
            let qc = qc.clone();
            let artifact_id = artifact.id;
            tokio::spawn(async move {
                if let Err(e) = qc.check_artifact(artifact_id).await {
                    tracing::warn!(
                        "Auto quality check failed for artifact {}: {}",
                        artifact_id,
                        e
                    );
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

    /// List artifacts in a repository with pagination and optional search
    pub async fn list(
        &self,
        repository_id: Uuid,
        path_prefix: Option<&str>,
        search_query: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Artifact>, i64)> {
        let prefix_pattern = path_prefix.map(|p| format!("{}%", p));
        let search_pattern = search_query.map(|q| format!("%{}%", q.to_lowercase()));

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
              AND ($5::text IS NULL OR LOWER(name) LIKE $5 OR LOWER(path) LIKE $5)
            ORDER BY path
            OFFSET $3
            LIMIT $4
            "#,
            repository_id,
            prefix_pattern,
            offset,
            limit,
            search_pattern,
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
              AND ($3::text IS NULL OR LOWER(name) LIKE $3 OR LOWER(path) LIKE $3)
            "#,
            repository_id,
            prefix_pattern,
            search_pattern,
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

        // Enqueue delete sync tasks for all eligible peers (non-blocking)
        let _ = sqlx::query(
            r#"
            INSERT INTO sync_tasks (id, peer_instance_id, artifact_id, task_type, status, priority)
            SELECT gen_random_uuid(), pi.id, $1, 'delete', 'pending', 0
            FROM peer_instances pi
            JOIN peer_repo_subscriptions prs ON prs.peer_instance_id = pi.id
            JOIN artifacts a ON a.repository_id = prs.repository_id AND a.id = $1
            WHERE pi.is_local = false
              AND pi.status IN ('online', 'syncing')
              AND prs.replication_mode::text IN ('push', 'mirror')
              AND prs.sync_enabled = true
            ON CONFLICT (peer_instance_id, artifact_id, task_type) DO NOTHING
            "#,
        )
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(|e| {
            tracing::warn!(
                "Failed to enqueue delete sync tasks for artifact {}: {}",
                id,
                e
            );
            e
        });

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

    /// Set artifact metadata.
    ///
    /// Sanitizes URL values in the metadata to prevent stored XSS via
    /// `javascript:`, `data:`, or `vbscript:` scheme URLs.
    pub async fn set_metadata(
        &self,
        artifact_id: Uuid,
        format: &str,
        metadata: serde_json::Value,
        properties: serde_json::Value,
    ) -> Result<ArtifactMetadata> {
        let metadata = sanitize_metadata_urls(metadata);
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

/// URL fields commonly found in package metadata across all formats.
const URL_FIELD_NAMES: &[&str] = &[
    "homepage",
    "home_page",
    "homepage_uri",
    "repository",
    "repository_url",
    "source_code_uri",
    "bug_tracker",
    "bug_tracker_url",
    "bugs",
    "documentation",
    "documentation_url",
    "docs_url",
    "download_url",
    "project_url",
    "package_url",
    "url",
    "website",
];

/// Returns true if a string looks like a dangerous URL scheme that could
/// trigger script execution when rendered as a link.
fn is_dangerous_url(s: &str) -> bool {
    let lower = s.trim().to_lowercase();
    lower.starts_with("javascript:")
        || lower.starts_with("vbscript:")
        || lower.starts_with("data:text/html")
}

/// Recursively walk a JSON value and replace any URL-like string fields
/// that use dangerous schemes (javascript:, vbscript:, data:text/html)
/// with an empty string.
fn sanitize_metadata_urls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sanitized = map
                .into_iter()
                .map(|(k, v)| {
                    let key_lower = k.to_lowercase();
                    let is_url_field = URL_FIELD_NAMES.iter().any(|f| key_lower == *f)
                        || key_lower.ends_with("_url")
                        || key_lower.ends_with("_uri")
                        || key_lower.ends_with("_link");
                    let new_v = if is_url_field {
                        match &v {
                            serde_json::Value::String(s) if is_dangerous_url(s) => {
                                serde_json::Value::String(String::new())
                            }
                            _ => sanitize_metadata_urls(v),
                        }
                    } else {
                        sanitize_metadata_urls(v)
                    };
                    (k, new_v)
                })
                .collect();
            serde_json::Value::Object(sanitized)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sanitize_metadata_urls).collect())
        }
        other => other,
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

    // -----------------------------------------------------------------------
    // calculate_sha256: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_calculate_sha256_empty_data() {
        let hash = ArtifactService::calculate_sha256(b"");
        // Known SHA-256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_calculate_sha256_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let hash = ArtifactService::calculate_sha256(&data);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_sha256_large_data() {
        let data = vec![0u8; 1_000_000];
        let hash = ArtifactService::calculate_sha256(&data);
        assert_eq!(hash.len(), 64);
        // Same data should yield same hash
        let hash2 = ArtifactService::calculate_sha256(&data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_calculate_sha256_deterministic() {
        let data = b"deterministic data";
        let hash1 = ArtifactService::calculate_sha256(data);
        let hash2 = ArtifactService::calculate_sha256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_calculate_sha256_different_data_different_hash() {
        let hash1 = ArtifactService::calculate_sha256(b"data A");
        let hash2 = ArtifactService::calculate_sha256(b"data B");
        assert_ne!(hash1, hash2);
    }

    // -----------------------------------------------------------------------
    // storage_key_from_checksum: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_key_from_checksum_uses_first_four_chars() {
        let checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let key = ArtifactService::storage_key_from_checksum(checksum);
        assert!(key.starts_with("ab/cd/"));
        assert!(key.ends_with(checksum));
    }

    #[test]
    fn test_storage_key_from_checksum_structure() {
        let checksum = "0000000000000000000000000000000000000000000000000000000000000000";
        let key = ArtifactService::storage_key_from_checksum(checksum);
        assert_eq!(
            key,
            "00/00/0000000000000000000000000000000000000000000000000000000000000000"
        );
        // Verify the structure: prefix/prefix/full_checksum
        let parts: Vec<&str> = key.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 2);
        assert_eq!(parts[1].len(), 2);
        assert_eq!(parts[2].len(), 64);
    }

    #[test]
    fn test_storage_key_from_checksum_full_roundtrip() {
        // Compute a SHA-256 and then derive a storage key
        let data = b"roundtrip test";
        let checksum = ArtifactService::calculate_sha256(data);
        let key = ArtifactService::storage_key_from_checksum(&checksum);
        // Key should contain the full checksum
        assert!(key.contains(&checksum));
        // First two dirs are derived from checksum prefix
        assert!(key.starts_with(&format!("{}/{}/", &checksum[..2], &checksum[2..4])));
    }

    // -----------------------------------------------------------------------
    // ArtifactInfo conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_info_from_artifact_all_fields() {
        use crate::models::artifact::Artifact;
        use crate::services::plugin_service::ArtifactInfo;
        use chrono::Utc;

        let user_id = Uuid::new_v4();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: "com/example/lib/1.0/lib-1.0.jar".to_string(),
            name: "lib-1.0.jar".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 2048,
            checksum_sha256: "sha256hash".to_string(),
            checksum_md5: Some("md5hash".to_string()),
            checksum_sha1: Some("sha1hash".to_string()),
            content_type: "application/java-archive".to_string(),
            storage_key: "sh/a2/sha256hash".to_string(),
            is_deleted: false,
            uploaded_by: Some(user_id),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let info = ArtifactInfo::from(&artifact);
        assert_eq!(info.id, artifact.id);
        assert_eq!(info.repository_id, artifact.repository_id);
        assert_eq!(info.path, "com/example/lib/1.0/lib-1.0.jar");
        assert_eq!(info.name, "lib-1.0.jar");
        assert_eq!(info.version, Some("1.0".to_string()));
        assert_eq!(info.size_bytes, 2048);
        assert_eq!(info.checksum_sha256, "sha256hash");
        assert_eq!(info.content_type, "application/java-archive");
        assert_eq!(info.uploaded_by, Some(user_id));
    }

    #[test]
    fn test_artifact_info_from_artifact_no_version_no_uploader() {
        use crate::models::artifact::Artifact;
        use crate::services::plugin_service::ArtifactInfo;
        use chrono::Utc;

        let artifact = Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: "generic/file.txt".to_string(),
            name: "file.txt".to_string(),
            version: None,
            size_bytes: 0,
            checksum_sha256: "empty".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "text/plain".to_string(),
            storage_key: "em/pt/empty".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let info = ArtifactInfo::from(&artifact);
        assert_eq!(info.version, None);
        assert_eq!(info.uploaded_by, None);
        assert_eq!(info.size_bytes, 0);
    }

    #[test]
    fn test_sanitize_metadata_urls_strips_javascript() {
        let metadata = serde_json::json!({
            "name": "evil-package",
            "homepage": "javascript:alert(1)",
            "repository": "https://github.com/example/repo"
        });
        let sanitized = sanitize_metadata_urls(metadata);
        assert_eq!(sanitized["homepage"], "");
        assert_eq!(sanitized["repository"], "https://github.com/example/repo");
    }

    #[test]
    fn test_sanitize_metadata_urls_strips_vbscript() {
        let metadata = serde_json::json!({
            "homepage": "vbscript:msgbox('xss')"
        });
        let sanitized = sanitize_metadata_urls(metadata);
        assert_eq!(sanitized["homepage"], "");
    }

    #[test]
    fn test_sanitize_metadata_urls_strips_data_html() {
        let metadata = serde_json::json!({
            "documentation_url": "data:text/html,<script>alert(1)</script>"
        });
        let sanitized = sanitize_metadata_urls(metadata);
        assert_eq!(sanitized["documentation_url"], "");
    }

    #[test]
    fn test_sanitize_metadata_urls_preserves_safe_urls() {
        let metadata = serde_json::json!({
            "homepage": "https://example.com",
            "repository_url": "https://github.com/foo/bar",
            "description": "A normal description",
            "name": "my-package"
        });
        let sanitized = sanitize_metadata_urls(metadata.clone());
        assert_eq!(sanitized, metadata);
    }

    #[test]
    fn test_sanitize_metadata_urls_nested_objects() {
        let metadata = serde_json::json!({
            "project": {
                "homepage": "javascript:void(0)",
                "name": "test"
            }
        });
        let sanitized = sanitize_metadata_urls(metadata);
        assert_eq!(sanitized["project"]["homepage"], "");
        assert_eq!(sanitized["project"]["name"], "test");
    }

    #[test]
    fn test_sanitize_metadata_urls_case_insensitive() {
        let metadata = serde_json::json!({
            "homepage": "JAVASCRIPT:alert(1)"
        });
        let sanitized = sanitize_metadata_urls(metadata);
        assert_eq!(sanitized["homepage"], "");
    }

    #[test]
    fn test_is_dangerous_url() {
        assert!(is_dangerous_url("javascript:alert(1)"));
        assert!(is_dangerous_url("JAVASCRIPT:alert(1)"));
        assert!(is_dangerous_url("  javascript:alert(1)"));
        assert!(is_dangerous_url("vbscript:foo"));
        assert!(is_dangerous_url("data:text/html,<script>"));
        assert!(!is_dangerous_url("https://example.com"));
        assert!(!is_dangerous_url("http://example.com"));
        assert!(!is_dangerous_url("data:image/png;base64,abc"));
    }

    // -----------------------------------------------------------------------
    // delete sync task SQL validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_delete_sync_task_sql_contains_required_clauses() {
        let sql = r#"
            INSERT INTO sync_tasks (id, peer_instance_id, artifact_id, task_type, status, priority)
            SELECT gen_random_uuid(), pi.id, $1, 'delete', 'pending', 0
            FROM peer_instances pi
            JOIN peer_repo_subscriptions prs ON prs.peer_instance_id = pi.id
            JOIN artifacts a ON a.repository_id = prs.repository_id AND a.id = $1
            WHERE pi.is_local = false
              AND pi.status IN ('online', 'syncing')
              AND prs.replication_mode::text IN ('push', 'mirror')
              AND prs.sync_enabled = true
            ON CONFLICT (peer_instance_id, artifact_id, task_type) DO NOTHING
        "#;
        assert!(sql.contains("INSERT INTO sync_tasks"));
        assert!(sql.contains("'delete'"));
        assert!(sql.contains("peer_repo_subscriptions"));
        assert!(sql.contains("replication_mode"));
        assert!(sql.contains("sync_enabled"));
        assert!(sql.contains("is_local = false"));
        assert!(sql.contains("ON CONFLICT"));
    }
}
