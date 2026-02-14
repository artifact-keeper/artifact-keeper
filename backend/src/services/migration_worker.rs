//! Migration worker - handles background migration processing.
//!
//! This worker processes migration jobs asynchronously, handling:
//! - Artifact downloads and uploads
//! - Checksum verification
//! - Progress tracking
//! - Checkpoint saving for resumability

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::models::migration::{MigrationItemType, MigrationJobStatus};
use crate::services::artifact_service::ArtifactService;
use crate::services::artifactory_client::ArtifactoryClient;
use crate::services::migration_service::{MigrationError, MigrationService};
use crate::services::source_registry::SourceRegistry;
use crate::storage::StorageBackend;

/// Configuration for the migration worker
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Number of concurrent artifact transfers
    pub concurrency: usize,
    /// Delay between requests in milliseconds (for throttling)
    pub throttle_delay_ms: u64,
    /// Maximum retries for failed transfers
    pub max_retries: u32,
    /// Batch size for artifact listing
    pub batch_size: i64,
    /// Whether to verify checksums after transfer
    pub verify_checksums: bool,
    /// Dry-run mode - preview changes without making them
    pub dry_run: bool,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            throttle_delay_ms: 100,
            max_retries: 3,
            batch_size: 100,
            verify_checksums: true,
            dry_run: false,
        }
    }
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Skip if artifact exists with same checksum
    Skip,
    /// Overwrite existing artifact
    Overwrite,
    /// Rename with suffix (e.g., file_1.jar)
    Rename,
}

impl ConflictResolution {
    /// Parse from string representation
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "overwrite" => Self::Overwrite,
            "rename" => Self::Rename,
            _ => Self::Skip,
        }
    }
}

/// Progress update message
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub job_id: Uuid,
    pub completed: i32,
    pub failed: i32,
    pub skipped: i32,
    pub transferred_bytes: i64,
    pub current_item: Option<String>,
    pub status: MigrationJobStatus,
}

/// Migration worker for processing migration jobs
pub struct MigrationWorker {
    db: PgPool,
    migration_service: MigrationService,
    storage: Arc<dyn StorageBackend>,
    config: WorkerConfig,
    cancel_token: CancellationToken,
}

impl MigrationWorker {
    /// Create a new migration worker
    pub fn new(
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        config: WorkerConfig,
        cancel_token: CancellationToken,
    ) -> Self {
        let migration_service = MigrationService::new(db.clone());
        Self {
            db,
            migration_service,
            storage,
            config,
            cancel_token,
        }
    }

    /// Get a reference to the database pool
    pub fn db_ref(&self) -> &PgPool {
        &self.db
    }

    /// Process a migration job
    pub async fn process_job(
        &self,
        job_id: Uuid,
        client: Arc<dyn SourceRegistry>,
        conflict_resolution: ConflictResolution,
        progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        tracing::info!(job_id = %job_id, "Starting migration job processing");

        // Get job details
        let job: (serde_json::Value,) =
            sqlx::query_as("SELECT config FROM migration_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&self.db)
                .await?;

        let config: crate::models::migration::MigrationConfig =
            serde_json::from_value(job.0).unwrap_or_default();
        let include_artifacts = true;
        let include_metadata = true;
        let repos = config.include_repos.clone();

        // Update job status to running
        self.migration_service
            .update_job_status(job_id, MigrationJobStatus::Running)
            .await?;

        let mut total_completed = 0i32;
        let mut total_failed = 0i32;
        let mut total_skipped = 0i32;
        let mut total_transferred = 0i64;

        // Process each repository
        for repo_key in &repos {
            // Check for pause/cancel
            if self.cancel_token.is_cancelled() {
                tracing::info!(job_id = %job_id, "Migration cancelled by user");
                self.migration_service
                    .update_job_status(job_id, MigrationJobStatus::Cancelled)
                    .await?;
                return Ok(());
            }
            if self.is_paused(job_id).await? {
                tracing::info!(job_id = %job_id, "Migration paused by user");
                return Ok(());
            }

            if include_artifacts {
                match self
                    .process_repository_artifacts(
                        job_id,
                        client.clone(),
                        repo_key,
                        conflict_resolution,
                        include_metadata,
                        &mut total_completed,
                        &mut total_failed,
                        &mut total_skipped,
                        &mut total_transferred,
                        progress_tx.clone(),
                    )
                    .await
                {
                    Ok(_) => {
                        tracing::info!(repo = %repo_key, "Repository artifacts processed");
                    }
                    Err(e) => {
                        tracing::error!(repo = %repo_key, error = %e, "Failed to process repository");
                        // Continue with other repos
                    }
                }
            }
        }

        // Update final status
        let final_status = if total_failed > 0 && total_completed == 0 {
            MigrationJobStatus::Failed
        } else {
            MigrationJobStatus::Completed
        };

        self.migration_service
            .update_job_status(job_id, final_status)
            .await?;

        // Mark job as finished
        sqlx::query("UPDATE migration_jobs SET finished_at = NOW() WHERE id = $1")
            .bind(job_id)
            .execute(&self.db)
            .await?;

        // Send final progress update
        if let Some(tx) = progress_tx {
            let _ = tx
                .send(ProgressUpdate {
                    job_id,
                    completed: total_completed,
                    failed: total_failed,
                    skipped: total_skipped,
                    transferred_bytes: total_transferred,
                    current_item: None,
                    status: final_status,
                })
                .await;
        }

        tracing::info!(
            job_id = %job_id,
            completed = total_completed,
            failed = total_failed,
            skipped = total_skipped,
            "Migration job completed"
        );

        Ok(())
    }

    /// Process artifacts for a single repository
    #[allow(clippy::too_many_arguments)]
    async fn process_repository_artifacts(
        &self,
        job_id: Uuid,
        client: Arc<dyn SourceRegistry>,
        repo_key: &str,
        conflict_resolution: ConflictResolution,
        include_metadata: bool,
        completed: &mut i32,
        failed: &mut i32,
        skipped: &mut i32,
        transferred: &mut i64,
        progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        let mut offset = 0i64;
        let limit = self.config.batch_size;

        loop {
            // List artifacts with pagination
            let artifacts = client.list_artifacts(repo_key, offset, limit).await?;

            if artifacts.results.is_empty() {
                break;
            }

            for artifact in &artifacts.results {
                // Check for pause/cancel between artifacts
                if self.cancel_token.is_cancelled() || self.is_paused(job_id).await? {
                    return Ok(());
                }

                let artifact_path = if artifact.path == "." {
                    artifact.name.clone()
                } else {
                    format!("{}/{}", artifact.path, artifact.name)
                };

                let source_path = format!("{}/{}", repo_key, artifact_path);
                let size = artifact.size.unwrap_or(0);
                let checksum = artifact
                    .sha256
                    .clone()
                    .or_else(|| artifact.actual_sha1.clone());

                // Skip if already completed (resume support)
                let already_done: Option<(String,)> = sqlx::query_as(
                    "SELECT status FROM migration_items WHERE job_id = $1 AND source_path = $2 AND status = 'completed'"
                )
                .bind(job_id)
                .bind(&source_path)
                .fetch_optional(&self.db)
                .await?;
                if already_done.is_some() {
                    *skipped += 1;
                    continue;
                }

                // Add migration item to database (or get existing one on resume)
                let item_id = self
                    .add_migration_item(
                        job_id,
                        MigrationItemType::Artifact,
                        &source_path,
                        size,
                        checksum.as_deref(),
                    )
                    .await?;

                // Check for duplicates/conflicts
                let should_skip = self
                    .check_artifact_duplicate(
                        &source_path,
                        checksum.as_deref(),
                        conflict_resolution,
                    )
                    .await?;

                if should_skip {
                    self.migration_service
                        .skip_item(item_id, "Artifact already exists")
                        .await?;
                    *skipped += 1;
                } else {
                    // Process the artifact
                    match self
                        .transfer_artifact(
                            client.clone(),
                            repo_key,
                            &artifact_path,
                            include_metadata,
                        )
                        .await
                    {
                        Ok(transfer_result) => {
                            // Verify checksum if enabled
                            let checksum_verified = if self.config.verify_checksums {
                                match (&checksum, &transfer_result.calculated_checksum) {
                                    (Some(expected), Some(actual)) => expected == actual,
                                    _ => true, // No checksum to verify
                                }
                            } else {
                                true
                            };

                            if checksum_verified {
                                self.migration_service
                                    .complete_item(
                                        item_id,
                                        &transfer_result.target_path,
                                        transfer_result
                                            .calculated_checksum
                                            .as_deref()
                                            .unwrap_or(""),
                                    )
                                    .await?;
                                *completed += 1;
                                *transferred += size;
                            } else {
                                self.migration_service
                                    .fail_item(
                                        item_id,
                                        &format!(
                                            "Checksum mismatch: expected {:?}, got {:?}",
                                            checksum, transfer_result.calculated_checksum
                                        ),
                                    )
                                    .await?;
                                *failed += 1;
                            }
                        }
                        Err(e) => {
                            self.migration_service
                                .fail_item(item_id, &e.to_string())
                                .await?;
                            *failed += 1;
                        }
                    }
                }

                // Update progress
                self.migration_service
                    .update_job_progress(job_id, *completed, *failed, *skipped, *transferred)
                    .await?;

                // Send progress update
                if let Some(ref tx) = progress_tx {
                    let _ = tx
                        .send(ProgressUpdate {
                            job_id,
                            completed: *completed,
                            failed: *failed,
                            skipped: *skipped,
                            transferred_bytes: *transferred,
                            current_item: Some(source_path.clone()),
                            status: MigrationJobStatus::Running,
                        })
                        .await;
                }

                // Throttle
                if self.config.throttle_delay_ms > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        self.config.throttle_delay_ms,
                    ))
                    .await;
                }
            }

            // Check if we've processed all artifacts
            if (offset + artifacts.results.len() as i64) >= artifacts.range.total {
                break;
            }

            offset += limit;
        }

        Ok(())
    }

    /// Add a migration item to the database
    async fn add_migration_item(
        &self,
        job_id: Uuid,
        item_type: MigrationItemType,
        source_path: &str,
        size_bytes: i64,
        checksum: Option<&str>,
    ) -> Result<Uuid, MigrationError> {
        let item_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO migration_items (job_id, item_type, source_path, size_bytes, checksum_source)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (job_id, source_path) DO UPDATE SET size_bytes = EXCLUDED.size_bytes
            RETURNING id
            "#,
        )
        .bind(job_id)
        .bind(item_type.to_string())
        .bind(source_path)
        .bind(size_bytes)
        .bind(checksum)
        .fetch_one(&self.db)
        .await?;

        Ok(item_id.0)
    }

    /// Check if an artifact already exists with the same checksum
    async fn check_artifact_duplicate(
        &self,
        path: &str,
        checksum: Option<&str>,
        conflict_resolution: ConflictResolution,
    ) -> Result<bool, MigrationError> {
        // Check if an artifact with this path already exists
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT checksum_sha256 FROM artifacts WHERE path = $1 AND is_deleted = false LIMIT 1",
        )
        .bind(path)
        .fetch_optional(&self.db)
        .await?;

        match existing {
            None => Ok(false), // No duplicate
            Some((existing_checksum,)) => match conflict_resolution {
                ConflictResolution::Skip => {
                    // Skip if checksums match (identical content)
                    Ok(checksum.map_or(true, |c| c == existing_checksum))
                }
                ConflictResolution::Overwrite => Ok(false), // Always process
                ConflictResolution::Rename => Ok(false),    // Always process (will rename)
            },
        }
    }

    /// Transfer an artifact from Artifactory to Artifact Keeper
    async fn transfer_artifact(
        &self,
        client: Arc<dyn SourceRegistry>,
        repo_key: &str,
        artifact_path: &str,
        include_metadata: bool,
    ) -> Result<TransferResult, MigrationError> {
        // Download artifact from Artifactory
        let artifact_data = client.download_artifact(repo_key, artifact_path).await?;
        let content_size = artifact_data.len();

        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(&artifact_data);
        let checksum = hex::encode(hasher.finalize());

        // Get metadata if requested
        let metadata = if include_metadata {
            match client.get_properties(repo_key, artifact_path).await {
                Ok(props) => props.properties,
                Err(_) => None,
            }
        } else {
            None
        };

        // Upload to Artifact Keeper storage using CAS key
        let storage_key = ArtifactService::storage_key_from_checksum(&checksum);

        if !self.config.dry_run {
            // Check if content already exists (deduplication)
            let exists = self.storage.exists(&storage_key).await.unwrap_or(false);
            if !exists {
                self.storage
                    .put(&storage_key, artifact_data)
                    .await
                    .map_err(|e| MigrationError::StorageError(e.to_string()))?;
            }

            // Insert artifact record into the database
            let repo_id: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                    .bind(repo_key)
                    .fetch_optional(&self.db)
                    .await?;

            if let Some((repository_id,)) = repo_id {
                let name = artifact_path.rsplit('/').next().unwrap_or(artifact_path);
                let path_str = format!("{}/{}", repo_key, artifact_path);
                sqlx::query(
                    r#"
                    INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, storage_key, content_type)
                    VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream')
                    ON CONFLICT (repository_id, path) WHERE is_deleted = false DO NOTHING
                    "#,
                )
                .bind(repository_id)
                .bind(&path_str)
                .bind(name)
                .bind(content_size as i64)
                .bind(&checksum)
                .bind(&storage_key)
                .execute(&self.db)
                .await?;
            }
        }

        let target_path = format!("{}/{}", repo_key, artifact_path);

        tracing::debug!(
            path = %artifact_path,
            size = content_size,
            checksum = %checksum,
            "Artifact transferred"
        );

        Ok(TransferResult {
            target_path,
            calculated_checksum: Some(checksum),
            metadata,
        })
    }

    // ============ User Migration Methods ============

    /// Migrate users from Artifactory to Artifact Keeper
    pub async fn migrate_users(
        &self,
        job_id: Uuid,
        client: Arc<ArtifactoryClient>,
        completed: &mut i32,
        failed: &mut i32,
        skipped: &mut i32,
        _progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        tracing::info!(job_id = %job_id, "Starting user migration");

        // List users from Artifactory
        let users = client.list_users().await?;

        for user in &users {
            let source_path = format!("user:{}", user.name);

            // Add migration item
            let item_id = self
                .add_migration_item(job_id, MigrationItemType::User, &source_path, 0, None)
                .await?;

            // Check if user has email (required for identity in AK)
            if user.email.is_none() {
                self.migration_service
                    .skip_item(
                        item_id,
                        "User has no email address - cannot migrate without identity",
                    )
                    .await?;
                *skipped += 1;
                continue;
            }

            // Check if user already exists in Artifact Keeper
            let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
                .bind(&user.email)
                .fetch_optional(&self.db)
                .await?;

            if existing.is_some() {
                self.migration_service
                    .skip_item(item_id, "User with this email already exists")
                    .await?;
                *skipped += 1;
                continue;
            }

            // Create user in Artifact Keeper
            match self
                .create_user(
                    &user.name,
                    user.email.as_deref(),
                    user.admin.unwrap_or(false),
                )
                .await
            {
                Ok(user_id) => {
                    self.migration_service
                        .complete_item(item_id, &format!("user:{}", user_id), "")
                        .await?;
                    *completed += 1;
                }
                Err(e) => {
                    self.migration_service
                        .fail_item(item_id, &e.to_string())
                        .await?;
                    *failed += 1;
                }
            }

            // Update progress
            self.migration_service
                .update_job_progress(job_id, *completed, *failed, *skipped, 0)
                .await?;

            // Throttle
            if self.config.throttle_delay_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    self.config.throttle_delay_ms,
                ))
                .await;
            }
        }

        Ok(())
    }

    /// Create a user in Artifact Keeper
    async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        is_admin: bool,
    ) -> Result<Uuid, MigrationError> {
        let email = email.ok_or_else(|| MigrationError::ConfigError("Email required".into()))?;

        let user_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO users (username, email, role, status, metadata)
            VALUES ($1, $2, $3, 'active', $4)
            RETURNING id
            "#,
        )
        .bind(username)
        .bind(email)
        .bind(if is_admin { "admin" } else { "user" })
        .bind(serde_json::json!({
            "migrated_from": "artifactory",
            "original_username": username,
        }))
        .fetch_one(&self.db)
        .await?;

        Ok(user_id.0)
    }

    /// Migrate groups from Artifactory to Artifact Keeper
    pub async fn migrate_groups(
        &self,
        job_id: Uuid,
        client: Arc<ArtifactoryClient>,
        completed: &mut i32,
        failed: &mut i32,
        skipped: &mut i32,
        _progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        tracing::info!(job_id = %job_id, "Starting group migration");

        // List groups from Artifactory
        let groups = client.list_groups().await?;

        for group in &groups {
            let source_path = format!("group:{}", group.name);

            // Add migration item
            let item_id = self
                .add_migration_item(job_id, MigrationItemType::Group, &source_path, 0, None)
                .await?;

            // Check if group already exists
            let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE name = $1")
                .bind(&group.name)
                .fetch_optional(&self.db)
                .await?;

            if existing.is_some() {
                self.migration_service
                    .skip_item(item_id, "Group with this name already exists")
                    .await?;
                *skipped += 1;
                continue;
            }

            // Create group in Artifact Keeper
            match self
                .create_group(&group.name, group.description.as_deref())
                .await
            {
                Ok(group_id) => {
                    self.migration_service
                        .complete_item(item_id, &format!("group:{}", group_id), "")
                        .await?;
                    *completed += 1;
                }
                Err(e) => {
                    self.migration_service
                        .fail_item(item_id, &e.to_string())
                        .await?;
                    *failed += 1;
                }
            }

            // Update progress
            self.migration_service
                .update_job_progress(job_id, *completed, *failed, *skipped, 0)
                .await?;
        }

        Ok(())
    }

    /// Create a group in Artifact Keeper
    async fn create_group(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Uuid, MigrationError> {
        let group_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO groups (name, description, metadata)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(serde_json::json!({
            "migrated_from": "artifactory",
        }))
        .fetch_one(&self.db)
        .await?;

        Ok(group_id.0)
    }

    /// Migrate permissions from Artifactory to Artifact Keeper
    pub async fn migrate_permissions(
        &self,
        job_id: Uuid,
        client: Arc<ArtifactoryClient>,
        completed: &mut i32,
        failed: &mut i32,
        skipped: &mut i32,
        _progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        tracing::info!(job_id = %job_id, "Starting permission migration");

        // List permission targets from Artifactory
        let permissions_response = client.list_permissions().await?;

        for permission in &permissions_response.permissions {
            let source_path = format!("permission:{}", permission.name);

            // Add migration item
            let item_id = self
                .add_migration_item(job_id, MigrationItemType::Permission, &source_path, 0, None)
                .await?;

            // Extract repository permissions
            if let Some(ref repo) = permission.repo {
                if let Some(ref repos) = repo.repositories {
                    // Map each repository permission
                    for repo_key in repos {
                        // Find the repository in Artifact Keeper
                        let ak_repo: Option<(Uuid,)> =
                            sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                                .bind(repo_key)
                                .fetch_optional(&self.db)
                                .await?;

                        let repo_id = match ak_repo {
                            Some((id,)) => id,
                            None => {
                                tracing::warn!(
                                    permission = %permission.name,
                                    repo = %repo_key,
                                    "Repository not found, skipping permission"
                                );
                                continue;
                            }
                        };

                        // Process user permissions
                        if let Some(ref actions) = repo.actions {
                            if let Some(ref users) = actions.users {
                                for (username, perms) in users {
                                    for perm in perms {
                                        if let Some(mapped_perm) = crate::services::migration_service::MigrationService::map_permission(perm) {
                                            // Create permission in AK
                                            let _ = self.create_permission_rule(
                                                repo_id,
                                                Some(username),
                                                None,
                                                mapped_perm,
                                            ).await;
                                        }
                                    }
                                }
                            }

                            // Process group permissions
                            if let Some(ref groups) = actions.groups {
                                for (group_name, perms) in groups {
                                    for perm in perms {
                                        if let Some(mapped_perm) = crate::services::migration_service::MigrationService::map_permission(perm) {
                                            // Create permission in AK
                                            let _ = self.create_permission_rule(
                                                repo_id,
                                                None,
                                                Some(group_name),
                                                mapped_perm,
                                            ).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            self.migration_service
                .complete_item(item_id, &format!("permission:{}", permission.name), "")
                .await?;
            *completed += 1;

            // Update progress
            self.migration_service
                .update_job_progress(job_id, *completed, *failed, *skipped, 0)
                .await?;
        }

        Ok(())
    }

    /// Create a permission rule in Artifact Keeper
    async fn create_permission_rule(
        &self,
        repository_id: Uuid,
        username: Option<&str>,
        group_name: Option<&str>,
        permission: &str,
    ) -> Result<(), MigrationError> {
        // Look up user or group ID
        let (user_id, group_id) = if let Some(uname) = username {
            let user: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE username = $1")
                .bind(uname)
                .fetch_optional(&self.db)
                .await?;
            (user.map(|u| u.0), None)
        } else if let Some(gname) = group_name {
            let group: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE name = $1")
                .bind(gname)
                .fetch_optional(&self.db)
                .await?;
            (None, group.map(|g| g.0))
        } else {
            return Ok(());
        };

        // Insert permission (ignore duplicates)
        let _ = sqlx::query(
            r#"
            INSERT INTO repository_permissions (repository_id, user_id, group_id, permission)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(repository_id)
        .bind(user_id)
        .bind(group_id)
        .bind(permission)
        .execute(&self.db)
        .await;

        Ok(())
    }

    /// Check if the job has been paused via the database
    async fn is_paused(&self, job_id: Uuid) -> Result<bool, MigrationError> {
        let status: (String,) = sqlx::query_as("SELECT status FROM migration_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&self.db)
            .await?;
        Ok(status.0 == "paused" || status.0 == "cancelled")
    }

    /// Resume a paused migration job
    pub async fn resume_job(
        &self,
        job_id: Uuid,
        client: Arc<dyn SourceRegistry>,
        conflict_resolution: ConflictResolution,
        progress_tx: Option<mpsc::Sender<ProgressUpdate>>,
    ) -> Result<(), MigrationError> {
        // Get current progress
        let progress: (i32, i32, i32, i64) = sqlx::query_as(
            "SELECT completed_items, failed_items, skipped_items, transferred_bytes FROM migration_jobs WHERE id = $1"
        )
        .bind(job_id)
        .fetch_one(&self.db)
        .await?;

        tracing::info!(
            job_id = %job_id,
            completed = progress.0,
            "Resuming migration job from checkpoint"
        );

        // Continue processing from checkpoint
        // The implementation would skip already completed items
        self.process_job(job_id, client, conflict_resolution, progress_tx)
            .await
    }
}

/// Result of a successful artifact transfer
#[allow(dead_code)]
struct TransferResult {
    target_path: String,
    calculated_checksum: Option<String>,
    metadata: Option<std::collections::HashMap<String, Vec<String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_resolution_from_str() {
        assert_eq!(
            ConflictResolution::from_str("skip"),
            ConflictResolution::Skip
        );
        assert_eq!(
            ConflictResolution::from_str("overwrite"),
            ConflictResolution::Overwrite
        );
        assert_eq!(
            ConflictResolution::from_str("rename"),
            ConflictResolution::Rename
        );
        assert_eq!(
            ConflictResolution::from_str("unknown"),
            ConflictResolution::Skip
        );
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.max_retries, 3);
        assert!(config.verify_checksums);
    }

    // -----------------------------------------------------------------------
    // WorkerConfig - all fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_worker_config_default_all_fields() {
        let config = WorkerConfig::default();
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.throttle_delay_ms, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.batch_size, 100);
        assert!(config.verify_checksums);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_worker_config_custom() {
        let config = WorkerConfig {
            concurrency: 8,
            throttle_delay_ms: 0,
            max_retries: 5,
            batch_size: 500,
            verify_checksums: false,
            dry_run: true,
        };
        assert_eq!(config.concurrency, 8);
        assert_eq!(config.throttle_delay_ms, 0);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.batch_size, 500);
        assert!(!config.verify_checksums);
        assert!(config.dry_run);
    }

    #[test]
    fn test_worker_config_clone() {
        let config = WorkerConfig::default();
        let cloned = config.clone();
        assert_eq!(config.concurrency, cloned.concurrency);
        assert_eq!(config.throttle_delay_ms, cloned.throttle_delay_ms);
        assert_eq!(config.max_retries, cloned.max_retries);
        assert_eq!(config.batch_size, cloned.batch_size);
        assert_eq!(config.verify_checksums, cloned.verify_checksums);
        assert_eq!(config.dry_run, cloned.dry_run);
    }

    #[test]
    fn test_worker_config_debug() {
        let config = WorkerConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("WorkerConfig"));
        assert!(debug_str.contains("concurrency"));
    }

    // -----------------------------------------------------------------------
    // ConflictResolution - exhaustive from_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_resolution_from_str_skip() {
        assert_eq!(
            ConflictResolution::from_str("skip"),
            ConflictResolution::Skip
        );
        assert_eq!(
            ConflictResolution::from_str("SKIP"),
            ConflictResolution::Skip
        );
        assert_eq!(
            ConflictResolution::from_str("Skip"),
            ConflictResolution::Skip
        );
    }

    #[test]
    fn test_conflict_resolution_from_str_overwrite() {
        assert_eq!(
            ConflictResolution::from_str("overwrite"),
            ConflictResolution::Overwrite
        );
        assert_eq!(
            ConflictResolution::from_str("OVERWRITE"),
            ConflictResolution::Overwrite
        );
        assert_eq!(
            ConflictResolution::from_str("Overwrite"),
            ConflictResolution::Overwrite
        );
    }

    #[test]
    fn test_conflict_resolution_from_str_rename() {
        assert_eq!(
            ConflictResolution::from_str("rename"),
            ConflictResolution::Rename
        );
        assert_eq!(
            ConflictResolution::from_str("RENAME"),
            ConflictResolution::Rename
        );
        assert_eq!(
            ConflictResolution::from_str("Rename"),
            ConflictResolution::Rename
        );
    }

    #[test]
    fn test_conflict_resolution_from_str_defaults_to_skip() {
        assert_eq!(
            ConflictResolution::from_str("unknown"),
            ConflictResolution::Skip
        );
        assert_eq!(ConflictResolution::from_str(""), ConflictResolution::Skip);
        assert_eq!(
            ConflictResolution::from_str("merge"),
            ConflictResolution::Skip
        );
        assert_eq!(
            ConflictResolution::from_str("delete"),
            ConflictResolution::Skip
        );
    }

    #[test]
    fn test_conflict_resolution_eq() {
        assert_eq!(ConflictResolution::Skip, ConflictResolution::Skip);
        assert_eq!(ConflictResolution::Overwrite, ConflictResolution::Overwrite);
        assert_eq!(ConflictResolution::Rename, ConflictResolution::Rename);
        assert_ne!(ConflictResolution::Skip, ConflictResolution::Overwrite);
        assert_ne!(ConflictResolution::Skip, ConflictResolution::Rename);
        assert_ne!(ConflictResolution::Overwrite, ConflictResolution::Rename);
    }

    #[test]
    fn test_conflict_resolution_copy() {
        let cr = ConflictResolution::Overwrite;
        let copied = cr; // Copy
        assert_eq!(cr, copied);
    }

    #[test]
    fn test_conflict_resolution_debug() {
        let cr = ConflictResolution::Skip;
        let debug_str = format!("{:?}", cr);
        assert_eq!(debug_str, "Skip");
    }

    // -----------------------------------------------------------------------
    // ProgressUpdate construction and fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_update_construction() {
        let job_id = Uuid::new_v4();
        let update = ProgressUpdate {
            job_id,
            completed: 10,
            failed: 2,
            skipped: 3,
            transferred_bytes: 1024 * 1024,
            current_item: Some("libs-release/com/example/lib.jar".to_string()),
            status: MigrationJobStatus::Running,
        };
        assert_eq!(update.job_id, job_id);
        assert_eq!(update.completed, 10);
        assert_eq!(update.failed, 2);
        assert_eq!(update.skipped, 3);
        assert_eq!(update.transferred_bytes, 1024 * 1024);
        assert!(update.current_item.is_some());
    }

    #[test]
    fn test_progress_update_no_current_item() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 100,
            failed: 0,
            skipped: 5,
            transferred_bytes: 10_000_000,
            current_item: None,
            status: MigrationJobStatus::Completed,
        };
        assert!(update.current_item.is_none());
    }

    #[test]
    fn test_progress_update_clone() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 5,
            failed: 1,
            skipped: 0,
            transferred_bytes: 500,
            current_item: Some("test.jar".to_string()),
            status: MigrationJobStatus::Running,
        };
        let cloned = update.clone();
        assert_eq!(update.job_id, cloned.job_id);
        assert_eq!(update.completed, cloned.completed);
        assert_eq!(update.current_item, cloned.current_item);
    }

    #[test]
    fn test_progress_update_debug() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 0,
            failed: 0,
            skipped: 0,
            transferred_bytes: 0,
            current_item: None,
            status: MigrationJobStatus::Running,
        };
        let debug_str = format!("{:?}", update);
        assert!(debug_str.contains("ProgressUpdate"));
    }

    // -----------------------------------------------------------------------
    // TransferResult construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_transfer_result_construction() {
        let result = TransferResult {
            target_path: "libs-release/com/example/lib.jar".to_string(),
            calculated_checksum: Some("abc123def456".to_string()),
            metadata: Some(std::collections::HashMap::from([(
                "key".to_string(),
                vec!["value1".to_string(), "value2".to_string()],
            )])),
        };
        assert_eq!(result.target_path, "libs-release/com/example/lib.jar");
        assert!(result.calculated_checksum.is_some());
        assert!(result.metadata.is_some());
    }

    #[test]
    fn test_transfer_result_no_metadata() {
        let result = TransferResult {
            target_path: "repo/file.bin".to_string(),
            calculated_checksum: None,
            metadata: None,
        };
        assert!(result.calculated_checksum.is_none());
        assert!(result.metadata.is_none());
    }

    // -----------------------------------------------------------------------
    // MigrationJobStatus usage in progress updates
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_update_various_statuses() {
        let statuses = [
            MigrationJobStatus::Running,
            MigrationJobStatus::Completed,
            MigrationJobStatus::Failed,
            MigrationJobStatus::Cancelled,
        ];
        for status in &statuses {
            let update = ProgressUpdate {
                job_id: Uuid::new_v4(),
                completed: 0,
                failed: 0,
                skipped: 0,
                transferred_bytes: 0,
                current_item: None,
                status: *status,
            };
            let _ = format!("{:?}", update);
        }
    }
}
