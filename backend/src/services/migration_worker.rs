//! Migration worker - handles background migration processing.
//!
//! This worker processes migration jobs asynchronously, handling:
//! - Artifact downloads and uploads
//! - Checksum verification
//! - Progress tracking
//! - Checkpoint saving for resumability

use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::models::migration::{MigrationItemType, MigrationJobStatus};
use crate::services::artifact_service::ArtifactService;
use crate::services::artifactory_client::ArtifactoryClient;
use crate::services::migration_service::{ConflictType, MigrationError, MigrationService};
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
            // AQL default page size. Kept at 1000 (Artifactory's typical
            // ceiling) so a single page can cover most repositories without
            // hammering the source API. The migration worker still paginates
            // through as many pages as needed to enumerate every artifact.
            batch_size: 1000,
            verify_checksums: true,
            dry_run: false,
        }
    }
}

/// Maximum number of AQL pages a single repository migration is allowed to
/// fetch. Acts as a safety guard against an infinite pagination loop if the
/// source API misbehaves (for example, by always returning a full page of
/// results regardless of offset). At the default batch size of 1000 this
/// still lets a single repository contain up to 100 million artifacts.
pub(crate) const MAX_ARTIFACT_PAGES: usize = 100_000;

/// Decide whether artifact pagination should continue after processing a
/// page. The Artifactory AQL `range.total` field reports the number of rows
/// in the current page (not the overall result set), so the termination
/// decision must be based on page shape, not on a running total.
///
/// Returns `true` when the caller should fetch the next page, `false` when
/// the enumeration is complete.
pub(crate) fn should_fetch_next_page(page_len: usize, limit: i64) -> bool {
    if page_len == 0 {
        return false;
    }
    // A short page means we've reached the end of the result set. AQL always
    // fills pages up to the requested limit unless there are no more rows.
    let limit_usize = usize::try_from(limit.max(0)).unwrap_or(usize::MAX);
    page_len >= limit_usize
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

        // Provision destination repositories before transferring artifacts.
        //
        // Without this step, `transfer_artifact` looks up the destination
        // repository row inside an `if let Some(...) = repo_id` and silently
        // skips the `INSERT INTO artifacts` when the lookup misses. The job
        // then reports "completed" with bytes in CAS but no addressable
        // entries in the registry — silent data loss.
        //
        // We fetch the source-side repository list once, then for each repo
        // requested by the job ensure a destination row exists with the same
        // key. Conflicts (existing repo with same key but different type or
        // format) are logged and the source repo is skipped so the rest of
        // the job can still make progress.
        // `list_repositories` returns `ArtifactoryError`; the `?` converts via
        // `MigrationError::from(ArtifactoryError)` on the existing `#[from]` impl.
        let source_repos = client.list_repositories().await?;
        let mut repos_to_process: Vec<&String> = Vec::with_capacity(repos.len());
        for repo_key in &repos {
            let source_repo = match source_repos.iter().find(|r| r.key == *repo_key) {
                Some(r) => r,
                None => {
                    tracing::error!(
                        job_id = %job_id, repo = %repo_key,
                        "Source repository not found in source registry; skipping",
                    );
                    total_failed += 1;
                    continue;
                }
            };

            let migration_config =
                match MigrationService::prepare_repository_migration(source_repo, None) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            job_id = %job_id, repo = %repo_key, error = %e,
                            "Failed to prepare repository migration config; skipping",
                        );
                        total_failed += 1;
                        continue;
                    }
                };

            // Skip if a repo with the same key already exists with a
            // compatible type+format; recreate would be ambiguous and
            // potentially destructive. Surface incompatible matches as an
            // error so the operator can resolve manually.
            let conflict = self
                .migration_service
                .check_repository_conflict(
                    &migration_config.target_key,
                    migration_config.repo_type,
                    &migration_config.package_type,
                )
                .await?;
            if conflict.has_conflict {
                match conflict.conflict_type {
                    Some(ConflictType::SameKey) => {
                        tracing::info!(
                            job_id = %job_id, repo = %repo_key,
                            "Destination repository already exists with matching type+format; reusing",
                        );
                    }
                    _ => {
                        tracing::error!(
                            job_id = %job_id, repo = %repo_key,
                            conflict = ?conflict.conflict_type,
                            message = %conflict.message,
                            "Destination repository conflict; skipping artifact transfer for this repo",
                        );
                        total_failed += 1;
                        continue;
                    }
                }
            } else {
                match self
                    .migration_service
                    .create_repository(&migration_config)
                    .await
                {
                    Ok(_) => {
                        tracing::info!(
                            job_id = %job_id, repo = %repo_key,
                            format = %migration_config.package_type,
                            repo_type = ?migration_config.repo_type,
                            "Provisioned destination repository",
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            job_id = %job_id, repo = %repo_key, error = %e,
                            "Failed to create destination repository; skipping",
                        );
                        total_failed += 1;
                        continue;
                    }
                }
            }

            repos_to_process.push(repo_key);
        }

        // Process each repository
        for repo_key in repos_to_process {
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
        let final_status = determine_final_status(total_failed, total_completed);

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
        let limit = self.config.batch_size.max(1);
        let mut pages_fetched = 0usize;

        loop {
            // Safety guard: refuse to keep paginating forever if the source
            // API repeatedly returns full pages without advancing.
            if pages_fetched >= MAX_ARTIFACT_PAGES {
                tracing::warn!(
                    job_id = %job_id,
                    repo = %repo_key,
                    pages = pages_fetched,
                    "Reached MAX_ARTIFACT_PAGES while listing artifacts; stopping pagination"
                );
                break;
            }

            // List artifacts with pagination
            let artifacts = client.list_artifacts(repo_key, offset, limit).await?;
            pages_fetched += 1;

            let page_len = artifacts.results.len();

            if page_len == 0 {
                break;
            }

            for artifact in &artifacts.results {
                // Check for pause/cancel between artifacts
                if self.cancel_token.is_cancelled() || self.is_paused(job_id).await? {
                    return Ok(());
                }

                let artifact_path = build_artifact_path(&artifact.path, &artifact.name);

                let source_path = build_source_path(repo_key, &artifact_path);
                let size = artifact.size.unwrap_or(0);
                // Keep sha256 and sha1 separate so verification can compare
                // each digest against the corresponding locally computed
                // value. Picking a single "checksum" field and computing
                // only sha256 locally would cause a false mismatch whenever
                // the source advertises only sha1 (issue #856).
                let expected_sha256 = artifact.sha256.clone();
                let expected_sha1 = artifact.actual_sha1.clone();
                // Prefer sha256 for bookkeeping/dedup since that is what
                // Artifact Keeper uses internally.
                let item_checksum = expected_sha256.clone().or_else(|| expected_sha1.clone());

                // Skip if already completed (resume support)
                if self.is_item_already_completed(job_id, &source_path).await? {
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
                        item_checksum.as_deref(),
                    )
                    .await?;

                self.process_single_artifact(
                    item_id,
                    client.clone(),
                    repo_key,
                    &artifact_path,
                    &source_path,
                    size,
                    ExpectedChecksums {
                        sha256: expected_sha256,
                        sha1: expected_sha1,
                    },
                    conflict_resolution,
                    include_metadata,
                    completed,
                    failed,
                    skipped,
                    transferred,
                )
                .await?;

                // Update progress
                self.migration_service
                    .update_job_progress(job_id, *completed, *failed, *skipped, *transferred)
                    .await?;

                self.send_progress_update(
                    &progress_tx,
                    job_id,
                    *completed,
                    *failed,
                    *skipped,
                    *transferred,
                    Some(source_path.clone()),
                )
                .await;

                self.apply_throttle().await;
            }

            // Advance the cursor. AQL's `range.total` reports the count of
            // rows in the current page (matching `end_pos - start_pos`), so
            // termination must be decided from the page shape, not from a
            // running total. A short page (fewer rows than `limit`) means
            // the result set is exhausted.
            if !should_fetch_next_page(page_len, limit) {
                break;
            }

            // Guard against a pathological source that returns full pages
            // without advancing the cursor. This prevents an infinite loop
            // if the offset fails to move forward.
            let new_offset = offset.saturating_add(page_len as i64);
            if new_offset <= offset {
                tracing::warn!(
                    job_id = %job_id,
                    repo = %repo_key,
                    offset,
                    "AQL pagination cursor failed to advance; stopping to avoid infinite loop"
                );
                break;
            }
            offset = new_offset;
        }

        Ok(())
    }

    /// Check if a migration item was already completed (for resume support)
    async fn is_item_already_completed(
        &self,
        job_id: Uuid,
        source_path: &str,
    ) -> Result<bool, MigrationError> {
        let already_done: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM migration_items WHERE job_id = $1 AND source_path = $2 AND status = 'completed'"
        )
        .bind(job_id)
        .bind(source_path)
        .fetch_optional(&self.db)
        .await?;
        Ok(already_done.is_some())
    }

    /// Process a single artifact: check duplicates, transfer, verify, and update status
    #[allow(clippy::too_many_arguments)]
    async fn process_single_artifact(
        &self,
        item_id: Uuid,
        client: Arc<dyn SourceRegistry>,
        repo_key: &str,
        artifact_path: &str,
        source_path: &str,
        size: i64,
        expected: ExpectedChecksums,
        conflict_resolution: ConflictResolution,
        include_metadata: bool,
        completed: &mut i32,
        failed: &mut i32,
        skipped: &mut i32,
        transferred: &mut i64,
    ) -> Result<(), MigrationError> {
        // Prefer sha256 for duplicate detection since that is what Artifact
        // Keeper stores internally. Fall back to sha1 when the source only
        // provides that (common for older Nexus artifacts).
        let dedup_checksum = expected.sha256.clone().or_else(|| expected.sha1.clone());

        let should_skip = self
            .check_artifact_duplicate(source_path, dedup_checksum.as_deref(), conflict_resolution)
            .await?;

        if should_skip {
            self.migration_service
                .skip_item(item_id, "Artifact already exists")
                .await?;
            *skipped += 1;
            return Ok(());
        }

        match self
            .transfer_artifact(client, repo_key, artifact_path, include_metadata)
            .await
        {
            Ok(transfer_result) => {
                self.finalize_transfer(
                    item_id,
                    &transfer_result,
                    &expected,
                    size,
                    completed,
                    failed,
                    transferred,
                )
                .await?;
            }
            Err(e) => {
                self.migration_service
                    .fail_item(item_id, &e.to_string())
                    .await?;
                *failed += 1;
            }
        }

        Ok(())
    }

    /// Verify checksum and record transfer result as completed or failed
    #[allow(clippy::too_many_arguments)]
    async fn finalize_transfer(
        &self,
        item_id: Uuid,
        transfer_result: &TransferResult,
        expected: &ExpectedChecksums,
        size: i64,
        completed: &mut i32,
        failed: &mut i32,
        transferred: &mut i64,
    ) -> Result<(), MigrationError> {
        if let Some(mismatch) = self.verify_transfer_checksums(expected, transfer_result) {
            self.migration_service.fail_item(item_id, &mismatch).await?;
            *failed += 1;
            return Ok(());
        }

        self.migration_service
            .complete_item(
                item_id,
                &transfer_result.target_path,
                transfer_result.calculated_checksum.as_deref().unwrap_or(""),
            )
            .await?;
        *completed += 1;
        *transferred += size;
        Ok(())
    }

    /// Verify a transfer's checksums against the expected values.
    ///
    /// Compares each advertised digest (sha256 and sha1) against the
    /// locally computed digest of the same algorithm. A previous version
    /// of this check compared the single "best" expected digest against a
    /// locally computed sha256, which produced a guaranteed false positive
    /// whenever the source only advertised sha1 (issue #856).
    ///
    /// Returns `None` when verification passes or is not applicable, and
    /// `Some(error_message)` when a mismatch is detected.
    fn verify_transfer_checksums(
        &self,
        expected: &ExpectedChecksums,
        actual: &TransferResult,
    ) -> Option<String> {
        verify_expected_checksums(
            self.config.verify_checksums,
            expected,
            actual.calculated_sha256.as_deref(),
            actual.calculated_sha1.as_deref(),
        )
    }

    /// Send a progress update through the channel, if one is configured
    #[allow(clippy::too_many_arguments)]
    async fn send_progress_update(
        &self,
        progress_tx: &Option<mpsc::Sender<ProgressUpdate>>,
        job_id: Uuid,
        completed: i32,
        failed: i32,
        skipped: i32,
        transferred_bytes: i64,
        current_item: Option<String>,
    ) {
        if let Some(ref tx) = progress_tx {
            let _ = tx
                .send(ProgressUpdate {
                    job_id,
                    completed,
                    failed,
                    skipped,
                    transferred_bytes,
                    current_item,
                    status: MigrationJobStatus::Running,
                })
                .await;
        }
    }

    /// Apply throttle delay between artifact transfers if configured
    async fn apply_throttle(&self) {
        if self.config.throttle_delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                self.config.throttle_delay_ms,
            ))
            .await;
        }
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

        // Calculate both sha256 and sha1. Computing both lets the
        // verification step compare the source's advertised digest against
        // the matching locally computed value regardless of which algorithm
        // the source uses (issue #856).
        let (sha256_hex, sha1_hex) = compute_dual_checksums(&artifact_data);

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
        let storage_key = ArtifactService::storage_key_from_checksum(&sha256_hex);

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
                let name = extract_name_from_path(artifact_path);
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
                .bind(&sha256_hex)
                .bind(&storage_key)
                .execute(&self.db)
                .await?;
            }
        }

        let target_path = build_source_path(repo_key, artifact_path);

        tracing::debug!(
            path = %artifact_path,
            size = content_size,
            sha256 = %sha256_hex,
            sha1 = %sha1_hex,
            "Artifact transferred"
        );

        Ok(TransferResult {
            target_path,
            calculated_checksum: Some(sha256_hex.clone()),
            calculated_sha256: Some(sha256_hex),
            calculated_sha1: Some(sha1_hex),
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

            self.process_permission_target(permission).await?;

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

    /// Process a single permission target by iterating its repositories and applying rules
    async fn process_permission_target(
        &self,
        permission: &crate::services::artifactory_client::PermissionTarget,
    ) -> Result<(), MigrationError> {
        let repo = match permission.repo {
            Some(ref r) => r,
            None => return Ok(()),
        };
        let repos = match repo.repositories {
            Some(ref r) => r,
            None => return Ok(()),
        };

        for repo_key in repos {
            let repo_id = match self.lookup_repository_id(repo_key).await? {
                Some(id) => id,
                None => {
                    tracing::warn!(
                        permission = %permission.name,
                        repo = %repo_key,
                        "Repository not found, skipping permission"
                    );
                    continue;
                }
            };

            self.apply_repo_permission_actions(repo_id, repo).await?;
        }

        Ok(())
    }

    /// Look up a repository ID by its key
    async fn lookup_repository_id(&self, repo_key: &str) -> Result<Option<Uuid>, MigrationError> {
        let ak_repo: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
            .bind(repo_key)
            .fetch_optional(&self.db)
            .await?;
        Ok(ak_repo.map(|(id,)| id))
    }

    /// Apply user and group permission actions for a single repository
    async fn apply_repo_permission_actions(
        &self,
        repo_id: Uuid,
        repo: &crate::services::artifactory_client::PermissionRepo,
    ) -> Result<(), MigrationError> {
        let actions = match repo.actions {
            Some(ref a) => a,
            None => return Ok(()),
        };

        if let Some(ref users) = actions.users {
            for (username, perms) in users {
                self.apply_principal_permissions(repo_id, Some(username), None, perms)
                    .await?;
            }
        }

        if let Some(ref groups) = actions.groups {
            for (group_name, perms) in groups {
                self.apply_principal_permissions(repo_id, None, Some(group_name), perms)
                    .await?;
            }
        }

        Ok(())
    }

    /// Apply mapped permissions for a single user or group principal
    async fn apply_principal_permissions(
        &self,
        repo_id: Uuid,
        username: Option<&str>,
        group_name: Option<&str>,
        perms: &[String],
    ) -> Result<(), MigrationError> {
        for perm in perms {
            let mapped = crate::services::migration_service::MigrationService::map_permission(perm);
            if let Some(mapped_perm) = mapped {
                let _ = self
                    .create_permission_rule(repo_id, username, group_name, mapped_perm)
                    .await;
            }
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

/// Result of a successful artifact transfer.
///
/// Carries both locally computed digests so the caller can compare against
/// whichever algorithm the source advertised (issue #856).
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct TransferResult {
    target_path: String,
    /// Legacy alias for `calculated_sha256`, retained so existing callers
    /// that inspect `calculated_checksum` continue to see the sha256 value.
    calculated_checksum: Option<String>,
    calculated_sha256: Option<String>,
    calculated_sha1: Option<String>,
    metadata: Option<std::collections::HashMap<String, Vec<String>>>,
}

/// Digests that the source registry declared for an artifact.
///
/// Both fields are optional because sources vary in what they report.
/// Nexus, for example, always returns `sha1` for Maven artifacts but may
/// omit `sha256` for older ones. Keeping them separate lets the worker
/// compare each advertised digest against the matching locally computed
/// value instead of guessing which algorithm to verify against (issue
/// #856).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ExpectedChecksums {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
}

impl ExpectedChecksums {
    /// Returns true when at least one digest was declared.
    #[allow(dead_code)]
    pub fn has_any(&self) -> bool {
        self.sha256.is_some() || self.sha1.is_some()
    }
}

/// Compute both sha256 and sha1 hex digests over the same payload in a
/// single pass over the bytes. Returns `(sha256_hex, sha1_hex)`.
pub(crate) fn compute_dual_checksums(data: &[u8]) -> (String, String) {
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let sha256_hex = hex::encode(sha256.finalize());

    let mut sha1 = Sha1::new();
    sha1.update(data);
    let sha1_hex = hex::encode(sha1.finalize());

    (sha256_hex, sha1_hex)
}

/// Compare each advertised digest against the matching locally computed
/// digest. Returns `None` when verification passes (all advertised digests
/// match, or verification is disabled, or no digests were advertised) and
/// `Some(error_message)` when any advertised digest disagrees with the
/// locally computed value of the same algorithm.
///
/// Comparison is hex and case-insensitive. A missing local digest for an
/// algorithm the source advertised is treated as a verification failure
/// rather than a pass, so we never silently accept an unverified artifact
/// when the user has verification enabled.
pub(crate) fn verify_expected_checksums(
    verify_enabled: bool,
    expected: &ExpectedChecksums,
    actual_sha256: Option<&str>,
    actual_sha1: Option<&str>,
) -> Option<String> {
    if !verify_enabled {
        return None;
    }

    if let Some(exp_sha256) = expected.sha256.as_deref() {
        let exp_norm = exp_sha256.to_ascii_lowercase();
        match actual_sha256 {
            Some(actual) if actual.eq_ignore_ascii_case(&exp_norm) => {}
            Some(actual) => {
                return Some(format!(
                    "Checksum mismatch (sha256): expected {}, got {}",
                    exp_norm, actual
                ));
            }
            None => {
                return Some(format!(
                    "Checksum mismatch (sha256): expected {}, got none",
                    exp_norm
                ));
            }
        }
    }

    if let Some(exp_sha1) = expected.sha1.as_deref() {
        let exp_norm = exp_sha1.to_ascii_lowercase();
        match actual_sha1 {
            Some(actual) if actual.eq_ignore_ascii_case(&exp_norm) => {}
            Some(actual) => {
                return Some(format!(
                    "Checksum mismatch (sha1): expected {}, got {}",
                    exp_norm, actual
                ));
            }
            None => {
                return Some(format!(
                    "Checksum mismatch (sha1): expected {}, got none",
                    exp_norm
                ));
            }
        }
    }

    None
}

/// Determine the final job status based on completed and failed counts.
/// Returns Failed only when all items failed (failed > 0 and completed == 0),
/// otherwise returns Completed.
pub(crate) fn determine_final_status(
    total_failed: i32,
    total_completed: i32,
) -> MigrationJobStatus {
    if total_failed > 0 && total_completed == 0 {
        MigrationJobStatus::Failed
    } else {
        MigrationJobStatus::Completed
    }
}

/// Check whether an expected checksum matches an actual checksum.
///
/// Returns true (pass) when verification is disabled, when either value
/// is missing, or when both values are present and equal. This is a thin
/// legacy wrapper retained so callers and tests outside the worker can
/// still perform a single-digest comparison; the worker itself now uses
/// [`verify_expected_checksums`] to compare each advertised digest against
/// the locally computed value of the same algorithm (issue #856).
#[allow(dead_code)]
pub(crate) fn verify_checksums_match(
    verify_enabled: bool,
    expected: &Option<String>,
    actual: &Option<String>,
) -> bool {
    if !verify_enabled {
        return true;
    }
    match (expected, actual) {
        (Some(exp), Some(act)) => exp.eq_ignore_ascii_case(act),
        _ => true,
    }
}

/// Build the artifact path from the directory path and artifact name.
/// When the path is "." (root), the name alone is used.
pub(crate) fn build_artifact_path(path: &str, name: &str) -> String {
    if path == "." {
        name.to_string()
    } else {
        format!("{}/{}", path, name)
    }
}

/// Build the full source path by combining a repository key with an artifact path.
pub(crate) fn build_source_path(repo_key: &str, artifact_path: &str) -> String {
    format!("{}/{}", repo_key, artifact_path)
}

/// Extract the file name from an artifact path.
/// Returns the portion after the last '/' separator, or the entire
/// string if no separator is present.
pub(crate) fn extract_name_from_path(artifact_path: &str) -> &str {
    artifact_path.rsplit('/').next().unwrap_or(artifact_path)
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
        assert_eq!(config.batch_size, 1000);
        assert!(config.verify_checksums);
        assert!(!config.dry_run);
    }

    // -----------------------------------------------------------------------
    // should_fetch_next_page (#671 pagination fix)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_fetch_next_page_full_page_continues() {
        // A full page (page_len == limit) means more rows are likely available
        assert!(should_fetch_next_page(1000, 1000));
        assert!(should_fetch_next_page(100, 100));
    }

    #[test]
    fn test_should_fetch_next_page_short_page_terminates() {
        // A short page (page_len < limit) means the result set is exhausted
        assert!(!should_fetch_next_page(42, 1000));
        assert!(!should_fetch_next_page(999, 1000));
    }

    #[test]
    fn test_should_fetch_next_page_empty_terminates() {
        // An empty page always terminates
        assert!(!should_fetch_next_page(0, 1000));
        assert!(!should_fetch_next_page(0, 1));
    }

    #[test]
    fn test_should_fetch_next_page_negative_limit_handled() {
        // Defensive: negative or zero limits should not panic
        assert!(!should_fetch_next_page(0, -1));
        assert!(should_fetch_next_page(5, -1));
    }

    #[test]
    fn test_should_fetch_next_page_boundary_limit_of_one() {
        // A single-row page with limit=1 means more rows could exist
        assert!(should_fetch_next_page(1, 1));
        // Zero rows with limit=1 means empty result set
        assert!(!should_fetch_next_page(0, 1));
    }

    #[test]
    fn test_should_fetch_next_page_limit_zero_always_continues() {
        // Zero limit collapses to max usize so any non-empty page continues
        assert!(should_fetch_next_page(1, 0));
        assert!(!should_fetch_next_page(0, 0));
    }

    #[test]
    fn test_should_fetch_next_page_page_larger_than_limit() {
        // Defensive: if the server returns more rows than requested,
        // treat it as a full page (continue fetching)
        assert!(should_fetch_next_page(200, 100));
    }

    #[test]
    fn test_max_artifact_pages_constant_is_safety_guard() {
        // Sanity check the safety guard is reasonable: with 1000 rows per
        // page, this allows enumerating up to 100M artifacts in a single
        // repository before bailing out.
        let min_pages = 10_000;
        assert!(MAX_ARTIFACT_PAGES >= min_pages);
    }

    #[test]
    fn test_default_batch_size_is_reasonable_for_aql() {
        // Default batch size should be large enough to avoid excessive
        // round trips but not so large it stresses the source API.
        let config = WorkerConfig::default();
        assert!(config.batch_size >= 100);
        assert!(config.batch_size <= 10_000);
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
            calculated_sha256: Some("abc123def456".to_string()),
            calculated_sha1: Some("abc1".to_string()),
            metadata: Some(std::collections::HashMap::from([(
                "key".to_string(),
                vec!["value1".to_string(), "value2".to_string()],
            )])),
        };
        assert_eq!(result.target_path, "libs-release/com/example/lib.jar");
        assert!(result.calculated_checksum.is_some());
        assert!(result.calculated_sha256.is_some());
        assert!(result.calculated_sha1.is_some());
        assert!(result.metadata.is_some());
    }

    #[test]
    fn test_transfer_result_no_metadata() {
        let result = TransferResult {
            target_path: "repo/file.bin".to_string(),
            ..TransferResult::default()
        };
        assert!(result.calculated_checksum.is_none());
        assert!(result.calculated_sha256.is_none());
        assert!(result.calculated_sha1.is_none());
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

    // -----------------------------------------------------------------------
    // determine_final_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_determine_final_status_all_completed() {
        let status = determine_final_status(0, 50);
        assert_eq!(status, MigrationJobStatus::Completed);
    }

    #[test]
    fn test_determine_final_status_all_failed() {
        let status = determine_final_status(10, 0);
        assert_eq!(status, MigrationJobStatus::Failed);
    }

    #[test]
    fn test_determine_final_status_mixed() {
        let status = determine_final_status(3, 7);
        assert_eq!(status, MigrationJobStatus::Completed);
    }

    #[test]
    fn test_determine_final_status_no_items() {
        let status = determine_final_status(0, 0);
        assert_eq!(status, MigrationJobStatus::Completed);
    }

    #[test]
    fn test_determine_final_status_one_failure_one_success() {
        let status = determine_final_status(1, 1);
        assert_eq!(status, MigrationJobStatus::Completed);
    }

    #[test]
    fn test_determine_final_status_single_failure() {
        let status = determine_final_status(1, 0);
        assert_eq!(status, MigrationJobStatus::Failed);
    }

    #[test]
    fn test_determine_final_status_large_counts() {
        assert_eq!(
            determine_final_status(0, 100_000),
            MigrationJobStatus::Completed
        );
        assert_eq!(
            determine_final_status(100_000, 0),
            MigrationJobStatus::Failed
        );
        assert_eq!(
            determine_final_status(50_000, 50_000),
            MigrationJobStatus::Completed
        );
    }

    // -----------------------------------------------------------------------
    // verify_checksums_match
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_checksums_match_disabled() {
        let expected = Some("abc123".to_string());
        let actual = Some("different".to_string());
        assert!(verify_checksums_match(false, &expected, &actual));
    }

    #[test]
    fn test_verify_checksums_match_both_present_equal() {
        let expected = Some("abc123".to_string());
        let actual = Some("abc123".to_string());
        assert!(verify_checksums_match(true, &expected, &actual));
    }

    #[test]
    fn test_verify_checksums_match_both_present_different() {
        let expected = Some("abc123".to_string());
        let actual = Some("def456".to_string());
        assert!(!verify_checksums_match(true, &expected, &actual));
    }

    #[test]
    fn test_verify_checksums_match_expected_none() {
        let actual = Some("abc123".to_string());
        assert!(verify_checksums_match(true, &None, &actual));
    }

    #[test]
    fn test_verify_checksums_match_actual_none() {
        let expected = Some("abc123".to_string());
        assert!(verify_checksums_match(true, &expected, &None));
    }

    #[test]
    fn test_verify_checksums_match_both_none() {
        assert!(verify_checksums_match(true, &None, &None));
    }

    #[test]
    fn test_verify_checksums_match_disabled_both_none() {
        assert!(verify_checksums_match(false, &None, &None));
    }

    #[test]
    fn test_verify_checksums_match_empty_strings() {
        let expected = Some(String::new());
        let actual = Some(String::new());
        assert!(verify_checksums_match(true, &expected, &actual));
    }

    #[test]
    fn test_verify_checksums_match_case_insensitive() {
        // Updated behavior (issue #856): some registries return digests in
        // uppercase hex, so the single-digest helper now performs a
        // case-insensitive comparison to stay in sync with
        // `verify_expected_checksums`.
        let expected = Some("ABC123".to_string());
        let actual = Some("abc123".to_string());
        assert!(verify_checksums_match(true, &expected, &actual));
    }

    // -----------------------------------------------------------------------
    // build_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_path_root() {
        assert_eq!(build_artifact_path(".", "lib.jar"), "lib.jar");
    }

    #[test]
    fn test_build_artifact_path_nested() {
        assert_eq!(
            build_artifact_path("com/example", "lib.jar"),
            "com/example/lib.jar"
        );
    }

    #[test]
    fn test_build_artifact_path_single_directory() {
        assert_eq!(
            build_artifact_path("libs", "artifact.tar.gz"),
            "libs/artifact.tar.gz"
        );
    }

    #[test]
    fn test_build_artifact_path_deep_nesting() {
        assert_eq!(
            build_artifact_path(
                "org/apache/maven/plugins",
                "maven-compiler-plugin-3.11.0.jar"
            ),
            "org/apache/maven/plugins/maven-compiler-plugin-3.11.0.jar"
        );
    }

    #[test]
    fn test_build_artifact_path_empty_name_at_root() {
        assert_eq!(build_artifact_path(".", ""), "");
    }

    #[test]
    fn test_build_artifact_path_empty_path() {
        assert_eq!(build_artifact_path("", "file.jar"), "/file.jar");
    }

    // -----------------------------------------------------------------------
    // build_source_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_source_path_simple() {
        assert_eq!(
            build_source_path("libs-release", "com/example/lib.jar"),
            "libs-release/com/example/lib.jar"
        );
    }

    #[test]
    fn test_build_source_path_root_artifact() {
        assert_eq!(build_source_path("my-repo", "file.bin"), "my-repo/file.bin");
    }

    #[test]
    fn test_build_source_path_empty_repo() {
        assert_eq!(build_source_path("", "file.jar"), "/file.jar");
    }

    #[test]
    fn test_build_source_path_empty_artifact() {
        assert_eq!(build_source_path("repo", ""), "repo/");
    }

    // -----------------------------------------------------------------------
    // extract_name_from_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_from_path_nested() {
        assert_eq!(
            extract_name_from_path("com/example/lib-1.0.jar"),
            "lib-1.0.jar"
        );
    }

    #[test]
    fn test_extract_name_from_path_root_file() {
        assert_eq!(extract_name_from_path("file.jar"), "file.jar");
    }

    #[test]
    fn test_extract_name_from_path_deep() {
        assert_eq!(
            extract_name_from_path("org/apache/maven/plugins/maven-compiler-plugin-3.11.0.jar"),
            "maven-compiler-plugin-3.11.0.jar"
        );
    }

    #[test]
    fn test_extract_name_from_path_empty() {
        assert_eq!(extract_name_from_path(""), "");
    }

    #[test]
    fn test_extract_name_from_path_trailing_slash() {
        assert_eq!(extract_name_from_path("com/example/"), "");
    }

    #[test]
    fn test_extract_name_from_path_no_extension() {
        assert_eq!(extract_name_from_path("dir/LICENSE"), "LICENSE");
    }

    #[test]
    fn test_extract_name_from_path_dots_in_name() {
        assert_eq!(
            extract_name_from_path("repo/artifact-1.2.3-SNAPSHOT.jar"),
            "artifact-1.2.3-SNAPSHOT.jar"
        );
    }

    // -----------------------------------------------------------------------
    // Integration of helpers: artifact path -> source path -> name extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_path_pipeline_root_artifact() {
        let artifact_path = build_artifact_path(".", "my-library.jar");
        let source_path = build_source_path("libs-release", &artifact_path);
        let name = extract_name_from_path(&artifact_path);

        assert_eq!(artifact_path, "my-library.jar");
        assert_eq!(source_path, "libs-release/my-library.jar");
        assert_eq!(name, "my-library.jar");
    }

    #[test]
    fn test_full_path_pipeline_nested_artifact() {
        let artifact_path = build_artifact_path("com/example/1.0", "example-1.0.pom");
        let source_path = build_source_path("maven-central", &artifact_path);
        let name = extract_name_from_path(&artifact_path);

        assert_eq!(artifact_path, "com/example/1.0/example-1.0.pom");
        assert_eq!(source_path, "maven-central/com/example/1.0/example-1.0.pom");
        assert_eq!(name, "example-1.0.pom");
    }

    // -----------------------------------------------------------------------
    // TransferResult with metadata map
    // -----------------------------------------------------------------------

    #[test]
    fn test_transfer_result_metadata_multiple_keys() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("build.name".to_string(), vec!["my-build".to_string()]);
        metadata.insert(
            "build.number".to_string(),
            vec!["42".to_string(), "43".to_string()],
        );

        let result = TransferResult {
            target_path: "repo/artifact.jar".to_string(),
            calculated_checksum: Some("deadbeef".to_string()),
            calculated_sha256: Some("deadbeef".to_string()),
            calculated_sha1: None,
            metadata: Some(metadata),
        };

        let meta = result.metadata.as_ref().unwrap();
        assert_eq!(meta.len(), 2);
        assert_eq!(meta["build.name"], vec!["my-build".to_string()]);
        assert_eq!(meta["build.number"].len(), 2);
    }

    #[test]
    fn test_transfer_result_empty_metadata() {
        let result = TransferResult {
            target_path: "repo/file.bin".to_string(),
            metadata: Some(std::collections::HashMap::new()),
            ..TransferResult::default()
        };
        assert!(result.metadata.as_ref().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // ProgressUpdate - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_progress_update_zero_bytes() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 50,
            failed: 0,
            skipped: 0,
            transferred_bytes: 0,
            current_item: None,
            status: MigrationJobStatus::Running,
        };
        assert_eq!(update.transferred_bytes, 0);
        assert_eq!(update.completed, 50);
    }

    #[test]
    fn test_progress_update_large_transfer() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 10_000,
            failed: 100,
            skipped: 500,
            transferred_bytes: 1_000_000_000_000, // 1 TB
            current_item: Some("large-artifact.tar.gz".to_string()),
            status: MigrationJobStatus::Running,
        };
        assert_eq!(update.transferred_bytes, 1_000_000_000_000);
        assert_eq!(update.completed, 10_000);
    }

    #[test]
    fn test_progress_update_failed_status() {
        let update = ProgressUpdate {
            job_id: Uuid::new_v4(),
            completed: 0,
            failed: 50,
            skipped: 0,
            transferred_bytes: 0,
            current_item: None,
            status: MigrationJobStatus::Failed,
        };
        assert_eq!(update.failed, 50);
        assert_eq!(update.completed, 0);
    }

    // -----------------------------------------------------------------------
    // ConflictResolution - mixed case and whitespace-adjacent
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_resolution_from_str_mixed_case() {
        assert_eq!(
            ConflictResolution::from_str("oVeRwRiTe"),
            ConflictResolution::Overwrite
        );
        assert_eq!(
            ConflictResolution::from_str("rEnAmE"),
            ConflictResolution::Rename
        );
    }

    #[test]
    fn test_conflict_resolution_from_str_whitespace_not_trimmed() {
        assert_eq!(
            ConflictResolution::from_str(" skip "),
            ConflictResolution::Skip
        );
        assert_eq!(
            ConflictResolution::from_str(" overwrite"),
            ConflictResolution::Skip
        );
    }

    // -----------------------------------------------------------------------
    // WorkerConfig - boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn test_worker_config_zero_concurrency() {
        let config = WorkerConfig {
            concurrency: 0,
            ..WorkerConfig::default()
        };
        assert_eq!(config.concurrency, 0);
    }

    #[test]
    fn test_worker_config_max_retries_zero() {
        let config = WorkerConfig {
            max_retries: 0,
            ..WorkerConfig::default()
        };
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_worker_config_large_batch_size() {
        let config = WorkerConfig {
            batch_size: i64::MAX,
            ..WorkerConfig::default()
        };
        assert_eq!(config.batch_size, i64::MAX);
    }

    // -----------------------------------------------------------------------
    // compute_dual_checksums (issue #856)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_dual_checksums_empty_payload() {
        // Known reference values for the empty string.
        let (sha256, sha1) = compute_dual_checksums(b"");
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_compute_dual_checksums_known_payload() {
        // Known reference values for the ASCII string "abc".
        let (sha256, sha1) = compute_dual_checksums(b"abc");
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_compute_dual_checksums_digest_lengths() {
        // Guard against algorithm swaps: sha256 hex is 64 chars, sha1 is 40.
        let (sha256, sha1) = compute_dual_checksums(b"the quick brown fox");
        assert_eq!(sha256.len(), 64);
        assert_eq!(sha1.len(), 40);
    }

    // -----------------------------------------------------------------------
    // verify_expected_checksums (issue #856)
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_expected_checksums_disabled_skips_everything() {
        // When verification is disabled the function must never report a
        // mismatch, even if the advertised and computed digests differ.
        let expected = ExpectedChecksums {
            sha256: Some("deadbeef".into()),
            sha1: Some("feedface".into()),
        };
        assert!(verify_expected_checksums(false, &expected, Some("00"), Some("00")).is_none());
    }

    #[test]
    fn test_verify_expected_checksums_no_expected_values() {
        // With nothing advertised there's nothing to verify against.
        let expected = ExpectedChecksums::default();
        assert!(verify_expected_checksums(true, &expected, Some("abc"), Some("def")).is_none());
    }

    #[test]
    fn test_verify_expected_checksums_sha256_match() {
        let (sha256, sha1) = compute_dual_checksums(b"hello world");
        let expected = ExpectedChecksums {
            sha256: Some(sha256.clone()),
            sha1: None,
        };
        assert!(verify_expected_checksums(true, &expected, Some(&sha256), Some(&sha1)).is_none());
    }

    #[test]
    fn test_verify_expected_checksums_sha1_only_match() {
        // Regression test for issue #856: when the source (e.g. Nexus) only
        // advertises sha1, verification must compare sha1 to sha1. Before
        // the fix the worker always computed sha256 locally and compared it
        // against the advertised sha1, guaranteeing a false mismatch.
        let (_sha256, sha1) = compute_dual_checksums(b"hello world");
        let expected = ExpectedChecksums {
            sha256: None,
            sha1: Some(sha1.clone()),
        };
        let result = verify_expected_checksums(
            true,
            &expected,
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            Some(&sha1),
        );
        assert!(
            result.is_none(),
            "sha1-only match should pass, got: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_expected_checksums_sha1_only_mismatch_reports_sha1_not_sha256() {
        // The reporter's log showed "expected <sha1>, got <sha256>". After
        // the fix, a genuine sha1 mismatch must report algorithms that
        // actually disagreed, and sha256 must never be compared against an
        // advertised sha1.
        let expected = ExpectedChecksums {
            sha256: None,
            sha1: Some("0692b094dbd155ac5885d8369b32d4cb8dadf74d".into()),
        };
        let (actual_sha256, actual_sha1) = compute_dual_checksums(b"corrupted");
        let result =
            verify_expected_checksums(true, &expected, Some(&actual_sha256), Some(&actual_sha1));
        let message = result.expect("expected a mismatch");
        assert!(
            message.contains("sha1"),
            "expected sha1 mismatch message, got: {}",
            message
        );
        assert!(
            !message.contains("sha256"),
            "sha1-only expectation should not mention sha256, got: {}",
            message
        );
    }

    #[test]
    fn test_verify_expected_checksums_both_advertised_both_match() {
        let (sha256, sha1) = compute_dual_checksums(b"payload");
        let expected = ExpectedChecksums {
            sha256: Some(sha256.clone()),
            sha1: Some(sha1.clone()),
        };
        assert!(verify_expected_checksums(true, &expected, Some(&sha256), Some(&sha1)).is_none());
    }

    #[test]
    fn test_verify_expected_checksums_sha256_mismatch_reported_first() {
        // When both digests are advertised and sha256 is the one that
        // disagrees, the reported error must call out sha256.
        let expected = ExpectedChecksums {
            sha256: Some("00".into()),
            sha1: Some("11".into()),
        };
        let result = verify_expected_checksums(true, &expected, Some("ff"), Some("22"));
        let msg = result.expect("mismatch");
        assert!(msg.contains("sha256"), "{}", msg);
    }

    #[test]
    fn test_verify_expected_checksums_case_insensitive() {
        // Nexus and Artifactory have both been observed emitting digests in
        // uppercase hex on older releases. Comparison must ignore case.
        let expected = ExpectedChecksums {
            sha256: None,
            sha1: Some("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709".into()),
        };
        let result = verify_expected_checksums(
            true,
            &expected,
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        );
        assert!(
            result.is_none(),
            "case-insensitive match failed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_expected_checksums_missing_local_digest_is_mismatch() {
        // If the source advertises a sha1 but for some reason the worker
        // has no local sha1, fail loudly instead of silently passing.
        let expected = ExpectedChecksums {
            sha256: None,
            sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".into()),
        };
        let result = verify_expected_checksums(true, &expected, Some("abcd"), None);
        assert!(result.is_some());
    }

    #[test]
    fn test_expected_checksums_has_any() {
        assert!(!ExpectedChecksums::default().has_any());
        assert!(ExpectedChecksums {
            sha256: Some("x".into()),
            sha1: None,
        }
        .has_any());
        assert!(ExpectedChecksums {
            sha256: None,
            sha1: Some("y".into()),
        }
        .has_any());
    }

    // -----------------------------------------------------------------------
    // WorkerConfig.verify_checksums default (issue #856 plumbing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_worker_config_default_verifies_checksums() {
        // Verification must be enabled by default so existing users do not
        // silently accept corrupted artifacts after an upgrade.
        let config = WorkerConfig::default();
        assert!(config.verify_checksums);
    }

    #[test]
    fn test_worker_config_verify_checksums_can_be_disabled() {
        let config = WorkerConfig {
            verify_checksums: false,
            ..WorkerConfig::default()
        };
        assert!(!config.verify_checksums);
    }
}
