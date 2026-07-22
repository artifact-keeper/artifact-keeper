//! Migration worker - handles background migration processing.
//!
//! This worker processes migration jobs asynchronously, handling:
//! - Artifact downloads and uploads
//! - Checksum verification
//! - Progress tracking
//! - Checkpoint saving for resumability

use crate::models::migration::{MigrationItemType, MigrationJobStatus};
use crate::services::artifact_service::ArtifactService;
use crate::services::artifactory_client::ArtifactoryClient;
use crate::services::migration_service::{
    ConflictType, MigrationError, MigrationService, RepositoryType,
};
use crate::services::opensearch_service::{ArtifactDocument, OpenSearchService};
use crate::services::source_registry::SourceRegistry;
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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
    /// Filesystem base under which streamed artifact bodies are spilled while
    /// checksums are computed and before the storage put. This MUST live on
    /// the same durable volume as `STORAGE_PATH` (not the pod's ephemeral
    /// `/tmp`); otherwise a multi-GiB Maven JAR fills `/tmp` and triggers
    /// Kubernetes pod eviction (issue #1608, same class as the incus upload
    /// fix #1622). When empty, the OS temp dir is used as a fallback so unit
    /// tests and `WorkerConfig::default()` callers keep working.
    pub staging_path: String,
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
            // Empty => fall back to the OS temp dir. Production call sites
            // override this with `STORAGE_PATH` so spills land on the durable
            // storage volume rather than the pod's ephemeral `/tmp`.
            staging_path: String::new(),
        }
    }
}

/// Resolve the directory under which streamed artifact bodies are spilled and
/// ensure it exists.
///
/// When `staging_path` is non-empty it is used verbatim as the spill base and
/// created (recursively) if missing — mirroring the scanner's
/// `create_dir_all` + `NamedTempFile::new_in` convention so multi-GiB
/// artifacts spill onto the durable `STORAGE_PATH` volume instead of the pod's
/// ephemeral `/tmp` (issue #1608, cf. incus fix #1622). When it is empty
/// (e.g. `WorkerConfig::default()` in unit tests) the OS temp dir is returned
/// unchanged, preserving the historical `NamedTempFile::new()` behavior.
///
/// Returns the base directory in which a `NamedTempFile` should be created.
async fn resolve_migration_staging_dir(
    staging_path: &str,
) -> Result<std::path::PathBuf, MigrationError> {
    if staging_path.is_empty() {
        return Ok(std::env::temp_dir());
    }
    let base = std::path::PathBuf::from(staging_path);
    tokio::fs::create_dir_all(&base).await.map_err(|e| {
        MigrationError::StorageError(format!(
            "Failed to create migration staging dir {}: {e}",
            base.display()
        ))
    })?;
    Ok(base)
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

/// Whether a resolved destination repository should have its member artifacts
/// physically transferred from the source.
///
/// A virtual repository (Nexus `group`) only *aggregates* its members — it owns
/// no bytes of its own. When the source is Nexus, the group endpoint serves the
/// aggregated member components, so transferring against a virtual repo would
/// download those member bytes and duplicate them into the virtual repo's
/// storage (issue #2821, a regression of the #2783 member-correlation work).
/// Local/Remote destinations own their artifacts and must still be transferred.
///
/// The repo is still provisioned and its membership still correlated; only the
/// artifact transfer is gated.
pub(crate) fn should_transfer_artifacts(repo_type: RepositoryType) -> bool {
    repo_type != RepositoryType::Virtual
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
    storage_registry: Arc<StorageRegistry>,
    config: WorkerConfig,
    cancel_token: CancellationToken,
    /// Optional search backend. When present, every imported artifact is
    /// indexed into OpenSearch as it commits so migrated content is
    /// searchable/visible without waiting for a manual or startup reindex
    /// (#2784). Best-effort by contract: indexing failures are logged and
    /// never fail a migration item.
    search_service: Option<Arc<OpenSearchService>>,
}

impl MigrationWorker {
    /// Create a new migration worker
    pub fn new(
        db: PgPool,
        storage_registry: Arc<StorageRegistry>,
        config: WorkerConfig,
        cancel_token: CancellationToken,
    ) -> Self {
        let migration_service = MigrationService::new(db.clone());
        Self {
            db,
            migration_service,
            storage_registry,
            config,
            cancel_token,
            search_service: None,
        }
    }

    /// Attach an OpenSearch service so imported artifacts are indexed for
    /// full-text search as they are migrated (#2784). Returns `self` for
    /// builder-style chaining at the call site; passing `None` is a no-op and
    /// leaves migration behaving exactly as before (e.g. when the deployment
    /// has no OpenSearch configured).
    pub fn with_search_service(mut self, search_service: Option<Arc<OpenSearchService>>) -> Self {
        self.search_service = search_service;
        self
    }

    /// Best-effort index of a just-committed migrated artifact into
    /// OpenSearch (#2784).
    ///
    /// No-op when no search backend is attached. Loads the artifact's live
    /// row joined with its repository (matching the fields the live index
    /// path and `full_reindex_artifacts` use, including the repository's
    /// canonical `format`) and upserts the document. Any failure — the row
    /// having been concurrently removed, or the search cluster being
    /// unavailable — is logged and swallowed so migration never fails an
    /// item whose content already committed.
    async fn index_migrated_artifact(&self, repository_id: Uuid, path: &str) {
        let Some(search) = self.search_service.clone() else {
            return;
        };

        let row: Result<Option<MigratedArtifactIndexRow>, _> = sqlx::query_as(
            r#"
            SELECT
                a.id,
                a.name,
                a.path,
                a.version,
                a.content_type,
                a.size_bytes,
                a.created_at,
                r.key AS repository_key,
                r.name AS repository_name,
                r.format::text AS format,
                r.is_public
            FROM artifacts a
            INNER JOIN repositories r ON a.repository_id = r.id
            WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false
            LIMIT 1
            "#,
        )
        .bind(repository_id)
        .bind(path)
        .fetch_optional(&self.db)
        .await;

        let row = match row {
            Ok(Some(row)) => row,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    repository_id = %repository_id,
                    path = %path,
                    error = %e,
                    "Failed to load migrated artifact for OpenSearch indexing"
                );
                return;
            }
        };

        let doc = ArtifactDocument {
            id: row.id.to_string(),
            name: row.name,
            path: row.path,
            version: row.version,
            format: row.format,
            repository_id: repository_id.to_string(),
            repository_key: row.repository_key,
            repository_name: row.repository_name,
            content_type: row.content_type,
            size_bytes: row.size_bytes,
            download_count: 0,
            is_public: row.is_public,
            created_at: row.created_at.timestamp(),
        };

        if let Err(e) = search.index_artifact(&doc).await {
            tracing::warn!(
                artifact_id = %doc.id,
                "Failed to index migrated artifact in OpenSearch: {e}"
            );
        }
    }

    async fn storage_for_repo(
        &self,
        repo_key: &str,
    ) -> Result<Arc<dyn StorageBackend>, MigrationError> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT storage_backend, storage_path FROM repositories WHERE key = $1")
                .bind(repo_key)
                .fetch_optional(&self.db)
                .await?;

        let (backend, path) = row.ok_or_else(|| {
            MigrationError::StorageError(format!(
                "Repository '{}' not found while resolving storage backend",
                repo_key
            ))
        })?;

        self.storage_registry
            .backend_for(&StorageLocation { backend, path })
            .map_err(|e| MigrationError::StorageError(e.to_string()))
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
        let date_from = config.date_from.map(|dt| dt.to_rfc3339());
        let date_to = config.date_to.map(|dt| dt.to_rfc3339());

        if date_from.is_some() || date_to.is_some() {
            tracing::info!(
                job_id = %job_id,
                date_from = ?date_from,
                date_to = ?date_to,
                "Migration job will process only artifacts in the requested date window"
            );
        }

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
        //
        // `list_repositories` returns `ArtifactoryError`; the `?` converts via
        // `MigrationError::from(ArtifactoryError)` on the existing `#[from]` impl.
        // NOTE: total_failed below is incremented per *repo* during
        // provisioning (missing-from-source, unsupported config, conflict,
        // create_repository failure). A skipped repo with N artifacts
        // contributes 1 to failed, not N. determine_final_status only
        // checks failed > 0 && completed == 0, so the final job status is
        // still correct, but the operator-facing failed count understates
        // impact. Per-artifact accounting would require listing the
        // source repo's artifacts before deciding to skip — deferred.
        let source_repos = client.list_repositories().await.map_err(|e| {
            tracing::error!(
                job_id = %job_id, error = %e,
                "Failed to list source repositories; aborting provisioning pre-pass",
            );
            e
        })?;
        let plan = resolve_repos_for_provisioning(&repos, &source_repos);
        for missing_key in &plan.missing {
            tracing::error!(
                job_id = %job_id, repo = %missing_key,
                "Source repository not found in source registry; skipping",
            );
            total_failed += 1;
        }
        for unsupported in &plan.unsupported {
            tracing::error!(
                job_id = %job_id, repo = %unsupported.repo_key, error = %unsupported.reason,
                "Failed to prepare repository migration config; skipping",
            );
            total_failed += 1;
        }

        // (target_key, package_type) — package_type is threaded into
        // process_repository_artifacts so the INSERT can populate name+version
        // using format-aware filename parsing (see artifact_metadata module).
        let mut repos_to_process: Vec<(String, String)> = Vec::with_capacity(plan.resolved.len());
        // Virtual (Nexus `group`) repos whose membership still needs to be
        // correlated to the migrated AK members. Collected here and wired up
        // *after* the whole provisioning loop so every possible member repo
        // already exists, regardless of source ordering (issue #2783).
        let mut virtual_members_to_wire: Vec<(String, Vec<String>)> = Vec::new();
        // Count repos that were successfully provisioned (reused or created),
        // including virtual repos that are provisioned but never transferred.
        // A group-only job therefore does not trip the "nothing to process"
        // warning below (issue #2821).
        let mut provisioned_repos: usize = 0;
        for migration_config in plan.resolved {
            if migration_config.repo_type == RepositoryType::Virtual
                && !migration_config.members.is_empty()
            {
                virtual_members_to_wire.push((
                    migration_config.target_key.clone(),
                    migration_config.members.clone(),
                ));
            }
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
                        provisioned_repos += 1;
                        tracing::info!(
                            job_id = %job_id, repo = %migration_config.target_key,
                            "Destination repository already exists with matching type+format; reusing",
                        );
                    }
                    Some(other) => {
                        tracing::error!(
                            job_id = %job_id, repo = %migration_config.target_key,
                            conflict = ?other,
                            message = %conflict.message,
                            "Destination repository conflict; skipping artifact transfer for this repo",
                        );
                        total_failed += 1;
                        continue;
                    }
                    None => {
                        // has_conflict=true with conflict_type=None is a
                        // contract violation in check_repository_conflict.
                        // Treat it as a conflict (don't silently route
                        // through the "other" arm) so the bug surfaces.
                        tracing::error!(
                            job_id = %job_id, repo = %migration_config.target_key,
                            message = %conflict.message,
                            "has_conflict=true but conflict_type=None; treating as conflict",
                        );
                        total_failed += 1;
                        continue;
                    }
                }
            } else {
                // Auto-provisioned repos inherit the server's default storage
                // backend; without this they fall back to the column default
                // `filesystem`, stranding cloud deployments' artifacts (#2336).
                let backend = self.storage_registry.default_backend();
                match self
                    .migration_service
                    .create_repository(&migration_config, &self.config.staging_path, backend)
                    .await
                {
                    Ok(_) => {
                        provisioned_repos += 1;
                        tracing::info!(
                            job_id = %job_id, repo = %migration_config.target_key,
                            format = %migration_config.package_type,
                            repo_type = ?migration_config.repo_type,
                            "Provisioned destination repository",
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            job_id = %job_id, repo = %migration_config.target_key, error = %e,
                            "Failed to create destination repository; skipping",
                        );
                        total_failed += 1;
                        continue;
                    }
                }
            }

            // Virtual (Nexus `group`) repos aggregate their members and own no
            // bytes; transferring against them would download the aggregated
            // member components from the source and duplicate them into the
            // virtual repo's storage (issue #2821). The repo has already been
            // provisioned above and its membership is correlated below, so only
            // the artifact transfer is skipped here.
            if should_transfer_artifacts(migration_config.repo_type) {
                repos_to_process.push((migration_config.target_key, migration_config.package_type));
            }
        }

        // Correlate virtual (Nexus `group`) repository membership now that every
        // destination repo has been provisioned. Each source member name is
        // resolved to the migrated AK repo and written into `virtual_repo_members`
        // in source order; members that never migrated are skipped (not written as
        // dangling references). Without this the migrated virtual repo has zero
        // members and both the API and the UI error out over it (issue #2783).
        for (virtual_key, member_names) in &virtual_members_to_wire {
            match self
                .migration_service
                .correlate_virtual_repo_members(virtual_key, member_names)
                .await
            {
                Ok(outcome) => {
                    if outcome.skipped.is_empty() {
                        tracing::info!(
                            job_id = %job_id, repo = %virtual_key,
                            correlated = outcome.correlated,
                            "Correlated virtual repository members",
                        );
                    } else {
                        tracing::warn!(
                            job_id = %job_id, repo = %virtual_key,
                            correlated = outcome.correlated,
                            skipped = ?outcome.skipped,
                            "Correlated virtual repository members; some source members \
                             were not migrated and were skipped",
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        job_id = %job_id, repo = %virtual_key, error = %e,
                        "Failed to correlate virtual repository members; the migrated \
                         virtual repo may have no members",
                    );
                    total_failed += 1;
                }
            }
        }

        // Surface the no-op case explicitly. Without this, a job that ended
        // up with zero processable repos would walk straight to
        // `determine_final_status(0, 0) = Completed` and the operator would
        // see a "Completed 0/0" run with no log line explaining why — the
        // exact UX gap reported in issue #1901 before the `include_repos: []`
        // semantics were fixed. We still let the job finish normally so the
        // existing UI/state-machine contracts hold.
        if repos_to_process.is_empty() && provisioned_repos == 0 {
            tracing::warn!(
                job_id = %job_id,
                requested = repos.len(),
                source_repos = source_repos.len(),
                "No repositories available to migrate; the source listed none, every requested key was missing/unsupported, or every resolved candidate conflicted with an incompatible destination. Job will complete as a no-op."
            );
        }

        // Process each repository
        for (repo_key, package_type) in &repos_to_process {
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
                let repo_storage = match self.storage_for_repo(repo_key).await {
                    Ok(storage) => storage,
                    Err(e) => {
                        tracing::error!(repo = %repo_key, error = %e, "Failed to resolve repository storage");
                        continue;
                    }
                };

                match self
                    .process_repository_artifacts(
                        job_id,
                        client.clone(),
                        repo_storage,
                        repo_key,
                        package_type,
                        date_from.as_deref(),
                        date_to.as_deref(),
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
        repo_storage: Arc<dyn StorageBackend>,
        repo_key: &str,
        package_type: &str,
        date_from: Option<&str>,
        date_to: Option<&str>,
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

            // List artifacts with pagination, optionally filtered to a date
            // window for incremental / delta migration runs.
            let artifacts = client
                .list_artifacts_with_date_filter(repo_key, offset, limit, date_from, date_to)
                .await?;
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

                // Skip if already completed in THIS job (resume support within same job)
                if self.is_item_already_completed(job_id, &source_path).await? {
                    *skipped += 1;
                    continue;
                }

                // Check for duplicates in the artifacts table (cross-job support)
                // This is checked BEFORE creating migration_item so we avoid tracking
                // duplicates that already exist, which makes delta migrations work
                let should_skip_duplicate = self
                    .check_artifact_duplicate(
                        repo_key,
                        &artifact_path,
                        &source_path,
                        &ExpectedChecksums {
                            sha256: expected_sha256.clone(),
                            sha1: expected_sha1.clone(),
                        },
                        conflict_resolution,
                    )
                    .await?;

                if should_skip_duplicate {
                    tracing::debug!(
                        repo = %repo_key,
                        path = %artifact_path,
                        "Skipping duplicate artifact (already exists with matching checksum)"
                    );
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

                // Log debug info for Docker manifests (especially helpful if they fail due to repo not being offline)
                if is_docker_manifest_path(&artifact_path) {
                    tracing::debug!(
                        repo = %repo_key,
                        path = %artifact_path,
                        "Attempting download of Docker manifest (requires source repo to be offline)"
                    );
                }

                self.process_single_artifact(
                    item_id,
                    client.clone(),
                    repo_storage.clone(),
                    repo_key,
                    package_type,
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
        repo_storage: Arc<dyn StorageBackend>,
        repo_key: &str,
        package_type: &str,
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
        let should_skip = self
            .check_artifact_duplicate(
                repo_key,
                artifact_path,
                source_path,
                &expected,
                conflict_resolution,
            )
            .await?;

        if should_skip {
            self.migration_service
                .skip_item(item_id, "Artifact already exists")
                .await?;
            *skipped += 1;
            return Ok(());
        }

        match self
            .transfer_artifact(
                client,
                repo_storage,
                repo_key,
                package_type,
                artifact_path,
                include_metadata,
                &expected,
            )
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
                let err_msg = e.to_string();

                // Skip only when source reports not found right now.
                // This keeps items eligible for future migration runs when cache entries become available.
                if should_skip_failed_cache_artifact(&err_msg, repo_key, artifact_path) {
                    let skip_reason = build_cache_skip_reason(&err_msg);

                    tracing::info!(
                        item_id = %item_id,
                        repo = %repo_key,
                        path = %artifact_path,
                        "Cache metadata/index artifact currently unavailable from source; skipping for this run and eligible on future runs"
                    );

                    self.migration_service
                        .skip_item(item_id, &skip_reason)
                        .await?;
                    *skipped += 1;
                } else {
                    self.migration_service.fail_item(item_id, &err_msg).await?;
                    *failed += 1;
                }
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
        repo_key: &str,
        artifact_path: &str,
        legacy_source_path: &str,
        expected: &ExpectedChecksums,
        conflict_resolution: ConflictResolution,
    ) -> Result<bool, MigrationError> {
        // Match artifacts in the same repository by repository-relative path.
        // Keep a fallback for legacy rows where path was saved as repo-prefixed.
        let existing: Option<(String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT a.checksum_sha256, a.checksum_sha1
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE r.key = $1
              AND a.is_deleted = false
              AND (a.path = $2 OR a.path = $3)
            ORDER BY CASE WHEN a.path = $2 THEN 0 ELSE 1 END
            LIMIT 1
            "#,
        )
        .bind(repo_key)
        .bind(artifact_path)
        .bind(legacy_source_path)
        .fetch_optional(&self.db)
        .await?;

        match existing {
            None => Ok(false), // No duplicate
            Some((existing_sha256, existing_sha1)) => Ok(decide_duplicate_match(
                expected,
                &existing_sha256,
                existing_sha1.as_deref(),
                conflict_resolution,
            )),
        }
    }

    /// Transfer an artifact from Artifactory to Artifact Keeper.
    ///
    /// Streams the source response straight to a temp file on disk. Each
    /// chunk is hashed (sha256 + sha1) and discarded as soon as it lands on
    /// disk, so peak memory usage is O(chunk_size) instead of
    /// O(artifact_size). Without this, a 10 GB Maven artifact would buffer
    /// the entire body into a `Bytes` before storage write and OOM the AK
    /// host (issue #1422).
    ///
    /// The temp file is then handed to `StorageBackend::put_stream` (not
    /// `put_file`) using a `ReaderStream`, so the upload path is also
    /// memory-bounded. The previous default `put_file` impl called
    /// `tokio::fs::read(path)` which reintroduced the full-body buffer at
    /// the storage layer (#1512 review): cloud backends inherited it, so
    /// streaming to a temp file but then loading 10 GB into RAM still OOM'd
    /// the host. Routing through `put_stream` engages each backend's real
    /// streaming primitive (S3 multipart, GCS resumable, filesystem
    /// temp-and-rename, Azure single-PUT with `wrap_stream`).
    ///
    /// Checksum verification (when an expected sha256/sha1 was advertised
    /// by the source) runs BEFORE the storage put, not after. A truncated
    /// or corrupted body is detected on the temp file and returns
    /// `MigrationError::ChecksumMismatch` without ever writing to permanent
    /// storage or inserting an `artifacts` row. Previously, mismatch
    /// detection happened in `finalize_transfer` AFTER the bytes were
    /// committed, leaving corrupt blobs in storage on failure (#1512
    /// review).
    #[allow(clippy::too_many_arguments)]
    async fn transfer_artifact(
        &self,
        client: Arc<dyn SourceRegistry>,
        repo_storage: Arc<dyn StorageBackend>,
        repo_key: &str,
        package_type: &str,
        artifact_path: &str,
        include_metadata: bool,
        expected: &ExpectedChecksums,
    ) -> Result<TransferResult, MigrationError> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        // Open the source as a chunked stream rather than `download_artifact`,
        // which buffers the whole body in memory (#1422).
        let mut stream = client
            .download_artifact_stream(repo_key, artifact_path)
            .await?;

        // Spill chunks to a NamedTempFile while computing checksums
        // incrementally. `NamedTempFile` is created via the blocking
        // tempfile crate, but reopened as a `tokio::fs::File` so writes go
        // through the async executor without per-chunk blocking-thread
        // hops. Each chunk is hashed (sha256 + sha1) and dropped as soon
        // as it lands on disk so peak memory is O(chunk_size).
        //
        // The spill base is the configured staging dir (STORAGE_PATH-backed),
        // NOT the default `NamedTempFile::new()` location (`$TMPDIR`/`/tmp`).
        // On Kubernetes `/tmp` is the pod's ephemeral overlay and a multi-GiB
        // Maven JAR would fill it and trigger eviction (issue #1608, same
        // class as the incus upload fix #1622).
        let staging_dir = resolve_migration_staging_dir(&self.config.staging_path).await?;
        let temp = tempfile::NamedTempFile::new_in(&staging_dir).map_err(|e| {
            MigrationError::StorageError(format!(
                "Failed to create temp file in {}: {e}",
                staging_dir.display()
            ))
        })?;
        let temp_path = temp.path().to_path_buf();
        let mut writer = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await
            .map_err(|e| {
                MigrationError::StorageError(format!("Failed to open temp file for write: {e}"))
            })?;

        let mut sha256_hasher = Sha256::new();
        let mut sha1_hasher = Sha1::new();
        let mut content_size: usize = 0;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(MigrationError::from)?;
            sha256_hasher.update(&chunk);
            sha1_hasher.update(&chunk);
            content_size += chunk.len();
            writer.write_all(&chunk).await.map_err(|e| {
                MigrationError::StorageError(format!("Failed to write chunk to temp: {e}"))
            })?;
            // Explicit drop so the chunk's heap allocation is released
            // before we await the next read. Belt-and-suspenders: the
            // borrow checker would drop it at end of scope anyway.
            drop(chunk);
        }

        // Drop the stream so the underlying connection can be reused.
        drop(stream);

        // Flush and sync so the file's contents are fully on disk before
        // storage reads back from `temp_path` and before we hand off to
        // metadata extraction. Without this, a fast `put_file` rename can
        // race the kernel's writeback and surface a short read.
        writer
            .flush()
            .await
            .map_err(|e| MigrationError::StorageError(format!("Failed to flush temp file: {e}")))?;
        writer
            .sync_all()
            .await
            .map_err(|e| MigrationError::StorageError(format!("Failed to sync temp file: {e}")))?;
        drop(writer);

        let sha256_hex = hex::encode(sha256_hasher.finalize());
        let sha1_hex = hex::encode(sha1_hasher.finalize());

        // Verify advertised checksums against locally computed digests
        // BEFORE committing the temp file to storage. This is the
        // "fail-fast on corruption" guarantee added in #1512 review: prior
        // versions of this code ran verification in `finalize_transfer`,
        // AFTER `put_file` had already written the (potentially corrupt)
        // bytes to storage and inserted an `artifacts` row. The
        // `NamedTempFile` is dropped on the early return, so the
        // truncated/tampered body never reaches permanent storage and no
        // database rows are inserted.
        if let Some(mismatch) = verify_expected_checksums(
            self.config.verify_checksums,
            expected,
            Some(&sha256_hex),
            Some(&sha1_hex),
        ) {
            return Err(MigrationError::ChecksumMismatch {
                path: artifact_path.to_string(),
                expected: format!(
                    "sha256={} sha1={}",
                    expected.sha256.as_deref().unwrap_or("none"),
                    expected.sha1.as_deref().unwrap_or("none"),
                ),
                actual: mismatch,
            });
        }

        // #2457: Docker/OCI destinations need format-aware registration.
        // The generic path below stores bytes under a CAS key and inserts an
        // `artifacts` row, but V2 pulls resolve ONLY through `oci_tags` +
        // `oci-manifests/<digest>` / `oci_blobs`, so a migrated image was
        // unpullable (MANIFEST_UNKNOWN) even though the job reported success.
        // Derive the artifact's role from the source path layout; anything
        // unrecognized (and every non-docker format) keeps the generic path
        // byte-for-byte.
        let oci_role = if is_oci_package_type(package_type) {
            classify_oci_source_artifact(artifact_path)
        } else {
            OciRole::NotOci
        };
        let computed_digest = format!("sha256:{sha256_hex}");

        // Content-addressed identity guard: when the source path itself names
        // a digest (blob files, content-addressed child-manifest folders), the
        // downloaded bytes MUST hash to it. Registering under the path digest
        // would serve corrupt bytes; registering under the computed digest
        // would leave the referenced digest dangling. Fail the item instead.
        let path_digest = match &oci_role {
            OciRole::Blob { digest } => Some(digest.as_str()),
            OciRole::Manifest { reference, .. } if reference.starts_with("sha256:") => {
                Some(reference.as_str())
            }
            _ => None,
        };
        if let Some(path_digest) = path_digest {
            if path_digest != computed_digest {
                return Err(MigrationError::ChecksumMismatch {
                    path: artifact_path.to_string(),
                    expected: path_digest.to_string(),
                    actual: computed_digest,
                });
            }
        }

        // Manifests must be buffered (they are handed to the OCI tag/ref
        // registration as JSON) — but only manifests. Layer blobs stay on the
        // streamed path below, preserving the O(chunk) memory guarantee
        // (#1422/#1512). A "manifest" beyond the index-manifest cap is not a
        // real manifest; fail the item rather than buffer it.
        let oci_manifest_body: Option<bytes::Bytes> = if matches!(
            oci_role,
            OciRole::Manifest { .. }
        ) {
            if content_size > crate::services::oci_manifest_refs_backfill::MAX_INDEX_MANIFEST_BYTES
            {
                return Err(MigrationError::Other(format!(
                    "Docker/OCI manifest '{artifact_path}' exceeds the {} byte manifest cap (got {content_size} bytes)",
                    crate::services::oci_manifest_refs_backfill::MAX_INDEX_MANIFEST_BYTES
                )));
            }
            let body = tokio::fs::read(&temp_path).await.map_err(|e| {
                MigrationError::StorageError(format!(
                    "Failed to read manifest temp file for OCI registration: {e}"
                ))
            })?;
            Some(bytes::Bytes::from(body))
        } else {
            None
        };

        // Classify manifest bodies by CONTENT, mirroring the live push path
        // (`handle_put_manifest`). A body that is neither an image nor an
        // index must surface as a per-item failure — silently importing it
        // would reproduce the unpullable-tag bug this fixes.
        let oci_manifest_class = match &oci_manifest_body {
            Some(body) => {
                let class = crate::api::handlers::oci_v2::classify_manifest(body);
                if matches!(
                    class,
                    crate::api::handlers::oci_v2::ManifestClass::Malformed
                ) {
                    return Err(MigrationError::Other(format!(
                        "Docker/OCI manifest '{artifact_path}' is neither an image manifest nor an image index (or is not valid JSON)"
                    )));
                }
                Some(class)
            }
            None => None,
        };

        // Extract format-specific package metadata (npm package.json, helm
        // Chart.yaml, etc.) from the on-disk temp file BEFORE storage takes
        // ownership of it. Reading from disk (vs. an in-memory buffer)
        // keeps the streaming-memory guarantee for non-npm/helm formats
        // and is bounded for npm/helm because those tarballs are small.
        // Returns None for unknown formats; the artifact INSERT proceeds
        // either way and only the metadata row is skipped.
        // #2561: permit-scoped decode; on saturation skip the best-effort
        // extraction (only the metadata row is skipped).
        let extracted_metadata = crate::util::bounded_archive::with_ingest_extraction(|| {
            crate::services::artifact_metadata::extract_artifact_metadata_from_path(
                package_type,
                &temp_path,
            )
        })
        .ok()
        .flatten();

        // Get metadata if requested
        let metadata = if include_metadata {
            match client.get_properties(repo_key, artifact_path).await {
                Ok(props) => props.properties,
                Err(_) => None,
            }
        } else {
            None
        };

        // Upload to Artifact Keeper storage. Docker/OCI manifests and blobs
        // go to the digest-addressed keys the V2 pull path resolves
        // (`oci-manifests/<digest>`, `oci-blobs/<digest>`); everything else
        // keeps the generic CAS key. The `artifacts` row below points at the
        // same key in all cases, so the UI/download API keep working.
        let storage_key = match &oci_role {
            OciRole::Blob { digest } => crate::api::handlers::oci_v2::blob_storage_key(digest),
            OciRole::Manifest { .. } => {
                crate::api::handlers::oci_v2::manifest_storage_key(&computed_digest)
            }
            OciRole::NotOci => ArtifactService::storage_key_from_checksum(&sha256_hex),
        };

        if !self.config.dry_run {
            // Check if content already exists (deduplication)
            let exists = repo_storage.exists(&storage_key).await.unwrap_or(false);
            if !exists {
                // Open the temp file as a `ReaderStream` and hand it to
                // `put_stream` so the upload itself is memory-bounded. The
                // previous code called `put_file`, whose default trait impl
                // loaded the whole file into a `Bytes` before forwarding to
                // `put` -- which would OOM the host on a 10 GB Maven artifact
                // even though the download path streamed to disk (#1512
                // review). S3, GCS, and Azure all back `put_stream` with their
                // native streaming upload primitives; filesystem still does a
                // temp-and-rename internally.
                use tokio::io::BufReader;
                use tokio_util::io::ReaderStream;

                let file = tokio::fs::File::open(&temp_path).await.map_err(|e| {
                    MigrationError::StorageError(format!(
                        "Failed to reopen temp file for upload: {e}"
                    ))
                })?;
                let reader = BufReader::with_capacity(256 * 1024, file);
                let stream = ReaderStream::with_capacity(reader, 256 * 1024);
                let mapped = futures::StreamExt::map(stream, |r| {
                    r.map_err(|e| {
                        crate::error::AppError::Storage(format!(
                            "Temp file read error during upload: {e}"
                        ))
                    })
                });
                repo_storage
                    .put_stream(&storage_key, Box::pin(mapped))
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
                // #2457: bind the `artifacts` row, the OCI tag/ref registration,
                // and every referenced blob/child-manifest registration into
                // ONE transaction. A migrated Docker tag must never be committed
                // without its backing content: if the referenced-content walk
                // below fails to fetch a blob or child manifest, this whole
                // transaction rolls back (no `oci_tags`, no partial `oci_blobs`)
                // and the item is marked FAILED. For non-OCI formats the
                // transaction just wraps the same INSERT + metadata upsert as
                // before, a behaviour-preserving no-op.
                let mut tx = self.db.begin().await?;
                // Format-aware name + version. extract_name_from_path returns
                // the filename, which is what Artifact Keeper stored prior to
                // this fix — leaving `name` set to the full filename and
                // `version` NULL. That broke per-format index endpoints
                // (PyPI simple/, Helm index.yaml, npm metadata) since those
                // group by canonical package name and require a version.
                // parse_name_and_version uses the destination repo's package
                // type to choose the right parser; unknown formats fall back
                // to the legacy filename-as-name behaviour with NULL version.
                let filename = extract_name_from_path(artifact_path);
                let parsed = crate::services::artifact_metadata::parse_name_and_version(
                    package_type,
                    filename,
                    artifact_path,
                );
                // Match the path shape AK's per-format publish handlers
                // already use: `<name>/<version>/<filename>`. Without this,
                // the migration produced paths like
                // `<repo>/<source-relative-path>` which collide with the
                // download lookups: npm's `serve_tarball` matches
                // `path LIKE '<package>/%/<filename>'` (no leading wildcard)
                // and never finds migrated rows. PyPI and Helm tolerate the
                // legacy shape because their lookups use a leading-wildcard
                // pattern, but writing the canonical publish shape here
                // closes the inconsistency for everyone and keeps a single
                // source-of-truth path layout in the artifacts table.
                // Falls back to the legacy `<repo>/<source-path>` shape only
                // when the format-aware parser couldn't recover a version
                // (unknown format / unparseable filename).
                let path_str = migration_artifact_path(
                    package_type,
                    &parsed.name,
                    parsed.version.as_deref(),
                    filename,
                    repo_key,
                    artifact_path,
                );
                // Path-traversal guard: `path_str` is stored verbatim and
                // used as the load-bearing lookup path, so reject anything
                // with a leading `/` or a `..` segment rather than writing it.
                if has_unsafe_path(&path_str) {
                    return Err(MigrationError::Other(format!(
                        "Rejected unsafe artifact path: {path_str}"
                    )));
                }
                // Resurrect a soft-deleted tombstone on conflict (#2457 F3).
                // The full UNIQUE(repository_id, path) keeps a row for a
                // deleted artifact with `is_deleted = true`
                // (`artifact_service::delete`). A prior `DO NOTHING` left that
                // tombstone deleted on re-import while the OCI tag was still
                // (re)registered — an orphan tag with no live artifacts row.
                // `DO UPDATE ... is_deleted = false` refreshes the row and
                // clears the tombstone so the tag always has a live backing
                // artifact, matching the live push path (artifact_service.rs).
                sqlx::query(
                    r#"
                    INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, checksum_sha1, storage_key, content_type)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'application/octet-stream')
                    ON CONFLICT (repository_id, path) DO UPDATE SET
                        name = EXCLUDED.name,
                        version = EXCLUDED.version,
                        size_bytes = EXCLUDED.size_bytes,
                        checksum_sha256 = EXCLUDED.checksum_sha256,
                        checksum_sha1 = EXCLUDED.checksum_sha1,
                        storage_key = EXCLUDED.storage_key,
                        is_deleted = false,
                        updated_at = NOW()
                    "#,
                )
                .bind(repository_id)
                .bind(&path_str)
                .bind(&parsed.name)
                .bind(parsed.version.as_deref())
                .bind(content_size as i64)
                .bind(&sha256_hex)
                .bind(&sha1_hex)
                .bind(&storage_key)
                .execute(&mut *tx)
                .await?;

                // Upsert format-specific package metadata. Look up the
                // artifact id by (repository_id, path) — works whether the
                // INSERT above produced a new row or hit ON CONFLICT DO
                // NOTHING on a re-run, and avoids the RETURNING/DO UPDATE
                // dance that ON CONFLICT DO NOTHING would require.
                if let Some(metadata_json) = &extracted_metadata {
                    let artifact_row: Option<(Uuid,)> = sqlx::query_as(
                        "SELECT id FROM artifacts \
                         WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
                         LIMIT 1",
                    )
                    .bind(repository_id)
                    .bind(&path_str)
                    .fetch_optional(&mut *tx)
                    .await?;
                    if let Some((artifact_id,)) = artifact_row {
                        sqlx::query(
                            "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
                             VALUES ($1, $2, $3) \
                             ON CONFLICT (artifact_id) DO UPDATE \
                             SET metadata = EXCLUDED.metadata",
                        )
                        .bind(artifact_id)
                        .bind(package_type)
                        .bind(metadata_json)
                        .execute(&mut *tx)
                        .await?;
                    }
                }

                // #2457: register Docker/OCI content in the OCI index so the
                // migrated image is actually pullable through the V2 API.
                // Reuses the live push path's registration
                // (`persist_tag_and_refs`) so tag rows, index→child edges and
                // manifest→blob edges land exactly as a native `docker push`
                // would write them. Failures propagate as per-item failures
                // (the caller routes them through `fail_item`) — a migrated
                // tag must never be acked without its index registration.
                match &oci_role {
                    OciRole::Blob { digest } => {
                        // Mirrors the monolithic-upload insert in oci_v2:
                        // resurrect a GC-marked blob on conflict.
                        sqlx::query(
                            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                             VALUES ($1, $2, $3, $4) \
                             ON CONFLICT (repository_id, digest) DO UPDATE SET pending_delete_at = NULL",
                        )
                        .bind(repository_id)
                        .bind(digest)
                        .bind(content_size as i64)
                        .bind(&storage_key)
                        .execute(&mut *tx)
                        .await?;
                    }
                    OciRole::Manifest { image, reference } => {
                        let body = oci_manifest_body.as_ref().ok_or_else(|| {
                            MigrationError::Other(
                                "OCI manifest body missing after buffering".to_string(),
                            )
                        })?;
                        let class = oci_manifest_class.as_ref().ok_or_else(|| {
                            MigrationError::Other(
                                "OCI manifest class missing after classification".to_string(),
                            )
                        })?;
                        // Derive the stored media type from the BODY's own
                        // `mediaType` (there is no client Content-Type header
                        // on this path). Serving a Docker schema2 body under
                        // the OCI media type makes `docker pull` reject the
                        // manifest as a mediaType mismatch; the sniff keeps
                        // the two consistent, and `stored_media_type_for`
                        // still canonicalizes it against the content class.
                        let content_type = crate::api::handlers::oci_v2::stored_media_type_for(
                            class,
                            &crate::api::handlers::oci_v2::resolve_manifest_content_type(
                                None, body,
                            ),
                        );
                        crate::api::handlers::oci_v2::persist_tag_and_refs_in_tx(
                            &mut tx,
                            repository_id,
                            image,
                            reference,
                            &computed_digest,
                            &content_type,
                            class,
                            body,
                        )
                        .await
                        .map_err(|e| {
                            MigrationError::Other(format!(
                                "Failed to register OCI manifest '{artifact_path}' in the index: {e}"
                            ))
                        })?;

                        // #2457 ROOT FIX: a Docker/OCI source enumerates only
                        // the tag manifests; the config/layer blobs and per-arch
                        // child manifests they reference are addressed by digest
                        // and never listed, so pre-fix a migrated image was
                        // hollow (blobs + children 404, `docker pull` failed).
                        // Fetch and register that referenced content by digest,
                        // in THIS transaction, so the tag is committed only when
                        // its content is complete. A fetch failure rolls the tag
                        // back and fails the item (fail-closed). Content the
                        // source enumerates as its own items (Artifactory blobs)
                        // is deduped, so this is a no-op there.
                        let walk = crate::services::oci_referenced_content::walk_and_register_referenced_content(
                            &mut tx,
                            &repo_storage,
                            &client,
                            &staging_dir,
                            repository_id,
                            repo_key,
                            image,
                            class,
                            body,
                            &crate::services::oci_referenced_content::WalkCaps::default(),
                        )
                        .await
                        .map_err(|e| {
                            MigrationError::Other(format!(
                                "Failed to fetch/register content referenced by OCI manifest '{artifact_path}': {e}"
                            ))
                        })?;
                        tracing::debug!(
                            image = %image,
                            reference = %reference,
                            blobs_registered = walk.blobs_registered,
                            children_registered = walk.children_registered,
                            deduped = walk.deduped,
                            "referenced-content walk complete"
                        );
                    }
                    OciRole::NotOci => {}
                }

                tx.commit().await?;

                // #2676: surface the migrated artifact in the packages
                // catalog. The web UI's Packages tab reads `packages` /
                // `package_versions` (via /api/v1/packages), NOT `artifacts`
                // — every live publish path (nuget, npm, pypi, helm proxy,
                // the OCI manifest-PUT, the generic upload path) populates
                // the catalog after its artifact insert, but the import
                // path only wrote `artifacts` (+ the OCI index tables), so
                // a migrated repository showed artifacts under an empty
                // Packages tab. Reuse the exact shared UPSERT path the live
                // handlers call: it is idempotent (re-running a migration
                // re-upserts the same rows instead of duplicating them) and
                // best-effort by contract (a catalog failure must not fail
                // an item whose content already committed — the wrapper
                // logs and swallows, mirroring the live paths).
                if let Some(entry) = migration_catalog_entry(package_type, &oci_role, &parsed) {
                    let size_bytes = match (&oci_role, &oci_manifest_body) {
                        // Docker: size the catalog row like the live push —
                        // config+layers for an image manifest, plus the sum
                        // of already-imported child manifest sizes for a
                        // multi-arch index (whose own body carries no
                        // layers).
                        (OciRole::Manifest { .. }, Some(body)) => {
                            let base = crate::api::handlers::oci_v2::manifest_total_size(body);
                            let child_sum = if matches!(
                                oci_manifest_class,
                                Some(crate::api::handlers::oci_v2::ManifestClass::Index)
                            ) {
                                crate::api::handlers::oci_v2::index_child_artifact_size_sum(
                                    &self.db,
                                    repository_id,
                                    &computed_digest,
                                )
                                .await
                            } else {
                                0
                            };
                            base.saturating_add(child_sum)
                        }
                        _ => content_size as i64,
                    };
                    crate::services::package_service::PackageService::new(self.db.clone())
                        .try_create_or_update_from_artifact(
                            repository_id,
                            &entry.name,
                            &entry.version,
                            size_bytes,
                            &sha256_hex,
                            None,
                            Some(serde_json::json!({ "format": entry.format })),
                        )
                        .await;
                }

                // #2784: index the freshly-imported artifact into OpenSearch
                // so migrated content is searchable/visible immediately. The
                // live upload paths index via `artifact_service`, but the
                // importer writes `artifacts` directly, so without this a
                // migrated repository stayed invisible to search until a
                // manual or startup reindex. Best-effort: a search failure
                // must never fail an item whose content already committed.
                self.index_migrated_artifact(repository_id, &path_str).await;
            }
        }

        let target_path = build_source_path(repo_key, artifact_path);

        tracing::debug!(
            path = %artifact_path,
            size = content_size,
            sha256 = %sha256_hex,
            sha1 = %sha1_hex,
            "Artifact transferred via streaming (no memory buffering)"
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
///
/// Kept for test fixtures and any future buffered callers. The streaming
/// `transfer_artifact` path (#1422) hashes chunks incrementally instead of
/// calling this on a full in-memory buffer.
#[allow(dead_code)]
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

/// A source repository requested for migration that could not be turned
/// into a [`RepositoryMigrationConfig`] (typically because the source's
/// repository type or package format isn't recognized by Artifact Keeper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnsupportedRepo {
    pub repo_key: String,
    pub reason: String,
}

/// Outcome of pre-pass resolution before destination provisioning.
///
/// Each requested key in `process_job`'s `include_repos` list lands in
/// exactly one of the three buckets: it has a valid source-side row and
/// gets turned into a `RepositoryMigrationConfig` (`resolved`); the source
/// has no row with that key (`missing`); or the source row exists but its
/// type/format can't be mapped to a destination config (`unsupported`).
#[derive(Debug, Default)]
pub(crate) struct ResolveRepoPlan {
    pub resolved: Vec<crate::services::migration_service::RepositoryMigrationConfig>,
    pub missing: Vec<String>,
    pub unsupported: Vec<UnsupportedRepo>,
}

/// Match each requested repository key against the source-side repository
/// list and prepare a `RepositoryMigrationConfig` for it.
///
/// An empty `requested` slice is treated as "every repository the source
/// reports" — matching the convention used by include/exclude filter pairs
/// in apt, yum, Bazel, Helm, etc. The previous "empty == migrate nothing"
/// behavior caused jobs submitted with the default `include_repos: []`
/// (which is what the UI sends when no specific repo is picked) to silently
/// complete in ~200ms with `0/0/0`, never enumerating the source and never
/// writing `migration_items` or `migration_reports` rows (issue #1901).
///
/// Pure (no DB, no I/O) so it can be unit-tested end-to-end. The DB-touching
/// `check_repository_conflict` / `create_repository` follow-up runs in
/// `MigrationWorker::process_job` over the `resolved` slice.
pub(crate) fn resolve_repos_for_provisioning(
    requested: &[String],
    source_repos: &[crate::services::artifactory_client::RepositoryListItem],
) -> ResolveRepoPlan {
    let mut plan = ResolveRepoPlan::default();

    if requested.is_empty() {
        for source_repo in source_repos {
            match MigrationService::prepare_repository_migration(source_repo, None) {
                Ok(c) => plan.resolved.push(c),
                Err(e) => plan.unsupported.push(UnsupportedRepo {
                    repo_key: source_repo.key.clone(),
                    reason: e.to_string(),
                }),
            }
        }
        return plan;
    }

    for repo_key in requested {
        let source_repo = match source_repos.iter().find(|r| &r.key == repo_key) {
            Some(r) => r,
            None => {
                plan.missing.push(repo_key.clone());
                continue;
            }
        };
        match MigrationService::prepare_repository_migration(source_repo, None) {
            Ok(c) => plan.resolved.push(c),
            Err(e) => plan.unsupported.push(UnsupportedRepo {
                repo_key: repo_key.clone(),
                reason: e.to_string(),
            }),
        }
    }
    plan
}

/// Determine the final job status based on completed and failed counts.
///
/// - all items failed (failed > 0, completed == 0) → `Failed`
/// - some failed, some succeeded (failed > 0, completed > 0) →
///   `CompletedWithErrors`, so a partial/hollow migration is not surfaced as a
///   clean success (#2457 — the OP saw "completed" over an unpullable import).
///   The per-item counters/report carry which items failed.
/// - nothing failed → `Completed`
pub(crate) fn determine_final_status(
    total_failed: i32,
    total_completed: i32,
) -> MigrationJobStatus {
    match (total_failed > 0, total_completed > 0) {
        (true, false) => MigrationJobStatus::Failed,
        (true, true) => MigrationJobStatus::CompletedWithErrors,
        _ => MigrationJobStatus::Completed,
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

fn migration_artifact_path(
    package_type: &str,
    parsed_name: &str,
    version: Option<&str>,
    filename: &str,
    repo_key: &str,
    artifact_path: &str,
) -> String {
    match package_type {
        // Maven/sbt/ivy paths include a group prefix
        // (e.g. com/example/artifact/version/file.jar) that clients use
        // verbatim when resolving.
        "maven" | "gradle" | "sbt" | "ivy" => artifact_path.to_string(),
        _ => match version {
            Some(ver) if !ver.is_empty() => format!("{}/{}/{}", parsed_name, ver, filename),
            _ => format!("{}/{}", repo_key, artifact_path),
        },
    }
}

/// Row shape for loading a just-committed migrated artifact (joined with its
/// repository) to build an OpenSearch [`ArtifactDocument`] (#2784).
#[derive(Debug, sqlx::FromRow)]
struct MigratedArtifactIndexRow {
    id: Uuid,
    name: String,
    path: String,
    version: Option<String>,
    content_type: String,
    size_bytes: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    repository_key: String,
    repository_name: String,
    format: String,
    is_public: bool,
}

/// The `packages`-catalog identity of a migrated artifact, or `None` when
/// the artifact must not produce a catalog row (#2676).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogEntry {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) format: String,
}

/// Decide whether a migrated artifact gets a `packages`/`package_versions`
/// row and under what identity, mirroring the live publish paths (#2676):
///
/// - Docker/OCI: only tag manifests are user-facing versions — the catalog
///   row is `<image>@<tag>`, exactly like the live manifest-PUT handler.
///   Digest-addressed child manifests and layer/config blobs are skipped
///   (mirrors the live path's `oci_reference_is_tag` filter).
/// - Maven family: skipped. Live maven catalog names are
///   `groupId:artifactId` and `parse_name_and_version` recovers only the
///   artifactId, so writing rows here would diverge from the shape the
///   repository components view expects (follow-up, not in #2676's scope).
/// - Everything else (helm, nuget, npm, pypi, generic, ...): a row is
///   written whenever the importer recovered a version, under the same
///   `(name, version)` the artifact row itself carries.
pub(crate) fn migration_catalog_entry(
    package_type: &str,
    oci_role: &OciRole,
    parsed: &crate::services::artifact_metadata::ParsedArtifact,
) -> Option<CatalogEntry> {
    match oci_role {
        OciRole::Blob { .. } => None,
        OciRole::Manifest { image, reference } => {
            if crate::api::handlers::oci_v2::oci_reference_is_tag(reference) {
                Some(CatalogEntry {
                    name: image.clone(),
                    version: reference.clone(),
                    format: "docker".to_string(),
                })
            } else {
                None
            }
        }
        OciRole::NotOci => {
            let pt = package_type.to_lowercase();
            if matches!(pt.as_str(), "maven" | "gradle" | "sbt" | "ivy") {
                return None;
            }
            let version = parsed.version.clone()?;
            Some(CatalogEntry {
                name: parsed.name.clone(),
                version,
                format: pt,
            })
        }
    }
}

/// Reject artifact paths that could escape the repository root once stored
/// verbatim. The migration now persists the raw external path as the
/// load-bearing `path`, so a crafted export with a leading `/` or a `..`
/// segment must never reach the INSERT.
fn has_unsafe_path(path: &str) -> bool {
    path.starts_with('/') || path.split('/').any(|seg| seg == "..")
}

/// Whether a destination package type is Docker/OCI and therefore needs
/// format-aware registration into the OCI index during import (#2457).
pub(crate) fn is_oci_package_type(package_type: &str) -> bool {
    package_type.eq_ignore_ascii_case("docker") || package_type.eq_ignore_ascii_case("oci")
}

/// Normalize a digest-shaped path segment to the canonical `sha256:<hex>`
/// form. Accepts both the Artifactory filesystem form (`sha256__<hex>`) and
/// the registry form (`sha256:<hex>`); returns `None` for anything else
/// (including non-lowercase or wrong-length hex), so a tag that merely
/// *looks* digest-ish is left alone.
pub(crate) fn normalize_digest_segment(segment: &str) -> Option<String> {
    let hex = segment
        .strip_prefix("sha256__")
        .or_else(|| segment.strip_prefix("sha256:"))?;
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Some(format!("sha256:{hex}"))
    } else {
        None
    }
}

/// Role a Docker/OCI source artifact plays in the OCI index, derived from
/// the source path layout (#2457).
///
/// Both supported source layouts are recognized by shape:
/// - Artifactory: `<image>/<reference>/manifest.json`,
///   `<image>/<reference>/list.manifest.json` (the `<reference>` folder is a
///   tag or a content-addressed `sha256__<hex>` folder), and layer/config
///   blobs stored as `.../sha256__<hex>` files.
/// - Nexus: `v2/<image>/manifests/<reference>` and blobs enumerated as
///   `v2/.../blobs/sha256:<hex>`.
///
/// Whether a manifest is an image or an index is NOT decided here — that
/// classification comes from the downloaded bytes
/// ([`crate::api::handlers::oci_v2::classify_manifest`]), never the filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OciRole {
    /// A manifest (image or index). `image` is the image name within the
    /// destination repository; `reference` is a tag or a `sha256:<hex>`
    /// digest.
    Manifest { image: String, reference: String },
    /// A layer or config blob addressed by `sha256:<hex>` digest.
    Blob { digest: String },
    /// Not recognizably part of a Docker/OCI source layout; the artifact
    /// takes the generic import path unchanged.
    NotOci,
}

/// Classify a Docker/OCI source artifact path into its [`OciRole`].
///
/// Only called for docker/oci destination repositories; every other format
/// bypasses this entirely (see [`is_oci_package_type`]). Unrecognized shapes
/// return [`OciRole::NotOci`] and fall through to the generic import path,
/// which matches the pre-#2457 behavior byte-for-byte.
pub(crate) fn classify_oci_source_artifact(artifact_path: &str) -> OciRole {
    let segments: Vec<&str> = artifact_path.split('/').filter(|s| !s.is_empty()).collect();
    let Some((&last, dirs)) = segments.split_last() else {
        return OciRole::NotOci;
    };

    // Blob shapes. Artifactory stores layer/config blobs as `sha256__<hex>`
    // files; Nexus enumerates them under a `blobs/` segment as
    // `blobs/sha256:<hex>`.
    if last.starts_with("sha256__") {
        if let Some(digest) = normalize_digest_segment(last) {
            return OciRole::Blob { digest };
        }
    }
    if dirs.last() == Some(&"blobs") {
        if let Some(digest) = normalize_digest_segment(last) {
            return OciRole::Blob { digest };
        }
    }

    // Artifactory manifest shape: `<image>/<reference>/(list.)manifest.json`.
    // A content-addressed `sha256__<hex>` reference folder (multi-arch child
    // manifest) normalizes to a digest reference; anything else is a tag.
    if last == "manifest.json" || last == "list.manifest.json" {
        if let Some((&ref_seg, image_segs)) = dirs.split_last() {
            if !image_segs.is_empty() {
                let reference =
                    normalize_digest_segment(ref_seg).unwrap_or_else(|| ref_seg.to_string());
                return OciRole::Manifest {
                    image: image_segs.join("/"),
                    reference,
                };
            }
        }
        return OciRole::NotOci;
    }

    // Nexus manifest shape: `v2/<image>/manifests/<reference>`. Strip the
    // registry-API prefix segments (`v2`, and the `-` catch-all namespace)
    // so `image` matches what a client pulls through AK's own V2 endpoint.
    if dirs.last() == Some(&"manifests") {
        let mut image_segs = &dirs[..dirs.len() - 1];
        if image_segs.first() == Some(&"v2") {
            image_segs = &image_segs[1..];
        }
        if image_segs.first() == Some(&"-") {
            image_segs = &image_segs[1..];
        }
        if !image_segs.is_empty() {
            let reference = normalize_digest_segment(last).unwrap_or_else(|| last.to_string());
            return OciRole::Manifest {
                image: image_segs.join("/"),
                reference,
            };
        }
    }

    OciRole::NotOci
}

/// Detect Docker/OCI manifest paths laid out by Artifactory's filesystem
/// layout (`.../sha256__<digest>/manifest.json` or `.../list.manifest.json`).
///
/// Used purely for logging context when initiating a download attempt of a
/// manifest, since manifest downloads require the source repo to be offline
/// for Artifactory to surface them via the storage API.
fn is_docker_manifest_path(artifact_path: &str) -> bool {
    artifact_path.contains("/sha256__")
        && (artifact_path.ends_with("/manifest.json")
            || artifact_path.ends_with("/list.manifest.json"))
}

/// Detect cache-only artifacts from Artifactory remote cache repositories.
///
/// These are metadata/index files that exist in AQL but cannot be downloaded via HTTP
/// because they are:
/// 1. Dynamically generated during cache revalidation
/// 2. Index files (e.g., Debian Release files, Cargo config, PyPI index pages)
/// 3. Expired cache entries that cannot be revalidated with upstream
///
/// Skipping these prevents failed migration items while preserving actual downloadable
/// artifacts (packages, blobs, tarballs, etc.)
fn should_skip_cache_only_artifact(repo_key: &str, artifact_path: &str) -> bool {
    let repo_lower = repo_key.to_lowercase();
    let path_lower = artifact_path.to_lowercase();

    // Docker/OCI: skip cache metadata manifests, not blob payloads.
    if (repo_lower.contains("docker") || repo_lower.contains("oci"))
        && path_lower.contains("sha256__")
        && (path_lower.ends_with("/manifest.json") || path_lower.ends_with("/list.manifest.json"))
    {
        return true;
    }

    // PyPI cache: simple index HTML files
    if repo_lower.contains("pypi")
        && path_lower.starts_with(".pypi/")
        && path_lower.ends_with(".html")
    {
        return true;
    }

    // Cargo cache: auto-generated registry-root config.json. Match the EXACT
    // root path "config.json" (no slashes), not any nested path that happens
    // to end with config.json, otherwise we would skip real crate artifacts
    // that ship a config.json inside their tarball.
    if repo_lower.contains("cargo") && artifact_path == "config.json" {
        return true;
    }

    // Debian/Apt/Ubuntu repository metadata and package indices
    let is_deb_metadata = path_lower.ends_with("release")
        || path_lower.ends_with("release.gpg")
        || path_lower.ends_with("inrelease")
        || path_lower.ends_with("packages.gz")
        || path_lower.ends_with("packages.bz2")
        || path_lower.ends_with("packages.xz")
        || path_lower.ends_with("packages")
        || path_lower.ends_with("packages.dir")
        || path_lower.ends_with("contents.gz")
        || path_lower.ends_with("contents");

    if is_deb_metadata
        && (repo_lower.contains("debian")
            || repo_lower.contains("apt")
            || repo_lower.contains("ubuntu")
            || repo_lower.contains("bazel"))
    {
        return true;
    }

    false
}

/// Decide whether a failed transfer should be marked as skipped (versus
/// failed) so the item stays eligible for a future migration run.
///
/// The combined predicate is intentionally narrow: only when the source
/// reports the artifact as currently missing AND the (repo, path) pair
/// matches the known cache-only metadata layout. Anything else surfaces
/// as a hard failure so genuine outages stay visible.
fn should_skip_failed_cache_artifact(err_msg: &str, repo_key: &str, artifact_path: &str) -> bool {
    err_msg.contains("Artifact not found")
        && should_skip_cache_only_artifact(repo_key, artifact_path)
}

/// Build the user-facing reason string recorded on migration items that
/// were skipped because their cache entry is currently unavailable.
fn build_cache_skip_reason(err_msg: &str) -> String {
    format!(
        "{err_msg} | Cache metadata/index artifact is currently unavailable from source. Skipped for this run only; rerun migration when source cache entry becomes available."
    )
}

/// Extract the file name from an artifact path.
/// Returns the portion after the last '/' separator, or the entire
/// string if no separator is present.
pub(crate) fn extract_name_from_path(artifact_path: &str) -> &str {
    artifact_path.rsplit('/').next().unwrap_or(artifact_path)
}

/// Decide whether a duplicate artifact row should be treated as already
/// present (return `true` -> skip the transfer) or processed (return
/// `false` -> proceed with the upload).
///
/// Pure, DB-free predicate extracted from `check_artifact_duplicate` so the
/// branch table is exercised by inline tests without standing up Postgres.
///
/// Rules, in order:
/// - `Overwrite` and `Rename` always re-process the artifact.
/// - For `Skip`, prefer the strongest declared digest:
///   - sha256: exact match against the stored sha256.
///   - sha1 (no sha256 declared): exact match against the stored sha1 if
///     present; if the stored row has no sha1, treat the path collision as
///     a duplicate (avoids endless remigration loops on legacy rows).
///   - Neither digest declared: treat as duplicate by path.
pub(crate) fn decide_duplicate_match(
    expected: &ExpectedChecksums,
    existing_sha256: &str,
    existing_sha1: Option<&str>,
    conflict_resolution: ConflictResolution,
) -> bool {
    match conflict_resolution {
        ConflictResolution::Overwrite | ConflictResolution::Rename => false,
        ConflictResolution::Skip => {
            if let Some(expected_sha256) = expected.sha256.as_deref() {
                expected_sha256 == existing_sha256
            } else if let Some(expected_sha1) = expected.sha1.as_deref() {
                existing_sha1.map_or(true, |s| s == expected_sha1)
            } else {
                true
            }
        }
    }
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

    // -----------------------------------------------------------------------
    // should_transfer_artifacts (#2821 virtual-repo no-transfer gate)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_transfer_artifacts_virtual_is_skipped() {
        // A virtual (Nexus `group`) repo only aggregates its members and owns
        // no bytes; it must never have artifacts physically transferred into
        // it (issue #2821).
        assert!(!should_transfer_artifacts(RepositoryType::Virtual));
    }

    #[test]
    fn test_should_transfer_artifacts_local_and_remote_are_transferred() {
        // Local (hosted) and Remote (proxy) destinations own their artifacts
        // and must still be transferred.
        assert!(should_transfer_artifacts(RepositoryType::Local));
        assert!(should_transfer_artifacts(RepositoryType::Remote));
    }

    #[test]
    fn test_transfer_gate_excludes_only_virtual_from_processing() {
        // Mirror the enqueue decision in process_job: every resolved repo is
        // provisioned, but only non-virtual repos are pushed onto the
        // artifact-transfer worklist. A group-only job must yield an empty
        // worklist even though its virtual repo was provisioned (issue #2821).
        let resolved = [
            ("local-libs", RepositoryType::Local),
            ("remote-proxy", RepositoryType::Remote),
            ("group-all", RepositoryType::Virtual),
        ];

        let to_process: Vec<&str> = resolved
            .iter()
            .filter(|(_, ty)| should_transfer_artifacts(*ty))
            .map(|(key, _)| *key)
            .collect();

        assert_eq!(to_process, vec!["local-libs", "remote-proxy"]);
        assert!(!to_process.contains(&"group-all"));

        // A source with only a virtual (group) repo transfers nothing.
        let group_only = [("group-all", RepositoryType::Virtual)];
        let group_only_process: Vec<&str> = group_only
            .iter()
            .filter(|(_, ty)| should_transfer_artifacts(*ty))
            .map(|(key, _)| *key)
            .collect();
        assert!(group_only_process.is_empty());
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
    fn test_should_skip_cache_only_artifact_docker() {
        // Docker/OCI cache paths with sha256__
        assert!(should_skip_cache_only_artifact(
            "docker-remote-cache",
            "anchore/grype/sha256__1a58983ca4abb6bd0b0ae9f171541ff67d8f6a15bfcc49203ab97f9d01d3294e/manifest.json"
        ));
        assert!(should_skip_cache_only_artifact(
            "oci-cache",
            "library/nginx/sha256__52e3/list.manifest.json"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_pypi() {
        // PyPI cache HTML index files
        assert!(should_skip_cache_only_artifact(
            "pypi-remote-cache",
            ".pypi/invoke.html"
        ));
        assert!(should_skip_cache_only_artifact(
            "pypi-cache",
            ".pypi/ipaddress.html"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_cargo() {
        // Cargo auto-generated registry-root config.json is skipped
        assert!(should_skip_cache_only_artifact(
            "cargo-remote-cache",
            "config.json"
        ));
        // Nested paths that happen to end with config.json are NOT registry
        // metadata and must be migrated normally (Round 1 fix).
        assert!(!should_skip_cache_only_artifact(
            "cargo-cache",
            "1/registry/config.json"
        ));
        // And a real crate tarball that happens to contain "config.json" as
        // its file name should still migrate.
        assert!(!should_skip_cache_only_artifact(
            "cargo-cache",
            "crates/foo/foo-1.0.0/config.json"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_debian_metadata() {
        // Debian/Apt/Ubuntu repository metadata
        assert!(should_skip_cache_only_artifact(
            "debian-cache",
            "dists/focal/Release"
        ));
        assert!(should_skip_cache_only_artifact(
            "ubuntu-cache",
            "dists/jammy/InRelease"
        ));
        assert!(should_skip_cache_only_artifact(
            "apt-cache",
            "dists/bullseye/Packages.gz"
        ));
        assert!(should_skip_cache_only_artifact(
            "bazel-cache",
            "dists/Contents.gz"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_allows_real_packages() {
        // Non-cache artifacts should not be skipped
        assert!(!should_skip_cache_only_artifact(
            "pypi-cache",
            "13/2c/5e079cefe955ae58e5a052fe037c850ce493eb7269dedeb960237e78fb0f/wheel-0.46.2-py3-none-any.whl"
        ));
        assert!(!should_skip_cache_only_artifact(
            "docker-cache",
            "library/nginx/sha256__52e3/layer.tar"
        ));
        assert!(!should_skip_cache_only_artifact(
            "cargo-cache",
            "requests/requests-2.28.0-py3-none-any.whl"
        ));
    }

    // -----------------------------------------------------------------------
    // migration_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_artifact_path_preserves_maven_family_paths() {
        let artifact_path = "com/depop/example/1.0.0/example-1.0.0.jar";

        for package_type in ["maven", "gradle", "sbt", "ivy"] {
            assert_eq!(
                migration_artifact_path(
                    package_type,
                    "example",
                    Some("1.0.0"),
                    "example-1.0.0.jar",
                    "depop-maven",
                    artifact_path
                ),
                artifact_path
            );
        }
    }

    #[test]
    fn test_migration_artifact_path_builds_canonical_non_maven_versioned_path() {
        assert_eq!(
            migration_artifact_path(
                "npm",
                "lodash",
                Some("4.17.21"),
                "lodash-4.17.21.tgz",
                "depop-npm",
                "lodash/-/lodash-4.17.21.tgz"
            ),
            "lodash/4.17.21/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn test_migration_artifact_path_falls_back_without_version() {
        assert_eq!(
            migration_artifact_path(
                "generic",
                "artifact.bin",
                None,
                "artifact.bin",
                "depop-generic",
                "nested/path/artifact.bin"
            ),
            "depop-generic/nested/path/artifact.bin"
        );
    }

    // -----------------------------------------------------------------------
    // has_unsafe_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_unsafe_path_rejects_traversal_and_absolute() {
        assert!(has_unsafe_path("../etc/passwd"));
        assert!(has_unsafe_path("com/example/../../secret/file.jar"));
        assert!(has_unsafe_path("/etc/passwd"));
        assert!(has_unsafe_path(".."));
    }

    #[test]
    fn test_has_unsafe_path_allows_normal_paths() {
        assert!(!has_unsafe_path(
            "com/example/artifact/1.0.0/artifact-1.0.0.jar"
        ));
        assert!(!has_unsafe_path("requests/1.0.0/requests-1.0.0.whl"));
        // A `..` substring inside a segment is not a traversal segment.
        assert!(!has_unsafe_path("my..pkg/1.0.0/my..pkg-1.0.0.tgz"));
    }

    // -----------------------------------------------------------------------
    // is_docker_manifest_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_docker_manifest_path_detects_single_arch_manifest() {
        assert!(is_docker_manifest_path(
            "library/nginx/sha256__abc123/manifest.json"
        ));
    }

    #[test]
    fn test_is_docker_manifest_path_detects_multi_arch_list_manifest() {
        assert!(is_docker_manifest_path(
            "library/nginx/sha256__abc123/list.manifest.json"
        ));
    }

    #[test]
    fn test_is_docker_manifest_path_rejects_layer_payload() {
        // sha256__ subdirectory but not a manifest filename
        assert!(!is_docker_manifest_path(
            "library/nginx/sha256__abc123/layer.tar"
        ));
    }

    #[test]
    fn test_is_docker_manifest_path_rejects_manifest_without_sha256_prefix() {
        // manifest.json filename but no sha256__ marker upstream
        assert!(!is_docker_manifest_path(
            "library/nginx/latest/manifest.json"
        ));
    }

    #[test]
    fn test_is_docker_manifest_path_rejects_empty_path() {
        assert!(!is_docker_manifest_path(""));
    }

    // -----------------------------------------------------------------------
    // should_skip_failed_cache_artifact + build_cache_skip_reason
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_skip_failed_cache_artifact_matches_not_found_for_cache_metadata() {
        // Real-world error string from Artifactory client wrapping a 404
        let err = "Artifact not found: docker-remote-cache/library/nginx/sha256__abc/manifest.json";
        assert!(should_skip_failed_cache_artifact(
            err,
            "docker-remote-cache",
            "library/nginx/sha256__abc/manifest.json"
        ));
    }

    #[test]
    fn test_should_skip_failed_cache_artifact_rejects_not_found_for_real_payload() {
        // A 404 on an actual package payload is a real failure, not a cache skip
        let err = "Artifact not found: pypi-remote-cache/wheel-0.46.2-py3-none-any.whl";
        assert!(!should_skip_failed_cache_artifact(
            err,
            "pypi-remote-cache",
            "wheel-0.46.2-py3-none-any.whl"
        ));
    }

    #[test]
    fn test_should_skip_failed_cache_artifact_rejects_non_not_found_errors() {
        // Connection errors, 500s, etc. must surface as failures even on
        // cache-metadata paths so genuine outages stay visible.
        let err = "Connection refused while contacting source registry";
        assert!(!should_skip_failed_cache_artifact(
            err,
            "docker-remote-cache",
            "library/nginx/sha256__abc/manifest.json"
        ));
    }

    #[test]
    fn test_build_cache_skip_reason_preserves_underlying_error_message() {
        let reason = build_cache_skip_reason("Artifact not found: foo/bar.json");
        assert!(reason.starts_with("Artifact not found: foo/bar.json"));
        assert!(reason.contains("currently unavailable from source"));
        assert!(reason.contains("rerun migration"));
    }

    // -----------------------------------------------------------------------
    // should_skip_cache_only_artifact - additional branch coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_skip_cache_only_artifact_docker_rejects_non_manifest_filenames() {
        // Docker/OCI repo but path does not match the manifest filename
        // pattern: must not be skipped (it is a real blob/payload).
        assert!(!should_skip_cache_only_artifact(
            "docker-remote-cache",
            "library/nginx/sha256__abc/config.json"
        ));
        assert!(!should_skip_cache_only_artifact(
            "oci-remote-cache",
            "library/nginx/sha256__abc/blob.bin"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_docker_rejects_manifest_without_sha256_marker() {
        // manifest.json filename but no sha256__ in the path: not a cache
        // manifest, must not be skipped.
        assert!(!should_skip_cache_only_artifact(
            "docker-remote-cache",
            "library/nginx/manifest.json"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_pypi_rejects_non_html() {
        // PyPI repo but the path is not an .html index file
        assert!(!should_skip_cache_only_artifact(
            "pypi-remote-cache",
            ".pypi/wheel-0.46.2-py3-none-any.whl"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_pypi_rejects_html_outside_pypi_prefix() {
        // .html file but not inside the `.pypi/` cache directory
        assert!(!should_skip_cache_only_artifact(
            "pypi-remote-cache",
            "docs/index.html"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_cargo_rejects_non_config_files() {
        // Cargo repo but file is not config.json
        assert!(!should_skip_cache_only_artifact(
            "cargo-remote-cache",
            "1/r/registry.crate"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_debian_metadata_requires_known_repo_family() {
        // Debian-style metadata filename but the repo key does not look like
        // a debian/apt/ubuntu/bazel repo: must not be skipped.
        assert!(!should_skip_cache_only_artifact(
            "generic-remote-cache",
            "dists/focal/Release"
        ));
        assert!(!should_skip_cache_only_artifact(
            "maven-remote-cache",
            "dists/focal/Packages.gz"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_debian_metadata_covers_each_variant() {
        // Walk every debian-metadata file extension the helper recognises so
        // each branch of the `is_deb_metadata` chain is exercised.
        let variants = [
            "dists/focal/Release",
            "dists/focal/Release.gpg",
            "dists/focal/InRelease",
            "dists/focal/main/binary-amd64/Packages.gz",
            "dists/focal/main/binary-amd64/Packages.bz2",
            "dists/focal/main/binary-amd64/Packages.xz",
            "dists/focal/main/binary-amd64/Packages",
            "dists/focal/main/binary-amd64/Packages.dir",
            "dists/focal/Contents.gz",
            "dists/focal/Contents",
        ];
        for path in variants {
            assert!(
                should_skip_cache_only_artifact("debian-remote-cache", path),
                "expected debian metadata variant to be skippable: {path}"
            );
        }
    }

    #[test]
    fn test_should_skip_cache_only_artifact_unknown_repo_unknown_path_returns_false() {
        // Exercises the trailing `false` branch: no Docker/OCI, no PyPI,
        // no Cargo, no debian-family rule applies.
        assert!(!should_skip_cache_only_artifact(
            "maven-remote-cache",
            "com/example/lib/1.0/lib-1.0.jar"
        ));
    }

    #[test]
    fn test_should_skip_cache_only_artifact_is_repo_key_case_insensitive() {
        // The helper lowercases the repo key, so mixed-case keys still
        // route into the docker branch.
        assert!(should_skip_cache_only_artifact(
            "Docker-Remote-Cache",
            "library/nginx/sha256__abc/manifest.json"
        ));
    }

    // -----------------------------------------------------------------------
    // decide_duplicate_match - DB-free predicate extracted from
    // check_artifact_duplicate. Each branch of the digest-fallback table is
    // exercised so the helper has direct coverage instead of being reached
    // only through the integration path.
    // -----------------------------------------------------------------------

    fn checksums(sha256: Option<&str>, sha1: Option<&str>) -> ExpectedChecksums {
        ExpectedChecksums {
            sha256: sha256.map(String::from),
            sha1: sha1.map(String::from),
        }
    }

    #[test]
    fn test_decide_duplicate_match_overwrite_always_reprocesses() {
        // Overwrite ignores any digest agreement and always returns false so
        // the caller re-uploads the artifact.
        assert!(!decide_duplicate_match(
            &checksums(Some("abc"), Some("def")),
            "abc",
            Some("def"),
            ConflictResolution::Overwrite,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_rename_always_reprocesses() {
        // Rename currently maps to overwrite semantics in migration.
        assert!(!decide_duplicate_match(
            &checksums(Some("abc"), None),
            "abc",
            None,
            ConflictResolution::Rename,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_sha256_exact_match() {
        // Strongest digest available and stored: must agree exactly.
        assert!(decide_duplicate_match(
            &checksums(Some("abc"), None),
            "abc",
            None,
            ConflictResolution::Skip,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_sha256_mismatch_reprocesses() {
        // sha256 declared but the stored row differs: not a duplicate.
        assert!(!decide_duplicate_match(
            &checksums(Some("abc"), Some("ignored")),
            "xyz",
            Some("ignored"),
            ConflictResolution::Skip,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_sha1_match_when_no_sha256() {
        // Source declares only sha1: must compare against stored sha1.
        assert!(decide_duplicate_match(
            &checksums(None, Some("def")),
            "irrelevant-stored-sha256",
            Some("def"),
            ConflictResolution::Skip,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_sha1_mismatch_reprocesses() {
        // sha1 declared but stored sha1 differs: not a duplicate.
        assert!(!decide_duplicate_match(
            &checksums(None, Some("def")),
            "stored-sha256",
            Some("other-sha1"),
            ConflictResolution::Skip,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_sha1_legacy_row_without_stored_sha1() {
        // Source declares sha1 but legacy row predates sha1 storage. To
        // avoid endless remigration loops we treat the path collision as a
        // duplicate.
        assert!(decide_duplicate_match(
            &checksums(None, Some("def")),
            "stored-sha256",
            None,
            ConflictResolution::Skip,
        ));
    }

    #[test]
    fn test_decide_duplicate_match_skip_no_digests_treats_as_duplicate() {
        // Neither digest declared: by-path duplicate.
        assert!(decide_duplicate_match(
            &checksums(None, None),
            "stored-sha256",
            Some("stored-sha1"),
            ConflictResolution::Skip,
        ));
    }

    // -----------------------------------------------------------------------
    // migration_artifact_path - pure path-shape helper. Migration must write
    // the same `<name>/<version>/<filename>` shape AK's publish handlers use
    // (with a fallback) so download lookups find the migrated rows. These
    // exercise the non-maven (name/version) and fallback branches.
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_artifact_path_uses_name_version_filename_when_parsed() {
        // Happy path: a parseable filename (e.g. npm tarball) yields the
        // canonical `<name>/<version>/<filename>` shape that AK's publish
        // handlers already use.
        let path = migration_artifact_path(
            "npm",
            "lodash",
            Some("4.17.21"),
            "lodash-4.17.21.tgz",
            "npm-remote-cache",
            "lodash/-/lodash-4.17.21.tgz",
        );
        assert_eq!(path, "lodash/4.17.21/lodash-4.17.21.tgz");
    }

    #[test]
    fn test_migration_artifact_path_falls_back_when_version_missing() {
        // No version recovered (unknown format / unparseable filename):
        // legacy `<repo>/<source-path>` shape.
        let path = migration_artifact_path(
            "generic",
            "raw-blob",
            None,
            "blob.bin",
            "generic-cache",
            "some/deep/path/blob.bin",
        );
        assert_eq!(path, "generic-cache/some/deep/path/blob.bin");
    }

    #[test]
    fn test_migration_artifact_path_falls_back_when_version_is_empty() {
        // Defensive: empty-string version must also trigger the fallback so
        // we never write `<name>//<filename>` to the artifacts table.
        let path = migration_artifact_path(
            "generic",
            "weird-pkg",
            Some(""),
            "weird-pkg.tar",
            "raw-cache",
            "weird-pkg.tar",
        );
        assert_eq!(path, "raw-cache/weird-pkg.tar");
    }

    #[test]
    fn test_migration_artifact_path_preserves_filename_independent_of_source_layout() {
        // The canonical shape ignores the source-side layout entirely once a
        // version was recovered. A PyPI wheel migrated from a deeply nested
        // hash-prefixed cache path still lands under <name>/<version>/<file>.
        let path = migration_artifact_path(
            "pypi",
            "wheel",
            Some("0.46.2"),
            "wheel-0.46.2-py3-none-any.whl",
            "pypi-remote-cache",
            "13/2c/5e07/wheel-0.46.2-py3-none-any.whl",
        );
        assert_eq!(path, "wheel/0.46.2/wheel-0.46.2-py3-none-any.whl");
    }

    #[test]
    fn test_migration_artifact_path_maven_uses_group_prefixed_source_path() {
        // Maven-family formats keep the full group-prefixed source path
        // verbatim (clients resolve `com/example/.../file.jar` directly).
        let path = migration_artifact_path(
            "maven",
            "commons-lang3",
            Some("3.12.0"),
            "commons-lang3-3.12.0.jar",
            "maven-cache",
            "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar",
        );
        assert_eq!(
            path,
            "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
        );
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
            staging_path: "/var/lib/artifact-keeper/artifacts".to_string(),
        };
        assert_eq!(config.concurrency, 8);
        assert_eq!(config.throttle_delay_ms, 0);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.batch_size, 500);
        assert!(!config.verify_checksums);
        assert!(config.dry_run);
        assert_eq!(config.staging_path, "/var/lib/artifact-keeper/artifacts");
    }

    #[test]
    fn test_worker_config_default_staging_path_is_empty() {
        // Default leaves staging_path empty so the helper falls back to the
        // OS temp dir, preserving the historical NamedTempFile::new() behavior
        // for tests and non-HTTP callers.
        let config = WorkerConfig::default();
        assert!(config.staging_path.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_staging_dir_empty_falls_back_to_os_temp() {
        // Empty staging_path => OS temp dir, never an error.
        let resolved = resolve_migration_staging_dir("").await.unwrap();
        assert_eq!(resolved, std::env::temp_dir());
    }

    #[tokio::test]
    async fn test_resolve_staging_dir_uses_configured_base_not_tmp() {
        // A configured base (simulating STORAGE_PATH) is returned verbatim and
        // is NOT the OS temp dir — this is the core invariant of #1608.
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("staging-base");
        let base_str = base.to_str().unwrap();

        let resolved = resolve_migration_staging_dir(base_str).await.unwrap();

        assert_eq!(resolved, base);
        assert_ne!(
            resolved,
            std::env::temp_dir(),
            "spill base must be the configured STORAGE_PATH-backed dir, not /tmp"
        );
        assert!(resolved.starts_with(tmp.path()));
    }

    #[tokio::test]
    async fn test_resolve_staging_dir_errors_when_base_uncreatable() {
        // If a path component is a regular file, create_dir_all fails and the
        // resolver must surface a StorageError rather than silently falling
        // back to /tmp (which would reintroduce the eviction bug).
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("a-file");
        std::fs::write(&file_path, b"not a dir").unwrap();
        // Treat the file as if it were a directory parent.
        let bad_base = file_path.join("staging");

        let err = resolve_migration_staging_dir(bad_base.to_str().unwrap())
            .await
            .unwrap_err();

        match err {
            MigrationError::StorageError(msg) => {
                assert!(
                    msg.contains("Failed to create migration staging dir"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected StorageError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_resolve_staging_dir_creates_missing_dir() {
        // The resolver must create the base if it does not yet exist, so the
        // subsequent NamedTempFile::new_in succeeds on a fresh volume.
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("nested").join("does-not-exist-yet");
        assert!(!base.exists());

        let resolved = resolve_migration_staging_dir(base.to_str().unwrap())
            .await
            .unwrap();

        assert!(resolved.is_dir(), "resolver must create the staging dir");
        // And a NamedTempFile can actually be created under it.
        let f = tempfile::NamedTempFile::new_in(&resolved).unwrap();
        assert!(f.path().starts_with(&base));
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
        // Partial failure must surface as CompletedWithErrors, not a clean
        // Completed (#2457): the OP's hollow import reported "completed".
        let status = determine_final_status(3, 7);
        assert_eq!(status, MigrationJobStatus::CompletedWithErrors);
    }

    #[test]
    fn test_determine_final_status_no_items() {
        let status = determine_final_status(0, 0);
        assert_eq!(status, MigrationJobStatus::Completed);
    }

    #[test]
    fn test_determine_final_status_one_failure_one_success() {
        let status = determine_final_status(1, 1);
        assert_eq!(status, MigrationJobStatus::CompletedWithErrors);
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
            MigrationJobStatus::CompletedWithErrors
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

    // -----------------------------------------------------------------------
    // resolve_repos_for_provisioning — pre-pass before create_repository
    // (the fix for the silent-failure bug: process_job would previously
    // skip create_repository entirely; now we resolve each requested key
    // against the source's listing first.)
    // -----------------------------------------------------------------------

    use crate::services::artifactory_client::RepositoryListItem;

    fn mk_source_repo(key: &str, repo_type: &str, package_type: &str) -> RepositoryListItem {
        RepositoryListItem {
            key: key.into(),
            repo_type: repo_type.into(),
            package_type: package_type.into(),
            url: None,
            description: None,
            members: vec![],
        }
    }

    #[test]
    fn test_resolve_repos_all_present_and_supported() {
        let source = vec![
            mk_source_repo("maven-releases", "LOCAL", "Maven"),
            mk_source_repo("npm-releases", "LOCAL", "Npm"),
        ];
        let requested = vec!["maven-releases".to_string(), "npm-releases".to_string()];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert_eq!(plan.resolved.len(), 2);
        assert!(plan.missing.is_empty());
        assert!(plan.unsupported.is_empty());
        let resolved_keys: Vec<&str> = plan
            .resolved
            .iter()
            .map(|c| c.target_key.as_str())
            .collect();
        assert!(resolved_keys.contains(&"maven-releases"));
        assert!(resolved_keys.contains(&"npm-releases"));
    }

    #[test]
    fn test_resolve_repos_missing_from_source_lands_in_missing_bucket() {
        let source = vec![mk_source_repo("maven-releases", "LOCAL", "Maven")];
        let requested = vec!["maven-releases".to_string(), "does-not-exist".to_string()];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert_eq!(plan.resolved.len(), 1);
        assert_eq!(plan.missing, vec!["does-not-exist".to_string()]);
        assert!(plan.unsupported.is_empty());
    }

    #[test]
    fn test_resolve_repos_empty_request_resolves_all_source_repos() {
        // Empty `include_repos` means "every repository the source reports"
        // — matching the apt/yum/Bazel/Helm include-list convention. The
        // previous "empty == migrate nothing" behavior caused jobs created
        // with the default empty list to silently no-op (issue #1901).
        let source = vec![
            mk_source_repo("maven-releases", "LOCAL", "Maven"),
            mk_source_repo("npm-releases", "LOCAL", "Npm"),
        ];
        let plan = resolve_repos_for_provisioning(&[], &source);
        assert_eq!(plan.resolved.len(), 2);
        assert!(plan.missing.is_empty());
        assert!(plan.unsupported.is_empty());
        let resolved_keys: Vec<&str> = plan
            .resolved
            .iter()
            .map(|c| c.target_key.as_str())
            .collect();
        assert!(resolved_keys.contains(&"maven-releases"));
        assert!(resolved_keys.contains(&"npm-releases"));
    }

    #[test]
    fn test_resolve_repos_empty_request_routes_unsupported_source_repos_to_unsupported_bucket() {
        // Even in the "empty == all" path, an unmappable source repo type
        // must land in `unsupported` rather than poison the rest of the
        // plan or short-circuit the whole job.
        let source = vec![
            mk_source_repo("maven-releases", "LOCAL", "Maven"),
            mk_source_repo("weird-repo", "BOGUS_TYPE", "Maven"),
        ];
        let plan = resolve_repos_for_provisioning(&[], &source);
        assert_eq!(plan.resolved.len(), 1);
        assert_eq!(plan.resolved[0].target_key, "maven-releases");
        assert!(plan.missing.is_empty());
        assert_eq!(plan.unsupported.len(), 1);
        assert_eq!(plan.unsupported[0].repo_key, "weird-repo");
    }

    #[test]
    fn test_resolve_repos_empty_request_with_empty_source_yields_empty_plan() {
        // When both sides are empty there really is nothing to migrate;
        // verify we return a fully empty plan (caller turns that into a
        // "no repositories to migrate" warning).
        let plan = resolve_repos_for_provisioning(&[], &[]);
        assert!(plan.resolved.is_empty());
        assert!(plan.missing.is_empty());
        assert!(plan.unsupported.is_empty());
    }

    #[test]
    fn test_resolve_repos_extra_source_repos_are_ignored() {
        // Source has repos we did NOT request; those should not show up
        // anywhere in the plan.
        let source = vec![
            mk_source_repo("maven-releases", "LOCAL", "Maven"),
            mk_source_repo("unrequested-repo", "LOCAL", "Generic"),
        ];
        let requested = vec!["maven-releases".to_string()];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert_eq!(plan.resolved.len(), 1);
        assert_eq!(plan.resolved[0].target_key, "maven-releases");
        assert!(plan.missing.is_empty());
        assert!(plan.unsupported.is_empty());
    }

    #[test]
    fn test_resolve_repos_unsupported_repo_type_lands_in_unsupported_bucket() {
        // `prepare_repository_migration` rejects unknown repo types via
        // RepositoryType::from_artifactory; we surface that here as
        // `unsupported` rather than panicking or pretending the key is
        // missing from source.
        let source = vec![mk_source_repo("weird-repo", "BOGUS_TYPE", "Maven")];
        let requested = vec!["weird-repo".to_string()];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert!(plan.resolved.is_empty());
        assert!(plan.missing.is_empty());
        assert_eq!(plan.unsupported.len(), 1);
        assert_eq!(plan.unsupported[0].repo_key, "weird-repo");
        assert!(!plan.unsupported[0].reason.is_empty());
    }

    #[test]
    fn test_resolve_repos_target_key_matches_source_key_by_default() {
        // We don't currently rename repos; documenting the contract so a
        // future change that breaks it gets caught here.
        let source = vec![mk_source_repo("maven-releases", "LOCAL", "Maven")];
        let requested = vec!["maven-releases".to_string()];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert_eq!(plan.resolved.len(), 1);
        let cfg = &plan.resolved[0];
        assert_eq!(cfg.source_key, "maven-releases");
        assert_eq!(cfg.target_key, "maven-releases");
    }

    #[test]
    fn test_resolve_repos_unsupported_repo_does_not_block_subsequent_repos() {
        // Mixed batch: 1 valid + 1 unsupported + 1 missing. All three
        // should reach their respective buckets; the unsupported one
        // must not short-circuit the loop.
        let source = vec![
            mk_source_repo("maven-releases", "LOCAL", "Maven"),
            mk_source_repo("weird-repo", "BOGUS_TYPE", "Maven"),
        ];
        let requested = vec![
            "maven-releases".to_string(),
            "weird-repo".to_string(),
            "missing-repo".to_string(),
        ];
        let plan = resolve_repos_for_provisioning(&requested, &source);
        assert_eq!(plan.resolved.len(), 1);
        assert_eq!(plan.resolved[0].target_key, "maven-releases");
        assert_eq!(plan.missing, vec!["missing-repo".to_string()]);
        assert_eq!(plan.unsupported.len(), 1);
        assert_eq!(plan.unsupported[0].repo_key, "weird-repo");
    }

    // -----------------------------------------------------------------------
    // PR #1512 review fixes -- streaming + verify-before-write
    // -----------------------------------------------------------------------

    /// Hashing parity: feeding the same bytes through the chunked
    /// streaming path (one `update` per chunk) must yield the exact same
    /// hex digest as `compute_dual_checksums` on a single buffer. This is
    /// the invariant `transfer_artifact` relies on -- if the digests
    /// diverged between code paths, every checksum verification would
    /// fail.
    #[test]
    fn test_chunked_hashing_matches_buffered_compute_dual_checksums() {
        // Sample sizes: 1 MiB, 8 MiB, and a non-power-of-two off-by-one
        // case (1 MiB + 17 bytes) that catches "block boundary" bugs in
        // chunked hashers.
        let sizes = [1024 * 1024, 8 * 1024 * 1024, 1024 * 1024 + 17];

        for &size in &sizes {
            // Deterministic non-zero payload.
            let mut payload = Vec::with_capacity(size);
            let mut x: u32 = 0xDEAD_BEEF;
            for _ in 0..size {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                payload.push((x >> 16) as u8);
            }

            let (buffered_sha256, buffered_sha1) = compute_dual_checksums(&payload);

            // Now hash the same payload as if it were arriving in
            // arbitrary-size chunks (mirror what `transfer_artifact` does
            // on each iteration of its `stream.next()` loop).
            let mut sha256 = Sha256::new();
            let mut sha1 = Sha1::new();
            for chunk in payload.chunks(13 * 1024 + 7) {
                sha256.update(chunk);
                sha1.update(chunk);
            }
            let chunked_sha256 = hex::encode(sha256.finalize());
            let chunked_sha1 = hex::encode(sha1.finalize());

            assert_eq!(
                chunked_sha256, buffered_sha256,
                "sha256 parity broken at size {}",
                size
            );
            assert_eq!(
                chunked_sha1, buffered_sha1,
                "sha1 parity broken at size {}",
                size
            );
        }
    }

    /// End-to-end-ish test for the verify-before-write ordering fix.
    /// Runs `transfer_artifact` against a mock source that emits a known
    /// payload AND advertises a deliberately wrong sha256. The recording
    /// storage backend must observe ZERO `put_stream` / `put_file` calls
    /// because the worker should bail out at the checksum-verify step
    /// BEFORE handing the temp file to storage. Pre-fix, the corrupted
    /// body was committed to storage and an `artifacts` row was inserted,
    /// and only THEN was the mismatch detected by `finalize_transfer`.
    ///
    /// DB-gated via `try_pool` so it skips cleanly when `DATABASE_URL`
    /// is not set.
    #[tokio::test]
    async fn test_transfer_artifact_rejects_mismatch_without_writing_storage() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::artifactory_client::ArtifactoryError;
        use crate::services::source_registry::ArtifactByteStream;
        use crate::services::source_registry::SourceRegistry;
        use async_trait::async_trait;
        use bytes::Bytes;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        struct ChunkedMockSource;

        #[async_trait]
        impl SourceRegistry for ChunkedMockSource {
            async fn ping(&self) -> Result<bool, ArtifactoryError> {
                Ok(true)
            }
            async fn get_version(
                &self,
            ) -> Result<crate::services::artifactory_client::SystemVersionResponse, ArtifactoryError>
            {
                unimplemented!()
            }
            async fn list_repositories(
                &self,
            ) -> Result<
                Vec<crate::services::artifactory_client::RepositoryListItem>,
                ArtifactoryError,
            > {
                Ok(vec![])
            }
            async fn list_artifacts(
                &self,
                _repo_key: &str,
                _offset: i64,
                _limit: i64,
            ) -> Result<crate::services::artifactory_client::AqlResponse, ArtifactoryError>
            {
                unimplemented!()
            }
            async fn download_artifact(
                &self,
                _repo_key: &str,
                _path: &str,
            ) -> Result<Bytes, ArtifactoryError> {
                Ok(Bytes::from_static(b"some payload here"))
            }
            async fn download_artifact_stream(
                &self,
                _repo_key: &str,
                _path: &str,
            ) -> Result<ArtifactByteStream, ArtifactoryError> {
                // Emit a known multi-chunk stream so the worker has to
                // accumulate hashes across iterations.
                let chunks: Vec<Result<Bytes, ArtifactoryError>> = vec![
                    Ok(Bytes::from_static(b"hello ")),
                    Ok(Bytes::from_static(b"world ")),
                    Ok(Bytes::from_static(b"payload!")),
                ];
                Ok(Box::pin(futures::stream::iter(chunks)))
            }
            async fn get_properties(
                &self,
                _repo_key: &str,
                _path: &str,
            ) -> Result<crate::services::artifactory_client::PropertiesResponse, ArtifactoryError>
            {
                Ok(crate::services::artifactory_client::PropertiesResponse {
                    properties: None,
                    uri: None,
                })
            }
            fn source_type(&self) -> &'static str {
                "mock"
            }
        }

        /// Counts how many times the storage was asked to commit bytes.
        struct CountingStorage {
            put_stream_calls: Arc<AtomicUsize>,
            put_file_calls: Arc<AtomicUsize>,
            put_calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl StorageBackend for CountingStorage {
            async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
                self.put_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
                Ok(Bytes::new())
            }
            async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
                Ok(false)
            }
            async fn delete(&self, _key: &str) -> crate::error::Result<()> {
                Ok(())
            }
            async fn put_file(
                &self,
                _key: &str,
                _path: &std::path::Path,
            ) -> crate::error::Result<()> {
                self.put_file_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn put_stream(
                &self,
                _key: &str,
                _stream: futures::stream::BoxStream<'static, crate::error::Result<Bytes>>,
            ) -> crate::error::Result<crate::storage::PutStreamResult> {
                self.put_stream_calls.fetch_add(1, Ordering::SeqCst);
                Ok(crate::storage::PutStreamResult {
                    checksum_sha256: String::new(),
                    bytes_written: 0,
                })
            }
        }

        let put_stream_calls = Arc::new(AtomicUsize::new(0));
        let put_file_calls = Arc::new(AtomicUsize::new(0));
        let put_calls = Arc::new(AtomicUsize::new(0));

        let storage = Arc::new(CountingStorage {
            put_stream_calls: put_stream_calls.clone(),
            put_file_calls: put_file_calls.clone(),
            put_calls: put_calls.clone(),
        });

        // transfer_artifact takes the per-repo storage directly (#1420); the
        // worker's registry is unused on this path, so wrap the counting mock
        // in a single-backend registry just to satisfy the constructor.
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "filesystem".to_string(),
            storage.clone() as Arc<dyn StorageBackend>,
        );
        let registry = Arc::new(StorageRegistry::new(backends, "filesystem".to_string()));
        let worker = MigrationWorker::new(
            pool.clone(),
            registry,
            WorkerConfig {
                verify_checksums: true,
                dry_run: false,
                ..WorkerConfig::default()
            },
            CancellationToken::new(),
        );

        // Advertised sha256 deliberately wrong. The real sha256 of
        // "hello world payload!" is what the worker will compute; we set
        // expected to something else so verify_expected_checksums returns
        // Some(mismatch).
        let expected = ExpectedChecksums {
            sha256: Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
            sha1: None,
        };

        let result = worker
            .transfer_artifact(
                Arc::new(ChunkedMockSource),
                storage.clone(),
                "irrelevant-repo",
                "generic",
                "irrelevant/path",
                false,
                &expected,
            )
            .await;

        // Must fail with ChecksumMismatch, NOT a storage error.
        match result {
            Err(MigrationError::ChecksumMismatch { .. }) => {}
            other => panic!("expected ChecksumMismatch, got {:?}", other),
        }

        // The critical invariant: storage was never asked to commit the
        // bytes. Pre-fix, `put_file` would have been called BEFORE
        // verification.
        assert_eq!(
            put_stream_calls.load(Ordering::SeqCst),
            0,
            "put_stream must not run when checksum mismatches"
        );
        assert_eq!(
            put_file_calls.load(Ordering::SeqCst),
            0,
            "put_file must not run when checksum mismatches"
        );
        assert_eq!(
            put_calls.load(Ordering::SeqCst),
            0,
            "put must not run when checksum mismatches"
        );
    }

    /// Companion to the above: when checksums match, the worker
    /// proceeds to call `put_stream` (NOT `put_file`). The PR review
    /// blocker was that the worker called `put_file`, whose trait
    /// default loaded the whole file into memory. After the fix the
    /// migration path must invoke each backend's streaming primitive.
    #[tokio::test]
    async fn test_transfer_artifact_uses_put_stream_on_happy_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::artifactory_client::ArtifactoryError;
        use crate::services::source_registry::ArtifactByteStream;
        use crate::services::source_registry::SourceRegistry;
        use async_trait::async_trait;
        use bytes::Bytes;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        struct ChunkedMockSource;
        #[async_trait]
        impl SourceRegistry for ChunkedMockSource {
            async fn ping(&self) -> Result<bool, ArtifactoryError> {
                Ok(true)
            }
            async fn get_version(
                &self,
            ) -> Result<crate::services::artifactory_client::SystemVersionResponse, ArtifactoryError>
            {
                unimplemented!()
            }
            async fn list_repositories(
                &self,
            ) -> Result<
                Vec<crate::services::artifactory_client::RepositoryListItem>,
                ArtifactoryError,
            > {
                Ok(vec![])
            }
            async fn list_artifacts(
                &self,
                _r: &str,
                _o: i64,
                _l: i64,
            ) -> Result<crate::services::artifactory_client::AqlResponse, ArtifactoryError>
            {
                unimplemented!()
            }
            async fn download_artifact(
                &self,
                _r: &str,
                _p: &str,
            ) -> Result<Bytes, ArtifactoryError> {
                Ok(Bytes::from_static(b"x"))
            }
            async fn download_artifact_stream(
                &self,
                _r: &str,
                _p: &str,
            ) -> Result<ArtifactByteStream, ArtifactoryError> {
                let chunks: Vec<Result<Bytes, ArtifactoryError>> =
                    vec![Ok(Bytes::from_static(b"abc"))];
                Ok(Box::pin(futures::stream::iter(chunks)))
            }
            async fn get_properties(
                &self,
                _r: &str,
                _p: &str,
            ) -> Result<crate::services::artifactory_client::PropertiesResponse, ArtifactoryError>
            {
                Ok(crate::services::artifactory_client::PropertiesResponse {
                    properties: None,
                    uri: None,
                })
            }
            fn source_type(&self) -> &'static str {
                "mock"
            }
        }

        struct CountingStorage {
            put_stream_calls: Arc<AtomicUsize>,
            put_file_calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl StorageBackend for CountingStorage {
            async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
                Ok(())
            }
            async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
                Ok(Bytes::new())
            }
            async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
                Ok(false)
            }
            async fn delete(&self, _key: &str) -> crate::error::Result<()> {
                Ok(())
            }
            async fn put_file(
                &self,
                _key: &str,
                _path: &std::path::Path,
            ) -> crate::error::Result<()> {
                self.put_file_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn put_stream(
                &self,
                _key: &str,
                mut stream: futures::stream::BoxStream<'static, crate::error::Result<Bytes>>,
            ) -> crate::error::Result<crate::storage::PutStreamResult> {
                use futures::StreamExt;
                self.put_stream_calls.fetch_add(1, Ordering::SeqCst);
                let mut total = 0u64;
                while let Some(c) = stream.next().await {
                    total += c?.len() as u64;
                }
                Ok(crate::storage::PutStreamResult {
                    checksum_sha256: String::new(),
                    bytes_written: total,
                })
            }
        }

        let put_stream_calls = Arc::new(AtomicUsize::new(0));
        let put_file_calls = Arc::new(AtomicUsize::new(0));
        let storage = Arc::new(CountingStorage {
            put_stream_calls: put_stream_calls.clone(),
            put_file_calls: put_file_calls.clone(),
        });

        // transfer_artifact takes the per-repo storage directly (#1420); wrap
        // the counting mock in a single-backend registry for the constructor.
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "filesystem".to_string(),
            storage.clone() as Arc<dyn StorageBackend>,
        );
        let registry = Arc::new(StorageRegistry::new(backends, "filesystem".to_string()));
        let worker = MigrationWorker::new(
            pool.clone(),
            registry,
            WorkerConfig {
                verify_checksums: true,
                dry_run: false,
                ..WorkerConfig::default()
            },
            CancellationToken::new(),
        );

        // No expected checksums -> verification passes; worker proceeds
        // through the storage write path.
        let expected = ExpectedChecksums {
            sha256: None,
            sha1: None,
        };

        let _ = worker
            .transfer_artifact(
                Arc::new(ChunkedMockSource),
                storage.clone(),
                "irrelevant-repo",
                "generic",
                "irrelevant/path",
                false,
                &expected,
            )
            .await;

        // The migration path must use put_stream (the streaming upload
        // primitive on each backend). put_file must NOT be invoked, since
        // its trait default in this mock would buffer the whole body.
        assert_eq!(
            put_stream_calls.load(Ordering::SeqCst),
            1,
            "transfer_artifact must call put_stream once on the happy path"
        );
        assert_eq!(
            put_file_calls.load(Ordering::SeqCst),
            0,
            "transfer_artifact must NOT call put_file (would buffer on cloud backends)"
        );
    }

    // -----------------------------------------------------------------------
    // #2457: Docker/OCI source-path classification (pure, no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_oci_package_type() {
        assert!(is_oci_package_type("docker"));
        assert!(is_oci_package_type("Docker"));
        assert!(is_oci_package_type("oci"));
        assert!(!is_oci_package_type("maven"));
        assert!(!is_oci_package_type("npm"));
        assert!(!is_oci_package_type("helm_oci"));
    }

    #[test]
    fn test_normalize_digest_segment_accepts_both_forms() {
        let hex = "a".repeat(64);
        assert_eq!(
            normalize_digest_segment(&format!("sha256__{hex}")),
            Some(format!("sha256:{hex}"))
        );
        assert_eq!(
            normalize_digest_segment(&format!("sha256:{hex}")),
            Some(format!("sha256:{hex}"))
        );
    }

    #[test]
    fn test_normalize_digest_segment_rejects_non_digests() {
        assert_eq!(normalize_digest_segment("latest"), None);
        assert_eq!(normalize_digest_segment("sha256__short"), None);
        // Uppercase hex is not a canonical registry digest.
        let upper = "A".repeat(64);
        assert_eq!(normalize_digest_segment(&format!("sha256__{upper}")), None);
        // Wrong length.
        let long = "a".repeat(65);
        assert_eq!(normalize_digest_segment(&format!("sha256:{long}")), None);
        // Non-hex characters.
        let bad = "g".repeat(64);
        assert_eq!(normalize_digest_segment(&format!("sha256__{bad}")), None);
    }

    #[test]
    fn test_classify_artifactory_tag_manifest() {
        assert_eq!(
            classify_oci_source_artifact("hello-world/latest/manifest.json"),
            OciRole::Manifest {
                image: "hello-world".to_string(),
                reference: "latest".to_string(),
            }
        );
        // Nested image namespaces keep every segment.
        assert_eq!(
            classify_oci_source_artifact("org/team/app/v1.2/manifest.json"),
            OciRole::Manifest {
                image: "org/team/app".to_string(),
                reference: "v1.2".to_string(),
            }
        );
    }

    #[test]
    fn test_classify_artifactory_list_manifest_and_child() {
        let hex = "b".repeat(64);
        assert_eq!(
            classify_oci_source_artifact("app/latest/list.manifest.json"),
            OciRole::Manifest {
                image: "app".to_string(),
                reference: "latest".to_string(),
            }
        );
        // Content-addressed child manifest folder => digest reference.
        assert_eq!(
            classify_oci_source_artifact(&format!("app/sha256__{hex}/manifest.json")),
            OciRole::Manifest {
                image: "app".to_string(),
                reference: format!("sha256:{hex}"),
            }
        );
    }

    #[test]
    fn test_classify_artifactory_blob() {
        let hex = "c".repeat(64);
        assert_eq!(
            classify_oci_source_artifact(&format!("app/latest/sha256__{hex}")),
            OciRole::Blob {
                digest: format!("sha256:{hex}"),
            }
        );
    }

    #[test]
    fn test_classify_nexus_manifest_tag_and_digest() {
        let hex = "d".repeat(64);
        assert_eq!(
            classify_oci_source_artifact("v2/myimage/manifests/latest"),
            OciRole::Manifest {
                image: "myimage".to_string(),
                reference: "latest".to_string(),
            }
        );
        assert_eq!(
            classify_oci_source_artifact(&format!("v2/org/app/manifests/sha256:{hex}")),
            OciRole::Manifest {
                image: "org/app".to_string(),
                reference: format!("sha256:{hex}"),
            }
        );
    }

    #[test]
    fn test_classify_nexus_blob() {
        let hex = "e".repeat(64);
        assert_eq!(
            classify_oci_source_artifact(&format!("v2/-/blobs/sha256:{hex}")),
            OciRole::Blob {
                digest: format!("sha256:{hex}"),
            }
        );
        assert_eq!(
            classify_oci_source_artifact(&format!("v2/myimage/blobs/sha256:{hex}")),
            OciRole::Blob {
                digest: format!("sha256:{hex}"),
            }
        );
    }

    #[test]
    fn test_classify_rejects_non_oci_shapes() {
        // Generic files fall through to the generic import path.
        assert_eq!(
            classify_oci_source_artifact("com/example/lib/1.0/lib-1.0.jar"),
            OciRole::NotOci
        );
        // A manifest.json with no image segment is not addressable.
        assert_eq!(
            classify_oci_source_artifact("manifest.json"),
            OciRole::NotOci
        );
        assert_eq!(
            classify_oci_source_artifact("latest/manifest.json"),
            OciRole::NotOci
        );
        // A blobs/ segment whose leaf is not a digest is not a blob.
        assert_eq!(
            classify_oci_source_artifact("v2/app/blobs/notadigest"),
            OciRole::NotOci
        );
        // Empty path.
        assert_eq!(classify_oci_source_artifact(""), OciRole::NotOci);
    }

    // -----------------------------------------------------------------------
    // #2457: OCI-aware import (DB-gated via try_pool)
    // -----------------------------------------------------------------------

    /// Mock source registry that serves a fixed path->bytes map through the
    /// buffered download API (the default stream impl wraps it), mirroring
    /// what Artifactory/Nexus enumerate.
    struct MapSource {
        files: std::collections::HashMap<String, bytes::Bytes>,
    }

    #[async_trait::async_trait]
    impl crate::services::source_registry::SourceRegistry for MapSource {
        async fn ping(
            &self,
        ) -> Result<bool, crate::services::artifactory_client::ArtifactoryError> {
            Ok(true)
        }
        async fn get_version(
            &self,
        ) -> Result<
            crate::services::artifactory_client::SystemVersionResponse,
            crate::services::artifactory_client::ArtifactoryError,
        > {
            unimplemented!()
        }
        async fn list_repositories(
            &self,
        ) -> Result<
            Vec<crate::services::artifactory_client::RepositoryListItem>,
            crate::services::artifactory_client::ArtifactoryError,
        > {
            Ok(vec![])
        }
        async fn list_artifacts(
            &self,
            _repo_key: &str,
            _offset: i64,
            _limit: i64,
        ) -> Result<
            crate::services::artifactory_client::AqlResponse,
            crate::services::artifactory_client::ArtifactoryError,
        > {
            unimplemented!()
        }
        async fn download_artifact(
            &self,
            _repo_key: &str,
            path: &str,
        ) -> Result<bytes::Bytes, crate::services::artifactory_client::ArtifactoryError> {
            self.files.get(path).cloned().ok_or_else(|| {
                crate::services::artifactory_client::ArtifactoryError::NotFound(format!(
                    "Artifact not found: {path}"
                ))
            })
        }
        async fn get_properties(
            &self,
            _repo_key: &str,
            _path: &str,
        ) -> Result<
            crate::services::artifactory_client::PropertiesResponse,
            crate::services::artifactory_client::ArtifactoryError,
        > {
            Ok(crate::services::artifactory_client::PropertiesResponse {
                properties: None,
                uri: None,
            })
        }
        fn source_type(&self) -> &'static str {
            "mock"
        }
    }

    fn sha256_hex_of(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Build a Docker schema2 image-manifest body over the given config and
    /// layer bytes. Shared by the import tests so the JSON scaffolding lives
    /// in one place.
    fn docker_image_manifest_json(config_bytes: &[u8], layer_bytes: &[u8]) -> String {
        format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\",\
              \"config\":{{\"mediaType\":\"application/vnd.docker.container.image.v1+json\",\"size\":{},\"digest\":\"sha256:{}\"}},\
              \"layers\":[{{\"mediaType\":\"application/vnd.docker.image.rootfs.diff.tar.gzip\",\"size\":{},\"digest\":\"sha256:{}\"}}]}}",
            config_bytes.len(),
            sha256_hex_of(config_bytes),
            layer_bytes.len(),
            sha256_hex_of(layer_bytes)
        )
    }

    /// Build a worker + filesystem storage rooted in a fresh temp dir and a
    /// repository row pointing at it. Returns everything a #2457 import test
    /// needs.
    async fn setup_repo_for_import(
        pool: &sqlx::PgPool,
        prefix: &str,
        format: &str,
    ) -> (
        MigrationWorker,
        Arc<dyn StorageBackend>,
        tempfile::TempDir,
        Uuid,
        String,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_id = Uuid::new_v4();
        let repo_key = format!("{prefix}-{}", &repo_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $2, $3, 'local', $4::repository_format, true)",
        )
        .bind(repo_id)
        .bind(&repo_key)
        .bind(tmp.path().to_str().unwrap())
        .bind(format)
        .execute(pool)
        .await
        .expect("insert repo");

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(tmp.path().to_str().unwrap()),
        );
        let registry = Arc::new(StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let worker = MigrationWorker::new(
            pool.clone(),
            registry,
            WorkerConfig::default(),
            CancellationToken::new(),
        );
        (worker, storage, tmp, repo_id, repo_key)
    }

    async fn transfer_one(
        worker: &MigrationWorker,
        storage: &Arc<dyn StorageBackend>,
        files: &std::collections::HashMap<String, bytes::Bytes>,
        repo_key: &str,
        package_type: &str,
        path: &str,
    ) -> Result<TransferResult, MigrationError> {
        worker
            .transfer_artifact(
                Arc::new(MapSource {
                    files: files.clone(),
                }),
                storage.clone(),
                repo_key,
                package_type,
                path,
                false,
                &ExpectedChecksums {
                    sha256: None,
                    sha1: None,
                },
            )
            .await
    }

    /// End-to-end #2457 import over the Artifactory source layout: a config
    /// blob, a layer blob, and a tagged image manifest must land in the OCI
    /// index (oci_blobs + oci_tags + manifest_blob_refs) with bytes at the
    /// digest-addressed keys the V2 pull path reads. Pre-fix, none of these
    /// rows existed and the tag pulled as MANIFEST_UNKNOWN.
    #[tokio::test]
    async fn test_docker_import_registers_manifest_and_blobs_artifactory_layout() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-art", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer_bytes = bytes::Bytes::from_static(b"layer-bytes-2457");
        let config_hex = sha256_hex_of(&config_bytes);
        let layer_hex = sha256_hex_of(&layer_bytes);
        let manifest = docker_image_manifest_json(&config_bytes, &layer_bytes);
        let manifest_bytes = bytes::Bytes::from(manifest);
        let manifest_digest = format!("sha256:{}", sha256_hex_of(&manifest_bytes));

        let config_path = format!("hello/latest/sha256__{config_hex}");
        let layer_path = format!("hello/latest/sha256__{layer_hex}");
        let manifest_path = "hello/latest/manifest.json".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(config_path.clone(), config_bytes.clone());
        files.insert(layer_path.clone(), layer_bytes.clone());
        files.insert(manifest_path.clone(), manifest_bytes.clone());

        for path in [&config_path, &layer_path, &manifest_path] {
            transfer_one(&worker, &storage, &files, &repo_key, "docker", path)
                .await
                .unwrap_or_else(|e| panic!("transfer of {path} failed: {e}"));
        }

        // Tag row resolves the migrated tag to the manifest digest.
        let tag_row: Option<(String, String)> = sqlx::query_as(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags \
             WHERE repository_id = $1 AND name = 'hello' AND tag = 'latest'",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .expect("query oci_tags");
        let (digest, content_type) = tag_row.expect("migrated tag must be registered in oci_tags");
        assert_eq!(digest, manifest_digest);
        // Stored media type must match the body's own mediaType — a Docker
        // schema2 body stored under the OCI type breaks `docker pull`.
        assert_eq!(
            content_type,
            "application/vnd.docker.distribution.manifest.v2+json"
        );

        // Manifest bytes live at the digest-addressed key the V2 GET reads.
        let stored = storage
            .get(&format!("oci-manifests/{manifest_digest}"))
            .await
            .expect("manifest bytes at oci-manifests/<digest>");
        assert_eq!(stored, manifest_bytes);

        // Both blobs registered and their bytes at oci-blobs/<digest>.
        for hex in [&config_hex, &layer_hex] {
            let blob: Option<(String,)> = sqlx::query_as(
                "SELECT storage_key FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
            )
            .bind(repo_id)
            .bind(format!("sha256:{hex}"))
            .fetch_optional(&pool)
            .await
            .expect("query oci_blobs");
            let (key,) = blob.expect("blob must be registered in oci_blobs");
            assert!(storage.exists(&key).await.unwrap(), "blob bytes at {key}");
        }

        // Image manifest edges recorded for GC protection.
        let ref_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM manifest_blob_refs WHERE repository_id = $1 AND manifest_digest = $2",
        )
        .bind(repo_id)
        .bind(&manifest_digest)
        .fetch_one(&pool)
        .await
        .expect("count manifest_blob_refs");
        assert_eq!(ref_count.0, 2, "config + layer edges must be recorded");

        // The artifacts row is preserved for the UI/download API.
        let artifact_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("count artifacts");
        assert_eq!(artifact_count.0, 3);

        // Re-import is idempotent (ON CONFLICT paths, no errors).
        transfer_one(
            &worker,
            &storage,
            &files,
            &repo_key,
            "docker",
            &manifest_path,
        )
        .await
        .expect("re-import of the manifest must be idempotent");

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// Multi-arch over the Nexus source layout: the child image manifest
    /// (digest reference) and the index (tag reference) are separate source
    /// artifacts; importing both must record the parent->child edge in
    /// oci_manifest_refs and register the child under its digest.
    #[tokio::test]
    async fn test_docker_import_multiarch_index_nexus_layout() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-nx", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let config_hex = sha256_hex_of(&config_bytes);
        let child = format!(
            "{{\"schemaVersion\":2,\
              \"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\
              \"layers\":[]}}",
            config_bytes.len(),
            config_hex
        );
        let child_bytes = bytes::Bytes::from(child);
        let child_hex = sha256_hex_of(&child_bytes);
        let index = format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.oci.image.index.v1+json\",\
              \"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\
              \"size\":{},\"digest\":\"sha256:{}\",\
              \"platform\":{{\"architecture\":\"amd64\",\"os\":\"linux\"}}}}]}}",
            child_bytes.len(),
            child_hex
        );
        let index_bytes = bytes::Bytes::from(index);
        let index_digest = format!("sha256:{}", sha256_hex_of(&index_bytes));

        let blob_path = format!("v2/app/blobs/sha256:{config_hex}");
        let child_path = format!("v2/app/manifests/sha256:{child_hex}");
        let index_path = "v2/app/manifests/latest".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(blob_path.clone(), config_bytes.clone());
        files.insert(child_path.clone(), child_bytes.clone());
        files.insert(index_path.clone(), index_bytes.clone());

        for path in [&blob_path, &child_path, &index_path] {
            transfer_one(&worker, &storage, &files, &repo_key, "docker", path)
                .await
                .unwrap_or_else(|e| panic!("transfer of {path} failed: {e}"));
        }

        // Tag resolves to the index, stored with an index media type so the
        // GC gate treats it as an index.
        let tag_row: Option<(String, String)> = sqlx::query_as(
            "SELECT manifest_digest, manifest_content_type FROM oci_tags \
             WHERE repository_id = $1 AND name = 'app' AND tag = 'latest'",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .expect("query oci_tags");
        let (digest, content_type) = tag_row.expect("index tag must be registered");
        assert_eq!(digest, index_digest);
        assert_eq!(content_type, "application/vnd.oci.image.index.v1+json");

        // Parent->child edge recorded; child registered under its digest.
        let edge: Option<(String,)> = sqlx::query_as(
            "SELECT child_digest FROM oci_manifest_refs \
             WHERE repository_id = $1 AND parent_digest = $2",
        )
        .bind(repo_id)
        .bind(&index_digest)
        .fetch_optional(&pool)
        .await
        .expect("query oci_manifest_refs");
        assert_eq!(edge.expect("index edge").0, format!("sha256:{child_hex}"));

        let child_row: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags \
             WHERE repository_id = $1 AND manifest_digest = $2 LIMIT 1",
        )
        .bind(repo_id)
        .bind(format!("sha256:{child_hex}"))
        .fetch_optional(&pool)
        .await
        .expect("query child tag row");
        assert!(
            child_row.is_some(),
            "child manifest must resolve by digest (as the live push path records it)"
        );
        assert!(
            storage
                .exists(&format!("oci-manifests/sha256:{child_hex}"))
                .await
                .unwrap(),
            "child manifest bytes at its digest-addressed key"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// #2457 ROOT: a real Nexus enumerates ONLY the tag manifests. Importing
    /// just the index tag (its child manifests + all config/layer blobs are
    /// available by digest but NOT enumerated) must leave the image fully
    /// pullable: the walker fetches the child manifest and every blob, so
    /// `oci_blobs` is populated and the child resolves by digest. This is the
    /// exact shape the oracle exercises — the child/blobs are NOT pre-seeded as
    /// their own transfer items (that masking pre-seed hid the bug).
    #[tokio::test]
    async fn test_docker_import_walks_referenced_content_nexus_only_tags() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-walk", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\",\"arch\":\"amd64\"}");
        let layer_bytes = bytes::Bytes::from_static(b"real-layer-bytes-2457-walk");
        let config_hex = sha256_hex_of(&config_bytes);
        let layer_hex = sha256_hex_of(&layer_bytes);
        let child = format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\
              \"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\
              \"layers\":[{{\"size\":{},\"digest\":\"sha256:{}\"}}]}}",
            config_bytes.len(),
            config_hex,
            layer_bytes.len(),
            layer_hex
        );
        let child_bytes = bytes::Bytes::from(child);
        let child_hex = sha256_hex_of(&child_bytes);
        let index = format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.oci.image.index.v1+json\",\
              \"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\
              \"size\":{},\"digest\":\"sha256:{}\",\
              \"platform\":{{\"architecture\":\"amd64\",\"os\":\"linux\"}}}}]}}",
            child_bytes.len(),
            child_hex
        );
        let index_bytes = bytes::Bytes::from(index);
        let index_digest = format!("sha256:{}", sha256_hex_of(&index_bytes));

        // Source contents: the index tag (enumerated) PLUS the by-digest
        // content the walker fetches (child manifest, config, layer). Only the
        // index tag is transferred as an item.
        let index_path = "v2/app/manifests/latest".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(index_path.clone(), index_bytes.clone());
        files.insert(
            format!("v2/app/manifests/sha256:{child_hex}"),
            child_bytes.clone(),
        );
        files.insert(
            format!("v2/app/blobs/sha256:{config_hex}"),
            config_bytes.clone(),
        );
        files.insert(
            format!("v2/app/blobs/sha256:{layer_hex}"),
            layer_bytes.clone(),
        );

        transfer_one(&worker, &storage, &files, &repo_key, "docker", &index_path)
            .await
            .expect("index import must succeed and walk referenced content");

        // Index tag registered.
        let tag: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id = $1 AND name='app' AND tag='latest'",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(tag.expect("index tag").0, index_digest);

        // Child manifest resolved by digest + bytes present.
        let child_row: Option<(String,)> = sqlx::query_as(
            "SELECT manifest_digest FROM oci_tags WHERE repository_id=$1 AND manifest_digest=$2 LIMIT 1",
        )
        .bind(repo_id)
        .bind(format!("sha256:{child_hex}"))
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(
            child_row.is_some(),
            "child must resolve by digest after walk"
        );
        assert!(storage
            .exists(&format!("oci-manifests/sha256:{child_hex}"))
            .await
            .unwrap());

        // Both blobs registered with real bytes (the pre-fix hollow bug had
        // oci_blobs == 0 here).
        let blob_ct: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(blob_ct.0, 2, "config + layer registered by the walker");
        for hex in [&config_hex, &layer_hex] {
            let blob: Option<(String,)> = sqlx::query_as(
                "SELECT storage_key FROM oci_blobs WHERE repository_id=$1 AND digest=$2",
            )
            .bind(repo_id)
            .bind(format!("sha256:{hex}"))
            .fetch_optional(&pool)
            .await
            .unwrap();
            let (key,) = blob.expect("blob registered by walker");
            assert!(storage.exists(&key).await.unwrap(), "blob bytes at {key}");
        }

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Fail-closed: a source that 404s a referenced layer must FAIL the item
    /// and commit NOTHING — no oci_tags, no partial oci_blobs, no artifacts row
    /// for the manifest. The whole item transaction rolls back.
    #[tokio::test]
    async fn test_docker_import_fails_closed_on_unfetchable_layer() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-fc", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer_bytes = bytes::Bytes::from_static(b"layer-that-source-will-404");
        let config_hex = sha256_hex_of(&config_bytes);
        let layer_hex = sha256_hex_of(&layer_bytes);
        let manifest = format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\",\
              \"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\
              \"layers\":[{{\"size\":{},\"digest\":\"sha256:{}\"}}]}}",
            config_bytes.len(),
            config_hex,
            layer_bytes.len(),
            layer_hex
        );
        let manifest_bytes = bytes::Bytes::from(manifest);

        // Enumerate the image tag; provide config but NOT the layer -> the
        // walker's layer fetch 404s.
        let tag_path = "v2/app/manifests/latest".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(tag_path.clone(), manifest_bytes.clone());
        files.insert(
            format!("v2/app/blobs/sha256:{config_hex}"),
            config_bytes.clone(),
        );
        // layer digest intentionally absent.

        let res = transfer_one(&worker, &storage, &files, &repo_key, "docker", &tag_path).await;
        assert!(res.is_err(), "unfetchable layer must fail the item");

        // Nothing committed: no tag, no blobs, no manifest artifacts row.
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM oci_tags WHERE repository_id=$1), \
                    (SELECT COUNT(*) FROM oci_blobs WHERE repository_id=$1), \
                    (SELECT COUNT(*) FROM artifacts WHERE repository_id=$1 AND is_deleted=false)",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            counts,
            (0, 0, 0),
            "fail-closed: the item transaction must roll back entirely"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// F3: deleting a migrated tag then re-migrating must leave exactly one
    /// LIVE artifacts row (the tombstone resurrected) and zero orphan oci_tags.
    #[tokio::test]
    async fn test_docker_reimport_resurrects_soft_deleted_row() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-f3", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let config_hex = sha256_hex_of(&config_bytes);
        let manifest = format!(
            "{{\"schemaVersion\":2,\
              \"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\",\
              \"config\":{{\"size\":{},\"digest\":\"sha256:{}\"}},\"layers\":[]}}",
            config_bytes.len(),
            config_hex
        );
        let manifest_bytes = bytes::Bytes::from(manifest);
        let tag_path = "v2/app/manifests/latest".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(tag_path.clone(), manifest_bytes.clone());
        files.insert(
            format!("v2/app/blobs/sha256:{config_hex}"),
            config_bytes.clone(),
        );

        transfer_one(&worker, &storage, &files, &repo_key, "docker", &tag_path)
            .await
            .expect("first import");

        // Soft-delete the migrated manifest artifacts row (tombstone).
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path LIKE '%manifests/latest'",
        )
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();

        // Re-migrate (overwrite): the tombstone must be resurrected, not
        // left dead beneath a re-registered tag.
        transfer_one(&worker, &storage, &files, &repo_key, "docker", &tag_path)
            .await
            .expect("re-import");

        let live_manifest_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id=$1 AND path LIKE '%manifests/latest' AND is_deleted=false",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            live_manifest_rows.0, 1,
            "exactly one live manifest artifact"
        );

        // No orphan oci_tags: every tag has a backing live artifacts row.
        let orphan: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oci_tags ot WHERE ot.repository_id=$1 \
             AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.repository_id=ot.repository_id \
                             AND 'sha256:'||a.checksum_sha256 = ot.manifest_digest AND a.is_deleted=false)",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            orphan.0, 0,
            "no orphan oci_tags after resurrecting re-import"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A malformed manifest body (valid path shape, degenerate content) must
    /// fail the item — silently importing it would recreate the unpullable
    /// state this fix removes.
    #[tokio::test]
    async fn test_docker_import_rejects_malformed_manifest_body() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-bad", "docker").await;

        let mut files = std::collections::HashMap::new();
        files.insert(
            "broken/latest/manifest.json".to_string(),
            bytes::Bytes::from_static(b"not-json-at-all"),
        );

        let result = transfer_one(
            &worker,
            &storage,
            &files,
            &repo_key,
            "docker",
            "broken/latest/manifest.json",
        )
        .await;
        assert!(
            result.is_err(),
            "malformed manifest must fail the item, not import silently"
        );

        let tags: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .expect("count oci_tags");
        assert_eq!(tags.0, 0);

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// A blob whose bytes do not hash to the digest in its path must fail
    /// (registering either digest would corrupt or dangle the reference).
    #[tokio::test]
    async fn test_docker_import_rejects_blob_digest_mismatch() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-mm", "docker").await;

        let wrong_hex = "f".repeat(64);
        let blob_path = format!("app/latest/sha256__{wrong_hex}");
        let mut files = std::collections::HashMap::new();
        files.insert(blob_path.clone(), bytes::Bytes::from_static(b"whatever"));

        let result = transfer_one(&worker, &storage, &files, &repo_key, "docker", &blob_path).await;
        assert!(
            matches!(result, Err(MigrationError::ChecksumMismatch { .. })),
            "digest mismatch must surface as ChecksumMismatch, got {result:?}"
        );

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    /// Regression guard: non-docker formats keep the generic import path
    /// byte-for-byte — CAS storage key, artifacts row, and NO OCI rows, even
    /// for a path that looks like a Docker layout.
    #[tokio::test]
    async fn test_non_docker_import_keeps_generic_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2457-gen", "generic").await;

        let body = bytes::Bytes::from_static(b"generic payload that is not oci");
        let body_hex = sha256_hex_of(&body);
        let path = "hello/latest/manifest.json";
        let mut files = std::collections::HashMap::new();
        files.insert(path.to_string(), body.clone());

        transfer_one(&worker, &storage, &files, &repo_key, "generic", path)
            .await
            .expect("generic transfer must succeed");

        // Bytes at the CAS key, exactly as before #2457.
        let cas_key = ArtifactService::storage_key_from_checksum(&body_hex);
        assert!(storage.exists(&cas_key).await.unwrap(), "CAS key populated");

        let oci_rows: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1), \
                    (SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1)",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("count oci rows");
        assert_eq!((oci_rows.0, oci_rows.1), (0, 0), "no OCI rows for generic");

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    // -----------------------------------------------------------------------
    // #2676: packages-catalog population (decision logic, pure, no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn test_catalog_entry_docker_tag_manifest() {
        let parsed = crate::services::artifact_metadata::ParsedArtifact {
            name: "manifest.json".to_string(),
            version: None,
        };
        let entry = migration_catalog_entry(
            "docker",
            &OciRole::Manifest {
                image: "org/app".to_string(),
                reference: "v1.2".to_string(),
            },
            &parsed,
        )
        .expect("tag manifest must produce a catalog entry");
        assert_eq!(entry.name, "org/app");
        assert_eq!(entry.version, "v1.2");
        assert_eq!(entry.format, "docker");
    }

    #[test]
    fn test_catalog_entry_skips_digest_manifests_and_blobs() {
        let parsed = crate::services::artifact_metadata::ParsedArtifact {
            name: "manifest.json".to_string(),
            version: None,
        };
        // A digest-addressed child manifest is not a user-facing version
        // (mirrors the live push path's tag-only filter).
        assert_eq!(
            migration_catalog_entry(
                "docker",
                &OciRole::Manifest {
                    image: "app".to_string(),
                    reference: format!("sha256:{}", "a".repeat(64)),
                },
                &parsed,
            ),
            None
        );
        // Layer/config blobs never surface in the catalog.
        assert_eq!(
            migration_catalog_entry(
                "docker",
                &OciRole::Blob {
                    digest: format!("sha256:{}", "b".repeat(64)),
                },
                &parsed,
            ),
            None
        );
    }

    #[test]
    fn test_catalog_entry_non_oci_formats() {
        let parsed = crate::services::artifact_metadata::ParsedArtifact {
            name: "MyPackage".to_string(),
            version: Some("1.0.0".to_string()),
        };
        // Version recovered => catalog row under the parsed identity, with
        // the format key lowercased.
        let entry = migration_catalog_entry("NuGet", &OciRole::NotOci, &parsed)
            .expect("versioned non-OCI artifact must produce a catalog entry");
        assert_eq!(entry.name, "MyPackage");
        assert_eq!(entry.version, "1.0.0");
        assert_eq!(entry.format, "nuget");

        // No version => no catalog row (`packages.version` is NOT NULL and a
        // version-less blob is not a package release).
        let unversioned = crate::services::artifact_metadata::ParsedArtifact {
            name: "blob.bin".to_string(),
            version: None,
        };
        assert_eq!(
            migration_catalog_entry("generic", &OciRole::NotOci, &unversioned),
            None
        );

        // Maven-family catalog names are `groupId:artifactId`; the parser
        // only recovers the artifactId, so no row is written (follow-up).
        assert_eq!(
            migration_catalog_entry("maven", &OciRole::NotOci, &parsed),
            None
        );
        assert_eq!(
            migration_catalog_entry("gradle", &OciRole::NotOci, &parsed),
            None
        );

        // #2784: Go modules are non-OCI and carry a version, so they get a
        // catalog row under the recovered `(module, version)` identity.
        let go_parsed = crate::services::artifact_metadata::ParsedArtifact {
            name: "github.com/gorilla/mux".to_string(),
            version: Some("v1.8.0".to_string()),
        };
        let go_entry = migration_catalog_entry("go", &OciRole::NotOci, &go_parsed)
            .expect("versioned go module must produce a catalog entry");
        assert_eq!(go_entry.name, "github.com/gorilla/mux");
        assert_eq!(go_entry.version, "v1.8.0");
        assert_eq!(go_entry.format, "go");
    }

    // -----------------------------------------------------------------------
    // #2676: packages-catalog population on import (DB-gated via try_pool)
    // -----------------------------------------------------------------------

    /// Count the catalog rows for a repository:
    /// `(packages rows, package_versions rows)`.
    async fn catalog_counts(pool: &sqlx::PgPool, repo_id: Uuid) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM packages WHERE repository_id = $1), \
                    (SELECT COUNT(*) FROM package_versions pv \
                     JOIN packages p ON p.id = pv.package_id \
                     WHERE p.repository_id = $1)",
        )
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("count catalog rows")
    }

    /// The single `(name, version)` catalog row for a repository, if any.
    async fn single_catalog_row(pool: &sqlx::PgPool, repo_id: Uuid) -> Option<(String, String)> {
        sqlx::query_as(
            "SELECT p.name, pv.version FROM packages p \
             JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1",
        )
        .bind(repo_id)
        .fetch_optional(pool)
        .await
        .expect("query catalog")
    }

    /// Delete the test repository row (cascades to artifacts + catalog rows).
    async fn cleanup_repo(pool: &sqlx::PgPool, repo_id: Uuid) {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("cleanup repo");
    }

    /// A migrated NuGet package must land in `packages`/`package_versions`
    /// (the tables the web UI's Packages tab reads) exactly like a live
    /// `nuget push`, and re-running the migration must not duplicate rows.
    /// Pre-fix, the import wrote only `artifacts` and the tab stayed empty.
    #[tokio::test]
    async fn test_nuget_import_populates_package_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2676-nuget", "nuget").await;

        let path = "MyPackage/1.0.0/MyPackage.1.0.0.nupkg";
        let mut files = std::collections::HashMap::new();
        files.insert(
            path.to_string(),
            bytes::Bytes::from_static(b"fake nupkg bytes"),
        );

        transfer_one(&worker, &storage, &files, &repo_key, "nuget", path)
            .await
            .expect("nuget transfer must succeed");

        assert_eq!(
            single_catalog_row(&pool, repo_id).await,
            Some(("MyPackage".to_string(), "1.0.0".to_string())),
            "migrated nuget package must appear in the packages catalog"
        );

        // Re-import (migration re-run) must be idempotent: same single row.
        transfer_one(&worker, &storage, &files, &repo_key, "nuget", path)
            .await
            .expect("nuget re-import must succeed");
        assert_eq!(
            catalog_counts(&pool, repo_id).await,
            (1, 1),
            "re-running the migration must not duplicate catalog rows"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// Same guarantee for Helm: the chart identity parsed from
    /// `<name>-<version>.tgz` must land in the packages catalog.
    #[tokio::test]
    async fn test_helm_import_populates_package_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2676-helm", "helm").await;

        let path = "mychart-1.2.3.tgz";
        let mut files = std::collections::HashMap::new();
        files.insert(
            path.to_string(),
            bytes::Bytes::from_static(b"not a real tgz - metadata extraction is best-effort"),
        );

        transfer_one(&worker, &storage, &files, &repo_key, "helm", path)
            .await
            .expect("helm transfer must succeed");

        assert_eq!(
            single_catalog_row(&pool, repo_id).await,
            Some(("mychart".to_string(), "1.2.3".to_string())),
            "migrated helm chart must appear in the packages catalog"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// Docker: importing a tagged image manifest must create a catalog row
    /// `<image>@<tag>` sized from the manifest's config+layers (mirroring the
    /// live manifest-PUT), while the by-digest blobs the walker fetches must
    /// NOT create rows of their own.
    #[tokio::test]
    async fn test_docker_import_populates_package_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2676-docker", "docker").await;

        let config_bytes = bytes::Bytes::from_static(b"{\"os\":\"linux\"}");
        let layer_bytes = bytes::Bytes::from_static(b"layer-bytes-2676");
        let config_hex = sha256_hex_of(&config_bytes);
        let layer_hex = sha256_hex_of(&layer_bytes);
        let manifest = docker_image_manifest_json(&config_bytes, &layer_bytes);
        let manifest_bytes = bytes::Bytes::from(manifest);

        // Nexus layout: only the tag is enumerated; the walker fetches the
        // config/layer blobs by digest.
        let manifest_path = "v2/hello/manifests/latest".to_string();
        let mut files = std::collections::HashMap::new();
        files.insert(manifest_path.clone(), manifest_bytes.clone());
        files.insert(
            format!("v2/hello/blobs/sha256:{config_hex}"),
            config_bytes.clone(),
        );
        files.insert(
            format!("v2/hello/blobs/sha256:{layer_hex}"),
            layer_bytes.clone(),
        );

        transfer_one(
            &worker,
            &storage,
            &files,
            &repo_key,
            "docker",
            &manifest_path,
        )
        .await
        .expect("docker manifest import must succeed");

        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT p.name, pv.version, pv.size_bytes FROM packages p \
             JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1",
        )
        .bind(repo_id)
        .fetch_optional(&pool)
        .await
        .expect("query catalog");
        let (name, version, size) =
            row.expect("migrated docker tag must appear in the packages catalog");
        assert_eq!(name, "hello");
        assert_eq!(version, "latest");
        assert_eq!(
            size,
            (config_bytes.len() + layer_bytes.len()) as i64,
            "catalog size must be config+layers, like the live push path"
        );

        // Exactly one catalog row: the walked-in blobs and the digest child
        // content must not surface as packages.
        assert_eq!(catalog_counts(&pool, repo_id).await, (1, 1));

        cleanup_repo(&pool, repo_id).await;
    }

    /// #2784: a migrated Go module must recover its `(module, version)`
    /// identity from the GOPROXY `<module>/@v/<version>.zip` layout, land in
    /// `artifacts` under the canonical module path (not the raw filename),
    /// AND appear in `packages`/`package_versions` so the Packages tab shows
    /// it. Pre-fix, Go fell through to the filename-as-name/no-version
    /// fallback, so no catalog row was ever written. Re-import stays at one
    /// row (idempotency).
    #[tokio::test]
    async fn test_go_import_populates_package_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2784-go", "go").await;

        // The `.zip` is the module payload; the module path carries slashes
        // and a case-escaped segment (`!azure` == `Azure`).
        let path = "github.com/!azure/azure-sdk-for-go/@v/v1.8.0.zip";
        let mut files = std::collections::HashMap::new();
        files.insert(
            path.to_string(),
            bytes::Bytes::from_static(b"fake go module zip bytes"),
        );

        transfer_one(&worker, &storage, &files, &repo_key, "go", path)
            .await
            .expect("go module transfer must succeed");

        // Catalog row uses the decoded module path + version.
        assert_eq!(
            single_catalog_row(&pool, repo_id).await,
            Some((
                "github.com/Azure/azure-sdk-for-go".to_string(),
                "v1.8.0".to_string()
            )),
            "migrated go module must appear in the packages catalog"
        );

        // Artifact row is stored under the canonical module identity, not the
        // raw `v1.8.0.zip` filename.
        let artifact: (String, Option<String>) = sqlx::query_as(
            "SELECT name, version FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        )
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("query artifact");
        assert_eq!(artifact.0, "github.com/Azure/azure-sdk-for-go");
        assert_eq!(artifact.1, Some("v1.8.0".to_string()));

        // Re-import (migration re-run) must be idempotent: same single row.
        transfer_one(&worker, &storage, &files, &repo_key, "go", path)
            .await
            .expect("go re-import must succeed");
        assert_eq!(
            catalog_counts(&pool, repo_id).await,
            (1, 1),
            "re-running the migration must not duplicate catalog rows"
        );

        cleanup_repo(&pool, repo_id).await;
    }

    /// #2784: the `.mod` and `.info` sidecars of a Go module share the same
    /// `(module, version)`, so they upsert onto the same catalog row rather
    /// than each creating their own — mirroring how a real GOPROXY module is
    /// a single logical release across its three files.
    #[tokio::test]
    async fn test_go_import_sidecars_share_one_catalog_row() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (worker, storage, _tmp, repo_id, repo_key) =
            setup_repo_for_import(&pool, "mig2784-gomod", "go").await;

        let base = "example.com/foo/bar/@v/v0.1.0";
        let mut files = std::collections::HashMap::new();
        for ext in ["zip", "mod", "info"] {
            files.insert(
                format!("{base}.{ext}"),
                bytes::Bytes::from(format!("payload-{ext}")),
            );
        }
        for ext in ["zip", "mod", "info"] {
            transfer_one(
                &worker,
                &storage,
                &files,
                &repo_key,
                "go",
                &format!("{base}.{ext}"),
            )
            .await
            .unwrap_or_else(|e| panic!("go {ext} transfer failed: {e}"));
        }

        assert_eq!(
            single_catalog_row(&pool, repo_id).await,
            Some(("example.com/foo/bar".to_string(), "v0.1.0".to_string())),
        );
        assert_eq!(
            catalog_counts(&pool, repo_id).await,
            (1, 1),
            "the three sidecar files of one Go release must share one catalog row"
        );

        cleanup_repo(&pool, repo_id).await;
    }
}
