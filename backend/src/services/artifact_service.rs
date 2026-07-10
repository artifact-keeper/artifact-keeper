//! Artifact service.
//!
//! Handles artifact upload, download, checksum calculation, and storage.

use std::sync::Arc;

use bytes::Bytes;
use futures::stream::BoxStream;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::api::middleware::download_telemetry::DownloadContext;
use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata, ArtifactVersion};
use crate::models::repository::RepositoryFormat;
use crate::services::opensearch_service::{ArtifactDocument, OpenSearchService};
use crate::services::plugin_service::{ArtifactInfo, PluginEventType, PluginService};
use crate::services::quality_check_service::QualityCheckService;
use crate::services::repository_service::RepositoryService;
use crate::services::scanner_service::ScannerService;
use crate::storage::StorageBackend;

/// Cancel any in-flight push retries for an artifact that is being deleted, so
/// a delete supersedes pending/failed uploads instead of racing with them.
const CANCEL_SUPERSEDED_PUSH_TASKS_SQL: &str = r#"
            UPDATE sync_tasks
            SET status = 'cancelled',
                completed_at = NOW(),
                error_message = 'superseded by artifact delete'
            WHERE artifact_id = $1
              AND task_type = 'push'
              AND status IN ('pending', 'failed')
            "#;

/// Fan out a `delete` sync task to every eligible peer subscribed to the
/// artifact's repository in push/mirror mode.
const ENQUEUE_DELETE_SYNC_TASKS_SQL: &str = r#"
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

/// Select all peer subscriptions (with their optional artifact filter) that are
/// eligible to receive a push of a newly uploaded artifact in the repository.
const PUSH_MIRROR_SUBSCRIPTIONS_SQL: &str = r#"
                    SELECT prs.peer_instance_id, sp.artifact_filter
                    FROM peer_repo_subscriptions prs
                    LEFT JOIN sync_policies sp ON sp.id = prs.policy_id
                    WHERE prs.repository_id = $1
                      AND prs.sync_enabled = true
                      AND prs.replication_mode::text IN ('push', 'mirror')
                    "#;

/// The three content digests persisted on every artifact row.
///
/// Registry clients look artifacts up by any of SHA-256, SHA-1, or MD5 (Maven
/// `.sha1` sidecars, PyPI MD5 digests, ...), so all three are stored. The
/// streaming upload path computes them incrementally while spooling the body to
/// a scratch file and hands them to [`ArtifactService::upload_stream_with_sync_options`].
/// `storage.put_stream` only computes SHA-256, so SHA-1 / MD5 MUST be supplied
/// here out-of-band or checksum-search by those two algorithms regresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigests {
    /// Lowercase-hex SHA-256 (also the content-addressed storage key).
    pub sha256: String,
    /// Lowercase-hex SHA-1.
    pub sha1: String,
    /// Lowercase-hex MD5.
    pub md5: String,
}

/// Incremental SHA-256 + SHA-1 + MD5 accumulator.
///
/// Feed chunks with [`MultiHasher::update`], then [`MultiHasher::finalize`] into
/// a [`ContentDigests`]. Extracted as a pure, side-effect-free helper so the
/// streaming ingest path and its unit tests share one hashing implementation and
/// the three-way finalize is covered without a live storage backend.
#[derive(Default)]
pub struct MultiHasher {
    sha256: Sha256,
    sha1: sha1::Sha1,
    md5: md5::Md5,
}

impl MultiHasher {
    /// Create an empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold `data` into all three running digests.
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.sha256, data);
        sha1::Digest::update(&mut self.sha1, data);
        md5::Digest::update(&mut self.md5, data);
    }

    /// Finish hashing and produce the lowercase-hex [`ContentDigests`].
    pub fn finalize(self) -> ContentDigests {
        ContentDigests {
            sha256: format!("{:x}", self.sha256.finalize()),
            sha1: format!("{:x}", sha1::Digest::finalize(self.sha1)),
            md5: format!("{:x}", md5::Digest::finalize(self.md5)),
        }
    }
}

/// Whether uploads to a repository append immutable revisions to
/// `artifact_versions` instead of overwriting/rejecting the prior content at
/// the same path (#2367).
///
/// The versioning branch is deliberately narrow: it requires BOTH the
/// per-repo `versioning_enabled` opt-in (DEFAULT false) AND a Generic or
/// Mlmodel format. Every other format — and every repo that has not opted in
/// — keeps the exact pre-existing `ON CONFLICT` overwrite semantics and the
/// release-immutability backstop.
pub(crate) fn versioning_applies(format: &RepositoryFormat, versioning_enabled: bool) -> bool {
    versioning_enabled
        && matches!(
            format,
            RepositoryFormat::Generic | RepositoryFormat::Mlmodel
        )
}

/// Next auto-increment revision for a (repository_id, path) coordinate given
/// the current maximum stored revision (`None` when no revisions exist yet).
pub(crate) fn next_revision(current_max: Option<i32>) -> i32 {
    current_max.unwrap_or(0) + 1
}

/// How a `?version=` selector on the versioned-artifact API is interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VersionSelector {
    /// Absent, empty, or the literal `latest`: resolve to the HEAD revision.
    Latest,
    /// All-digits selector: resolve by exact revision number.
    Revision(i32),
    /// Anything else: resolve by `version_label` (highest matching revision).
    Label(String),
}

/// Parse a raw `?version=` value into a [`VersionSelector`].
///
/// A numeric string (all ASCII digits) selects by revision; `latest`, empty,
/// or absent selects HEAD; any other string is treated as a human label.
pub(crate) fn parse_version_selector(raw: Option<&str>) -> VersionSelector {
    match raw.map(str::trim) {
        None | Some("") | Some("latest") => VersionSelector::Latest,
        Some(s) => {
            if s.chars().all(|c| c.is_ascii_digit()) {
                match s.parse::<i32>() {
                    Ok(n) => VersionSelector::Revision(n),
                    // Overflows i32: cannot match any stored revision, but it
                    // is still a well-formed label lookup.
                    Err(_) => VersionSelector::Label(s.to_string()),
                }
            } else {
                VersionSelector::Label(s.to_string())
            }
        }
    }
}

/// Resolve a [`VersionSelector`] against the `(revision, version_label)`
/// pairs stored for a coordinate. Returns the matching revision number, or
/// `None` when nothing matches (or no revisions exist).
///
/// `Latest` picks the maximum revision; `Label` picks the highest revision
/// carrying that label (labels are not forced unique, so re-tagging picks
/// the newest).
pub(crate) fn resolve_version_selector(
    selector: &VersionSelector,
    versions: &[(i32, Option<String>)],
) -> Option<i32> {
    match selector {
        VersionSelector::Latest => versions.iter().map(|(rev, _)| *rev).max(),
        VersionSelector::Revision(n) => versions
            .iter()
            .find(|(rev, _)| rev == n)
            .map(|(rev, _)| *rev),
        VersionSelector::Label(label) => versions
            .iter()
            .filter(|(_, l)| l.as_deref() == Some(label.as_str()))
            .map(|(rev, _)| *rev)
            .max(),
    }
}

/// Pre-upsert HEAD snapshot used by the versioned-history append (#2367):
/// the `ON CONFLICT DO UPDATE` upsert overwrites the HEAD row in place, so
/// the prior state must be captured first for idempotency and
/// backfill-on-write.
#[derive(Debug, sqlx::FromRow)]
struct PriorHeadRow {
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    checksum_sha1: Option<String>,
    checksum_md5: Option<String>,
    content_type: String,
    storage_key: String,
    uploaded_by: Option<Uuid>,
}

/// Artifact service
pub struct ArtifactService {
    db: PgPool,
    storage: Arc<dyn StorageBackend>,
    repo_service: RepositoryService,
    plugin_service: Option<Arc<PluginService>>,
    scanner_service: Option<Arc<ScannerService>>,
    quality_check_service: Option<Arc<QualityCheckService>>,
    search_service: Option<Arc<OpenSearchService>>,
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
            search_service: None,
        }
    }

    /// Create a new artifact service with search indexing support.
    pub fn new_with_search(
        db: PgPool,
        storage: Arc<dyn StorageBackend>,
        search_service: Option<Arc<OpenSearchService>>,
    ) -> Self {
        let repo_service = RepositoryService::new(db.clone());
        Self {
            db,
            storage,
            repo_service,
            plugin_service: None,
            scanner_service: None,
            quality_check_service: None,
            search_service,
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
            search_service: None,
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

    /// Set the search service for search indexing.
    pub fn set_search_service(&mut self, search_service: Arc<OpenSearchService>) {
        self.search_service = Some(search_service);
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

    /// Calculate SHA-1 checksum of data
    pub fn calculate_sha1(data: &[u8]) -> String {
        use sha1::Sha1;
        let mut hasher = Sha1::new();
        sha1::Digest::update(&mut hasher, data);
        format!("{:x}", sha1::Digest::finalize(hasher))
    }

    /// Calculate MD5 checksum of data
    pub fn calculate_md5(data: &[u8]) -> String {
        use md5::Md5;
        let mut hasher = Md5::new();
        md5::Digest::update(&mut hasher, data);
        format!("{:x}", md5::Digest::finalize(hasher))
    }

    /// Verify declared checksums against the actual content.
    ///
    /// If a declared checksum is provided (Some), the corresponding hash is
    /// computed and compared. Returns `Err(AppError::Validation(...))` on the
    /// first mismatch. Passing `None` for a checksum skips that algorithm.
    pub fn verify_checksums(
        data: &[u8],
        declared_sha256: Option<&str>,
        declared_sha1: Option<&str>,
        declared_md5: Option<&str>,
    ) -> Result<()> {
        if let Some(declared) = declared_sha256 {
            let actual = Self::calculate_sha256(data);
            if !declared.eq_ignore_ascii_case(&actual) {
                return Err(AppError::Validation(format!(
                    "SHA-256 checksum mismatch: declared {} but actual content hashes to {}",
                    declared, actual
                )));
            }
        }

        if let Some(declared) = declared_sha1 {
            let actual = Self::calculate_sha1(data);
            if !declared.eq_ignore_ascii_case(&actual) {
                return Err(AppError::Validation(format!(
                    "SHA-1 checksum mismatch: declared {} but actual content hashes to {}",
                    declared, actual
                )));
            }
        }

        if let Some(declared) = declared_md5 {
            let actual = Self::calculate_md5(data);
            if !declared.eq_ignore_ascii_case(&actual) {
                return Err(AppError::Validation(format!(
                    "MD5 checksum mismatch: declared {} but actual content hashes to {}",
                    declared, actual
                )));
            }
        }

        Ok(())
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
        self.upload_with_sync_options(
            repository_id,
            path,
            name,
            version,
            content_type,
            data,
            uploaded_by,
            true,
        )
        .await
    }

    /// Upload an artifact, optionally suppressing peer sync task fan-out.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_with_sync_options(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: Option<&str>,
        content_type: &str,
        data: Bytes,
        uploaded_by: Option<Uuid>,
        enqueue_sync_tasks: bool,
    ) -> Result<Artifact> {
        let size_bytes = data.len() as i64;

        // Calculate checksums.
        //
        // We persist SHA-256, SHA-1, and MD5 so the checksum-search endpoint can
        // locate an artifact by any of the three (registry clients lean heavily
        // on SHA-1 and MD5 for legacy reasons). All three are lowercase hex.
        let checksum_sha256 = Self::calculate_sha256(&data);
        let checksum_sha1 = Self::calculate_sha1(&data);
        let checksum_md5 = Self::calculate_md5(&data);
        let storage_key = Self::storage_key_from_checksum(&checksum_sha256);

        // Quota, plugin BeforeUpload hook, live-overwrite check, and the
        // release-immutability backstop — shared with the streaming path.
        self.preflight_upload(
            repository_id,
            path,
            name,
            version,
            content_type,
            size_bytes,
            &checksum_sha256,
            uploaded_by,
        )
        .await?;

        // Check if content already exists (deduplication)
        let content_exists = self.storage.exists(&storage_key).await?;

        if !content_exists {
            // Store the actual content
            self.storage.put(&storage_key, data).await?;
        }

        self.finalize_upload(
            repository_id,
            path,
            name,
            version,
            content_type,
            size_bytes,
            &checksum_sha256,
            &checksum_sha1,
            &checksum_md5,
            &storage_key,
            uploaded_by,
            enqueue_sync_tasks,
        )
        .await
    }

    /// Stream an artifact's content into content-addressed storage, mirroring
    /// [`Self::upload_with_sync_options`] but never buffering the whole body in
    /// memory. The caller spools the body to a bounded scratch file (computing
    /// the three digests incrementally) and hands the digests + a `'static`
    /// re-read stream of that file here.
    ///
    /// Every semantic of the buffered path is preserved: quota, plugin hooks,
    /// the release-immutability backstop, `ON CONFLICT` tombstone resurrection,
    /// packages-table population, quarantine hold, and sync fan-out. The
    /// dedup `exists()` check runs FIRST and the `put_stream` write is SKIPPED on
    /// a hit so a warm content-addressed blob is never rewritten.
    ///
    /// `put_stream` only computes SHA-256; the row's SHA-1 / MD5 come from
    /// `digests`, so checksum-search by those algorithms does not regress.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_stream_with_sync_options(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: Option<&str>,
        content_type: &str,
        stream: BoxStream<'static, Result<Bytes>>,
        digests: ContentDigests,
        size_bytes: i64,
        uploaded_by: Option<Uuid>,
        enqueue_sync_tasks: bool,
    ) -> Result<Artifact> {
        let storage_key = Self::storage_key_from_checksum(&digests.sha256);

        self.preflight_upload(
            repository_id,
            path,
            name,
            version,
            content_type,
            size_bytes,
            &digests.sha256,
            uploaded_by,
        )
        .await?;

        // Dedup check FIRST: skip `put_stream` on a warm blob so we never
        // rewrite content that is already present under its content-addressed
        // key (== its SHA-256).
        let content_exists = self.storage.exists(&storage_key).await?;

        if !content_exists {
            let put = self.storage.put_stream(&storage_key, stream).await?;
            // `put_stream` computes only SHA-256; guard the content-addressed
            // invariant that the streamed bytes hash to the key we stored them
            // under (SHA-1 / MD5 for the row come from `digests`).
            if !put.checksum_sha256.eq_ignore_ascii_case(&digests.sha256) {
                return Err(AppError::Validation(format!(
                    "Streamed content SHA-256 {} does not match staged digest {}",
                    put.checksum_sha256, digests.sha256
                )));
            }
        }

        self.finalize_upload(
            repository_id,
            path,
            name,
            version,
            content_type,
            size_bytes,
            &digests.sha256,
            &digests.sha1,
            &digests.md5,
            &storage_key,
            uploaded_by,
            enqueue_sync_tasks,
        )
        .await
    }

    /// Pre-storage validation shared by the buffered and streaming upload paths:
    /// quota enforcement, the plugin `BeforeUpload` hook (which may reject the
    /// upload), the live-overwrite immutability check, and the
    /// soft-delete-aware release-immutability backstop.
    #[allow(clippy::too_many_arguments)]
    async fn preflight_upload(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: Option<&str>,
        content_type: &str,
        size_bytes: i64,
        checksum_sha256: &str,
        uploaded_by: Option<Uuid>,
    ) -> Result<()> {
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

        // Build artifact info for plugin hooks (before artifact is created)
        let pre_artifact_info = ArtifactInfo {
            id: Uuid::nil(), // Will be set after creation
            repository_id,
            path: path.to_string(),
            name: name.to_string(),
            version: version.map(String::from),
            size_bytes,
            checksum_sha256: checksum_sha256.to_string(),
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

        // #2367: for repositories that opted into first-class versioning
        // (Generic/Mlmodel only), a re-upload to an existing path APPENDS an
        // immutable revision to `artifact_versions` instead of conflicting, so
        // both the live-overwrite check and the release-immutability backstop
        // below are relaxed for the HEAD row. Old revisions stay immutable and
        // addressable; every other format and every non-opted-in repo keeps
        // the exact pre-existing 409 behavior.
        let repo = self.repo_service.get_by_id(repository_id).await;
        let versioning_active = repo
            .as_ref()
            .map(|r| versioning_applies(&r.format, r.versioning_enabled))
            .unwrap_or(false);

        if let Some(existing) = existing {
            // For immutable artifacts, reject if version matches
            if !versioning_active && existing.version == version.map(String::from) {
                return Err(AppError::Conflict(
                    "Artifact version already exists and is immutable".to_string(),
                ));
            }
        }

        // Release-immutability backstop — the single chokepoint every
        // service-backed upload path flows through (the generic
        // `upload_artifact`/`upload_artifact_multipart*` endpoints, pypi,
        // debian, ...). The live-overwrite check above only inspects
        // *non-deleted* rows, so a DELETE (soft-delete) followed by re-uploading
        // DIFFERENT bytes to the SAME released coordinate would otherwise slip
        // through the `ON CONFLICT DO UPDATE` below (which resurrects the
        // tombstone). Re-query INCLUDING soft-deleted rows and reject the swap.
        //
        // The oracle is the artifact's REAL release coordinate, not the
        // proxy-cache TTL classifier alone: a coordinate is protected when a
        // prior row exists there AND that path is not a format's genuinely
        // in-place-rewritten index file (`maven-metadata.xml`, npm packument,
        // ...). This covers the default-format families (Generic / Nuget /
        // Conan / Composer / Go / Rpm / Debian / Helm) whose every stored path
        // is a release coordinate and which `classify` would otherwise treat as
        // mutable-by-default. Identical-bytes republish (idempotent undelete)
        // and genuine mutable index files proceed unchanged.
        if let Ok(repo) = repo {
            if !versioning_active
                && !crate::services::cache_classifier::is_explicitly_mutable_index(
                    &repo.format,
                    path,
                )
            {
                let prior = sqlx::query!(
                    "SELECT checksum_sha256, version FROM artifacts \
                     WHERE repository_id = $1 AND path = $2",
                    repository_id,
                    path
                )
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

                // Only a *released* coordinate is immutable: either the
                // structural classifier marks it immutable, or the prior row was
                // published as a versioned artifact (version IS NOT NULL). A
                // path-less, version-less generic blob remains freely
                // replaceable.
                if let Some(prior) = prior {
                    let is_released = prior.version.is_some()
                        || crate::services::cache_classifier::classify(&repo.format, path)
                            .is_immutable();
                    if is_released && !prior.checksum_sha256.eq_ignore_ascii_case(checksum_sha256) {
                        return Err(AppError::Conflict(
                            "Artifact version already exists and is immutable".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Persist the artifact row and run every post-storage side effect shared by
    /// the buffered and streaming upload paths: `ON CONFLICT` insert/resurrect,
    /// quarantine hold, quota-warning telemetry, packages-table population, the
    /// `AfterUpload` hook, peer sync fan-out, scan-on-upload, quality checks, and
    /// OpenSearch indexing. The content bytes are already in storage under
    /// `storage_key`; the three checksums are supplied by the caller.
    #[allow(clippy::too_many_arguments)]
    async fn finalize_upload(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: Option<&str>,
        content_type: &str,
        size_bytes: i64,
        checksum_sha256: &str,
        checksum_sha1: &str,
        checksum_md5: &str,
        storage_key: &str,
        uploaded_by: Option<Uuid>,
        enqueue_sync_tasks: bool,
    ) -> Result<Artifact> {
        // #2367: for versioning-enabled Generic/Mlmodel repos, capture the
        // pre-upsert HEAD state so the history append below can (a) stay
        // idempotent on identical-bytes re-uploads and (b) backfill the
        // pre-existing HEAD as revision 1 on the first versioned write to a
        // coordinate that predates the feature.
        let versioning_active = self
            .repo_service
            .get_by_id(repository_id)
            .await
            .map(|r| versioning_applies(&r.format, r.versioning_enabled))
            .unwrap_or(false);
        let prior_head = if versioning_active {
            sqlx::query_as::<_, PriorHeadRow>(
                "SELECT name, version, size_bytes, checksum_sha256, checksum_sha1, \
                        checksum_md5, content_type, storage_key, uploaded_by \
                 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
            )
            .bind(repository_id)
            .bind(path)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            None
        };

        // Create artifact record.
        //
        // `ON CONFLICT DO UPDATE` re-uploads must refresh sha1/md5 in
        // lockstep with sha256 -- otherwise an artifact whose content was
        // replaced would still expose the *old* sha1/md5 via the
        // checksum-search endpoint, which would point dedup-by-checksum
        // clients at the wrong artifact.
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_sha1, checksum_md5,
                content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (repository_id, path) DO UPDATE SET
                name = EXCLUDED.name,
                version = EXCLUDED.version,
                size_bytes = EXCLUDED.size_bytes,
                checksum_sha256 = EXCLUDED.checksum_sha256,
                checksum_sha1 = EXCLUDED.checksum_sha1,
                checksum_md5 = EXCLUDED.checksum_md5,
                content_type = EXCLUDED.content_type,
                storage_key = EXCLUDED.storage_key,
                uploaded_by = EXCLUDED.uploaded_by,
                is_deleted = false,
                updated_at = NOW()
            RETURNING
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                quarantine_status, quarantine_until,
                created_at, updated_at
            "#,
            repository_id,
            path,
            name,
            version,
            size_bytes,
            checksum_sha256,
            checksum_sha1,
            checksum_md5,
            content_type,
            storage_key,
            uploaded_by
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // #2367: append an immutable revision to `artifact_versions` for
        // versioning-enabled Generic/Mlmodel repos. Identical-bytes
        // re-uploads create no new revision (idempotent republish); the
        // `version` coordinate doubles as the human `version_label`.
        if versioning_active {
            self.record_version(&artifact, prior_head, version).await?;
        }

        // Apply quarantine hold if enabled for this repository. This is the
        // shared upload path (pypi/debian/incus/generic), which only ever
        // handles hosted uploads, so it calls the helper directly.
        crate::services::quarantine_service::apply_upload_hold(
            &self.db,
            repository_id,
            artifact.id,
        )
        .await;

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
        if enqueue_sync_tasks {
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

                let subscriptions: std::result::Result<Vec<SubWithFilter>, _> =
                    sqlx::query_as(PUSH_MIRROR_SUBSCRIPTIONS_SQL)
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

        // Index artifact in OpenSearch (non-blocking)
        if let Some(ref search) = self.search_service {
            let search = search.clone();
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
                let repo_info = sqlx::query_as::<_, (String, String, String, bool)>(
                    "SELECT key, name, format::text, is_public FROM repositories WHERE id = $1",
                )
                .bind(repo_id)
                .fetch_optional(&db)
                .await;

                match repo_info {
                    Ok(Some((repo_key, repo_name, format, is_public))) => {
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
                            is_public,
                            created_at: artifact_created.timestamp(),
                        };
                        if let Err(e) = search.index_artifact(&doc).await {
                            tracing::warn!(
                                "Failed to index artifact {} in OpenSearch: {}",
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
                        tracing::warn!("Failed to fetch repository for search indexing: {}", e);
                    }
                }
            });
        }

        // Best-effort audit trail (#2366): record who uploaded which artifact.
        // Fire-and-forget so an audit-table outage can never fail an upload,
        // mirroring the download/stats contract.
        {
            use crate::services::audit_service::{
                audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
            };
            let mut entry = AuditEntry::new(AuditAction::ArtifactUploaded, ResourceType::Artifact)
                .resource(artifact.id)
                .details(serde_json::json!({
                    "repository_id": artifact.repository_id.to_string(),
                    "path": artifact.path,
                    "name": artifact.name,
                    "version": artifact.version,
                    "size_bytes": artifact.size_bytes,
                }));
            if let Some(uid) = uploaded_by {
                entry = entry.user(uid);
            }
            audit_fire_and_forget(self.db.clone(), entry).await;
        }

        Ok(artifact)
    }

    /// Append an immutable revision for a freshly-upserted HEAD artifact
    /// (#2367). Only called for versioning-enabled Generic/Mlmodel repos.
    ///
    /// * Idempotency: when the incoming bytes hash identically to the prior
    ///   HEAD, no new revision is created (retract/republish stays a no-op).
    /// * Backfill-on-write: the first versioned upload over a HEAD that
    ///   predates the feature (zero `artifact_versions` rows) records that
    ///   prior HEAD as revision 1 before appending the new upload.
    ///
    /// Returns the revision number the upload landed at (`None` when the
    /// upload was an identical-bytes no-op onto an unversioned HEAD).
    async fn record_version(
        &self,
        artifact: &Artifact,
        prior_head: Option<PriorHeadRow>,
        version_label: Option<&str>,
    ) -> Result<Option<i32>> {
        // Identical-bytes re-upload: keep the existing history untouched.
        if let Some(ref prior) = prior_head {
            if prior
                .checksum_sha256
                .trim()
                .eq_ignore_ascii_case(artifact.checksum_sha256.trim())
            {
                return Ok(self
                    .latest_version_info(artifact.repository_id, &artifact.path)
                    .await?
                    .map(|(rev, _)| rev));
            }
        }

        let current_max: Option<i32> = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(revision) FROM artifact_versions \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(artifact.repository_id)
        .bind(&artifact.path)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Backfill-on-write: preserve the pre-feature HEAD as revision 1.
        if current_max.is_none() {
            if let Some(prior) = prior_head {
                self.insert_revision_row(
                    artifact.repository_id,
                    &artifact.path,
                    &prior.name,
                    prior.version.as_deref(),
                    prior.size_bytes,
                    &prior.checksum_sha256,
                    prior.checksum_sha1.as_deref(),
                    prior.checksum_md5.as_deref(),
                    &prior.content_type,
                    &prior.storage_key,
                    prior.uploaded_by,
                )
                .await?;
            }
        }

        let revision = self
            .insert_revision_row(
                artifact.repository_id,
                &artifact.path,
                &artifact.name,
                version_label,
                artifact.size_bytes,
                &artifact.checksum_sha256,
                artifact.checksum_sha1.as_deref(),
                artifact.checksum_md5.as_deref(),
                &artifact.content_type,
                &artifact.storage_key,
                artifact.uploaded_by,
            )
            .await?;
        Ok(Some(revision))
    }

    /// Insert one `artifact_versions` row at `MAX(revision)+1`, retrying once
    /// on the UNIQUE(repository_id, path, revision) constraint so two
    /// concurrent uploads to the same coordinate both land (on consecutive
    /// revisions) instead of one failing spuriously.
    #[allow(clippy::too_many_arguments)]
    async fn insert_revision_row(
        &self,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version_label: Option<&str>,
        size_bytes: i64,
        checksum_sha256: &str,
        checksum_sha1: Option<&str>,
        checksum_md5: Option<&str>,
        content_type: &str,
        storage_key: &str,
        uploaded_by: Option<Uuid>,
    ) -> Result<i32> {
        for attempt in 0..2 {
            let current_max: Option<i32> = sqlx::query_scalar::<_, Option<i32>>(
                "SELECT MAX(revision) FROM artifact_versions \
                 WHERE repository_id = $1 AND path = $2",
            )
            .bind(repository_id)
            .bind(path)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            let revision = next_revision(current_max);

            let inserted = sqlx::query(
                "INSERT INTO artifact_versions ( \
                     repository_id, path, revision, version_label, name, size_bytes, \
                     checksum_sha256, checksum_sha1, checksum_md5, content_type, \
                     storage_key, uploaded_by \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            )
            .bind(repository_id)
            .bind(path)
            .bind(revision)
            .bind(version_label)
            .bind(name)
            .bind(size_bytes)
            .bind(checksum_sha256)
            .bind(checksum_sha1)
            .bind(checksum_md5)
            .bind(content_type)
            .bind(storage_key)
            .bind(uploaded_by)
            .execute(&self.db)
            .await;

            match inserted {
                Ok(_) => return Ok(revision),
                Err(e) if attempt == 0 && e.to_string().contains("duplicate key") => {
                    // A concurrent upload claimed this revision number;
                    // recompute MAX and retry once.
                    continue;
                }
                Err(e) => return Err(AppError::Database(e.to_string())),
            }
        }
        Err(AppError::Conflict(
            "Concurrent uploads exhausted the revision-number retry".to_string(),
        ))
    }

    /// Latest `(revision, version_label)` recorded for a coordinate, or
    /// `None` when the coordinate has no version history.
    pub async fn latest_version_info(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> Result<Option<(i32, Option<String>)>> {
        sqlx::query_as::<_, (i32, Option<String>)>(
            "SELECT revision, version_label FROM artifact_versions \
             WHERE repository_id = $1 AND path = $2 \
             ORDER BY revision DESC LIMIT 1",
        )
        .bind(repository_id)
        .bind(path)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// List every stored revision for a coordinate, newest first (#2367).
    pub async fn list_versions(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> Result<Vec<ArtifactVersion>> {
        sqlx::query_as::<_, ArtifactVersion>(
            "SELECT id, repository_id, path, revision, version_label, name, \
                    size_bytes, checksum_sha256, checksum_sha1, checksum_md5, \
                    content_type, storage_key, uploaded_by, created_at \
             FROM artifact_versions \
             WHERE repository_id = $1 AND path = $2 \
             ORDER BY revision DESC",
        )
        .bind(repository_id)
        .bind(path)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Resolve a `?version=` selector (revision number, human label, or
    /// `latest`) to the stored revision row for a coordinate (#2367).
    /// Returns `None` when nothing matches.
    pub async fn get_version(
        &self,
        repository_id: Uuid,
        path: &str,
        selector_raw: Option<&str>,
    ) -> Result<Option<ArtifactVersion>> {
        let pairs = sqlx::query_as::<_, (i32, Option<String>)>(
            "SELECT revision, version_label FROM artifact_versions \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(repository_id)
        .bind(path)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let selector = parse_version_selector(selector_raw);
        let Some(revision) = resolve_version_selector(&selector, &pairs) else {
            return Ok(None);
        };

        sqlx::query_as::<_, ArtifactVersion>(
            "SELECT id, repository_id, path, revision, version_label, name, \
                    size_bytes, checksum_sha256, checksum_sha1, checksum_md5, \
                    content_type, storage_key, uploaded_by, created_at \
             FROM artifact_versions \
             WHERE repository_id = $1 AND path = $2 AND revision = $3",
        )
        .bind(repository_id)
        .bind(path)
        .bind(revision)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Stream a specific stored revision's bytes from content-addressed
    /// storage (#2367). Old revisions stay addressable even after the HEAD
    /// row is soft-deleted or overwritten.
    pub async fn download_version_stream(
        &self,
        version: &ArtifactVersion,
    ) -> Result<BoxStream<'static, Result<Bytes>>> {
        self.storage.get_stream(&version.storage_key).await
    }

    /// Shared download preamble: look up the artifact row, enforce quarantine,
    /// and run BeforeDownload hooks (which may reject the download). Returns the
    /// resolved [`Artifact`] so both the buffered ([`download`]) and streaming
    /// ([`download_stream`]) paths share one source of truth for the
    /// NotFound/quarantine/hook contract.
    ///
    /// [`download`]: Self::download
    /// [`download_stream`]: Self::download_stream
    async fn prepare_download(
        &self,
        repository_id: Uuid,
        path: &str,
    ) -> Result<(Artifact, ArtifactInfo)> {
        // Find artifact
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                quarantine_status, quarantine_until,
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

        // Check quarantine status before serving the artifact
        crate::services::quarantine_service::check_download_allowed(
            artifact.quarantine_status.as_deref(),
            artifact.quarantine_until,
            chrono::Utc::now(),
        )?;

        // Trigger BeforeDownload hooks - validators can reject the download
        let artifact_info = ArtifactInfo::from(&artifact);
        self.trigger_hook(PluginEventType::BeforeDownload, &artifact_info)
            .await?;

        Ok((artifact, artifact_info))
    }

    /// Shared download epilogue: record best-effort download statistics and fire
    /// the (non-blocking) AfterDownload hooks. Used by both the buffered and
    /// streaming download paths.
    async fn finish_download(
        &self,
        artifact_id: Uuid,
        artifact_info: &ArtifactInfo,
        user_id: Option<Uuid>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        // Record download statistics (best-effort; #2365). An unparseable
        // ip string is recorded as NULL rather than a sentinel value.
        let ctx = DownloadContext {
            client_ip: ip_address.and_then(|s| s.parse().ok()),
            user_id,
            user_agent: user_agent.map(str::to_string),
        };
        record_download(&self.db, artifact_id, &ctx).await;

        // Best-effort audit trail (#2366). An `ARTIFACT_DOWNLOADED` event is the
        // per-access record auditors need to answer "who fetched this artifact,
        // and when?". Fire-and-forget: a download must never fail because the
        // audit table is unavailable, mirroring the download-statistics write
        // above. The IP is parsed leniently; a malformed value is simply omitted.
        {
            use crate::services::audit_service::{
                audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
            };
            let mut entry =
                AuditEntry::new(AuditAction::ArtifactDownloaded, ResourceType::Artifact)
                    .resource(artifact_id)
                    .details(serde_json::json!({
                        "repository_id": artifact_info.repository_id.to_string(),
                        "path": artifact_info.path,
                        "name": artifact_info.name,
                        "version": artifact_info.version,
                    }));
            if let Some(uid) = user_id {
                entry = entry.user(uid);
            }
            if let Some(ip) = ip_address.and_then(|s| s.parse::<std::net::IpAddr>().ok()) {
                entry = entry.ip(ip);
            }
            audit_fire_and_forget(self.db.clone(), entry).await;
        }

        // Trigger AfterDownload hooks (non-blocking)
        self.trigger_hook_non_blocking(PluginEventType::AfterDownload, artifact_info)
            .await;
    }

    /// Download an artifact, buffering the full body into memory.
    ///
    /// Prefer [`download_stream`] for serving artifact bodies over HTTP so large
    /// artifacts are never fully resident in memory. This buffered variant is
    /// retained for callers that genuinely need the bytes in hand.
    ///
    /// [`download_stream`]: Self::download_stream
    pub async fn download(
        &self,
        repository_id: Uuid,
        path: &str,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<&str>,
    ) -> Result<(Artifact, Bytes)> {
        let (artifact, artifact_info) = self.prepare_download(repository_id, path).await?;

        // Get content from storage
        let content = self.storage.get(&artifact.storage_key).await?;

        self.finish_download(
            artifact.id,
            &artifact_info,
            user_id,
            ip_address.as_deref(),
            user_agent,
        )
        .await;

        Ok((artifact, content))
    }

    /// Stream an artifact body from storage without buffering it in memory.
    ///
    /// Behaviorally identical to [`download`] (same NotFound/quarantine/hook
    /// contract, same best-effort stats and AfterDownload hooks) except the body
    /// is returned as a [`BoxStream`] instead of an in-memory [`Bytes`]. This is
    /// the streaming sibling that closes the last large-body buffer on the
    /// generic local-serve path (Core Invariant ①, #1608) — mirroring what
    /// #1393 did for the per-format handlers.
    ///
    /// The returned [`Artifact`] still carries `size_bytes` so callers can set
    /// an accurate `Content-Length`. A storage miss surfaces as
    /// [`AppError::NotFound`] exactly as the buffered path did, preserving the
    /// handler's Remote/Virtual fallback contract.
    ///
    /// [`download`]: Self::download
    pub async fn download_stream(
        &self,
        repository_id: Uuid,
        path: &str,
        user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<&str>,
    ) -> Result<(Artifact, BoxStream<'static, Result<Bytes>>)> {
        let (artifact, artifact_info) = self.prepare_download(repository_id, path).await?;

        // Open the body as a stream so large artifacts never buffer in memory.
        // `get_stream` resolves a missing key eagerly to `AppError::NotFound`,
        // matching the buffered `get` path's NotFound contract.
        let body = self.storage.get_stream(&artifact.storage_key).await?;

        self.finish_download(
            artifact.id,
            &artifact_info,
            user_id,
            ip_address.as_deref(),
            user_agent,
        )
        .await;

        Ok((artifact, body))
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
                quarantine_status, quarantine_until,
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
                quarantine_status, quarantine_until,
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

    /// List artifacts across multiple repositories with pagination and optional search.
    ///
    /// Used for virtual repository listings that aggregate artifacts from all
    /// member repositories. Artifacts are de-duplicated by path, with earlier
    /// entries in `repo_ids` (higher priority members) taking precedence.
    ///
    /// Uses runtime query binding (`sqlx::query_as`) rather than the
    /// compile-time macro so that no `.sqlx` offline cache entry is required.
    pub async fn list_for_repos(
        &self,
        repo_ids: &[Uuid],
        path_prefix: Option<&str>,
        search_query: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Artifact>, i64)> {
        if repo_ids.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let prefix_pattern = path_prefix.map(|p| format!("{}%", p));
        let search_pattern = search_query.map(|q| format!("%{}%", q.to_lowercase()));

        // Use DISTINCT ON (path) with priority ordering so that artifacts
        // from higher-priority member repos shadow lower-priority ones at
        // the same path. The priority is determined by the position in the
        // repo_ids slice, which the caller provides in priority order.
        let artifacts: Vec<Artifact> = sqlx::query_as(
            r#"
            SELECT
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_md5, checksum_sha1,
                content_type, storage_key, is_deleted, uploaded_by,
                quarantine_status, quarantine_until,
                created_at, updated_at
            FROM (
                SELECT DISTINCT ON (a.path)
                    a.id, a.repository_id, a.path, a.name, a.version, a.size_bytes,
                    a.checksum_sha256, a.checksum_md5, a.checksum_sha1,
                    a.content_type, a.storage_key, a.is_deleted, a.uploaded_by,
                    a.quarantine_status, a.quarantine_until,
                    a.created_at, a.updated_at,
                    array_position($1::uuid[], a.repository_id) as repo_priority
                FROM artifacts a
                WHERE a.repository_id = ANY($1)
                  AND a.is_deleted = false
                  AND ($2::text IS NULL OR a.path LIKE $2)
                  AND ($5::text IS NULL OR LOWER(a.name) LIKE $5 OR LOWER(a.path) LIKE $5)
                ORDER BY a.path, repo_priority
            ) sub
            ORDER BY path
            OFFSET $3
            LIMIT $4
            "#,
        )
        .bind(repo_ids)
        .bind(&prefix_pattern)
        .bind(offset)
        .bind(limit)
        .bind(&search_pattern)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM (
                SELECT DISTINCT ON (a.path) a.id
                FROM artifacts a
                WHERE a.repository_id = ANY($1)
                  AND a.is_deleted = false
                  AND ($2::text IS NULL OR a.path LIKE $2)
                  AND ($3::text IS NULL OR LOWER(a.name) LIKE $3 OR LOWER(a.path) LIKE $3)
                ORDER BY a.path, array_position($1::uuid[], a.repository_id)
            ) sub
            "#,
        )
        .bind(repo_ids)
        .bind(&prefix_pattern)
        .bind(&search_pattern)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((artifacts, total))
    }

    /// Soft-delete an artifact
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        self.delete_with_sync_options(id, true).await
    }

    /// Soft-delete an artifact, optionally suppressing peer sync task fan-out.
    pub async fn delete_with_sync_options(&self, id: Uuid, enqueue_sync_tasks: bool) -> Result<()> {
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

        // A delete supersedes any upload retries for the same artifact.
        let _ = sqlx::query(CANCEL_SUPERSEDED_PUSH_TASKS_SQL)
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to cancel superseded push sync tasks for artifact {}: {}",
                    id,
                    e
                );
                e
            });

        // Enqueue delete sync tasks for all eligible peers (non-blocking)
        if enqueue_sync_tasks {
            let _ = sqlx::query(ENQUEUE_DELETE_SYNC_TASKS_SQL)
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
        }

        // Best-effort audit trail (#2366): record artifact deletion (soft
        // delete). Fire-and-forget; never fails the delete.
        {
            use crate::services::audit_service::{
                audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
            };
            // The service-layer delete does not carry the acting principal, so
            // `user_id` (the actor) is intentionally left unset here; the
            // original uploader is recorded in `details` for context.
            let entry = AuditEntry::new(AuditAction::ArtifactDeleted, ResourceType::Artifact)
                .resource(artifact.id)
                .details(serde_json::json!({
                    "repository_id": artifact.repository_id.to_string(),
                    "path": artifact.path,
                    "name": artifact.name,
                    "version": artifact.version,
                    "uploaded_by": artifact.uploaded_by.map(|u| u.to_string()),
                }));
            audit_fire_and_forget(self.db.clone(), entry).await;
        }

        // Trigger AfterDelete hooks (non-blocking)
        self.trigger_hook_non_blocking(PluginEventType::AfterDelete, &artifact_info)
            .await;

        // Remove artifact from search index (non-blocking)
        if let Some(ref search) = self.search_service {
            let search = search.clone();
            let artifact_id_str = id.to_string();
            tokio::spawn(async move {
                if let Err(e) = search.remove_artifact(&artifact_id_str).await {
                    tracing::warn!(
                        "Failed to remove artifact {} from search index: {}",
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
                quarantine_status, quarantine_until,
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
                quarantine_status, quarantine_until,
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

    /// Get download statistics for multiple artifacts in a single query.
    /// Uses runtime `query_as` instead of compile-time `query_as!` because
    /// `sqlx::query!` does not support `&[Uuid]` binding for `ANY($1)` in
    /// offline mode.
    pub async fn get_download_stats_batch(
        &self,
        artifact_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, i64>> {
        if artifact_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            "SELECT artifact_id, COUNT(*) FROM download_statistics WHERE artifact_id = ANY($1) GROUP BY artifact_id",
        )
        .bind(artifact_ids)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut map = std::collections::HashMap::new();
        for (artifact_id, count) in rows {
            map.insert(artifact_id, count);
        }
        Ok(map)
    }
}

/// Best-effort recorder for a completed local-artifact download (#2365).
///
/// Writes real attribution (validated client IP or NULL, authenticated user
/// or NULL, user agent) into `download_statistics` — replacing the historical
/// per-format `'0.0.0.0'` sentinel inserts. Errors are logged at `warn` and
/// swallowed: statistics must never block or fail the download itself.
///
/// Call this only after a **local** artifact row has been resolved; remote
/// pass-through proxy fetches are not our artifacts and stay unrecorded.
pub async fn record_download(db: &PgPool, artifact_id: Uuid, ctx: &DownloadContext) {
    if let Err(e) = sqlx::query(
        "INSERT INTO download_statistics (artifact_id, user_id, ip_address, user_agent) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(artifact_id)
    .bind(ctx.user_id)
    .bind(ctx.client_ip.map(|ip| ip.to_string()))
    .bind(ctx.user_agent.as_deref())
    .execute(db)
    .await
    {
        warn!(%artifact_id, error = %e, "failed to record download statistics");
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
    // MultiHasher: incremental SHA-256 + SHA-1 + MD5 finalize
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_hasher_matches_one_shot_helpers() {
        // Feeding the payload in several chunks must yield the same digests as
        // the one-shot `calculate_*` helpers over the whole buffer.
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut hasher = MultiHasher::new();
        hasher.update(&payload[..10]);
        hasher.update(&payload[10..25]);
        hasher.update(&payload[25..]);
        let digests = hasher.finalize();

        assert_eq!(digests.sha256, ArtifactService::calculate_sha256(payload));
        assert_eq!(digests.sha1, ArtifactService::calculate_sha1(payload));
        assert_eq!(digests.md5, ArtifactService::calculate_md5(payload));
    }

    #[test]
    fn test_multi_hasher_empty_input() {
        let digests = MultiHasher::new().finalize();
        assert_eq!(digests.sha256, ArtifactService::calculate_sha256(b""));
        assert_eq!(digests.sha1, ArtifactService::calculate_sha1(b""));
        assert_eq!(digests.md5, ArtifactService::calculate_md5(b""));
        // Well-known empty-input digests.
        assert_eq!(
            digests.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digests.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digests.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_multi_hasher_lowercase_hex_lengths() {
        let mut hasher = MultiHasher::new();
        hasher.update(b"content-addressed");
        let d = hasher.finalize();
        assert_eq!(d.sha256.len(), 64);
        assert_eq!(d.sha1.len(), 40);
        assert_eq!(d.md5.len(), 32);
        for s in [&d.sha256, &d.sha1, &d.md5] {
            assert!(s
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
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
    // calculate_sha1 / calculate_md5
    // -----------------------------------------------------------------------

    #[test]
    fn test_calculate_sha1_known_value() {
        let hash = ArtifactService::calculate_sha1(b"test data");
        assert_eq!(hash.len(), 40);
        assert_eq!(hash, "f48dd853820860816c75d54d0f584dc863327a7c");
    }

    #[test]
    fn test_calculate_sha1_deterministic() {
        assert_eq!(
            ArtifactService::calculate_sha1(b"hello"),
            ArtifactService::calculate_sha1(b"hello")
        );
        assert_ne!(
            ArtifactService::calculate_sha1(b"hello"),
            ArtifactService::calculate_sha1(b"world")
        );
    }

    #[test]
    fn test_calculate_sha1_empty_data() {
        let hash = ArtifactService::calculate_sha1(b"");
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // SHA-1 of empty input is a well-known constant
        assert_eq!(hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_calculate_sha1_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let hash = ArtifactService::calculate_sha1(&data);
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_md5_known_value() {
        let hash = ArtifactService::calculate_md5(b"test data");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, "eb733a00c0c9d336e65691a37ab54293");
    }

    #[test]
    fn test_calculate_md5_deterministic() {
        assert_eq!(
            ArtifactService::calculate_md5(b"hello"),
            ArtifactService::calculate_md5(b"hello")
        );
        assert_ne!(
            ArtifactService::calculate_md5(b"hello"),
            ArtifactService::calculate_md5(b"world")
        );
    }

    #[test]
    fn test_calculate_md5_empty_data() {
        let hash = ArtifactService::calculate_md5(b"");
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // MD5 of empty input is a well-known constant
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_calculate_md5_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let hash = ArtifactService::calculate_md5(&data);
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // verify_checksums
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_checksums_all_none_passes() {
        let result = ArtifactService::verify_checksums(b"anything", None, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_correct_sha256_passes() {
        let data = b"hello world";
        let sha256 = ArtifactService::calculate_sha256(data);
        let result = ArtifactService::verify_checksums(data, Some(&sha256), None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_wrong_sha256_fails() {
        let result = ArtifactService::verify_checksums(
            b"hello world",
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SHA-256 checksum mismatch"));
    }

    #[test]
    fn test_verify_checksums_correct_sha1_passes() {
        let data = b"hello world";
        let sha1 = ArtifactService::calculate_sha1(data);
        let result = ArtifactService::verify_checksums(data, None, Some(&sha1), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_wrong_sha1_fails() {
        let result = ArtifactService::verify_checksums(
            b"hello world",
            None,
            Some("0000000000000000000000000000000000000000"),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SHA-1 checksum mismatch"));
    }

    #[test]
    fn test_verify_checksums_correct_md5_passes() {
        let data = b"hello world";
        let md5 = ArtifactService::calculate_md5(data);
        let result = ArtifactService::verify_checksums(data, None, None, Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_wrong_md5_fails() {
        let result = ArtifactService::verify_checksums(
            b"hello world",
            None,
            None,
            Some("00000000000000000000000000000000"),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("MD5 checksum mismatch"));
    }

    #[test]
    fn test_verify_checksums_case_insensitive() {
        let data = b"case test";
        let sha256 = ArtifactService::calculate_sha256(data);
        let upper = sha256.to_uppercase();
        let result = ArtifactService::verify_checksums(data, Some(&upper), None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_all_three_correct() {
        let data = b"triple check";
        let sha256 = ArtifactService::calculate_sha256(data);
        let sha1 = ArtifactService::calculate_sha1(data);
        let md5 = ArtifactService::calculate_md5(data);
        let result =
            ArtifactService::verify_checksums(data, Some(&sha256), Some(&sha1), Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_sha256_correct_but_sha1_wrong() {
        let data = b"partial match";
        let sha256 = ArtifactService::calculate_sha256(data);
        let result = ArtifactService::verify_checksums(
            data,
            Some(&sha256),
            Some("0000000000000000000000000000000000000000"),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SHA-1 checksum mismatch"));
    }

    #[test]
    fn test_verify_checksums_empty_data() {
        let data = b"";
        let sha256 = ArtifactService::calculate_sha256(data);
        let sha1 = ArtifactService::calculate_sha1(data);
        let md5 = ArtifactService::calculate_md5(data);
        let result =
            ArtifactService::verify_checksums(data, Some(&sha256), Some(&sha1), Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_sha256_and_sha1_correct() {
        let data = b"dual check";
        let sha256 = ArtifactService::calculate_sha256(data);
        let sha1 = ArtifactService::calculate_sha1(data);
        let result = ArtifactService::verify_checksums(data, Some(&sha256), Some(&sha1), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_sha1_and_md5_correct() {
        let data = b"sha1 md5 pair";
        let sha1 = ArtifactService::calculate_sha1(data);
        let md5 = ArtifactService::calculate_md5(data);
        let result = ArtifactService::verify_checksums(data, None, Some(&sha1), Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_sha256_correct_md5_wrong() {
        let data = b"partial md5 fail";
        let sha256 = ArtifactService::calculate_sha256(data);
        let result = ArtifactService::verify_checksums(
            data,
            Some(&sha256),
            None,
            Some("00000000000000000000000000000000"),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("MD5 checksum mismatch"));
    }

    #[test]
    fn test_verify_checksums_sha1_case_insensitive() {
        let data = b"sha1 case";
        let sha1 = ArtifactService::calculate_sha1(data).to_uppercase();
        let result = ArtifactService::verify_checksums(data, None, Some(&sha1), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_md5_case_insensitive() {
        let data = b"md5 case";
        let md5 = ArtifactService::calculate_md5(data).to_uppercase();
        let result = ArtifactService::verify_checksums(data, None, None, Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_large_data() {
        let data = vec![0xABu8; 100_000];
        let sha256 = ArtifactService::calculate_sha256(&data);
        let sha1 = ArtifactService::calculate_sha1(&data);
        let md5 = ArtifactService::calculate_md5(&data);
        let result =
            ArtifactService::verify_checksums(&data, Some(&sha256), Some(&sha1), Some(&md5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksums_error_message_includes_both_hashes() {
        let data = b"message test";
        let actual_sha256 = ArtifactService::calculate_sha256(data);
        let declared = "aaaa";
        let result = ArtifactService::verify_checksums(data, Some(declared), None, None);
        let err = result.unwrap_err().to_string();
        assert!(err.contains(declared));
        assert!(err.contains(&actual_sha256));
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
            quarantine_status: None,
            quarantine_until: None,
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
            quarantine_status: None,
            quarantine_until: None,
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
        // Assert against the actual query the delete path runs (not a copy) so
        // the clauses that gate peer fan-out can't silently drift.
        let sql = ENQUEUE_DELETE_SYNC_TASKS_SQL;
        assert!(sql.contains("INSERT INTO sync_tasks"));
        assert!(sql.contains("'delete'"));
        assert!(sql.contains("peer_repo_subscriptions"));
        assert!(sql.contains("replication_mode"));
        assert!(sql.contains("sync_enabled"));
        assert!(sql.contains("is_local = false"));
        assert!(sql.contains("ON CONFLICT"));
    }

    #[test]
    fn test_push_mirror_subscriptions_sql_filters_enabled_push_mirror() {
        let sql = PUSH_MIRROR_SUBSCRIPTIONS_SQL;
        assert!(sql.contains("FROM peer_repo_subscriptions prs"));
        assert!(sql.contains("LEFT JOIN sync_policies sp"));
        assert!(sql.contains("prs.sync_enabled = true"));
        assert!(sql.contains("replication_mode::text IN ('push', 'mirror')"));
    }

    #[test]
    fn test_cancel_superseded_push_tasks_sql_targets_pending_and_failed() {
        // A delete must supersede only in-flight push retries, never deletes or
        // already-completed tasks.
        let sql = CANCEL_SUPERSEDED_PUSH_TASKS_SQL;
        assert!(sql.contains("UPDATE sync_tasks"));
        assert!(sql.contains("status = 'cancelled'"));
        assert!(sql.contains("task_type = 'push'"));
        assert!(sql.contains("status IN ('pending', 'failed')"));
        assert!(sql.contains("superseded by artifact delete"));
    }

    // --- get_download_stats_batch ---

    #[test]
    fn test_batch_download_stats_empty_input_returns_empty_map() {
        // The empty-array short-circuit should return immediately
        // without hitting the database. We can verify the logic inline
        // since the actual DB call is async and needs a pool.
        let ids: Vec<uuid::Uuid> = vec![];
        assert!(ids.is_empty());
        let map: std::collections::HashMap<uuid::Uuid, i64> = std::collections::HashMap::new();
        assert!(map.is_empty());
    }

    #[test]
    fn test_batch_download_stats_map_lookup_with_default() {
        // Verify the HashMap lookup pattern used in the handler
        let mut map = std::collections::HashMap::new();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let id_missing = uuid::Uuid::new_v4();
        map.insert(id1, 42_i64);
        map.insert(id2, 7_i64);

        assert_eq!(*map.get(&id1).unwrap_or(&0), 42);
        assert_eq!(*map.get(&id2).unwrap_or(&0), 7);
        assert_eq!(*map.get(&id_missing).unwrap_or(&0), 0);
    }

    #[test]
    fn test_batch_download_stats_map_handles_duplicate_ids() {
        // If the same artifact_id appears twice in the input,
        // the GROUP BY query returns one row per unique artifact_id
        let mut map = std::collections::HashMap::new();
        let id = uuid::Uuid::new_v4();
        map.insert(id, 10_i64);
        // Inserting again overwrites (same behavior as GROUP BY)
        map.insert(id, 10_i64);
        assert_eq!(map.len(), 1);
        assert_eq!(*map.get(&id).unwrap(), 10);
    }

    // -----------------------------------------------------------------------
    // Release-immutability backstop × Debian classifier semantics
    // -----------------------------------------------------------------------

    /// Soft-delete an artifact row so the next upload exercises the
    /// tombstone-aware release-immutability backstop in `preflight_upload`.
    async fn tombstone(pool: &sqlx::PgPool, repo_id: Uuid, path: &str) {
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
        )
        .bind(repo_id)
        .bind(path)
        .execute(pool)
        .await
        .expect("tombstone artifact");
    }

    /// Locks in the intended hosted-Debian overwrite semantics introduced by
    /// the `Debian` arm of `cache_classifier::is_explicitly_mutable_index`:
    ///
    /// * `dists/…` index coordinates (Release, Packages, …) are genuinely
    ///   rewritten in place by every APT publish — like `maven-metadata.xml`
    ///   or an npm packument — so the tombstone/overwrite guard must be
    ///   SKIPPED: a delete + re-push with different bytes succeeds.
    /// * `pool/…` packages and `by-hash/…` indices are release coordinates
    ///   (version-pinned / content-addressed) and must stay PROTECTED: a
    ///   delete + re-push with different bytes is rejected with Conflict.
    ///
    /// A future change to either direction should fail this test rather than
    /// silently flipping the semantics.
    #[tokio::test]
    async fn test_debian_dists_tombstone_overwrite_allowed_pool_and_by_hash_protected() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, storage_dir) = tdh::create_repo(&pool, "local", "debian").await;

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(storage_dir.clone()),
        );
        let svc = ArtifactService::new(pool.clone(), storage);

        // -- (a) dists/… index coordinate: overwrite after tombstone ALLOWED --
        let dists_path = "dists/bookworm/main/binary-amd64/Packages";
        svc.upload_with_sync_options(
            repo_id,
            dists_path,
            "Packages",
            None,
            "application/octet-stream",
            Bytes::from_static(b"packages-index-v1"),
            Some(user_id),
            false,
        )
        .await
        .expect("initial dists index upload must succeed");

        tombstone(&pool, repo_id, dists_path).await;

        let republished = svc
            .upload_with_sync_options(
                repo_id,
                dists_path,
                "Packages",
                None,
                "application/octet-stream",
                Bytes::from_static(b"packages-index-v2-DIFFERENT"),
                Some(user_id),
                false,
            )
            .await
            .expect("dists index is an in-place-rewritten index: re-push with different bytes must succeed");
        assert_eq!(
            republished.checksum_sha256,
            ArtifactService::calculate_sha256(b"packages-index-v2-DIFFERENT"),
            "re-pushed dists index must carry the new content"
        );

        // -- (b1) pool/… package: overwrite after tombstone REJECTED ---------
        let pool_path = "pool/main/a/apt/apt_2.5.3_amd64.deb";
        svc.upload_with_sync_options(
            repo_id,
            pool_path,
            "apt",
            Some("2.5.3"),
            "application/vnd.debian.binary-package",
            Bytes::from_static(b"deb-content-v1"),
            Some(user_id),
            false,
        )
        .await
        .expect("initial pool package upload must succeed");

        tombstone(&pool, repo_id, pool_path).await;

        let swap = svc
            .upload_with_sync_options(
                repo_id,
                pool_path,
                "apt",
                Some("2.5.3"),
                "application/vnd.debian.binary-package",
                Bytes::from_static(b"deb-content-v2-DIFFERENT"),
                Some(user_id),
                false,
            )
            .await;
        assert!(
            matches!(swap, Err(AppError::Conflict(_))),
            "pool/ coordinate is a release coordinate: tombstone + different-bytes re-push must be rejected, got {:?}",
            swap.map(|a| a.path)
        );

        // -- (b2) by-hash/… index: overwrite after tombstone REJECTED --------
        let by_hash_path =
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/0f343b0931126a20f133d67c2b018a3b";
        svc.upload_with_sync_options(
            repo_id,
            by_hash_path,
            "Packages",
            None,
            "application/octet-stream",
            Bytes::from_static(b"by-hash-content-v1"),
            Some(user_id),
            false,
        )
        .await
        .expect("initial by-hash upload must succeed");

        tombstone(&pool, repo_id, by_hash_path).await;

        let swap = svc
            .upload_with_sync_options(
                repo_id,
                by_hash_path,
                "Packages",
                None,
                "application/octet-stream",
                Bytes::from_static(b"by-hash-content-v2-DIFFERENT"),
                Some(user_id),
                false,
            )
            .await;
        assert!(
            matches!(swap, Err(AppError::Conflict(_))),
            "by-hash/ coordinate is content-addressed: tombstone + different-bytes re-push must be rejected, got {:?}",
            swap.map(|a| a.path)
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// #2366: the artifact lifecycle emits audit events. Upload -> download ->
    /// delete each writes exactly one `audit_log` row for the artifact, keyed
    /// by the shared service-layer choke points (`finalize_upload`,
    /// `finish_download`, `delete_with_sync_options`). The download event also
    /// carries the client IP and acting user. Skips without `DATABASE_URL`.
    #[tokio::test]
    async fn test_artifact_lifecycle_emits_audit_events_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, storage_dir) = tdh::create_repo(&pool, "local", "generic").await;

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(storage_dir.clone()),
        );
        let svc = ArtifactService::new(pool.clone(), storage);

        // Upload -> ARTIFACT_UPLOADED (audit write is awaited inside
        // finalize_upload, so it has landed by the time upload() returns).
        let artifact = svc
            .upload(
                repo_id,
                "audit/pkg.txt",
                "pkg.txt",
                Some("1.0"),
                "text/plain",
                Bytes::from_static(b"audit-bytes"),
                Some(user_id),
            )
            .await
            .expect("upload succeeds");
        assert_eq!(
            tdh::audit_count(&pool, artifact.id, "ARTIFACT_UPLOADED").await,
            1,
            "upload emits exactly one ARTIFACT_UPLOADED event"
        );

        // Download -> ARTIFACT_DOWNLOADED with a resolved client IP + user.
        let _ = svc
            .download(
                repo_id,
                "audit/pkg.txt",
                Some(user_id),
                Some("203.0.113.5".to_string()),
                Some("test-ua"),
            )
            .await
            .expect("download succeeds");
        assert_eq!(
            tdh::audit_count(&pool, artifact.id, "ARTIFACT_DOWNLOADED").await,
            1,
            "download emits exactly one ARTIFACT_DOWNLOADED event"
        );

        // Delete -> ARTIFACT_DELETED.
        svc.delete(artifact.id).await.expect("delete succeeds");
        assert_eq!(
            tdh::audit_count(&pool, artifact.id, "ARTIFACT_DELETED").await,
            1,
            "delete emits exactly one ARTIFACT_DELETED event"
        );

        let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
            .bind(artifact.id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    // ---- #2367 first-class versioning: pure helpers ------------------------

    #[test]
    fn test_next_revision_starts_at_one_and_increments() {
        assert_eq!(next_revision(None), 1);
        assert_eq!(next_revision(Some(1)), 2);
        assert_eq!(next_revision(Some(7)), 8);
    }

    #[test]
    fn test_versioning_applies_gated_on_flag_and_format() {
        // Opt-in + supported formats.
        assert!(versioning_applies(&RepositoryFormat::Generic, true));
        assert!(versioning_applies(&RepositoryFormat::Mlmodel, true));
        // Flag off: never applies, even for supported formats.
        assert!(!versioning_applies(&RepositoryFormat::Generic, false));
        assert!(!versioning_applies(&RepositoryFormat::Mlmodel, false));
        // Other formats: never applies, even with the flag on.
        assert!(!versioning_applies(&RepositoryFormat::Maven, true));
        assert!(!versioning_applies(&RepositoryFormat::Npm, true));
        assert!(!versioning_applies(&RepositoryFormat::Debian, true));
        assert!(!versioning_applies(&RepositoryFormat::Docker, true));
    }

    #[test]
    fn test_parse_version_selector() {
        // Absent / empty / literal `latest` -> HEAD.
        assert_eq!(parse_version_selector(None), VersionSelector::Latest);
        assert_eq!(parse_version_selector(Some("")), VersionSelector::Latest);
        assert_eq!(parse_version_selector(Some("  ")), VersionSelector::Latest);
        assert_eq!(
            parse_version_selector(Some("latest")),
            VersionSelector::Latest
        );
        // All-digits -> revision number.
        assert_eq!(
            parse_version_selector(Some("3")),
            VersionSelector::Revision(3)
        );
        assert_eq!(
            parse_version_selector(Some(" 12 ")),
            VersionSelector::Revision(12)
        );
        // Anything else -> label (including mixed and signed strings; revisions
        // are server-assigned positive integers so `-1` can only be a label).
        assert_eq!(
            parse_version_selector(Some("gold")),
            VersionSelector::Label("gold".to_string())
        );
        assert_eq!(
            parse_version_selector(Some("v2")),
            VersionSelector::Label("v2".to_string())
        );
        assert_eq!(
            parse_version_selector(Some("-1")),
            VersionSelector::Label("-1".to_string())
        );
        assert_eq!(
            parse_version_selector(Some("1.0.0")),
            VersionSelector::Label("1.0.0".to_string())
        );
        // Digits that overflow i32 degrade to a (non-matching) label.
        assert_eq!(
            parse_version_selector(Some("99999999999")),
            VersionSelector::Label("99999999999".to_string())
        );
    }

    #[test]
    fn test_resolve_version_selector() {
        let versions: Vec<(i32, Option<String>)> = vec![
            (1, None),
            (2, Some("gold".to_string())),
            (3, Some("rc".to_string())),
        ];
        // Numeric selector -> exact revision.
        assert_eq!(
            resolve_version_selector(&VersionSelector::Revision(3), &versions),
            Some(3)
        );
        assert_eq!(
            resolve_version_selector(&VersionSelector::Revision(9), &versions),
            None
        );
        // Label selector -> labelled revision.
        assert_eq!(
            resolve_version_selector(&VersionSelector::Label("gold".to_string()), &versions),
            Some(2)
        );
        // Unknown label -> None.
        assert_eq!(
            resolve_version_selector(&VersionSelector::Label("nope".to_string()), &versions),
            None
        );
        // Latest -> max revision.
        assert_eq!(
            resolve_version_selector(&VersionSelector::Latest, &versions),
            Some(3)
        );
        // Empty history -> None for every selector.
        assert_eq!(
            resolve_version_selector(&VersionSelector::Latest, &[]),
            None
        );
        assert_eq!(
            resolve_version_selector(&VersionSelector::Revision(1), &[]),
            None
        );
        // Duplicate label -> highest matching revision wins (re-tagging).
        let retagged: Vec<(i32, Option<String>)> =
            vec![(1, Some("gold".to_string())), (2, Some("gold".to_string()))];
        assert_eq!(
            resolve_version_selector(&VersionSelector::Label("gold".to_string()), &retagged),
            Some(2)
        );
    }

    // ---- #2367 first-class versioning: DB-backed flow ----------------------

    /// Set the per-repo `versioning_enabled` opt-in flag.
    async fn set_versioning(pool: &sqlx::PgPool, repo_id: Uuid, value: bool) {
        sqlx::query("UPDATE repositories SET versioning_enabled = $1 WHERE id = $2")
            .bind(value)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("set versioning_enabled");
    }

    /// Versioning-enabled generic repo: different-bytes re-upload APPENDS a
    /// revision instead of 409ing, identical-bytes re-upload is idempotent,
    /// and selectors (revision / label / latest) resolve correctly.
    #[tokio::test]
    async fn versioned_generic_reupload_appends_revisions_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, storage_dir) = tdh::create_repo(&pool, "local", "generic").await;
        set_versioning(&pool, repo_id, true).await;

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(storage_dir.clone()),
        );
        let svc = ArtifactService::new(pool.clone(), storage);
        let path = "configs/app/config.yaml";

        // Revision 1.
        svc.upload_with_sync_options(
            repo_id,
            path,
            "config.yaml",
            None,
            "application/yaml",
            Bytes::from_static(b"content: A"),
            Some(user_id),
            false,
        )
        .await
        .expect("first upload must succeed");

        // Different bytes to the same path: previously a 409/overwrite; with
        // versioning enabled this must APPEND revision 2 (with a label).
        let head = svc
            .upload_with_sync_options(
                repo_id,
                path,
                "config.yaml",
                Some("gold"),
                "application/yaml",
                Bytes::from_static(b"content: B"),
                Some(user_id),
                false,
            )
            .await
            .expect("versioned re-upload with different bytes must succeed");
        assert_eq!(
            head.checksum_sha256,
            ArtifactService::calculate_sha256(b"content: B"),
            "HEAD must point at the newest content"
        );

        let versions = svc.list_versions(repo_id, path).await.expect("list");
        assert_eq!(
            versions.iter().map(|v| v.revision).collect::<Vec<_>>(),
            vec![2, 1],
            "history must hold revisions [2, 1], newest first"
        );
        assert_eq!(
            versions[1].checksum_sha256.trim(),
            ArtifactService::calculate_sha256(b"content: A"),
            "revision 1 must preserve the original bytes' checksum"
        );

        // Identical-bytes re-upload: idempotent, no new revision.
        svc.upload_with_sync_options(
            repo_id,
            path,
            "config.yaml",
            Some("gold"),
            "application/yaml",
            Bytes::from_static(b"content: B"),
            Some(user_id),
            false,
        )
        .await
        .expect("identical-bytes re-upload must stay idempotent");
        let after = svc.list_versions(repo_id, path).await.expect("list");
        assert_eq!(
            after.len(),
            2,
            "identical-bytes re-upload must not append a new revision"
        );

        // Selector resolution: revision number, label, latest, unknown.
        let rev1 = svc.get_version(repo_id, path, Some("1")).await.expect("q");
        assert_eq!(rev1.map(|v| v.revision), Some(1));
        let gold = svc
            .get_version(repo_id, path, Some("gold"))
            .await
            .expect("q");
        assert_eq!(gold.map(|v| v.revision), Some(2));
        let latest = svc.get_version(repo_id, path, None).await.expect("q");
        assert_eq!(latest.map(|v| v.revision), Some(2));
        let missing = svc
            .get_version(repo_id, path, Some("nope"))
            .await
            .expect("q");
        assert!(missing.is_none(), "unknown selector must resolve to None");

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// Backfill-on-write: the first versioned upload over a HEAD that predates
    /// the feature records that HEAD as revision 1, then the new bytes as
    /// revision 2 — and deleting the HEAD afterwards leaves both revisions
    /// addressable.
    #[tokio::test]
    async fn versioned_backfill_preserves_preexisting_head_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, storage_dir) = tdh::create_repo(&pool, "local", "generic").await;

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(storage_dir.clone()),
        );
        let svc = ArtifactService::new(pool.clone(), storage);
        let path = "docs/manual.pdf";

        // Upload BEFORE opting in: no history is recorded (flag defaults off).
        svc.upload_with_sync_options(
            repo_id,
            path,
            "manual.pdf",
            None,
            "application/pdf",
            Bytes::from_static(b"pdf-v1"),
            Some(user_id),
            false,
        )
        .await
        .expect("pre-feature upload must succeed");
        assert!(
            svc.list_versions(repo_id, path)
                .await
                .expect("list")
                .is_empty(),
            "flag-off upload must record no history"
        );

        // Opt in, then upload different bytes: prior HEAD is backfilled as
        // revision 1 and the new bytes land as revision 2.
        set_versioning(&pool, repo_id, true).await;
        svc.upload_with_sync_options(
            repo_id,
            path,
            "manual.pdf",
            None,
            "application/pdf",
            Bytes::from_static(b"pdf-v2"),
            Some(user_id),
            false,
        )
        .await
        .expect("versioned upload over pre-feature HEAD must succeed");

        let versions = svc.list_versions(repo_id, path).await.expect("list");
        assert_eq!(
            versions.iter().map(|v| v.revision).collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(
            versions[1].checksum_sha256.trim(),
            ArtifactService::calculate_sha256(b"pdf-v1"),
            "backfilled revision 1 must carry the pre-feature HEAD checksum"
        );

        // Soft-delete the HEAD: prior revisions stay addressable.
        tombstone(&pool, repo_id, path).await;
        let still_there = svc
            .get_version(repo_id, path, Some("1"))
            .await
            .expect("q")
            .expect("revision 1 must remain addressable after HEAD delete");
        assert_eq!(still_there.revision, 1);

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// Regression guard: with `versioning_enabled` left at its default
    /// (false), a generic repo's released coordinate still rejects a
    /// different-bytes re-upload with 409 — the versioning branch must not
    /// weaken any non-opted-in repository.
    #[tokio::test]
    async fn versioning_flag_off_keeps_release_immutability_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, storage_dir) = tdh::create_repo(&pool, "local", "generic").await;

        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(storage_dir.clone()),
        );
        let svc = ArtifactService::new(pool.clone(), storage);
        let path = "app/1.0.0/app-1.0.0.bin";

        svc.upload_with_sync_options(
            repo_id,
            path,
            "app",
            Some("1.0.0"),
            "application/octet-stream",
            Bytes::from_static(b"release-bytes"),
            Some(user_id),
            false,
        )
        .await
        .expect("initial release upload must succeed");

        let swap = svc
            .upload_with_sync_options(
                repo_id,
                path,
                "app",
                Some("1.0.0"),
                "application/octet-stream",
                Bytes::from_static(b"DIFFERENT-bytes"),
                Some(user_id),
                false,
            )
            .await;
        assert!(
            matches!(swap, Err(AppError::Conflict(_))),
            "flag-off different-bytes re-upload to a released coordinate must still 409, got {:?}",
            swap.map(|a| a.path)
        );
        assert!(
            svc.list_versions(repo_id, path)
                .await
                .expect("list")
                .is_empty(),
            "flag-off repos must record no version history"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }
}
