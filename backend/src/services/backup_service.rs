//! Backup and restore service.
//!
//! Handles full and incremental backups of the registry data and artifacts.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::io::Read;
use std::sync::Arc;
use tar::{Archive, Builder};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::storage_service::StorageService;

/// Backup status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "backup_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for BackupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupStatus::Pending => write!(f, "pending"),
            BackupStatus::InProgress => write!(f, "in_progress"),
            BackupStatus::Completed => write!(f, "completed"),
            BackupStatus::Failed => write!(f, "failed"),
            BackupStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Backup type
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "backup_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BackupType {
    Full,
    Incremental,
    Metadata,
}

/// Backup record
#[derive(Debug)]
pub struct Backup {
    pub id: Uuid,
    pub backup_type: BackupType,
    pub status: BackupStatus,
    pub storage_path: Option<String>,
    pub size_bytes: Option<i64>,
    pub artifact_count: Option<i64>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Backup manifest stored in each backup
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub backup_id: Uuid,
    pub backup_type: BackupType,
    pub created_at: DateTime<Utc>,
    pub database_tables: Vec<String>,
    /// Number of artifact objects whose bytes were successfully read and are
    /// present in the archive.
    pub artifact_count: i64,
    /// Number of enumerated artifact objects whose bytes could **not** be read
    /// and are therefore absent from the archive (#3170).
    ///
    /// Recorded so an existing archive can be audited without re-running the
    /// backup, and so [`BackupService::restore`] can refuse to present an
    /// incomplete archive as a clean restore. Defaults to `0` when absent so
    /// archives written before this field existed still deserialize.
    #[serde(default)]
    pub artifacts_unreadable: i64,
    pub total_size_bytes: i64,
    pub checksum: String,
}

/// Metadata key that opts a backup in to completing despite unreadable
/// artifact bytes (#3170).
///
/// Absent/false — the default — means a backup that cannot read an artifact's
/// bytes FAILS. Partial backups remain possible, but only as an explicit
/// operator choice, never as a silent default.
const ALLOW_PARTIAL_ARTIFACTS_KEY: &str = "allow_partial_artifacts";

/// Whether the backup's metadata opts in to a partial (best-effort) archive.
fn allow_partial_artifacts(metadata: Option<&serde_json::Value>) -> bool {
    metadata
        .and_then(|m| m.get(ALLOW_PARTIAL_ARTIFACTS_KEY))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Build the operator-facing message for a backup that could not read every
/// artifact's bytes (#3170).
///
/// Names the affected keys (capped, with an overflow count) so the job's
/// `error_message` is actionable without trawling logs.
fn unreadable_artifacts_message(unreadable: &[(String, String)]) -> String {
    const MAX_LISTED: usize = 5;
    let listed = unreadable
        .iter()
        .take(MAX_LISTED)
        .map(|(key, err)| format!("{key} ({err})"))
        .collect::<Vec<_>>()
        .join("; ");
    let overflow = unreadable.len().saturating_sub(MAX_LISTED);
    let suffix = if overflow > 0 {
        format!(" and {overflow} more")
    } else {
        String::new()
    };
    format!(
        "backup is missing artifact content: {} artifact object(s) could not be read: {}{}. \
         The archive does NOT contain these bytes. Set `{}` in the backup metadata to accept \
         a partial archive deliberately.",
        unreadable.len(),
        listed,
        suffix,
        ALLOW_PARTIAL_ARTIFACTS_KEY
    )
}

/// Request to create a backup
#[derive(Debug)]
pub struct CreateBackupRequest {
    pub backup_type: BackupType,
    pub repository_ids: Option<Vec<Uuid>>,
    /// Optional list of repository ids to exclude from the backup (#2772).
    ///
    /// Airgapped/bandwidth-limited deployments use this to keep specific
    /// repositories out of full and incremental backups. When `None` or
    /// empty no repositories are excluded, so existing behavior is unchanged.
    /// When an explicit include list is also supplied the excluded ids are
    /// removed from it; otherwise every repository except the excluded ones
    /// is backed up.
    pub exclude_repository_ids: Option<Vec<Uuid>>,
    /// Optional lower bound on artifact modification time (#2789).
    ///
    /// When set, only artifacts whose `updated_at >= since` are included in the
    /// backup, letting operators capture just the changes made from a given
    /// date/timestamp to now (an incremental "since this point" backup). When
    /// `None` every artifact is included, so full and incremental backups behave
    /// exactly as before.
    pub since: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    /// Optional operator-supplied name/label for the archive (#2790).
    ///
    /// When set it becomes the identifying part of the archive filename;
    /// when `None` the historical `{uuid}` name is used, so existing
    /// deployments are unaffected.
    pub name: Option<String>,
}

/// Backup service
pub struct BackupService {
    db: PgPool,
    /// Primary storage: where source artifacts are read from during a backup
    /// and restored to during a restore. Always the deployment's main storage
    /// bucket.
    storage: Arc<StorageService>,
    /// Storage for backup **archives** (`.tar.gz`). Defaults to `storage`, but
    /// points at a separate bucket when `BACKUP_S3_BUCKET` is configured
    /// (#2507). Only the archive read/write path uses this handle, so a
    /// dedicated backup bucket never changes where artifacts live.
    archive_storage: Arc<StorageService>,
    active_backup: Arc<Mutex<Option<Uuid>>>,
}

/// Allowlist of database tables that may be exported via backup.
const ALLOWED_EXPORT_TABLES: &[&str] = &[
    "users",
    "repositories",
    "artifacts",
    "download_statistics",
    "api_tokens",
    "roles",
    "user_roles",
    "permission_grants",
];

/// Validate that a table name is in the export allowlist.
fn validate_export_table(table: &str) -> Result<()> {
    if !ALLOWED_EXPORT_TABLES.contains(&table) {
        return Err(AppError::Validation(format!(
            "Invalid export table: {}",
            table
        )));
    }
    Ok(())
}

/// Build a tar.gz archive from pre-fetched table data and artifact data.
///
/// Uses `tar::Builder::append_data` instead of `header.set_path` + `tar.append`
/// so that paths longer than 100 characters are written as GNU LongLink
/// extensions (fixes #758).
///
/// `tables` is a list of (table_name, json_bytes) pairs.
/// `artifacts` is a list of (storage_key, content) pairs.
/// `manifest` is the serialized backup manifest.
fn build_backup_tar(
    tables: &[(&str, &[u8])],
    artifacts: &[(&str, &[u8])],
    manifest: &[u8],
) -> Result<Vec<u8>> {
    let mut tar_buffer = Vec::new();
    {
        let encoder = GzEncoder::new(&mut tar_buffer, Compression::default());
        let mut tar = Builder::new(encoder);

        for (table, json_bytes) in tables {
            let mut header = tar::Header::new_gnu();
            header.set_size(json_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(Utc::now().timestamp() as u64);
            header.set_cksum();

            tar.append_data(&mut header, format!("database/{}.json", table), *json_bytes)?;
        }

        for (key, content) in artifacts {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(Utc::now().timestamp() as u64);
            header.set_cksum();

            tar.append_data(&mut header, format!("artifacts/{}", key), *content)?;
        }

        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(Utc::now().timestamp() as u64);
        header.set_cksum();

        tar.append_data(&mut header, "manifest.json", manifest)?;

        tar.into_inner()?.finish()?;
    }

    Ok(tar_buffer)
}

/// Normalize the operator-supplied backup key prefix (`BACKUP_S3_PREFIX`).
///
/// Splits on `/` and drops empty, `.`, and `..` segments — the storage key
/// is joined into a filesystem path on the filesystem backend, so traversal
/// segments must never survive — then rejoins. Returns `None` when nothing
/// usable remains, so `BACKUP_S3_PREFIX=""` or `"/"` behaves like unset.
fn normalize_backup_prefix(raw: &str) -> Option<String> {
    let cleaned: Vec<&str> = raw
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.join("/"))
    }
}

/// Storage key for a new backup archive (#2508).
///
/// The relative key always keeps the `backups/` root; when a prefix is
/// configured via `BACKUP_S3_PREFIX` it is prepended, mirroring how
/// `S3_PREFIX` prepends to artifact keys:
/// `{BACKUP_S3_PREFIX}/backups/YYYY/MM/DD/{uuid}.tar.gz`.
///
/// Back-compat: reads, restores, and deletes always resolve through the
/// `backups.storage_path` recorded at creation time, so changing (or
/// unsetting) the prefix later never strands existing archives.
fn backup_storage_key(raw_prefix: Option<&str>, relative: &str) -> String {
    match raw_prefix.and_then(normalize_backup_prefix) {
        Some(prefix) => format!("{}/{}", prefix, relative),
        None => relative.to_string(),
    }
}

/// Maximum length of an operator-supplied backup name (before extension).
const MAX_BACKUP_NAME_LEN: usize = 128;

/// Resolve the base filename (including the `.tar.gz` extension) for a new
/// backup archive (#2790).
///
/// When an operator supplies a custom `name` it is sanitized and used as the
/// archive's identifying label, with a short unique suffix derived from
/// `file_id` appended so two backups sharing a name can never resolve to the
/// same storage key (which would silently overwrite the older archive). When
/// no name is given the historical `{uuid}.tar.gz` name is preserved, so
/// existing deployments are unaffected.
///
/// The custom name is restricted to `[A-Za-z0-9._-]`; anything containing a
/// path separator, `..`, whitespace, or any other character is rejected
/// rather than silently rewritten, so the name can never escape the
/// `backups/` prefix or smuggle in a traversal sequence.
fn resolve_backup_filename(name: Option<&str>, file_id: Uuid) -> Result<String> {
    let Some(raw) = name else {
        return Ok(format!("{}.tar.gz", file_id));
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(
            "Backup name must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_BACKUP_NAME_LEN {
        return Err(AppError::Validation(format!(
            "Backup name must be at most {} characters",
            MAX_BACKUP_NAME_LEN
        )));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(AppError::Validation(
            "Backup name must not be '.' or '..'".to_string(),
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(AppError::Validation(
            "Backup name may only contain letters, digits, '.', '_', and '-'".to_string(),
        ));
    }

    let suffix = file_id.simple().to_string();
    Ok(format!("{}-{}.tar.gz", trimmed, &suffix[..8]))
}

/// Count entries under the `artifacts/` prefix in a tar.gz archive.
fn count_artifacts_in_tar(tar_data: &[u8]) -> Result<i64> {
    let decoder = GzDecoder::new(tar_data);
    let mut archive = Archive::new(decoder);
    let mut count = 0i64;

    for entry in archive
        .entries()
        .map_err(|e| AppError::Internal(e.to_string()))?
    {
        let entry = entry.map_err(|e| AppError::Internal(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if path.starts_with("artifacts/") {
            count += 1;
        }
    }

    Ok(count)
}

/// Resolve the effective set of repository ids to back up given an optional
/// include-list and an optional exclude-list (#2772).
///
/// Returns `None` to mean "every repository" (no row filtering), matching the
/// historical default when neither list is supplied. This keeps the default
/// backup path byte-for-byte identical to before the exclude feature.
///
/// Semantics:
/// * No exclude list (or an empty one): the include list is returned as-is.
/// * Include + exclude: excluded ids are removed from the include list.
/// * Exclude only: every repository in `all_repository_ids` except the
///   excluded ones is returned.
fn resolve_effective_repository_ids(
    include: Option<Vec<Uuid>>,
    exclude: Option<Vec<Uuid>>,
    all_repository_ids: &[Uuid],
) -> Option<Vec<Uuid>> {
    // An empty exclude list is a no-op, indistinguishable from "no exclusions".
    let exclude = exclude.filter(|ex| !ex.is_empty());

    match (include, exclude) {
        (include, None) => include,
        (Some(include), Some(exclude)) => {
            let excluded: std::collections::HashSet<Uuid> = exclude.into_iter().collect();
            Some(
                include
                    .into_iter()
                    .filter(|id| !excluded.contains(id))
                    .collect(),
            )
        }
        (None, Some(exclude)) => {
            let excluded: std::collections::HashSet<Uuid> = exclude.into_iter().collect();
            Some(
                all_repository_ids
                    .iter()
                    .copied()
                    .filter(|id| !excluded.contains(id))
                    .collect(),
            )
        }
    }
}

/// Read the optional `since` cutoff (#2789) from a backup's stored metadata.
///
/// Returns `None` when no cutoff was recorded (the key is absent or JSON null),
/// which preserves the historical "every artifact" behavior. A malformed value
/// is treated as no cutoff rather than failing the backup.
fn parse_since_filter(metadata: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    metadata
        .and_then(|m| m.get("since"))
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value::<DateTime<Utc>>(v.clone()).ok())
}

impl BackupService {
    pub fn new(db: PgPool, storage: Arc<StorageService>) -> Self {
        // Default: backup archives live in the same bucket as artifacts, so
        // the archive handle is just a clone of primary storage. This keeps
        // behavior byte-identical when `BACKUP_S3_BUCKET` is unset (#2507).
        let archive_storage = storage.clone();
        Self {
            db,
            storage,
            archive_storage,
            active_backup: Arc::new(Mutex::new(None)),
        }
    }

    /// Construct a backup service whose **archives** are read from/written to a
    /// dedicated storage handle, separate from the artifact storage (#2507).
    ///
    /// Callers resolve `archive_storage` via
    /// [`StorageService::backup_archive_from_config`]; when `BACKUP_S3_BUCKET`
    /// is unset it is a clone of `storage`, so this is equivalent to
    /// [`BackupService::new`].
    pub fn with_archive_storage(
        db: PgPool,
        storage: Arc<StorageService>,
        archive_storage: Arc<StorageService>,
    ) -> Self {
        Self {
            db,
            storage,
            archive_storage,
            active_backup: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new backup job
    pub async fn create(&self, req: CreateBackupRequest) -> Result<Backup> {
        let prefix = std::env::var("BACKUP_S3_PREFIX").ok();
        let file_id = Uuid::new_v4();
        let filename = resolve_backup_filename(req.name.as_deref(), file_id)?;
        let storage_path = backup_storage_key(
            prefix.as_deref(),
            &format!("backups/{}/{}", Utc::now().format("%Y/%m/%d"), filename),
        );

        let backup = sqlx::query_as!(
            Backup,
            r#"
            INSERT INTO backups (backup_type, storage_path, created_by, metadata)
            VALUES ($1, $2, $3, $4)
            RETURNING
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            "#,
            req.backup_type as BackupType,
            storage_path,
            req.created_by,
            serde_json::json!({
                "repository_ids": req.repository_ids,
                "exclude_repository_ids": req.exclude_repository_ids,
                "since": req.since,
                "name": req.name,
            })
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(backup)
    }

    /// Get backup by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<Backup> {
        let backup = sqlx::query_as!(
            Backup,
            r#"
            SELECT
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            FROM backups
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Backup not found".to_string()))?;

        Ok(backup)
    }

    /// List backups
    pub async fn list(
        &self,
        status: Option<BackupStatus>,
        backup_type: Option<BackupType>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<Backup>, i64)> {
        let backups = sqlx::query_as!(
            Backup,
            r#"
            SELECT
                id, backup_type as "backup_type: BackupType",
                status as "status: BackupStatus",
                storage_path, size_bytes, artifact_count,
                started_at, completed_at, error_message,
                metadata, created_by, created_at
            FROM backups
            WHERE ($1::backup_status IS NULL OR status = $1)
              AND ($2::backup_type IS NULL OR backup_type = $2)
            ORDER BY created_at DESC
            OFFSET $3
            LIMIT $4
            "#,
            status as Option<BackupStatus>,
            backup_type as Option<BackupType>,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM backups
            WHERE ($1::backup_status IS NULL OR status = $1)
              AND ($2::backup_type IS NULL OR backup_type = $2)
            "#,
            status as Option<BackupStatus>,
            backup_type as Option<BackupType>
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((backups, total))
    }

    /// Execute a backup
    pub async fn execute(&self, backup_id: Uuid) -> Result<Backup> {
        // Check if another backup is running
        {
            let mut active = self.active_backup.lock().await;
            if active.is_some() {
                return Err(AppError::Conflict(
                    "Another backup is already in progress".to_string(),
                ));
            }
            *active = Some(backup_id);
        }

        // Mark as in progress
        self.update_status(backup_id, BackupStatus::InProgress, None)
            .await?;

        let result = self.do_backup(backup_id).await;

        // Clear active backup
        {
            let mut active = self.active_backup.lock().await;
            *active = None;
        }

        match result {
            Ok(backup) => {
                self.update_status(backup_id, BackupStatus::Completed, None)
                    .await?;
                Ok(backup)
            }
            Err(e) => {
                self.update_status(backup_id, BackupStatus::Failed, Some(&e.to_string()))
                    .await?;
                Err(e)
            }
        }
    }

    async fn do_backup(&self, backup_id: Uuid) -> Result<Backup> {
        let backup = self.get_by_id(backup_id).await?;

        // Export database tables as JSON
        let table_names = vec![
            "users",
            "repositories",
            "artifacts",
            "download_statistics",
            "api_tokens",
            "roles",
            "user_roles",
            "permission_grants",
        ];

        // Resolve which repositories this backup covers (#2772). `None` means
        // "every repository" and preserves the historical, unfiltered dump.
        let repository_filter = self
            .effective_repository_filter(backup.metadata.as_ref())
            .await?;

        // Optional "changes since" cutoff (#2789). When present only artifacts
        // modified at-or-after this timestamp are dumped, so an incremental
        // backup can capture just the delta from a given date to now. `None`
        // keeps every artifact, preserving the historical behavior.
        let since_filter = parse_since_filter(backup.metadata.as_ref());

        let mut table_data: Vec<(String, Vec<u8>)> = Vec::new();
        for table in &table_names {
            // The `artifacts` table is the only per-repository table exported,
            // so when a repository filter is in effect an excluded repository's
            // artifact rows are kept out of the dump too (not just its bytes).
            let json_data = if *table == "artifacts" {
                self.export_artifacts(repository_filter.as_deref(), since_filter)
                    .await?
            } else {
                self.export_table(table).await?
            };
            let json_bytes = serde_json::to_vec_pretty(&json_data)?;
            table_data.push((table.to_string(), json_bytes));
        }

        // Fetch artifact storage keys and content
        let storage_keys = self
            .artifact_storage_keys(repository_filter.as_deref(), since_filter)
            .await?;
        // Read each artifact's bytes, tracking failures rather than discarding
        // them (#3170). A read that fails means the archive will not contain
        // that artifact's content; that must never be invisible.
        let mut artifact_data: Vec<(String, Vec<u8>)> = Vec::new();
        let mut unreadable: Vec<(String, String)> = Vec::new();
        for key in storage_keys {
            match self.storage.get(&key).await {
                Ok(content) => artifact_data.push((key, content.to_vec())),
                Err(e) => {
                    tracing::warn!(
                        backup_id = %backup_id,
                        storage_key = %key,
                        error = %e,
                        "backup could not read artifact bytes; the archive will not contain this object"
                    );
                    unreadable.push((key, e.to_string()));
                }
            }
        }

        // Build manifest. Both counts are recorded so an archive can be audited
        // after the fact without re-running the backup (#3170).
        let manifest = BackupManifest {
            version: "1.0".to_string(),
            backup_id,
            backup_type: backup.backup_type,
            created_at: Utc::now(),
            database_tables: table_names.iter().map(|s| s.to_string()).collect(),
            artifact_count: artifact_data.len() as i64,
            artifacts_unreadable: unreadable.len() as i64,
            total_size_bytes: 0,     // Will be actual size in final backup
            checksum: String::new(), // Will be computed after archive is complete
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

        // Build tar.gz archive using append_data (supports paths > 100 chars)
        let tables_ref: Vec<(&str, &[u8])> = table_data
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect();
        let artifacts_ref: Vec<(&str, &[u8])> = artifact_data
            .iter()
            .map(|(key, data)| (key.as_str(), data.as_slice()))
            .collect();
        let tar_buffer = build_backup_tar(&tables_ref, &artifacts_ref, &manifest_bytes)?;

        // Store backup
        let storage_path = backup
            .storage_path
            .as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        // The archive itself is written to the (optionally separate) backup
        // bucket; the source artifacts read above stay on primary storage.
        self.archive_storage
            .put(storage_path, Bytes::from(tar_buffer.clone()))
            .await?;

        // Update backup record
        let artifact_count = count_artifacts_in_tar(&tar_buffer)?;
        sqlx::query(
            r#"
            UPDATE backups
            SET size_bytes = $2, artifact_count = $3, completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(backup_id)
        .bind(tar_buffer.len() as i64)
        .bind(artifact_count)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // A backup that could not read every artifact's bytes must not present
        // as a clean success (#3170). The archive and its manifest are written
        // first, deliberately: the partial data plus the recorded miss count is
        // strictly more useful to an operator than discarding both, and the
        // manifest is what lets `restore` refuse the archive later. The job
        // itself then fails, so the failure is visible at the moment it happens
        // rather than at restore time when there is no recourse.
        if !unreadable.is_empty() {
            let message = unreadable_artifacts_message(&unreadable);
            if allow_partial_artifacts(backup.metadata.as_ref()) {
                tracing::warn!(
                    backup_id = %backup_id,
                    unreadable = unreadable.len(),
                    "{}", message
                );
            } else {
                tracing::error!(backup_id = %backup_id, "{}", message);
                return Err(AppError::Internal(message));
            }
        }

        self.get_by_id(backup_id).await
    }

    async fn export_table(&self, table: &str) -> Result<serde_json::Value> {
        validate_export_table(table)?;

        // Export table data as JSON array
        let query = format!("SELECT row_to_json(t) FROM {} t", table);
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(serde_json::Value::Array(rows))
    }

    /// Resolve the effective set of repository ids covered by a backup from its
    /// stored metadata (#2772).
    ///
    /// Reads the optional `repository_ids` (include) and `exclude_repository_ids`
    /// (exclude) lists and combines them via [`resolve_effective_repository_ids`].
    /// Returns `None` when no filtering applies (no include list and no
    /// exclusions), so full backups keep dumping every repository exactly as
    /// before. The complete repository set is only queried for the exclude-only
    /// case, where it is needed to compute "everything except the excluded ids".
    async fn effective_repository_filter(
        &self,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<Vec<Uuid>>> {
        let include_filter: Option<Vec<Uuid>> = metadata
            .and_then(|m| m.get("repository_ids"))
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let exclude_filter: Option<Vec<Uuid>> = metadata
            .and_then(|m| m.get("exclude_repository_ids"))
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let needs_all_repositories = include_filter.is_none()
            && exclude_filter
                .as_ref()
                .is_some_and(|ex: &Vec<Uuid>| !ex.is_empty());
        let all_repository_ids: Vec<Uuid> = if needs_all_repositories {
            sqlx::query_scalar("SELECT id FROM repositories")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            Vec::new()
        };

        Ok(resolve_effective_repository_ids(
            include_filter,
            exclude_filter,
            &all_repository_ids,
        ))
    }

    /// List the artifact storage keys to include in a backup, honoring the
    /// resolved repository filter (`None` => every repository) and the optional
    /// `since` cutoff (#2789; `None` => every modification time). Both
    /// predicates are null-guarded so passing `None`/`None` returns every
    /// artifact exactly as before.
    async fn artifact_storage_keys(
        &self,
        repository_filter: Option<&[Uuid]>,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<String>> {
        // Runtime (non-macro) query so no offline `.sqlx` prepare is needed and
        // both optional predicates live in a single statement.
        let repo_ids: Option<Vec<Uuid>> = repository_filter.map(|r| r.to_vec());
        let keys: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT storage_key FROM artifacts
            WHERE ($1::uuid[] IS NULL OR repository_id = ANY($1))
              AND ($2::timestamptz IS NULL OR updated_at >= $2)
            "#,
        )
        .bind(repo_ids)
        .bind(since)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(keys)
    }

    /// Export the `artifacts` table as a JSON array, honoring the resolved
    /// repository filter (#2772) and the optional `since` cutoff (#2789).
    ///
    /// When both filters are `None` this returns every artifact row, identical
    /// to `export_table("artifacts")`, so unfiltered backups are unchanged. A
    /// repository filter keeps only the covered repositories' rows; a `since`
    /// cutoff keeps only rows with `updated_at >= since`, so an incremental
    /// backup dumps just the metadata changed after the given timestamp.
    async fn export_artifacts(
        &self,
        repository_filter: Option<&[Uuid]>,
        since: Option<DateTime<Utc>>,
    ) -> Result<serde_json::Value> {
        // Runtime (non-macro) query so no offline `.sqlx` prepare is needed and
        // both optional predicates live in a single statement.
        let repo_ids: Option<Vec<Uuid>> = repository_filter.map(|r| r.to_vec());
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            r#"
            SELECT row_to_json(t) FROM artifacts t
            WHERE ($1::uuid[] IS NULL OR repository_id = ANY($1))
              AND ($2::timestamptz IS NULL OR updated_at >= $2)
            "#,
        )
        .bind(repo_ids)
        .bind(since)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(serde_json::Value::Array(rows))
    }

    async fn update_status(
        &self,
        backup_id: Uuid,
        status: BackupStatus,
        error_message: Option<&str>,
    ) -> Result<()> {
        let started_at = if status == BackupStatus::InProgress {
            Some(Utc::now())
        } else {
            None
        };

        let completed_at = if matches!(
            status,
            BackupStatus::Completed | BackupStatus::Failed | BackupStatus::Cancelled
        ) {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE backups
            SET
                status = $2,
                error_message = COALESCE($3, error_message),
                started_at = COALESCE($4, started_at),
                completed_at = COALESCE($5, completed_at)
            WHERE id = $1
            "#,
        )
        .bind(backup_id)
        .bind(status)
        .bind(error_message)
        .bind(started_at)
        .bind(completed_at)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Restore from a backup.
    ///
    /// Extracts all tar entries synchronously first (tar::Archive is !Send),
    /// then performs async database/storage restore operations.
    pub async fn restore(&self, backup_id: Uuid, options: RestoreOptions) -> Result<RestoreResult> {
        let backup = self.get_by_id(backup_id).await?;

        if backup.status != BackupStatus::Completed {
            return Err(AppError::Validation(
                "Can only restore from completed backups".to_string(),
            ));
        }

        // Download backup archive
        let storage_path = backup
            .storage_path
            .as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        // Read the archive back from the (optionally separate) backup bucket.
        let tar_data = self.archive_storage.get(storage_path).await?;

        // Phase 1: Extract all entries synchronously (tar::Archive is !Send)
        let entries = Self::extract_entries(&tar_data)?;

        // Phase 2: Async restore from extracted data
        let mut result = RestoreResult {
            tables_restored: Vec::new(),
            artifacts_restored: 0,
            errors: Vec::new(),
        };

        // An archive whose manifest records unreadable artifacts is known to be
        // missing content. Surface that as a restore error so the restore can
        // never report `errors=[]` over an incomplete archive (#3170). This is
        // the second half of the honesty guarantee: the backup fails loudly at
        // capture time, and if a partial archive was deliberately opted in to,
        // the restore still refuses to call it clean.
        if let Some(manifest) = Self::read_manifest(&entries) {
            if manifest.artifacts_unreadable > 0 {
                result.errors.push(format!(
                    "archive is incomplete: its manifest records {} artifact object(s) that were \
                     unreadable at backup time and are absent from this archive (backup {}). \
                     {} artifact object(s) were captured.",
                    manifest.artifacts_unreadable, manifest.backup_id, manifest.artifact_count
                ));
            }
        }

        // Restore database tables in dependency order
        if options.restore_database {
            let table_order = [
                "users",
                "roles",
                "user_roles",
                "repositories",
                "permission_grants",
                "artifacts",
                "download_statistics",
                "api_tokens",
            ];

            // Restore ordered tables first
            for table_name in &table_order {
                if let Some(content) = entries.iter().find(|(p, _)| {
                    p.starts_with("database/")
                        && p.file_stem().and_then(|s| s.to_str()) == Some(table_name)
                }) {
                    match self.restore_table(table_name, &content.1).await {
                        Ok(rows) => {
                            tracing::info!("Restored {} rows into table '{}'", rows, table_name);
                            result.tables_restored.push(table_name.to_string());
                        }
                        Err(e) => result
                            .errors
                            .push(format!("Failed to restore {}: {}", table_name, e)),
                    }
                }
            }

            // Restore any remaining database entries not in the ordered list
            for (path, content) in &entries {
                if !path.starts_with("database/") {
                    continue;
                }
                let table_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                if table_order.contains(&table_name) {
                    continue; // already restored above
                }
                match self.restore_table(table_name, content).await {
                    Ok(rows) => {
                        tracing::info!("Restored {} rows into table '{}'", rows, table_name);
                        result.tables_restored.push(table_name.to_string());
                    }
                    Err(e) => result
                        .errors
                        .push(format!("Failed to restore {}: {}", table_name, e)),
                }
            }
        }

        // Restore artifact files
        if options.restore_artifacts {
            for (path, content) in &entries {
                if !path.starts_with("artifacts/") {
                    continue;
                }
                let storage_key = path
                    .strip_prefix("artifacts/")
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                if storage_key.is_empty() {
                    continue;
                }

                match self
                    .storage
                    .put(&storage_key, Bytes::from(content.clone()))
                    .await
                {
                    Ok(_) => result.artifacts_restored += 1,
                    Err(e) => result
                        .errors
                        .push(format!("Failed to restore {}: {}", storage_key, e)),
                }
            }
        }

        Ok(result)
    }

    /// Parse `manifest.json` out of already-extracted archive entries.
    ///
    /// Returns `None` when the archive has no manifest or it does not parse —
    /// both are tolerated so a malformed manifest never blocks an otherwise
    /// usable restore. Archives written before #3170 simply report
    /// `artifacts_unreadable = 0` via the field's serde default.
    fn read_manifest(entries: &[(std::path::PathBuf, Vec<u8>)]) -> Option<BackupManifest> {
        entries
            .iter()
            .find(|(path, _)| path.file_name().and_then(|n| n.to_str()) == Some("manifest.json"))
            .and_then(|(_, content)| serde_json::from_slice::<BackupManifest>(content).ok())
    }

    /// Extract all entries from a tar.gz archive synchronously.
    /// Returns a Vec of (path, content) pairs so that async code can
    /// process them without holding the non-Send Archive across await points.
    fn extract_entries(tar_data: &[u8]) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let decoder = GzDecoder::new(tar_data);
        let mut archive = Archive::new(decoder);
        let mut entries = Vec::new();

        for entry in archive
            .entries()
            .map_err(|e| AppError::Internal(format!("Failed to read archive entries: {}", e)))?
        {
            let mut entry =
                entry.map_err(|e| AppError::Internal(format!("Failed to read entry: {}", e)))?;
            let path = entry
                .path()
                .map_err(|e| AppError::Internal(format!("Failed to read entry path: {}", e)))?
                .to_path_buf();

            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| AppError::Internal(format!("Failed to read entry data: {}", e)))?;

            entries.push((path, content));
        }

        Ok(entries)
    }

    /// Restore a single database table from JSON data.
    /// Uses jsonb_populate_record for proper type coercion.
    async fn restore_table(&self, table: &str, content: &[u8]) -> Result<usize> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(content)?;
        let mut restored = 0usize;

        // Validate table name to prevent SQL injection (only allow alphanumeric + underscore)
        if !table.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(AppError::Validation(format!(
                "Invalid table name: {}",
                table
            )));
        }

        for row in &rows {
            // Use jsonb_populate_record to let Postgres handle type coercion
            let query = format!(
                "INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1) ON CONFLICT DO NOTHING"
            );

            match sqlx::query(&query).bind(row).execute(&self.db).await {
                Ok(result) => {
                    restored += result.rows_affected() as usize;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to restore row in '{}': {} (row: {})",
                        table,
                        e,
                        serde_json::to_string(row).unwrap_or_default()
                    );
                }
            }
        }

        Ok(restored)
    }

    /// Delete a backup
    pub async fn delete(&self, backup_id: Uuid) -> Result<()> {
        let backup = self.get_by_id(backup_id).await?;

        // Delete the archive from the (optionally separate) backup bucket.
        if let Some(storage_path) = &backup.storage_path {
            if self.archive_storage.exists(storage_path).await? {
                self.archive_storage.delete(storage_path).await?;
            }
        }

        // Delete from database
        sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Cancel a running backup
    pub async fn cancel(&self, backup_id: Uuid) -> Result<()> {
        let backup = self.get_by_id(backup_id).await?;

        if backup.status != BackupStatus::InProgress && backup.status != BackupStatus::Pending {
            // A backup in a terminal state (completed/failed/cancelled) cannot be
            // cancelled. This is a state conflict, not a malformed request, so it
            // maps to HTTP 409 rather than 400. The executor for an empty backup
            // can finish before the cancel call lands, so callers (and the E2E
            // lifecycle test) must be able to distinguish "too late to cancel"
            // (409) from "bad input" (400).
            return Err(AppError::Conflict(format!(
                "Cannot cancel backup in '{}' state; only pending or in-progress backups can be cancelled",
                backup.status
            )));
        }

        self.update_status(backup_id, BackupStatus::Cancelled, None)
            .await?;

        Ok(())
    }

    /// Clean up old backups based on retention policy.
    ///
    /// Removes the backup archive from storage in addition to the database row.
    /// Selecting the eligible rows first (rather than issuing a bare `DELETE`)
    /// is deliberate: once the row is gone its `storage_path` — the only handle
    /// to the archive — is lost, so a row-only delete would strand the
    /// `.tar.gz` in object storage forever, the opposite of what a
    /// space-reclaiming retention job should do (#2787).
    pub async fn cleanup(&self, keep_count: i32, keep_days: i32) -> Result<u64> {
        // Keep the most recent N completed backups; among the rest, remove those
        // older than the retention window.
        let doomed: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, storage_path FROM backups
            WHERE id NOT IN (
                SELECT id FROM backups
                WHERE status = 'completed'
                ORDER BY created_at DESC
                LIMIT $1
            )
            AND created_at < NOW() - make_interval(days => $2)
            AND status = 'completed'
            "#,
        )
        .bind(keep_count as i64)
        .bind(keep_days)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut deleted = 0u64;
        for (id, storage_path) in doomed {
            // Best-effort delete the archive before dropping the row. If storage
            // removal fails, keep the row so a later retention run retries
            // rather than silently orphaning the archive.
            if let Some(path) = storage_path.as_deref() {
                match self.archive_storage.exists(path).await {
                    Ok(true) => {
                        if let Err(e) = self.archive_storage.delete(path).await {
                            tracing::warn!(
                                backup_id = %id,
                                storage_path = path,
                                "backup retention: failed to delete archive, retaining row for retry: {}",
                                e
                            );
                            continue;
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(
                            backup_id = %id,
                            storage_path = path,
                            "backup retention: failed to stat archive, retaining row for retry: {}",
                            e
                        );
                        continue;
                    }
                }
            }

            sqlx::query("DELETE FROM backups WHERE id = $1")
                .bind(id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            deleted += 1;
        }

        Ok(deleted)
    }
}

/// Options for restore operation
#[derive(Debug, Default)]
pub struct RestoreOptions {
    pub restore_database: bool,
    pub restore_artifacts: bool,
    pub target_repository_id: Option<Uuid>,
}

/// Result of restore operation
#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use chrono::Utc;
    #[allow(unused_imports)]
    use flate2::write::GzEncoder;
    #[allow(unused_imports)]
    use flate2::Compression;
    #[allow(unused_imports)]
    use tar::Builder;

    // -----------------------------------------------------------------------
    // Backup storage key / BACKUP_S3_PREFIX tests (#2508)
    // -----------------------------------------------------------------------

    #[test]
    fn backup_key_without_prefix_keeps_legacy_root() {
        // Existing deployments (no BACKUP_S3_PREFIX) must keep writing the
        // exact key shape they always have.
        assert_eq!(
            backup_storage_key(None, "backups/2026/07/20/abc.tar.gz"),
            "backups/2026/07/20/abc.tar.gz"
        );
    }

    #[test]
    fn backup_key_prepends_configured_prefix() {
        assert_eq!(
            backup_storage_key(Some("team-a/registry"), "backups/2026/07/20/abc.tar.gz"),
            "team-a/registry/backups/2026/07/20/abc.tar.gz"
        );
    }

    #[test]
    fn backup_prefix_is_normalized() {
        // Leading/trailing/duplicate slashes collapse.
        assert_eq!(
            normalize_backup_prefix("/team-a//registry/").as_deref(),
            Some("team-a/registry")
        );
        // Dot and traversal segments are dropped: the key is joined into a
        // filesystem path on the filesystem backend, so `..` must not survive.
        assert_eq!(
            normalize_backup_prefix("../escape/./x").as_deref(),
            Some("escape/x")
        );
    }

    #[test]
    fn empty_or_degenerate_prefix_behaves_like_unset() {
        for raw in ["", "/", "//", ".", "..", "././.."] {
            assert!(normalize_backup_prefix(raw).is_none(), "raw = {raw:?}");
            assert_eq!(
                backup_storage_key(Some(raw), "backups/x.tar.gz"),
                "backups/x.tar.gz",
                "raw = {raw:?}"
            );
        }
    }

    #[test]
    fn prefixed_backup_key_cannot_collide_with_repo_scoped_artifact_keys() {
        // #2624/#2728 artifact keys on shared cloud namespaces are
        // `{format}/{repository_uuid}/{path}`. Even with an adversarial
        // BACKUP_S3_PREFIX that mimics a format/repo segment, the backup key
        // always continues with the `backups/` root plus a fresh UUIDv4
        // archive name, so it can never equal a scoped artifact key for any
        // artifact path an existing repository has recorded.
        let repo = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
        let scoped = crate::storage::StorageKeyScheme::RepoScoped.write_key(
            "s3",
            "maven",
            repo,
            "backups/2026/07/20/abc.tar.gz",
        );
        let backup = backup_storage_key(
            Some(&format!("maven/{repo}")),
            &format!("backups/2026/07/20/{}.tar.gz", Uuid::new_v4()),
        );
        assert_ne!(scoped, backup);
        // The repo-scoped segment stays intact in artifact keys regardless of
        // any backup prefix configuration.
        assert!(scoped.starts_with(&format!("maven/{repo}/")));
    }

    // -----------------------------------------------------------------------
    // BackupStatus Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_display_pending() {
        assert_eq!(BackupStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn test_backup_status_display_in_progress() {
        assert_eq!(BackupStatus::InProgress.to_string(), "in_progress");
    }

    #[test]
    fn test_backup_status_display_completed() {
        assert_eq!(BackupStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn test_backup_status_display_failed() {
        assert_eq!(BackupStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_backup_status_display_cancelled() {
        assert_eq!(BackupStatus::Cancelled.to_string(), "cancelled");
    }

    // -----------------------------------------------------------------------
    // BackupStatus equality tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_equality() {
        assert_eq!(BackupStatus::Pending, BackupStatus::Pending);
        assert_ne!(BackupStatus::Pending, BackupStatus::InProgress);
        assert_ne!(BackupStatus::Completed, BackupStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // BackupType serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_type_serialization() {
        let full = serde_json::to_string(&BackupType::Full).unwrap();
        assert_eq!(full, "\"full\"");

        let incremental = serde_json::to_string(&BackupType::Incremental).unwrap();
        assert_eq!(incremental, "\"incremental\"");

        let metadata = serde_json::to_string(&BackupType::Metadata).unwrap();
        assert_eq!(metadata, "\"metadata\"");
    }

    #[test]
    fn test_backup_type_deserialization() {
        let full: BackupType = serde_json::from_str("\"full\"").unwrap();
        assert_eq!(full, BackupType::Full);

        let incremental: BackupType = serde_json::from_str("\"incremental\"").unwrap();
        assert_eq!(incremental, BackupType::Incremental);

        let metadata: BackupType = serde_json::from_str("\"metadata\"").unwrap();
        assert_eq!(metadata, BackupType::Metadata);
    }

    // -----------------------------------------------------------------------
    // BackupStatus serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_status_serialization() {
        assert_eq!(
            serde_json::to_string(&BackupStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&BackupStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn test_backup_status_deserialization() {
        let pending: BackupStatus = serde_json::from_str("\"pending\"").unwrap();
        assert_eq!(pending, BackupStatus::Pending);

        let completed: BackupStatus = serde_json::from_str("\"completed\"").unwrap();
        assert_eq!(completed, BackupStatus::Completed);
    }

    // -----------------------------------------------------------------------
    // BackupManifest serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_manifest_serialization_roundtrip() {
        let manifest = BackupManifest {
            version: "1.0".to_string(),
            backup_id: Uuid::nil(),
            backup_type: BackupType::Full,
            created_at: Utc::now(),
            database_tables: vec!["users".to_string(), "artifacts".to_string()],
            artifact_count: 42,
            artifacts_unreadable: 0,
            total_size_bytes: 1024 * 1024,
            checksum: "abc123".to_string(),
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, "1.0");
        assert_eq!(deserialized.backup_id, Uuid::nil());
        assert_eq!(deserialized.backup_type, BackupType::Full);
        assert_eq!(deserialized.database_tables.len(), 2);
        assert_eq!(deserialized.artifact_count, 42);
        assert_eq!(deserialized.artifacts_unreadable, 0);
        assert_eq!(deserialized.total_size_bytes, 1024 * 1024);
        assert_eq!(deserialized.checksum, "abc123");
    }

    // -----------------------------------------------------------------------
    // RestoreOptions tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_options_default() {
        let opts = RestoreOptions::default();
        assert!(!opts.restore_database);
        assert!(!opts.restore_artifacts);
        assert!(opts.target_repository_id.is_none());
    }

    // -----------------------------------------------------------------------
    // RestoreResult serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_restore_result_serialization() {
        let result = RestoreResult {
            tables_restored: vec!["users".to_string()],
            artifacts_restored: 5,
            errors: vec!["some error".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"tables_restored\":[\"users\"]"));
        assert!(json.contains("\"artifacts_restored\":5"));
        assert!(json.contains("\"errors\":[\"some error\"]"));
    }

    // -----------------------------------------------------------------------
    // count_artifacts_in_backup tests (via extract_entries + tar creation)
    // -----------------------------------------------------------------------

    /// Helper: create a tar.gz archive in memory with the given entries.
    fn create_test_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buffer = Vec::new();
        {
            let encoder = GzEncoder::new(&mut tar_buffer, Compression::default());
            let mut tar = Builder::new(encoder);

            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();
                tar.append_data(&mut header, path, *data).unwrap();
            }

            tar.into_inner().unwrap().finish().unwrap();
        }
        tar_buffer
    }

    #[test]
    fn test_extract_entries_empty_archive() {
        let tar_data = create_test_tar_gz(&[]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_extract_entries_with_entries() {
        let tar_data = create_test_tar_gz(&[
            ("manifest.json", b"{}"),
            ("database/users.json", b"[]"),
            ("artifacts/key1", b"binary data"),
        ]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 3);

        let paths: Vec<String> = entries
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert!(paths.contains(&"manifest.json".to_string()));
        assert!(paths.contains(&"database/users.json".to_string()));
        assert!(paths.contains(&"artifacts/key1".to_string()));
    }

    #[test]
    fn test_extract_entries_preserves_content() {
        let tar_data = create_test_tar_gz(&[("test.txt", b"hello world")]);
        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"hello world");
    }

    #[test]
    fn test_extract_entries_invalid_data() {
        let result = BackupService::extract_entries(b"not a tar gz");
        assert!(result.is_err());
    }

    /// Regression test for #758: paths longer than 100 characters caused
    /// `set_path` to fail with "provided value is too long". Using
    /// `append_data` writes GNU LongLink extensions for long paths.
    #[test]
    fn test_tar_long_path_roundtrip() {
        let long_key = "proxy-cache/maven-test/org/springframework/boot/\
            spring-boot-starter-parent/4.0.5/\
            spring-boot-starter-parent-4.0.5.pom";
        let long_path = format!("artifacts/{}", long_key);
        assert!(
            long_path.len() > 100,
            "test path must exceed the 100-char POSIX tar limit"
        );

        let content = b"<project>pom content</project>";
        let tar_data = create_test_tar_gz(&[(&long_path, content.as_slice())]);

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.to_string_lossy(), long_path);
        assert_eq!(entries[0].1, content);
    }

    // -----------------------------------------------------------------------
    // build_backup_tar tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_backup_tar_empty() {
        let manifest = b"{}";
        let tar_data = build_backup_tar(&[], &[], manifest).unwrap();

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        // Only the manifest entry
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.to_string_lossy(), "manifest.json");
        assert_eq!(entries[0].1, b"{}");
    }

    #[test]
    fn test_build_backup_tar_with_tables_and_artifacts() {
        let table_data = b"[{\"id\":1}]";
        let artifact_data = b"binary content here";
        let manifest = b"{\"version\":\"1.0\"}";

        let tar_data = build_backup_tar(
            &[("users", table_data.as_slice())],
            &[("repo/pkg-1.0.tar.gz", artifact_data.as_slice())],
            manifest,
        )
        .unwrap();

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 3);

        let paths: Vec<String> = entries
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert!(paths.contains(&"database/users.json".to_string()));
        assert!(paths.contains(&"artifacts/repo/pkg-1.0.tar.gz".to_string()));
        assert!(paths.contains(&"manifest.json".to_string()));

        // Verify content matches
        let users_entry = entries
            .iter()
            .find(|(p, _)| p.to_string_lossy() == "database/users.json")
            .unwrap();
        assert_eq!(users_entry.1, table_data);
    }

    #[test]
    fn test_build_backup_tar_with_long_artifact_paths() {
        let long_key = "proxy-cache/maven-central/org/springframework/boot/\
            spring-boot-starter-parent/4.0.5/\
            spring-boot-starter-parent-4.0.5.pom";
        let expected_path = format!("artifacts/{}", long_key);
        assert!(
            expected_path.len() > 100,
            "path must exceed 100-char POSIX limit"
        );

        let content = b"<project>long-path pom</project>";
        let manifest = b"{\"version\":\"1.0\"}";

        let tar_data = build_backup_tar(&[], &[(long_key, content.as_slice())], manifest).unwrap();

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        assert_eq!(entries.len(), 2); // artifact + manifest

        let artifact = entries
            .iter()
            .find(|(p, _)| p.starts_with("artifacts/"))
            .unwrap();
        assert_eq!(artifact.0.to_string_lossy(), expected_path);
        assert_eq!(artifact.1, content);
    }

    #[test]
    fn test_build_backup_tar_multiple_tables() {
        let manifest = b"{}";
        let tar_data = build_backup_tar(
            &[
                ("users", b"[]".as_slice()),
                ("roles", b"[]".as_slice()),
                ("artifacts", b"[{\"id\":1}]".as_slice()),
                ("repositories", b"[{\"name\":\"test\"}]".as_slice()),
            ],
            &[],
            manifest,
        )
        .unwrap();

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        // 4 tables + 1 manifest
        assert_eq!(entries.len(), 5);

        let db_entries: Vec<_> = entries
            .iter()
            .filter(|(p, _)| p.starts_with("database/"))
            .collect();
        assert_eq!(db_entries.len(), 4);
    }

    #[test]
    fn test_build_backup_tar_multiple_long_path_artifacts() {
        let keys: Vec<String> = (0..5)
            .map(|i| {
                format!(
                    "proxy-cache/maven/org/example/deeply/nested/package/name/\
                     artifact-with-very-long-classifier-{}/1.0.0/\
                     artifact-with-very-long-classifier-{}-1.0.0.jar",
                    i, i
                )
            })
            .collect();

        // Verify all paths exceed the 100-char limit
        for key in &keys {
            let full_path = format!("artifacts/{}", key);
            assert!(
                full_path.len() > 100,
                "expected path > 100 chars: {}",
                full_path
            );
        }

        let artifacts: Vec<(&str, &[u8])> = keys
            .iter()
            .map(|k| (k.as_str(), b"jar-content".as_slice()))
            .collect();
        let manifest = b"{}";

        let tar_data = build_backup_tar(&[], &artifacts, manifest).unwrap();

        let entries = BackupService::extract_entries(&tar_data).unwrap();
        // 5 artifacts + 1 manifest
        assert_eq!(entries.len(), 6);

        let artifact_entries: Vec<_> = entries
            .iter()
            .filter(|(p, _)| p.starts_with("artifacts/"))
            .collect();
        assert_eq!(artifact_entries.len(), 5);

        // Verify all content is preserved
        for (_, content) in &artifact_entries {
            assert_eq!(content.as_slice(), b"jar-content");
        }
    }

    // -----------------------------------------------------------------------
    // count_artifacts_in_tar tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_count_artifacts_in_tar_empty_archive() {
        let tar_data = create_test_tar_gz(&[]);
        assert_eq!(count_artifacts_in_tar(&tar_data).unwrap(), 0);
    }

    #[test]
    fn test_count_artifacts_in_tar_no_artifacts() {
        let tar_data =
            create_test_tar_gz(&[("manifest.json", b"{}"), ("database/users.json", b"[]")]);
        assert_eq!(count_artifacts_in_tar(&tar_data).unwrap(), 0);
    }

    #[test]
    fn test_count_artifacts_in_tar_with_artifacts() {
        let tar_data = create_test_tar_gz(&[
            ("manifest.json", b"{}"),
            ("database/users.json", b"[]"),
            ("artifacts/repo/pkg-1.0.tar.gz", b"data1"),
            ("artifacts/repo/pkg-2.0.tar.gz", b"data2"),
            ("artifacts/other/file.bin", b"data3"),
        ]);
        assert_eq!(count_artifacts_in_tar(&tar_data).unwrap(), 3);
    }

    #[test]
    fn test_count_artifacts_in_tar_with_long_paths() {
        let long_key = "proxy-cache/maven-central/org/springframework/boot/\
            spring-boot-starter-parent/4.0.5/\
            spring-boot-starter-parent-4.0.5.pom";
        let long_path = format!("artifacts/{}", long_key);
        assert!(long_path.len() > 100);

        let tar_data = create_test_tar_gz(&[
            ("manifest.json", b"{}"),
            (&long_path, b"pom-content"),
            ("artifacts/short-key", b"other"),
        ]);
        assert_eq!(count_artifacts_in_tar(&tar_data).unwrap(), 2);
    }

    #[test]
    fn test_count_artifacts_in_tar_invalid_data() {
        let result = count_artifacts_in_tar(b"not valid tar gz data");
        assert!(result.is_err());
    }

    #[test]
    fn test_count_artifacts_in_tar_from_build_backup_tar() {
        let manifest = b"{\"version\":\"1.0\"}";
        let tar_data = build_backup_tar(
            &[("users", b"[]".as_slice()), ("roles", b"[]".as_slice())],
            &[
                ("repo/artifact-1.jar", b"jar1".as_slice()),
                ("repo/artifact-2.jar", b"jar2".as_slice()),
                ("other/file.txt", b"txt".as_slice()),
            ],
            manifest,
        )
        .unwrap();

        // 3 artifacts should be counted (database entries and manifest excluded)
        assert_eq!(count_artifacts_in_tar(&tar_data).unwrap(), 3);
    }

    // -----------------------------------------------------------------------
    // CreateBackupRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_backup_request_construction() {
        let req = CreateBackupRequest {
            backup_type: BackupType::Full,
            repository_ids: Some(vec![Uuid::new_v4()]),
            exclude_repository_ids: None,
            since: None,
            created_by: Some(Uuid::new_v4()),
            name: None,
        };
        assert_eq!(req.backup_type, BackupType::Full);
        assert!(req.repository_ids.is_some());
        assert!(req.created_by.is_some());
        assert!(req.since.is_none());
    }

    #[test]
    fn test_create_backup_request_no_optional_fields() {
        let req = CreateBackupRequest {
            backup_type: BackupType::Metadata,
            repository_ids: None,
            exclude_repository_ids: None,
            since: None,
            created_by: None,
            name: None,
        };
        assert_eq!(req.backup_type, BackupType::Metadata);
        assert!(req.repository_ids.is_none());
        assert!(req.created_by.is_none());
    }

    #[test]
    fn test_create_backup_request_with_since_cutoff() {
        // #2789: an incremental "changes since" backup carries an RFC3339 cutoff.
        let cutoff = DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let req = CreateBackupRequest {
            backup_type: BackupType::Incremental,
            repository_ids: None,
            exclude_repository_ids: None,
            since: Some(cutoff),
            created_by: None,
            name: None,
        };
        assert_eq!(req.backup_type, BackupType::Incremental);
        assert_eq!(req.since, Some(cutoff));
    }

    // -----------------------------------------------------------------------
    // resolve_backup_filename tests (#2790)
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_backup_filename_default_preserves_uuid_name() {
        let id = Uuid::new_v4();
        let name = resolve_backup_filename(None, id).unwrap();
        // Default (no custom name) preserves the historical `{uuid}.tar.gz`.
        assert_eq!(name, format!("{}.tar.gz", id));
    }

    #[test]
    fn test_resolve_backup_filename_custom_name_honored() {
        let id = Uuid::new_v4();
        let name = resolve_backup_filename(Some("nightly-prod"), id).unwrap();
        assert!(
            name.starts_with("nightly-prod-"),
            "custom label should lead the filename: {name}"
        );
        assert!(name.ends_with(".tar.gz"), "must keep the extension: {name}");
        // A unique suffix is appended so distinct backups never collide.
        let suffix = id.simple().to_string();
        assert_eq!(name, format!("nightly-prod-{}.tar.gz", &suffix[..8]));
    }

    #[test]
    fn test_resolve_backup_filename_trims_whitespace() {
        let id = Uuid::new_v4();
        let name = resolve_backup_filename(Some("  release  "), id).unwrap();
        assert!(name.starts_with("release-"), "should be trimmed: {name}");
    }

    #[test]
    fn test_resolve_backup_filename_unique_per_id() {
        let a = resolve_backup_filename(Some("weekly"), Uuid::new_v4()).unwrap();
        let b = resolve_backup_filename(Some("weekly"), Uuid::new_v4()).unwrap();
        assert_ne!(a, b, "same label + different id must not collide");
    }

    #[test]
    fn test_resolve_backup_filename_rejects_path_separator() {
        let id = Uuid::new_v4();
        assert!(resolve_backup_filename(Some("a/b"), id).is_err());
        assert!(resolve_backup_filename(Some("a\\b"), id).is_err());
    }

    #[test]
    fn test_resolve_backup_filename_rejects_traversal() {
        let id = Uuid::new_v4();
        assert!(resolve_backup_filename(Some(".."), id).is_err());
        assert!(resolve_backup_filename(Some("../etc/passwd"), id).is_err());
        assert!(resolve_backup_filename(Some("."), id).is_err());
    }

    #[test]
    fn test_resolve_backup_filename_rejects_empty_and_blank() {
        let id = Uuid::new_v4();
        assert!(resolve_backup_filename(Some(""), id).is_err());
        assert!(resolve_backup_filename(Some("   "), id).is_err());
    }

    #[test]
    fn test_resolve_backup_filename_rejects_unsafe_chars() {
        let id = Uuid::new_v4();
        // Spaces, control chars, and shell/path metacharacters are rejected.
        assert!(resolve_backup_filename(Some("my backup"), id).is_err());
        assert!(resolve_backup_filename(Some("name;rm -rf"), id).is_err());
        assert!(resolve_backup_filename(Some("null\0byte"), id).is_err());
    }

    #[test]
    fn test_resolve_backup_filename_rejects_overlong() {
        let id = Uuid::new_v4();
        let long = "a".repeat(MAX_BACKUP_NAME_LEN + 1);
        assert!(resolve_backup_filename(Some(&long), id).is_err());
        let ok = "a".repeat(MAX_BACKUP_NAME_LEN);
        assert!(resolve_backup_filename(Some(&ok), id).is_ok());
    }

    // -----------------------------------------------------------------------
    // BackupType Copy/Clone tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_type_clone_and_copy() {
        let bt = BackupType::Full;
        let bt2 = bt; // Copy
        let bt3 = bt; // Clone
        assert_eq!(bt, bt2);
        assert_eq!(bt, bt3);
    }

    #[test]
    fn test_backup_status_clone_and_copy() {
        let bs = BackupStatus::Completed;
        let bs2 = bs; // Copy
        let bs3 = bs; // Clone
        assert_eq!(bs, bs2);
        assert_eq!(bs, bs3);
    }

    // -----------------------------------------------------------------------
    // export_table allowlist validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_export_table_allowed_tables() {
        for table in ALLOWED_EXPORT_TABLES {
            assert!(
                validate_export_table(table).is_ok(),
                "expected '{}' to be allowed",
                table
            );
        }
    }

    #[test]
    fn test_validate_export_table_rejects_unknown() {
        assert!(validate_export_table("admin_secrets").is_err());
    }

    #[test]
    fn test_validate_export_table_rejects_sql_injection() {
        assert!(validate_export_table("users; DROP TABLE users").is_err());
    }

    #[test]
    fn test_validate_export_table_rejects_empty() {
        assert!(validate_export_table("").is_err());
    }

    #[test]
    fn test_validate_export_table_case_sensitive() {
        // "Users" (capital) should not match "users"
        assert!(validate_export_table("Users").is_err());
    }

    /// Regression test for #736: the table is "download_statistics", not "download_stats".
    #[test]
    fn test_allowed_tables_uses_download_statistics() {
        assert!(
            ALLOWED_EXPORT_TABLES.contains(&"download_statistics"),
            "ALLOWED_EXPORT_TABLES must reference 'download_statistics' (the actual table name)"
        );
        assert!(
            !ALLOWED_EXPORT_TABLES.contains(&"download_stats"),
            "ALLOWED_EXPORT_TABLES must not reference 'download_stats' (incorrect table name)"
        );
    }

    /// Regression test for #742: the table is "permission_grants" (migration 002),
    /// not "repository_permissions" which does not exist in any migration.
    #[test]
    fn test_allowed_tables_uses_permission_grants() {
        assert!(
            ALLOWED_EXPORT_TABLES.contains(&"permission_grants"),
            "ALLOWED_EXPORT_TABLES must reference 'permission_grants' (the actual table name from migration 002)"
        );
        assert!(
            !ALLOWED_EXPORT_TABLES.contains(&"repository_permissions"),
            "ALLOWED_EXPORT_TABLES must not reference 'repository_permissions' (non-existent table)"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_effective_repository_ids tests (#2772 exclude repositories)
    // -----------------------------------------------------------------------

    /// Sort a repository-id vec so set comparisons are order-independent.
    fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
        v.sort();
        v
    }

    #[test]
    fn test_effective_repos_default_is_none() {
        // No include and no exclude: back up everything (None => no filter),
        // identical to pre-#2772 behavior.
        assert!(resolve_effective_repository_ids(None, None, &[]).is_none());
    }

    #[test]
    fn test_effective_repos_empty_exclude_is_noop() {
        // An empty exclude list must behave exactly like "no exclusions".
        let all = vec![Uuid::new_v4(), Uuid::new_v4()];
        assert!(resolve_effective_repository_ids(None, Some(vec![]), &all).is_none());

        let include = vec![all[0]];
        let out = resolve_effective_repository_ids(Some(include.clone()), Some(vec![]), &all);
        assert_eq!(out, Some(include));
    }

    #[test]
    fn test_effective_repos_include_only_passthrough() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let out = resolve_effective_repository_ids(Some(vec![a, b]), None, &[]);
        assert_eq!(out, Some(vec![a, b]));
    }

    #[test]
    fn test_effective_repos_exclude_only_removes_from_all() {
        let keep = Uuid::new_v4();
        let drop = Uuid::new_v4();
        let all = vec![keep, drop];
        let out = resolve_effective_repository_ids(None, Some(vec![drop]), &all);
        // The excluded repo is absent, the other repo is present.
        assert_eq!(out, Some(vec![keep]));
        let out = out.unwrap();
        assert!(!out.contains(&drop));
        assert!(out.contains(&keep));
    }

    #[test]
    fn test_effective_repos_include_minus_exclude() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        // Explicit include of {a,b,c}, exclude {b}: result is {a,c}.
        let out = resolve_effective_repository_ids(Some(vec![a, b, c]), Some(vec![b]), &[]);
        assert_eq!(sorted(out.unwrap()), sorted(vec![a, c]));
    }

    #[test]
    fn test_effective_repos_exclude_non_member_is_noop() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let stranger = Uuid::new_v4();
        // Excluding an id that is not in the include list changes nothing.
        let out = resolve_effective_repository_ids(Some(vec![a, b]), Some(vec![stranger]), &[]);
        assert_eq!(sorted(out.unwrap()), sorted(vec![a, b]));
    }

    #[test]
    fn test_effective_repos_exclude_all_yields_empty_set() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let all = vec![a, b];
        // Excluding every repository yields an explicit empty set (Some([]))
        // -> the `= ANY(empty)` query backs up no artifacts, NOT all of them.
        let out = resolve_effective_repository_ids(None, Some(all.clone()), &all);
        assert_eq!(out, Some(vec![]));
    }

    // -----------------------------------------------------------------------
    // parse_since_filter tests (#2789 incremental "changes since" cutoff)
    // -----------------------------------------------------------------------

    /// Build the same metadata JSON that `create()` persists for a backup.
    fn backup_metadata(since: Option<DateTime<Utc>>) -> serde_json::Value {
        serde_json::json!({
            "repository_ids": Option::<Vec<Uuid>>::None,
            "exclude_repository_ids": Option::<Vec<Uuid>>::None,
            "since": since,
            "name": Option::<String>::None,
        })
    }

    #[test]
    fn test_parse_since_absent_metadata_is_none() {
        // No metadata at all => no cutoff, back up every artifact (unchanged).
        assert!(parse_since_filter(None).is_none());
    }

    #[test]
    fn test_parse_since_unset_is_none() {
        // A backup created without `since` stores JSON null => no cutoff.
        let meta = backup_metadata(None);
        assert!(parse_since_filter(Some(&meta)).is_none());
    }

    #[test]
    fn test_parse_since_roundtrips_through_create_metadata() {
        // The cutoff persisted by create() is read back verbatim by do_backup.
        let cutoff = DateTime::parse_from_rfc3339("2026-01-15T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let meta = backup_metadata(Some(cutoff));
        assert_eq!(parse_since_filter(Some(&meta)), Some(cutoff));
    }

    #[test]
    fn test_parse_since_malformed_is_treated_as_none() {
        // A non-timestamp value must not fail the backup; it means "no cutoff".
        let meta = serde_json::json!({ "since": "not-a-timestamp" });
        assert!(parse_since_filter(Some(&meta)).is_none());
    }

    /// Verify every table in ALLOWED_EXPORT_TABLES is a known migration table.
    /// This prevents future mismatches by listing all valid tables.
    #[test]
    fn test_allowed_tables_are_all_known_migration_tables() {
        // Tables created by migrations (only those relevant to backup)
        let known_migration_tables: &[&str] = &[
            "users",
            "roles",
            "user_roles",
            "permission_grants",
            "role_assignments",
            "repositories",
            "artifacts",
            "artifact_metadata",
            "download_statistics",
            "audit_log",
            "api_tokens",
            "backups",
            "plugins",
            "webhooks",
            "permissions",
            "groups",
        ];

        for table in ALLOWED_EXPORT_TABLES {
            assert!(
                known_migration_tables.contains(table),
                "ALLOWED_EXPORT_TABLES entry '{}' is not a known migration table",
                table
            );
        }
    }

    // -----------------------------------------------------------------------
    // #2789: end-to-end "changes since" filtering against a real database.
    // Skips cleanly when `DATABASE_URL` is unset (the CI coverage job seeds
    // Postgres, so it is exercised there). Everything is scoped to a unique
    // repository id so parallel test processes never see each other's rows.
    // -----------------------------------------------------------------------

    /// Build a backup service backed by `pool` with a throwaway filesystem
    /// storage handle (the artifact-enumeration paths under test never read
    /// bytes, so the backend is only needed to satisfy the constructor).
    fn service_for(pool: PgPool) -> BackupService {
        use crate::services::storage_service::FilesystemBackend;
        let dir = std::env::temp_dir().join(format!("bk-since-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let backend = Arc::new(FilesystemBackend::new(dir));
        let storage = Arc::new(StorageService::new(backend));
        BackupService::new(pool, storage)
    }

    /// Insert an artifact row with an explicit `updated_at` and return its key.
    async fn insert_artifact_at(
        pool: &PgPool,
        repo_id: Uuid,
        label: &str,
        updated_at: DateTime<Utc>,
    ) -> String {
        let key = format!("since-test/{}-{}", label, Uuid::new_v4());
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (repository_id, path, name, size_bytes, checksum_sha256,
                 content_type, storage_key, updated_at)
            VALUES ($1, $2, $3, 10, $4, 'application/octet-stream', $5, $6)
            "#,
        )
        .bind(repo_id)
        .bind(format!("path/{}", key))
        .bind(label)
        .bind("0".repeat(64))
        .bind(&key)
        .bind(updated_at)
        .execute(pool)
        .await
        .expect("insert artifact");
        key
    }

    #[tokio::test]
    async fn test_since_filter_excludes_older_includes_newer_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "generic").await;

        let old_at = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let new_at = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let cutoff = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let old_key = insert_artifact_at(&pool, repo_id, "old", old_at).await;
        let new_key = insert_artifact_at(&pool, repo_id, "new", new_at).await;

        let service = service_for(pool.clone());
        let repo_filter = [repo_id];

        // With a `since` cutoff only the artifact modified after it is included.
        let keys = service
            .artifact_storage_keys(Some(&repo_filter), Some(cutoff))
            .await
            .expect("storage keys with since");
        assert_eq!(
            keys,
            vec![new_key.clone()],
            "since keeps only the newer key"
        );
        assert!(!keys.contains(&old_key), "older artifact is excluded");

        // The exported metadata rows honor the same cutoff.
        let exported = service
            .export_artifacts(Some(&repo_filter), Some(cutoff))
            .await
            .expect("export with since");
        let rows = exported.as_array().expect("array");
        assert_eq!(rows.len(), 1, "only the newer artifact row is exported");
        assert_eq!(rows[0]["storage_key"], serde_json::json!(new_key));

        // Boundary: an artifact modified exactly at the cutoff is included
        // (predicate is `updated_at >= since`).
        let edge_key = insert_artifact_at(&pool, repo_id, "edge", cutoff).await;
        let keys_edge = service
            .artifact_storage_keys(Some(&repo_filter), Some(cutoff))
            .await
            .expect("storage keys with since (edge)");
        assert!(
            keys_edge.contains(&edge_key),
            "artifact at exactly the cutoff is included"
        );

        // No cutoff (`None`) => every artifact in the repo, unchanged behavior.
        let keys_all = service
            .artifact_storage_keys(Some(&repo_filter), None)
            .await
            .expect("storage keys without since");
        assert_eq!(keys_all.len(), 3, "unset since includes every artifact");

        // Cleanup: dropping the repo cascades to its artifacts.
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // #3170: a backup that cannot read an artifact's bytes must not report a
    // clean success. Historically the collect loop was
    //
    //     if let Ok(content) = self.storage.get(&key).await { ... }
    //
    // so a failed read was discarded entirely: not counted, not logged, not in
    // the manifest, not in the job status. The job reported `completed` with
    // `artifact_count=0` and the restore reported `errors=[]` while restoring
    // nothing — an operator got no signal at any point that the archive held
    // no content. These tests assert on honesty (the miss is surfaced), not on
    // any particular storage-path resolution, so they keep passing after the
    // #2863 root-resolution fix lands.
    // -----------------------------------------------------------------------

    /// Build a backup service whose primary storage is an **empty** directory,
    /// so every artifact key enumerated from the database is unreadable. This
    /// is the in-process stand-in for the real-world condition in #3170/#3171:
    /// the row says the bytes exist, the handle the backup reads through
    /// cannot find them.
    fn service_with_empty_storage(pool: PgPool) -> (BackupService, std::path::PathBuf) {
        use crate::services::storage_service::FilesystemBackend;
        let dir = std::env::temp_dir().join(format!("bk-3170-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let backend = Arc::new(FilesystemBackend::new(dir.clone()));
        let storage = Arc::new(StorageService::new(backend));
        (BackupService::new(pool, storage), dir)
    }

    fn full_backup_of(repo_id: Uuid) -> CreateBackupRequest {
        CreateBackupRequest {
            backup_type: BackupType::Full,
            repository_ids: Some(vec![repo_id]),
            exclude_repository_ids: None,
            since: None,
            created_by: None,
            name: None,
        }
    }

    #[tokio::test]
    async fn backup_with_unreadable_artifact_bytes_does_not_report_success() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, repo_dir) = tdh::create_repo(&pool, "local", "generic").await;

        // One artifact row whose bytes are NOT present at the resolved root.
        let missing_key = insert_artifact_at(&pool, repo_id, "unreadable", Utc::now()).await;

        let (service, storage_dir) = service_with_empty_storage(pool.clone());
        let backup = service
            .create(full_backup_of(repo_id))
            .await
            .expect("create backup job");

        let result = service.execute(backup.id).await;

        // The core assertion: the job must NOT succeed while the archive is
        // missing artifact content.
        assert!(
            result.is_err(),
            "backup whose artifact bytes are unreadable must not report success"
        );

        let row = service
            .get_by_id(backup.id)
            .await
            .expect("reload backup row");
        assert_ne!(
            row.status,
            BackupStatus::Completed,
            "a backup missing artifact content must not present as completed"
        );
        let message = row.error_message.unwrap_or_default();
        assert!(
            message.contains(&missing_key),
            "the unreadable key must be named in the job error; got {message:?}"
        );

        // A failed backup is not restorable, so the missing bytes can never be
        // silently "restored" as a clean run.
        let restore = service
            .restore(
                backup.id,
                RestoreOptions {
                    restore_database: false,
                    restore_artifacts: true,
                    target_repository_id: None,
                },
            )
            .await;
        assert!(
            restore.is_err(),
            "restore must refuse an archive whose backup did not complete cleanly"
        );

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&repo_dir);
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[tokio::test]
    async fn opt_in_partial_backup_records_misses_and_restore_refuses_them() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, repo_dir) = tdh::create_repo(&pool, "local", "generic").await;
        let missing_key = insert_artifact_at(&pool, repo_id, "unreadable", Utc::now()).await;

        let (service, storage_dir) = service_with_empty_storage(pool.clone());
        let backup = service
            .create(full_backup_of(repo_id))
            .await
            .expect("create backup job");

        // Operators who genuinely want a best-effort archive opt in explicitly.
        sqlx::query("UPDATE backups SET metadata = metadata || $2::jsonb WHERE id = $1")
            .bind(backup.id)
            .bind(serde_json::json!({ "allow_partial_artifacts": true }))
            .execute(&pool)
            .await
            .expect("set allow_partial_artifacts");

        service
            .execute(backup.id)
            .await
            .expect("opt-in partial backup completes");

        let row = service
            .get_by_id(backup.id)
            .await
            .expect("reload backup row");
        assert_eq!(
            row.status,
            BackupStatus::Completed,
            "an explicitly opted-in partial backup may complete"
        );

        // ...but the archive must record the miss so it can be audited without
        // re-running, and so the restore path can refuse it.
        let manifest = read_manifest_from_backup(&service, &row).await;
        assert_eq!(
            manifest.artifacts_unreadable, 1,
            "the manifest must record the unreadable artifact"
        );
        assert_eq!(
            manifest.artifact_count, 0,
            "the unreadable artifact must not be counted as captured"
        );

        let restore = service
            .restore(
                backup.id,
                RestoreOptions {
                    restore_database: false,
                    restore_artifacts: true,
                    target_repository_id: None,
                },
            )
            .await
            .expect("restore of a partial archive runs");
        assert!(
            restore
                .errors
                .iter()
                .any(|e| e.contains("unreadable") || e.contains(&missing_key)),
            "restore must not report errors=[] for an archive with recorded misses; got {:?}",
            restore.errors
        );

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&repo_dir);
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// Pull `backup/manifest.json` back out of a written archive.
    async fn read_manifest_from_backup(service: &BackupService, row: &Backup) -> BackupManifest {
        let path = row.storage_path.as_ref().expect("archive path");
        let bytes = service
            .archive_storage
            .get(path)
            .await
            .expect("archive readable");
        let entries = BackupService::extract_entries(&bytes).expect("extract archive");
        let (_, content) = entries
            .iter()
            .find(|(p, _)| p.to_string_lossy().contains("manifest.json"))
            .expect("archive contains a manifest");
        serde_json::from_slice(content).expect("manifest parses")
    }

    #[test]
    fn manifest_without_unreadable_field_defaults_to_zero() {
        // Archives written before #3170 have no `artifacts_unreadable` key;
        // they must still deserialize (as 0) so old backups stay auditable.
        let legacy = serde_json::json!({
            "version": "1.0",
            "backup_id": Uuid::nil(),
            "backup_type": "full",
            "created_at": "2026-01-01T00:00:00Z",
            "database_tables": ["users"],
            "artifact_count": 3,
            "total_size_bytes": 0,
            "checksum": ""
        });
        let manifest: BackupManifest =
            serde_json::from_value(legacy).expect("legacy manifest deserializes");
        assert_eq!(manifest.artifacts_unreadable, 0);
        assert_eq!(manifest.artifact_count, 3);
    }
}
