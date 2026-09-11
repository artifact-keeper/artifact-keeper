//! Backup and restore service.
//!
//! Handles full and incremental backups of the registry data and artifacts.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::io::Read;
use std::sync::Arc;
use tar::{Archive, Builder};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::metrics_service;
use crate::services::storage_service::StorageService;
use crate::util::bounded_archive;

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
    /// SHA-256 over the archive's payload entries, recorded at capture time
    /// and verified before any row of a restore is ingested (#3373).
    ///
    /// The anchor lives here, on the row, and not only in the archive's own
    /// manifest: an expected digest that travels inside the file it
    /// authenticates can be rewritten by whoever rewrote the file. `NULL`
    /// means the archive predates this column, in which case the restore falls
    /// back to the manifest's own checksum and refuses outright if there is
    /// none — see [`verify_archive_integrity`].
    pub payload_checksum: Option<String>,
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

/// The outcome of a backup run that actually executed.
///
/// A run that reaches a terminal state — including a FAILED one — is a fact
/// about the *backup*, recorded on the backup row as `status` plus
/// `error_message`. It is not a fact about the request that triggered it.
/// [`BackupService::execute_run`] therefore returns `Ok` for a failed run and
/// reports the failure in [`failure`](Self::failure), so a synchronous trigger
/// can answer with the backup resource (carrying `status = failed` and the
/// message naming what went wrong) instead of collapsing the run's outcome
/// into a transport-level error whose body discards it (#3327).
///
/// `failure` is `None` only for a run that completed with every enumerated
/// artifact's bytes captured; it is `Some` with the exact message persisted to
/// `backups.error_message` otherwise. Callers that want the historical
/// "a failed run is an `Err`" shape — the scheduler does, because a failed
/// occurrence must mark its `backup_schedule_runs` row failed — keep using
/// [`BackupService::execute`], which is a thin wrapper over this.
#[derive(Debug)]
pub struct BackupRun {
    /// The backup row as persisted after the run, i.e. with its terminal
    /// `status` and, for a failed run, its `error_message`.
    pub backup: Backup,
    /// `Some(message)` when the run reached a terminal FAILED state; the
    /// message is the same one written to `backups.error_message`.
    pub failure: Option<String>,
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

/// Tables restored by [`BackupService::restore`], in dependency order.
///
/// This MUST stay in sync with [`ALLOWED_EXPORT_TABLES`]: restore rejects any
/// table outside the allowlist (GHSA-95fx-g94v-8jqg, enforced in
/// `restore_table`), so an allowlisted table missing here would silently never
/// be restored. `test_restore_table_order_covers_allowlist` pins the
/// invariant.
const RESTORE_TABLE_ORDER: &[&str] = &[
    "users",
    "roles",
    "user_roles",
    "repositories",
    "permission_grants",
    "artifacts",
    "download_statistics",
    "api_tokens",
];

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

/// Reject backup requests whose declared type the archive would not honor
/// (#3011): an `Incremental` backup without a `since` anchor would produce a
/// byte-identical full archive while reporting itself incremental. Until the
/// incremental epic (#2788) gives it a stored anchor of its own, the anchor
/// must be explicit.
fn validate_backup_request(backup_type: BackupType, since: Option<DateTime<Utc>>) -> Result<()> {
    if backup_type == BackupType::Incremental && since.is_none() {
        return Err(AppError::Validation(
            "An incremental backup requires 'since': without a cutoff it would capture a full \
             archive while reporting itself incremental. Pass 'since' or request a full backup."
                .to_string(),
        ));
    }
    Ok(())
}

/// Whether archives of this backup type carry artifact BYTES (#3011).
///
/// A `Metadata` backup captures the database dump (including artifact rows)
/// and the manifest, but no artifact content — that is the distinction the
/// API advertises, so `do_backup` must actually honor it.
fn backup_includes_artifact_bytes(backup_type: BackupType) -> bool {
    match backup_type {
        BackupType::Full | BackupType::Incremental => true,
        BackupType::Metadata => false,
    }
}

/// Compute the manifest's integrity pair — total payload bytes and a SHA-256
/// over every payload entry (name and content, in archive order) — from the
/// same `(name, bytes)` pairs the tar is built from (#3011).
///
/// The digest covers entry names and lengths as well as content so a renamed
/// or reordered entry cannot collide with a clean archive.
fn payload_summary<'a>(entries: impl Iterator<Item = (&'a str, &'a [u8])>) -> (i64, String) {
    let mut hasher = Sha256::new();
    let mut total_size_bytes: i64 = 0;
    for (name, bytes) in entries {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        total_size_bytes += bytes.len() as i64;
    }
    (total_size_bytes, format!("{:x}", hasher.finalize()))
}

/// Map extracted archive entries back to the `(name, bytes)` payload pairs
/// [`payload_summary`] hashed at backup time: `database/<t>.json` contributes
/// its table name, `artifacts/<key>` its storage key; `manifest.json` (and
/// anything unrecognized) is not payload. Entry order is tar order, which is
/// the order the backup hashed them in.
fn archive_payload_entries(entries: &[(std::path::PathBuf, Vec<u8>)]) -> Vec<(String, &[u8])> {
    entries
        .iter()
        .filter_map(|(path, content)| {
            if path.starts_with("database/") {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|table| (table.to_string(), content.as_slice()))
            } else if path.starts_with("artifacts/") {
                path.strip_prefix("artifacts/")
                    .ok()
                    .map(|key| (key.to_string_lossy().to_string(), content.as_slice()))
            } else {
                None
            }
        })
        .collect()
}

/// Ceiling on decompressed bytes relative to the archive's compressed size
/// (#3373).
///
/// A backup archive is mostly artifact bytes, which are usually already
/// compressed, plus JSON table dumps, which compress at roughly 10:1. A factor
/// of 100 leaves an order of magnitude of headroom over the worst legitimate
/// case while still refusing the ~1000:1 expansion a zero-filled bomb needs.
/// Expressing the ceiling as a ratio rather than an absolute means a large
/// instance's genuinely large backup is not penalised: its budget grows with
/// it, while a small archive claiming to expand to gigabytes does not get one.
const MAX_DECOMPRESSION_RATIO: u64 = 100;

/// Floor under the decompressed-bytes ceiling (#3373).
///
/// The ratio alone would give a very small archive a very small budget, which
/// would refuse a legitimate metadata-only backup of a small instance. 32 MiB
/// is comfortably above that and far below anything that threatens the process.
const MIN_DECOMPRESSED_BYTES: u64 = 32 * 1024 * 1024;

/// Absolute stop on the number of entries a restore will decompress (#3373).
///
/// Belt and braces next to the byte budget: entry headers are themselves bytes
/// off the budget, so an entry swarm already costs, but a hard count keeps the
/// `Vec` of paths bounded regardless of how the byte budget was derived.
const MAX_ARCHIVE_ENTRIES: usize = 1_000_000;

/// Hard ceiling on decompressed bytes, whatever the ratio arm computes (#3373).
///
/// [`MAX_DECOMPRESSION_RATIO`] alone makes the budget a function of a length the
/// archive itself controls: `size_bytes` is checked first, but gzip tolerates
/// arbitrary trailing bytes, so a tamperer can pad an archive to exactly the
/// recorded length and buy the matching budget. At 100x, a 2 GiB backup would
/// hand out 200 GiB.
///
/// 8 GiB is a ceiling on what this restore path can do *at all* rather than a
/// policy about backup size: `do_restore` holds the compressed archive and every
/// decompressed entry in memory simultaneously (`tar::Archive` is `!Send`, so
/// the async restore cannot hold it across an await), so an archive that
/// genuinely expands past this could not be restored on any realistic host
/// regardless of this constant. Restoring archives larger than this needs a
/// streaming restore, not a bigger number.
const MAX_DECOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Bounds applied while decompressing a restore archive (#3373).
///
/// Carried as a value rather than read from constants inside the extractor so
/// the bomb behaviour is testable at kilobyte scale instead of gigabyte scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
}

impl ExtractLimits {
    /// Bounds for an archive of `compressed_len` compressed bytes:
    /// `clamp(compressed_len * RATIO, MIN_DECOMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES)`.
    ///
    /// The floor keeps a small legitimate backup from being refused for being
    /// small; the ratio keeps a large one from being refused for being large;
    /// the absolute ceiling keeps the budget from being a function of a length
    /// the archive controls. See each constant for why.
    pub fn for_archive(compressed_len: usize) -> Self {
        let ratio_budget = (compressed_len as u64).saturating_mul(MAX_DECOMPRESSION_RATIO);
        Self {
            max_entries: MAX_ARCHIVE_ENTRIES,
            max_total_bytes: ratio_budget.clamp(MIN_DECOMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES),
        }
    }
}

/// Refuse an archive entry whose path is not a plain relative path (#3373).
///
/// `do_restore` maps an `artifacts/<key>` entry straight to a storage key, so
/// the path in the archive chooses where the bytes land, and what that means
/// depends entirely on the configured backend:
///
/// * filesystem — `FilesystemBackend::key_to_path` drops `..` and root
///   components, so the write lands sanitised inside the storage root;
/// * S3 — `object_store`'s `PathPart` percent-encodes `.` and `..`, so the
///   segments stay literal;
/// * GCS — the key goes through `urlencoding::encode`;
/// * **Azure — `blob_url` interpolates the raw key into the blob URL with no
///   encoding at all (`storage/azure.rs`), and URL parsing removes dot
///   segments, so `../../other-container/x` resolves out of the configured
///   container.** On that backend a traversal entry is a cross-container write,
///   not a theoretical one.
///
/// Refusing the shape here covers every consumer of the entries at once and
/// stops the guarantee depending on which backend a deployment happens to run.
/// Nothing is lost: `tar::Builder` refuses to write a `..` path, so no archive
/// this product has ever produced contains one.
fn reject_unsafe_entry_path(path: &std::path::Path) -> Result<()> {
    use std::path::Component;
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::Validation(format!(
                    "archive rejected: entry path {:?} is not a plain relative path; a backup \
                     archive this product wrote never contains one",
                    path
                )));
            }
        }
    }
    Ok(())
}

/// The refusal an archive gets for busting its decompression budget (#3373).
fn bomb_error(limits: &ExtractLimits, compressed_len: usize) -> AppError {
    AppError::Validation(format!(
        "archive rejected: decompressing it exceeds the {} byte limit for an archive of {} \
         compressed bytes, which is the shape of a decompression bomb",
        limits.max_total_bytes, compressed_len
    ))
}

/// Which anchor established an archive's integrity (#3373).
///
/// Recorded on the restore's audit event so an operator can tell a restore that
/// was checked against the server's own record from one that was only checked
/// against the archive's own manifest — or not checked at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityAnchor {
    /// Verified against `backups.payload_checksum`, recorded at capture time
    /// and unreachable from the archive. This is the strong case.
    Recorded,
    /// Verified against the checksum inside the archive's own manifest. Detects
    /// corruption; a tamperer who rewrote the payload could have rewritten this
    /// too. Applies only to archives captured before `payload_checksum` existed.
    Manifest,
    /// Not verified at all — no recorded digest and no manifest checksum. Only
    /// reachable when the caller explicitly opted in.
    Waived,
}

impl std::fmt::Display for IntegrityAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityAnchor::Recorded => write!(f, "recorded"),
            IntegrityAnchor::Manifest => write!(f, "manifest"),
            IntegrityAnchor::Waived => write!(f, "waived"),
        }
    }
}

/// Establish that extracted archive entries are the ones this backup captured,
/// before a single row of them is ingested (#3373).
///
/// The archive is the untrusted input here — restore itself sits behind
/// `admin_middleware`, so the caller is already an admin; what is being
/// defended against is an archive tampered with at rest, or fetched back from
/// compromised or third-party storage. An expected digest that travels *inside*
/// that archive cannot serve as the check, which is exactly how the previous
/// version failed: it skipped verification whenever `manifest.checksum` was
/// empty, so blanking one JSON field disabled the control.
///
/// The anchors, in order of strength:
///
/// 1. `recorded_checksum` — `backups.payload_checksum`, written by `do_backup`
///    when the archive was captured. `restore` resolves its archive through a
///    `backups` row (there is no path that ingests a foreign archive), so this
///    column is always available for anything captured since #3373 and is not
///    reachable from the archive bytes.
/// 2. The manifest's own `checksum`, for archives captured before that column
///    existed. Detects corruption, not tampering — reported as such.
/// 3. Nothing. Refused, unless `allow_unverified` was explicitly set by the
///    caller; that is an affirmative operator decision, recorded on the audit
///    event, and it cannot be arranged by editing the archive.
///
/// A mismatch is always an error, even under `allow_unverified`: the opt-in
/// says "I accept an archive whose integrity cannot be established", not "I
/// accept one that is provably not the archive that was captured".
fn verify_archive_integrity(
    recorded_checksum: Option<&str>,
    manifest: Option<&BackupManifest>,
    entries: &[(std::path::PathBuf, Vec<u8>)],
    allow_unverified: bool,
) -> std::result::Result<IntegrityAnchor, String> {
    let recorded = recorded_checksum.map(str::trim).filter(|c| !c.is_empty());
    let from_manifest = manifest
        .map(|m| m.checksum.trim())
        .filter(|c| !c.is_empty());

    let (expected, anchor) = match (recorded, from_manifest) {
        (Some(expected), _) => (expected, IntegrityAnchor::Recorded),
        (None, Some(expected)) => (expected, IntegrityAnchor::Manifest),
        (None, None) => {
            if allow_unverified {
                return Ok(IntegrityAnchor::Waived);
            }
            return Err(
                "archive integrity cannot be established: this backup has no recorded payload \
                 checksum and the archive's manifest carries none either, so there is nothing to \
                 check the contents against. That is the expected state for an archive captured \
                 before this release -- but it is also what a tampered archive looks like, \
                 because blanking the manifest checksum or removing manifest.json is how an \
                 attacker turns this check off. A restore is a privileged operation and the \
                 archive is privileged material; prefer re-running the backup to capture one \
                 with a recorded checksum. Only if you can vouch for this archive's provenance, \
                 repeat the request with allow_unverified_archive=true to accept an unverifiable \
                 archive deliberately."
                    .to_string(),
            );
        }
    };

    let payload = archive_payload_entries(entries);
    let (_, actual) = payload_summary(payload.iter().map(|(n, b)| (n.as_str(), *b)));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "archive integrity check failed: the {} payload checksum for this backup is {} but \
             the archive's contents hash to {}; refusing to restore from an archive that is not \
             the one that was captured",
            anchor, expected, actual
        ));
    }
    Ok(anchor)
}

/// Fail the in-flight backup if its durable claim was lost (#3084).
///
/// Checked between chunks of work — table exports, artifact reads, the final
/// archive write — so a worker whose `backup_schedule_runs` claim another
/// replica reclaimed (renewal failure under a DB partition, expired TTL)
/// aborts instead of writing a second archive for the same occurrence.
fn ensure_backup_not_cancelled(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        return Err(AppError::Internal(
            "backup aborted: its run claim was lost, so another replica may own this occurrence"
                .to_string(),
        ));
    }
    Ok(())
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
        validate_backup_request(req.backup_type, req.since)?;
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
                metadata, created_by, created_at, payload_checksum
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
                metadata, created_by, created_at, payload_checksum
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
                metadata, created_by, created_at, payload_checksum
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

    /// Execute a backup, treating a failed run as an `Err`.
    ///
    /// Kept for callers whose own bookkeeping keys off the `Result` — the
    /// scheduler marks its `backup_schedule_runs` occurrence failed from this
    /// `Err` — so their behavior is byte-for-byte unchanged. Callers that need
    /// to report the run's outcome rather than react to it use
    /// [`execute_run`](Self::execute_run).
    pub async fn execute(&self, backup_id: Uuid) -> Result<Backup> {
        self.execute_cancellable(backup_id, CancellationToken::new())
            .await
    }

    /// [`execute`](Self::execute) with an external cancellation boundary: the
    /// scheduler passes the token wired to its run-claim renewal loop so a
    /// lost claim aborts the in-flight archive between chunks (#3084). A
    /// fresh, never-cancelled token makes this identical to `execute`.
    pub async fn execute_cancellable(
        &self,
        backup_id: Uuid,
        cancel: CancellationToken,
    ) -> Result<Backup> {
        let run = self.execute_run_cancellable(backup_id, cancel).await?;
        match run.failure {
            Some(message) => Err(AppError::Internal(message)),
            None => Ok(run.backup),
        }
    }

    /// Execute a backup and report how the run ended.
    ///
    /// Returns `Ok` for any run that actually executed, including one that
    /// FAILED — the failure is carried in [`BackupRun::failure`] and is already
    /// persisted on the backup row as `status = failed` plus `error_message`
    /// (#3327). `Err` is reserved for the cases where there is no run outcome
    /// to report: another backup is already in progress, the backup does not
    /// exist, or the status bookkeeping itself could not be written.
    pub async fn execute_run(&self, backup_id: Uuid) -> Result<BackupRun> {
        self.execute_run_cancellable(backup_id, CancellationToken::new())
            .await
    }

    /// [`execute_run`](Self::execute_run) with an external cancellation
    /// boundary — see [`execute_cancellable`](Self::execute_cancellable).
    pub async fn execute_run_cancellable(
        &self,
        backup_id: Uuid,
        cancel: CancellationToken,
    ) -> Result<BackupRun> {
        // Read the row up front so audit events and metrics can name the
        // backup's type and creator even when the run itself fails (#3011).
        let pending = self.get_by_id(backup_id).await?;
        let backup_type_str = format!("{:?}", pending.backup_type).to_lowercase();

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

        self.log_audit(
            AuditEntry::new(AuditAction::BackupStarted, ResourceType::Backup)
                .resource(backup_id)
                .details(serde_json::json!({ "backup_type": backup_type_str })),
            pending.created_by,
        )
        .await;

        let started = std::time::Instant::now();
        let result = self.do_backup(backup_id, &cancel).await;
        metrics_service::record_backup(
            &backup_type_str,
            result.is_ok(),
            started.elapsed().as_secs_f64(),
        );

        // Clear active backup
        {
            let mut active = self.active_backup.lock().await;
            *active = None;
        }

        match result {
            Ok(backup) => {
                self.update_status(backup_id, BackupStatus::Completed, None)
                    .await?;
                self.log_audit(
                    AuditEntry::new(AuditAction::BackupCompleted, ResourceType::Backup)
                        .resource(backup_id)
                        .details(serde_json::json!({
                            "backup_type": backup_type_str,
                            "size_bytes": backup.size_bytes,
                            "artifact_count": backup.artifact_count,
                        })),
                    pending.created_by,
                )
                .await;
                // Re-read for the same reason the failed arm does: `do_backup`
                // loaded the row while it was still `in_progress`, so returning
                // it unchanged would answer a caller that has just been told to
                // trust `status` with a status that is no longer true. Falls
                // back to the pre-read row if the re-read fails — the run did
                // complete, and that is not worth failing the call over.
                let backup = self.get_by_id(backup_id).await.unwrap_or(backup);
                Ok(BackupRun {
                    backup,
                    failure: None,
                })
            }
            Err(e) => {
                let message = e.to_string();
                self.update_status(backup_id, BackupStatus::Failed, Some(&message))
                    .await?;
                self.log_audit(
                    AuditEntry::new(AuditAction::BackupFailed, ResourceType::Backup)
                        .resource(backup_id)
                        .details(serde_json::json!({
                            "backup_type": backup_type_str,
                            "error": message,
                        })),
                    pending.created_by,
                )
                .await;
                // Re-read so the caller receives the row exactly as persisted
                // (`status = failed`, `error_message` set). If even that read
                // fails there is no recorded outcome to report, so the original
                // error propagates rather than being invented.
                match self.get_by_id(backup_id).await {
                    Ok(backup) => Ok(BackupRun {
                        backup,
                        failure: Some(message),
                    }),
                    Err(_) => Err(e),
                }
            }
        }
    }

    /// Best-effort audit write for backup/restore lifecycle events (#3011).
    ///
    /// Backup and restore are among the highest-privilege operations in the
    /// product, so every run leaves `BACKUP_*` / `RESTORE_*` entries in the
    /// audit trail. Audit failure never fails the operation itself — the run's
    /// own durable bookkeeping (the `backups` row) is the source of truth.
    async fn log_audit(&self, entry: AuditEntry, actor: Option<Uuid>) {
        let entry = match actor {
            Some(user_id) => entry.user(user_id),
            None => entry,
        };
        if let Err(e) = AuditService::new(self.db.clone()).log(entry).await {
            tracing::warn!(error = %e, "failed to write backup audit event");
        }
    }

    async fn do_backup(&self, backup_id: Uuid, cancel: &CancellationToken) -> Result<Backup> {
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
            ensure_backup_not_cancelled(cancel)?;
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

        // Fetch artifact storage keys and content. A metadata backup carries
        // no artifact bytes — that is the advertised distinction between the
        // types, so it must be honored rather than silently producing a full
        // archive (#3011).
        let storage_keys = if backup_includes_artifact_bytes(backup.backup_type) {
            self.artifact_storage_keys(repository_filter.as_deref(), since_filter)
                .await?
        } else {
            Vec::new()
        };
        // Read each artifact's bytes, tracking failures rather than discarding
        // them (#3170). A read that fails means the archive will not contain
        // that artifact's content; that must never be invisible.
        let mut artifact_data: Vec<(String, Vec<u8>)> = Vec::new();
        let mut unreadable: Vec<(String, String)> = Vec::new();
        for key in storage_keys {
            ensure_backup_not_cancelled(cancel)?;
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

        let tables_ref: Vec<(&str, &[u8])> = table_data
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect();
        let artifacts_ref: Vec<(&str, &[u8])> = artifact_data
            .iter()
            .map(|(key, data)| (key.as_str(), data.as_slice()))
            .collect();

        // Build manifest. Both counts are recorded so an archive can be audited
        // after the fact without re-running the backup (#3170), and the payload
        // size/checksum give the archive an integrity value the restore path
        // verifies (#3011).
        let (total_size_bytes, checksum) = payload_summary(
            tables_ref
                .iter()
                .copied()
                .chain(artifacts_ref.iter().copied()),
        );
        let manifest = BackupManifest {
            version: "1.0".to_string(),
            backup_id,
            backup_type: backup.backup_type,
            created_at: Utc::now(),
            database_tables: table_names.iter().map(|s| s.to_string()).collect(),
            artifact_count: artifact_data.len() as i64,
            artifacts_unreadable: unreadable.len() as i64,
            total_size_bytes,
            checksum,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

        // Build tar.gz archive using append_data (supports paths > 100 chars)
        let tar_buffer = build_backup_tar(&tables_ref, &artifacts_ref, &manifest_bytes)?;

        // A claim lost while chunks were being gathered must abort BEFORE the
        // externally visible side effect — the archive write — not after (#3084).
        ensure_backup_not_cancelled(cancel)?;

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

        // Update backup record. `payload_checksum` records the manifest's
        // digest on the ROW as well, which is what gives the restore path an
        // expected value that lives outside the archive it authenticates
        // (#3373): a tamperer who rewrites the archive — including its
        // manifest — cannot reach this column. `size_bytes` is the archive's
        // own length and is checked the same way, before a byte is
        // decompressed.
        let artifact_count = count_artifacts_in_tar(&tar_buffer)?;
        sqlx::query(
            r#"
            UPDATE backups
            SET size_bytes = $2, artifact_count = $3, payload_checksum = $4,
                completed_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(backup_id)
        .bind(tar_buffer.len() as i64)
        .bind(artifact_count)
        .bind(&manifest.checksum)
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
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(&*query))
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

        // `target_repository_id` has never been read by anything (#3373): a
        // caller who scoped a restore to one repository got a full global
        // ingest of the identity tables and a 200. Silently ignoring a
        // parameter is worse than not offering it, so it is refused until it
        // means something.
        if options.target_repository_id.is_some() {
            return Err(AppError::Validation(
                "target_repository_id is not supported: a restore always ingests the whole \
                 archive, and accepting a scope this operation does not honor would report a \
                 partial restore that did not happen. Omit the field."
                    .to_string(),
            ));
        }

        // Restore is among the highest-privilege operations in the product;
        // every attempt and its outcome must reach the audit trail (#3011).
        // `allow_unverified_archive` is recorded on the attempt because it is
        // the one way an archive whose integrity could not be established
        // reaches the database (#3373).
        self.log_audit(
            AuditEntry::new(AuditAction::RestoreStarted, ResourceType::Backup)
                .resource(backup_id)
                .details(serde_json::json!({
                    "restore_database": options.restore_database,
                    "restore_artifacts": options.restore_artifacts,
                    "allow_unverified_archive": options.allow_unverified_archive,
                })),
            options.actor,
        )
        .await;

        let result = self.do_restore(&backup, &options).await;
        match &result {
            Ok(r) => {
                self.log_audit(
                    AuditEntry::new(AuditAction::RestoreCompleted, ResourceType::Backup)
                        .resource(backup_id)
                        .details(serde_json::json!({
                            "tables_restored": r.tables_restored.len(),
                            "artifacts_restored": r.artifacts_restored,
                            "errors": r.errors.len(),
                            "integrity_anchor": r.integrity_anchor.to_string(),
                        })),
                    options.actor,
                )
                .await;
            }
            Err(e) => {
                self.log_audit(
                    AuditEntry::new(AuditAction::RestoreFailed, ResourceType::Backup)
                        .resource(backup_id)
                        .details(serde_json::json!({ "error": e.to_string() })),
                    options.actor,
                )
                .await;
            }
        }
        result
    }

    async fn do_restore(&self, backup: &Backup, options: &RestoreOptions) -> Result<RestoreResult> {
        // Download backup archive
        let storage_path = backup
            .storage_path
            .as_ref()
            .ok_or_else(|| AppError::Internal("Backup has no storage path".to_string()))?;
        // Read the archive back from the (optionally separate) backup bucket.
        let tar_data = self.archive_storage.get(storage_path).await?;

        // The archive's own length was recorded on the row at capture time, so
        // it can be checked before a single byte is decompressed (#3373). This
        // is the cheap half of the integrity check and it refuses a swapped
        // archive -- including a decompression bomb -- without paying for the
        // decompression. Rows with no recorded length predate `size_bytes`
        // being written and fall through to the checks below.
        if let Some(recorded_len) = backup.size_bytes {
            if recorded_len >= 0 && tar_data.len() as i64 != recorded_len {
                return Err(AppError::Validation(format!(
                    "archive integrity check failed: this backup recorded an archive of {} bytes \
                     but {} bytes were read back from storage; refusing to restore from an \
                     archive that is not the one that was captured",
                    recorded_len,
                    tar_data.len()
                )));
            }
        }

        // Phase 1: Extract all entries synchronously (tar::Archive is !Send).
        // Bounded: see `extract_entries_bounded` (#3373).
        let entries = Self::extract_entries(&tar_data)?;

        // The archive is the untrusted input. Establish that its contents are
        // the ones this backup captured BEFORE any row is ingested (#3373).
        // Refuses outright when there is nothing to check against, rather than
        // letting a blanked manifest field turn the control off.
        let manifest = Self::read_manifest(&entries);
        let integrity_anchor = verify_archive_integrity(
            backup.payload_checksum.as_deref(),
            manifest.as_ref(),
            &entries,
            options.allow_unverified_archive,
        )
        .map_err(AppError::Validation)?;

        // Phase 2: Async restore from extracted data
        let mut result = RestoreResult {
            tables_restored: Vec::new(),
            artifacts_restored: 0,
            errors: Vec::new(),
            integrity_anchor,
        };

        // A restore that could not be checked against the server's own record
        // must not look identical to one that was. The `manifest` anchor only
        // proves the archive agrees with itself, and `waived` proves nothing at
        // all -- and until operators re-run their backups, EVERY pre-existing
        // archive is on the `manifest` anchor, which is exactly where the
        // original #3373 exploit still produces a clean-looking 200. Same
        // treatment the `artifacts_unreadable` case below gets: it does not fail
        // the restore, it refuses to let it report itself clean.
        match integrity_anchor {
            IntegrityAnchor::Recorded => {}
            IntegrityAnchor::Manifest => {
                tracing::warn!(
                    backup_id = %backup.id,
                    "restoring an archive verified only against its own manifest"
                );
                result.errors.push(format!(
                    "archive integrity was checked only against the archive's own manifest \
                     (backup {} has no recorded payload checksum, so it predates #3373). That \
                     detects corruption but not tampering: whoever could rewrite the payload \
                     could rewrite the manifest with it. Re-run this backup to capture an \
                     archive whose digest is recorded outside it.",
                    backup.id
                ));
            }
            IntegrityAnchor::Waived => {
                tracing::warn!(
                    backup_id = %backup.id,
                    "restoring an archive whose integrity could not be established \
                     (allow_unverified_archive)"
                );
                result.errors.push(format!(
                    "archive integrity was NOT verified: backup {} has no recorded payload \
                     checksum and the archive carries no manifest checksum, and the caller set \
                     allow_unverified_archive. Every row below was ingested from an \
                     unauthenticated archive.",
                    backup.id
                ));
            }
        }

        // An archive whose manifest records unreadable artifacts is known to be
        // missing content. Surface that as a restore error so the restore can
        // never report `errors=[]` over an incomplete archive (#3170). This is
        // the second half of the honesty guarantee: the backup fails loudly at
        // capture time, and if a partial archive was deliberately opted in to,
        // the restore still refuses to call it clean.
        if let Some(manifest) = manifest.as_ref() {
            if manifest.artifacts_unreadable > 0 {
                result.errors.push(format!(
                    "archive is incomplete: its manifest records {} artifact object(s) that were \
                     unreadable at backup time and are absent from this archive (backup {}). \
                     {} artifact object(s) were captured.",
                    manifest.artifacts_unreadable, manifest.backup_id, manifest.artifact_count
                ));
            }
        }

        // Restore database tables in dependency order. There is deliberately
        // no catch-all pass for other `database/*.json` entries:
        // RESTORE_TABLE_ORDER already covers every table in
        // ALLOWED_EXPORT_TABLES, and `restore_table` rejects anything outside
        // the allowlist (GHSA-95fx-g94v-8jqg), so unknown entries are ignored
        // rather than inserted into attacker-chosen tables.
        if options.restore_database {
            for table_name in RESTORE_TABLE_ORDER {
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

    /// Extract all entries from a tar.gz archive synchronously, under the
    /// default bounds for an archive of this compressed size.
    ///
    /// Returns a Vec of (path, content) pairs so that async code can
    /// process them without holding the non-Send Archive across await points.
    fn extract_entries(tar_data: &[u8]) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        Self::extract_entries_bounded(tar_data, ExtractLimits::for_archive(tar_data.len()))
    }

    /// Extract a tar.gz archive under explicit bounds (#3373).
    ///
    /// The whole archive is decompressed into memory — that is inherent to the
    /// restore design, because `tar::Archive` is `!Send` and the async restore
    /// cannot hold it across an await. Without a bound that makes the archive a
    /// decompression-bomb surface: the compressed bytes are attacker-controlled
    /// in the same threat model that motivates the checksum
    /// ([`verify_archive_integrity`]), and a few hundred kilobytes of zeros
    /// expand to gigabytes.
    ///
    /// **The budget wraps the decoded stream BEFORE `tar::Archive::new`, and it
    /// has to.** A bound applied after the entry iterator yields cannot be
    /// complete, because `tar` consumes GNU LongName/LongLink and PAX extended
    /// headers *inside* `entries().next()` — `EntryFields::read_all`
    /// (`tar-0.4.46/src/entry.rs:297`, from `src/archive.rs:418/429/440`) caps
    /// only its preallocation at 128 KiB and then reads the full declared size.
    /// An entry-count check, a path guard and a per-entry `take` all run after
    /// that has already happened, so a 12 GiB extension record sails past every
    /// one of them. `build_backup_tar` emits GNU LongLink for any path over 100
    /// characters (#758), so these records are in ordinary archives, not just
    /// crafted ones. Wrapping the reader is also what `util::bounded_archive`
    /// has done for the ~20 other extractors in this codebase; this function
    /// now uses the same `BudgetReader` rather than a second, weaker scheme.
    ///
    /// Charging every byte the tar reader pulls means the budget covers entry
    /// bodies, extension records, the 512-byte header of every member and the
    /// padding between them — so an archive of a million empty entries is
    /// bounded by the same number as an archive of one huge file, and no
    /// allocation can outrun the budget because the reader stops supplying
    /// bytes at it.
    ///
    /// Entry count is bounded separately, and path shapes are rejected here
    /// rather than downstream so the guarantee does not depend on which storage
    /// backend happens to be configured: an entry whose path is absolute, or
    /// contains a `..` component, or has a root/prefix component, is refused.
    fn extract_entries_bounded(
        tar_data: &[u8],
        limits: ExtractLimits,
    ) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let decoder = GzDecoder::new(tar_data);
        let budgeted = bounded_archive::budgeted_to(decoder, limits.max_total_bytes);
        let mut archive = Archive::new(budgeted);
        let mut entries: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();

        let compressed_len = tar_data.len();
        let read_err = |what: &str, e: &std::io::Error| -> AppError {
            if bounded_archive::is_decompression_budget_breach(e) {
                bomb_error(&limits, compressed_len)
            } else {
                AppError::Internal(format!("Failed to {}: {}", what, e))
            }
        };

        for entry in archive
            .entries()
            .map_err(|e| read_err("read archive entries", &e))?
        {
            let mut entry = entry.map_err(|e| read_err("read entry", &e))?;
            let path = entry
                .path()
                .map_err(|e| read_err("read entry path", &e))?
                .to_path_buf();

            if entries.len() >= limits.max_entries {
                return Err(AppError::Validation(format!(
                    "archive rejected: it holds more than {} entries, which is past the limit \
                     this restore will decompress",
                    limits.max_entries
                )));
            }
            reject_unsafe_entry_path(&path)?;

            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| read_err("read entry data", &e))?;

            entries.push((path, content));
        }

        Ok(entries)
    }

    /// Restore a single database table from JSON data.
    /// Uses jsonb_populate_record for proper type coercion.
    async fn restore_table(&self, table: &str, content: &[u8]) -> Result<usize> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(content)?;
        let mut restored = 0usize;

        // GHSA-95fx-g94v-8jqg: enforce the export allowlist on the restore
        // path too. The table name is interpolated into the INSERT below, so
        // without this check a crafted backup archive could insert
        // attacker-controlled rows into any alphanumeric-named table
        // (`signing_keys`, `role_assignments`, ...).
        if !ALLOWED_EXPORT_TABLES.contains(&table) {
            return Err(AppError::Validation(format!(
                "Invalid restore table: {}",
                table
            )));
        }

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

            match sqlx::query(sqlx::AssertSqlSafe(&*query))
                .bind(row)
                .execute(&self.db)
                .await
            {
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
    /// Accept an archive whose integrity cannot be established (#3373).
    ///
    /// Only reachable for archives captured before `backups.payload_checksum`
    /// existed *and* carrying no manifest checksum either. It never waives a
    /// checksum that is present and does not match. Defaults to `false`, is
    /// recorded on the `RestoreStarted` audit event, and is an affirmative
    /// operator decision -- rewriting the archive cannot produce it.
    pub allow_unverified_archive: bool,
    /// The user who requested the restore, recorded on the `RESTORE_*` audit
    /// events (#3011). `None` for system-initiated restores.
    pub actor: Option<Uuid>,
}

/// Result of restore operation
#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub tables_restored: Vec<String>,
    pub artifacts_restored: i32,
    pub errors: Vec<String>,
    /// What the archive's contents were checked against (#3373). Reported so a
    /// restore verified against the server's own record is distinguishable from
    /// one verified only against the archive's own manifest.
    pub integrity_anchor: IntegrityAnchor,
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
        assert!(
            !opts.allow_unverified_archive,
            "archive verification must be on unless a caller deliberately turns it off (#3373)"
        );
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
            integrity_anchor: IntegrityAnchor::Recorded,
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
    // GHSA-95fx-g94v-8jqg: restore must never ingest non-allowlisted tables.
    //
    // The restore path used to have a catch-all second pass that fed EVERY
    // `database/*.json` entry in an archive to `restore_table`, which only
    // character-validated the derived table name before interpolating it into
    // `INSERT INTO {table} ... jsonb_populate_record(NULL::{table}, ...)`. A
    // crafted archive could therefore insert attacker-controlled rows into any
    // alphanumeric-named table (`signing_keys`, `audit_log`, ...). The export
    // allowlist is now enforced on restore as well, and the catch-all pass is
    // gone.
    // -----------------------------------------------------------------------

    /// The restore order must cover the whole allowlist; an allowlisted table
    /// missing from it would silently never be restored now that the catch-all
    /// second pass is gone.
    #[test]
    fn test_restore_table_order_covers_allowlist() {
        for table in ALLOWED_EXPORT_TABLES {
            assert!(
                RESTORE_TABLE_ORDER.contains(table),
                "allowlisted table '{}' is missing from RESTORE_TABLE_ORDER and would never be restored",
                table
            );
        }
        assert_eq!(
            RESTORE_TABLE_ORDER.len(),
            ALLOWED_EXPORT_TABLES.len(),
            "RESTORE_TABLE_ORDER must not contain non-allowlisted tables"
        );
    }

    /// `restore_table` rejects tables outside the export allowlist before any
    /// database access, so a lazy pool (which never connects) is enough.
    #[tokio::test]
    async fn test_restore_table_rejects_non_allowlisted_tables() {
        let pool = PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not contact the database");
        let service = service_for(pool);

        // Real tables that are NOT in the export allowlist.
        for table in ["audit_log", "signing_keys", "role_assignments"] {
            let err = service
                .restore_table(table, br#"[{"id": 1}]"#)
                .await
                .expect_err("non-allowlisted table must be rejected");
            assert!(
                matches!(err, AppError::Validation(_)),
                "expected Validation error for '{}', got {:?}",
                table,
                err
            );
        }

        // Sanity: an allowlisted table still passes validation (an empty row
        // set issues no queries, so the lazy pool is never touched).
        assert_eq!(
            service
                .restore_table("users", b"[]")
                .await
                .expect("allowlisted table passes validation"),
            0
        );
    }

    /// End-to-end GHSA-95fx-g94v-8jqg regression: a crafted archive carrying a
    /// `database/audit_log.json` entry (`audit_log` is a real table, but not
    /// in the export allowlist) must be skipped entirely — never attempted,
    /// never reported restored, no rows inserted. Skips cleanly when
    /// `DATABASE_URL` is unset, like the other DB-backed tests.
    #[tokio::test]
    async fn test_restore_skips_non_allowlisted_table_entries() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-ghsa95fx-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let backend = Arc::new(FilesystemBackend::new(dir.clone()));
        let storage = Arc::new(StorageService::new(backend));
        let service = BackupService::new(pool.clone(), storage);

        // Crafted archive: one legitimate allowlisted table, one rogue table
        // with attacker-controlled rows.
        let users: &[u8] = b"[]";
        let rogue: &[u8] = br#"[{"action": "privilege-escalation"}]"#;
        // The archive carries a real, matching payload digest, recorded on the
        // row the way a genuine backup does (#3373). The allowlist is what is
        // under test here, so the archive must clear the integrity gate on its
        // own rather than lean on a waiver.
        let (_, checksum) = payload_summary([("users", users), ("audit_log", rogue)].into_iter());
        let manifest = serde_json::to_vec(&serde_json::json!({
            "version": "1.0",
            "backup_id": Uuid::new_v4(),
            "backup_type": "full",
            "created_at": Utc::now(),
            "database_tables": ["users", "audit_log"],
            "artifact_count": 0,
            "total_size_bytes": 0,
            "checksum": checksum
        }))
        .expect("manifest serializes");
        let archive = build_backup_tar(&[("users", users), ("audit_log", rogue)], &[], &manifest)
            .expect("build crafted archive");
        let archive_len = archive.len() as i64;

        let storage_path = format!("backups/ghsa95fx/{}.tar.gz", Uuid::new_v4());
        service
            .archive_storage
            .put(&storage_path, Bytes::from(archive))
            .await
            .expect("write archive to storage");

        let backup_id: Uuid = sqlx::query_scalar(
            "INSERT INTO backups (backup_type, status, storage_path, completed_at, \
             payload_checksum, size_bytes) \
             VALUES ('full', 'completed', $1, now(), $2, $3) RETURNING id",
        )
        .bind(&storage_path)
        .bind(&checksum)
        .bind(archive_len)
        .fetch_one(&pool)
        .await
        .expect("insert completed backup row");

        let result = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect("restore runs");
        assert_eq!(
            result.integrity_anchor,
            IntegrityAnchor::Recorded,
            "this archive must pass the integrity gate on its own merits"
        );

        assert!(
            result.tables_restored.iter().any(|t| t == "users"),
            "the allowlisted table is restored normally"
        );
        assert!(
            !result.tables_restored.iter().any(|t| t == "audit_log"),
            "GHSA-95fx-g94v-8jqg: non-allowlisted table must never be restored"
        );
        assert!(
            !result.errors.iter().any(|e| e.contains("audit_log")),
            "the rogue entry is skipped, not attempted; got {:?}",
            result.errors
        );

        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
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
                    allow_unverified_archive: false,
                    actor: None,
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
                    allow_unverified_archive: false,
                    actor: None,
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

    // -----------------------------------------------------------------------
    // #3011 — BackupType is honored, not just stored
    // -----------------------------------------------------------------------

    #[test]
    fn incremental_backup_without_since_is_rejected() {
        let err = validate_backup_request(BackupType::Incremental, None)
            .expect_err("an incremental backup without a cutoff must be refused");
        assert!(
            matches!(err, AppError::Validation(_)),
            "must be a validation error, got {err:?}"
        );
        assert!(err.to_string().contains("since"));
    }

    #[test]
    fn full_metadata_and_anchored_incremental_requests_are_accepted() {
        assert!(validate_backup_request(BackupType::Full, None).is_ok());
        assert!(validate_backup_request(BackupType::Metadata, None).is_ok());
        assert!(validate_backup_request(BackupType::Incremental, Some(Utc::now())).is_ok());
        // A full backup MAY carry a cutoff (#2789); that is not incremental's
        // missing-anchor problem.
        assert!(validate_backup_request(BackupType::Full, Some(Utc::now())).is_ok());
    }

    #[test]
    fn only_metadata_backups_skip_artifact_bytes() {
        assert!(backup_includes_artifact_bytes(BackupType::Full));
        assert!(backup_includes_artifact_bytes(BackupType::Incremental));
        assert!(!backup_includes_artifact_bytes(BackupType::Metadata));
    }

    // -----------------------------------------------------------------------
    // #3011 — the manifest carries a real checksum and total size,
    //          and restore verifies it
    // -----------------------------------------------------------------------

    type Payload = Vec<(&'static str, &'static [u8])>;

    fn sample_payload() -> (Payload, Payload) {
        let tables: Vec<(&str, &[u8])> = vec![
            ("users", br#"[{"id":1}]"# as &[u8]),
            ("artifacts", br#"[]"# as &[u8]),
        ];
        let artifacts: Vec<(&str, &[u8])> = vec![(
            "repo-a/some/deep/path/artifact.bin",
            b"artifact-bytes" as &[u8],
        )];
        (tables, artifacts)
    }

    fn manifest_for(
        tables_len: usize,
        artifacts_len: usize,
        summary: (i64, String),
    ) -> BackupManifest {
        BackupManifest {
            version: "1.0".to_string(),
            backup_id: Uuid::nil(),
            backup_type: BackupType::Full,
            created_at: Utc::now(),
            database_tables: (0..tables_len).map(|i| format!("t{i}")).collect(),
            artifact_count: artifacts_len as i64,
            artifacts_unreadable: 0,
            total_size_bytes: summary.0,
            checksum: summary.1,
        }
    }

    #[test]
    fn payload_summary_is_deterministic_and_orders_and_names_matter() {
        let (tables, artifacts) = sample_payload();
        let all = || tables.iter().copied().chain(artifacts.iter().copied());
        let (total, checksum) = payload_summary(all());
        assert_eq!(
            total,
            (br#"[{"id":1}]"#.len() + br#"[]"#.len() + b"artifact-bytes".len()) as i64,
            "total must be the sum of payload entry sizes"
        );
        assert!(!checksum.is_empty());
        assert_eq!(payload_summary(all()), (total, checksum.clone()));

        // Reordering or renaming an entry must not collide with the original.
        let (_, reordered) =
            payload_summary(artifacts.iter().copied().chain(tables.iter().copied()));
        assert_ne!(reordered, checksum);
        let renamed: Vec<(&str, &[u8])> = vec![("users2", br#"[{"id":1}]"# as &[u8])];
        let (_, a) = payload_summary(renamed.iter().copied());
        let one: Vec<(&str, &[u8])> = vec![("users", br#"[{"id":1}]"# as &[u8])];
        let (_, b) = payload_summary(one.iter().copied());
        assert_ne!(a, b);
    }

    #[test]
    fn archive_checksum_roundtrips_through_the_tar() {
        let (tables, artifacts) = sample_payload();
        let summary = payload_summary(tables.iter().copied().chain(artifacts.iter().copied()));
        let manifest = manifest_for(tables.len(), artifacts.len(), summary);
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();

        let tar = build_backup_tar(&tables, &artifacts, &manifest_bytes).unwrap();
        let entries = BackupService::extract_entries(&tar).unwrap();
        let parsed = BackupService::read_manifest(&entries).expect("manifest present");
        assert!(
            !parsed.checksum.is_empty() && parsed.total_size_bytes > 0,
            "a written manifest must carry a real checksum and size (#3011)"
        );
        assert_eq!(
            verify_archive_integrity(None, Some(&parsed), &entries, false),
            Ok(IntegrityAnchor::Manifest),
            "an untampered archive must verify against its manifest"
        );
    }

    #[test]
    fn archive_checksum_catches_tampered_content() {
        let (tables, artifacts) = sample_payload();
        let summary = payload_summary(tables.iter().copied().chain(artifacts.iter().copied()));
        let manifest = manifest_for(tables.len(), artifacts.len(), summary);
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();

        let tampered_tables: Vec<(&str, &[u8])> = vec![
            ("users", br#"[{"id":2}]"# as &[u8]), // flipped content, same size
            ("artifacts", br#"[]"# as &[u8]),
        ];
        let tar = build_backup_tar(&tampered_tables, &artifacts, &manifest_bytes).unwrap();
        let entries = BackupService::extract_entries(&tar).unwrap();
        let parsed = BackupService::read_manifest(&entries).unwrap();
        let err = verify_archive_integrity(None, Some(&parsed), &entries, false)
            .expect_err("tampered payload must fail verification");
        assert!(err.contains("integrity"), "got: {err}");

        // The waiver accepts an archive that cannot be checked; it never
        // accepts one that provably fails its check (#3373).
        let err = verify_archive_integrity(None, Some(&parsed), &entries, true)
            .expect_err("allow_unverified_archive must not waive a FAILED checksum");
        assert!(err.contains("integrity"), "got: {err}");
    }

    /// #3373: an empty manifest checksum used to SKIP verification, which made
    /// the control switch itself off for anyone who could blank one JSON field.
    /// An archive with nothing to check against is now refused, and the only
    /// way past that is an explicit caller opt-in the archive cannot forge.
    #[test]
    fn archives_with_no_checkable_digest_are_refused_unless_the_caller_waives_it() {
        let (tables, artifacts) = sample_payload();
        let manifest = manifest_for(tables.len(), artifacts.len(), (0, String::new()));
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let tar = build_backup_tar(&tables, &artifacts, &manifest_bytes).unwrap();
        let entries = BackupService::extract_entries(&tar).unwrap();
        let parsed = BackupService::read_manifest(&entries).unwrap();

        let err = verify_archive_integrity(None, Some(&parsed), &entries, false)
            .expect_err("a blank checksum must not disable the check");
        assert!(
            err.contains("cannot be established") && err.contains("allow_unverified_archive"),
            "the refusal must say what happened and what the operator can do; got: {err}"
        );

        assert_eq!(
            verify_archive_integrity(None, Some(&parsed), &entries, true),
            Ok(IntegrityAnchor::Waived),
            "an operator may still deliberately restore a pre-#3011 archive"
        );

        // A missing manifest is the same situation as a blanked field, and was
        // the second way to reach the old skip: `read_manifest` returned None
        // and no verification ran at all.
        let err = verify_archive_integrity(None, None, &entries, false)
            .expect_err("an archive with no manifest at all must not skip the check either");
        assert!(err.contains("cannot be established"), "got: {err}");
    }

    /// A restore verified only against the archive's own manifest, or not
    /// verified at all, must not be reportable as clean (#3373 review F5).
    /// Until operators re-run their backups every existing archive is on the
    /// `manifest` anchor, which is precisely where the original exploit still
    /// yields a 200.
    #[tokio::test]
    async fn a_manifest_only_restore_reports_that_it_could_not_be_fully_verified_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-3373-weak-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            dir.clone(),
        ))));
        let service = BackupService::new(pool.clone(), storage);

        let honest: &[u8] = b"[]";
        let (_, checksum) = payload_summary([("users", honest)].into_iter());
        let archive = build_backup_tar(
            &[("users", honest)],
            &[],
            &manifest_bytes_with_checksum(&["users"], &checksum),
        )
        .expect("build archive");
        // No recorded digest: a pre-#3373 archive, which is what every existing
        // backup looks like after this upgrade.
        let backup_id = seed_archive_as_backup(&pool, &service, archive, None, true).await;

        let result = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect("a pre-#3373 archive with a valid manifest checksum still restores");
        assert_eq!(result.integrity_anchor, IntegrityAnchor::Manifest);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("only against the archive's own manifest")),
            "the weaker anchor must be reported, not silently accepted; got {:?}",
            result.errors
        );

        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of #3373: the expected digest recorded on the `backups` row
    /// is not reachable from the archive, so rewriting the archive — manifest
    /// and all — cannot disable or satisfy the check.
    #[test]
    fn a_recorded_digest_survives_a_self_consistent_rewrite_of_the_archive() {
        let (tables, artifacts) = sample_payload();
        let summary = payload_summary(tables.iter().copied().chain(artifacts.iter().copied()));
        let recorded = summary.1.clone();

        // Honest archive: verifies against the recorded digest, and the
        // recorded digest is what is used (not the manifest's).
        let manifest = manifest_for(tables.len(), artifacts.len(), summary);
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let tar = build_backup_tar(&tables, &artifacts, &manifest_bytes).unwrap();
        let entries = BackupService::extract_entries(&tar).unwrap();
        let parsed = BackupService::read_manifest(&entries).unwrap();
        assert_eq!(
            verify_archive_integrity(Some(&recorded), Some(&parsed), &entries, false),
            Ok(IntegrityAnchor::Recorded)
        );

        // Tampered archive, rewritten to be internally consistent: the payload
        // is changed AND the manifest is regenerated over the new payload, so
        // every check that lives inside the archive passes.
        let tampered: Vec<(&str, &[u8])> = vec![
            ("users", br#"[{"id":2,"is_admin":true}]"# as &[u8]),
            ("artifacts", br#"[]"# as &[u8]),
        ];
        let new_summary =
            payload_summary(tampered.iter().copied().chain(artifacts.iter().copied()));
        let new_manifest = manifest_for(tampered.len(), artifacts.len(), new_summary);
        let new_manifest_bytes = serde_json::to_vec_pretty(&new_manifest).unwrap();
        let tampered_tar = build_backup_tar(&tampered, &artifacts, &new_manifest_bytes).unwrap();
        let tampered_entries = BackupService::extract_entries(&tampered_tar).unwrap();
        let tampered_manifest = BackupService::read_manifest(&tampered_entries).unwrap();

        // Self-consistent, so the manifest anchor alone accepts it...
        assert_eq!(
            verify_archive_integrity(None, Some(&tampered_manifest), &tampered_entries, false),
            Ok(IntegrityAnchor::Manifest),
            "a manifest checksum only ever proves the archive agrees with itself"
        );
        // ...and the recorded anchor does not.
        let err = verify_archive_integrity(
            Some(&recorded),
            Some(&tampered_manifest),
            &tampered_entries,
            false,
        )
        .expect_err("the recorded digest must refuse a rewritten archive");
        assert!(err.contains("recorded"), "got: {err}");

        // Blanking the manifest checksum does not fall back to "unverifiable"
        // when a recorded digest exists — the recorded one still applies.
        let blanked = manifest_for(tampered.len(), artifacts.len(), (0, String::new()));
        let err =
            verify_archive_integrity(Some(&recorded), Some(&blanked), &tampered_entries, false)
                .expect_err("blanking the manifest must not downgrade to no check");
        assert!(err.contains("recorded"), "got: {err}");

        // Nor does the waiver reach it: the check is possible and it fails.
        let err = verify_archive_integrity(Some(&recorded), None, &tampered_entries, true)
            .expect_err("allow_unverified_archive must not waive a recorded-digest mismatch");
        assert!(err.contains("recorded"), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // #3084 — a lost run claim aborts the in-flight backup between chunks
    // -----------------------------------------------------------------------

    #[test]
    fn backup_proceeds_while_its_claim_is_held() {
        let cancel = CancellationToken::new();
        assert!(ensure_backup_not_cancelled(&cancel).is_ok());
    }

    #[test]
    fn backup_aborts_once_its_claim_is_lost() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = ensure_backup_not_cancelled(&cancel)
            .expect_err("a lost claim must abort the in-flight backup");
        assert!(
            err.to_string().contains("claim"),
            "the abort must name the lost claim; got {err}"
        );
    }

    // -----------------------------------------------------------------------
    // #3373 — the archive is untrusted input: bound what it can decompress to,
    // reject the paths it can name, and anchor its expected digest OUTSIDE it
    // -----------------------------------------------------------------------

    /// Build a tar (uncompressed) with one member whose path is written
    /// verbatim, bypassing the writer-side checks.
    ///
    /// `tar::Builder::append_data` refuses a path containing `..` ("paths in
    /// archives must not have `..`"), so no archive this product writes can
    /// carry one — but nothing stops a hand-rolled archive from doing so, and
    /// the READER surfaces whatever bytes are in the header. Hand-rolling the
    /// header is the only way to make the extractor's path guard falsifiable.
    fn raw_tar_member(name: &str, typeflag: u8, content: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() < 100, "test name must fit the ustar field");
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        header[100..107].copy_from_slice(b"0000644"); // mode
        header[108..115].copy_from_slice(b"0000000"); // uid
        header[116..123].copy_from_slice(b"0000000"); // gid
        header[124..135].copy_from_slice(format!("{:011o}", content.len()).as_bytes());
        header[136..147].copy_from_slice(b"00000000000"); // mtime
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // Checksum is computed with the checksum field itself read as spaces.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        header[148..156].copy_from_slice(chk.as_bytes());

        let mut out = header.to_vec();
        out.extend_from_slice(content);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    /// Two zero blocks terminate a tar.
    fn tar_end(mut members: Vec<u8>) -> Vec<u8> {
        members.extend_from_slice(&[0u8; 1024]);
        members
    }

    fn raw_tar_with_entry_name(name: &str, content: &[u8]) -> Vec<u8> {
        tar_end(raw_tar_member(name, b'0', content))
    }

    /// One PAX extended-header record: `"<len> <key>=<value>\n"`, where `<len>`
    /// counts its own decimal digits. Solved by iterating to a fixed point.
    fn pax_record(key: &str, value_len: usize) -> Vec<u8> {
        let body = key.len() + 1 + value_len + 2; // key + '=' + value + ' ' + '\n'
        let mut total = body + 1;
        loop {
            let next = body + total.to_string().len();
            if next == total {
                break;
            }
            total = next;
        }
        let mut out = format!("{} {}=", total, key).into_bytes();
        out.extend(std::iter::repeat_n(b'a', value_len));
        out.push(b'\n');
        assert_eq!(
            out.len(),
            total,
            "pax record length must be self-consistent"
        );
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extract_limits_scale_with_the_archive_and_never_fall_below_the_floor() {
        // A tiny archive still gets the floor, so a small legitimate backup is
        // not refused for being small.
        let small = ExtractLimits::for_archive(1024);
        assert_eq!(small.max_total_bytes, MIN_DECOMPRESSED_BYTES);

        // A large archive gets a budget proportional to itself, so a large
        // legitimate backup is not refused for being large.
        let big = ExtractLimits::for_archive(64 * 1024 * 1024);
        assert_eq!(
            big.max_total_bytes,
            64 * 1024 * 1024 * MAX_DECOMPRESSION_RATIO
        );
        assert!(big.max_total_bytes > MIN_DECOMPRESSED_BYTES);

        // The ratio is clamped, so the budget is never purely a function of a
        // length the archive controls (gzip tolerates trailing bytes, so a
        // tamperer can pad to whatever `size_bytes` records). At 100x, a 2 GiB
        // archive would otherwise buy a 200 GiB budget.
        let padded = ExtractLimits::for_archive(2 * 1024 * 1024 * 1024);
        assert_eq!(padded.max_total_bytes, MAX_DECOMPRESSED_BYTES);

        // No overflow panic on an absurd input.
        let huge = ExtractLimits::for_archive(usize::MAX);
        assert_eq!(huge.max_total_bytes, MAX_DECOMPRESSED_BYTES);
        assert_eq!(huge.max_entries, MAX_ARCHIVE_ENTRIES);
    }

    /// #3373: `extract_entries` decompressed an archive with no cap at all.
    /// Measured on the parent commit: a 521,905-byte archive expanded to
    /// 536,870,912 bytes (1028x) and was returned in full, so a few megabytes
    /// of attacker-controlled archive is gigabytes of resident memory.
    #[test]
    fn extract_entries_refuses_a_decompression_bomb() {
        // 16 MiB of zeros; compresses to ~16 KiB.
        let payload = vec![0u8; 16 * 1024 * 1024];
        let tar = create_test_tar_gz(&[("artifacts/bomb", payload.as_slice())]);
        assert!(
            tar.len() * 100 < payload.len(),
            "the test archive must actually be bomb-shaped; got {} compressed for {} raw",
            tar.len(),
            payload.len()
        );

        // Explicit small budget so the assertion is about the bound, not about
        // allocating gigabytes in a test process.
        let limits = ExtractLimits {
            max_entries: 16,
            max_total_bytes: 1024 * 1024,
        };
        let err = BackupService::extract_entries_bounded(&tar, limits)
            .expect_err("a bomb must be refused, not decompressed");
        assert!(err.to_string().contains("decompression bomb"), "got: {err}");

        // And the same archive is refused under the DEFAULT limits, because
        // 16 MiB from ~16 KiB is far past the ratio ceiling... except the floor
        // is what actually applies at this size, so bump past it to be sure the
        // real code path refuses a real bomb.
        let big = vec![0u8; (MIN_DECOMPRESSED_BYTES + 1) as usize];
        let big_tar = create_test_tar_gz(&[("artifacts/bomb", big.as_slice())]);
        let err = BackupService::extract_entries(&big_tar)
            .expect_err("the default limits must refuse a real bomb too");
        assert!(err.to_string().contains("decompression bomb"), "got: {err}");
    }

    /// The byte budget must be spent by entry HEADERS too, or an archive of
    /// millions of empty members costs nothing against it. Charging them falls
    /// out of bounding the reader rather than the entries: the 512-byte headers
    /// are bytes the tar reader pulls from the budgeted stream like any other.
    #[test]
    fn extract_entries_charges_entry_headers_against_the_budget() {
        const TAR_BLOCK: u64 = 512;
        let empty: &[u8] = b"";
        let entries: Vec<(&str, &[u8])> = vec![
            ("a", empty),
            ("b", empty),
            ("c", empty),
            ("d", empty),
            ("e", empty),
        ];
        let tar = create_test_tar_gz(&entries);

        // Five zero-length members still cost five header blocks, so a budget
        // of four must refuse them even though their content is zero bytes.
        let err = BackupService::extract_entries_bounded(
            &tar,
            ExtractLimits {
                max_entries: 1000,
                max_total_bytes: TAR_BLOCK * 4,
            },
        )
        .expect_err("empty entries must still cost their header block");
        assert!(err.to_string().contains("decompression bomb"), "got: {err}");

        // With room for the headers, the padding and the end-of-archive blocks,
        // all five extract — the cap bounds, it does not reject.
        let got = BackupService::extract_entries_bounded(
            &tar,
            ExtractLimits {
                max_entries: 1000,
                max_total_bytes: 64 * 1024,
            },
        )
        .expect("a real budget must extract all five");
        assert_eq!(got.len(), 5);
    }

    #[test]
    fn extract_entries_refuses_more_entries_than_the_limit() {
        let empty: &[u8] = b"";
        let entries: Vec<(&str, &[u8])> = vec![("a", empty), ("b", empty), ("c", empty)];
        let tar = create_test_tar_gz(&entries);
        let limits = ExtractLimits {
            max_entries: 2,
            max_total_bytes: u64::MAX,
        };
        let err = BackupService::extract_entries_bounded(&tar, limits)
            .expect_err("the entry count must be bounded independently of bytes");
        assert!(
            err.to_string().contains("more than 2 entries"),
            "got: {err}"
        );
    }

    /// A normal archive must still extract under the default limits — the cap
    /// must not be so tight that it breaks restore, which is the failure mode
    /// a limit like this introduces.
    #[test]
    fn extract_entries_default_limits_accept_a_normal_archive() {
        let tar = create_test_tar_gz(&[
            ("manifest.json", b"{}"),
            ("database/users.json", b"[{\"id\":1}]"),
            ("artifacts/some/deep/key", b"artifact bytes"),
        ]);
        let entries = BackupService::extract_entries(&tar).expect("a normal archive extracts");
        assert_eq!(entries.len(), 3);
    }

    /// #3373: entry paths choose where restored artifact bytes land.
    ///
    /// This is defence in depth rather than a live escape — `FilesystemBackend::
    /// key_to_path` already drops `..` and root components, so on that backend a
    /// traversal entry lands sanitised rather than outside the storage root, and
    /// `tar::Builder` will not write such a path in the first place. The guard
    /// is here so the property does not depend on which backend is configured,
    /// and so a hand-rolled archive is refused rather than partly applied.
    #[test]
    fn extract_entries_refuses_traversal_and_absolute_paths() {
        for name in [
            "artifacts/../../../../etc/cron.d/pwn",
            "../escape",
            "/etc/shadow",
            "database/../../x.json",
        ] {
            let tar = gzip(&raw_tar_with_entry_name(name, b"payload"));
            let err = BackupService::extract_entries(&tar)
                .err()
                .unwrap_or_else(|| panic!("{name:?} must be refused"));
            assert!(
                err.to_string().contains("plain relative path"),
                "{name:?} got: {err}"
            );
        }
    }

    /// F1: the tar reader consumes GNU LongName / LongLink and PAX extended
    /// headers **inside `entries().next()`**, via `EntryFields::read_all()`
    /// (`tar-0.4.46/src/entry.rs:297`, called from `src/archive.rs:418/429/440`).
    /// `read_all` caps only its *preallocation* at 128 KiB and then reads the
    /// full declared size. Any bound applied after the iterator yields — an
    /// entry-count check, a path guard, a per-entry `take` — never sees those
    /// bytes.
    ///
    /// This is not an exotic shape: `build_backup_tar` uses `append_data`
    /// precisely so paths over 100 characters are written as GNU LongLink
    /// (#758), so every real backup holding a long artifact key contains these
    /// records.
    ///
    /// The budget therefore has to wrap the decoded stream *before*
    /// `tar::Archive::new`, which is what `util::bounded_archive` has done for
    /// ~20 other extractors all along.
    #[test]
    fn extract_entries_bounds_tar_extension_records() {
        // 1 MiB declared inside an extension record, against a 1 KiB budget.
        // Small enough to be cheap either way; the mechanism is what is under
        // test, and it is the same mechanism at any size.
        const BOMB: usize = 1024 * 1024;
        let tiny = ExtractLimits {
            max_entries: 16,
            max_total_bytes: 1024,
        };

        let long_name = vec![b'a'; BOMB];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "GNU LongName",
                [
                    raw_tar_member("././@LongName", b'L', &long_name),
                    raw_tar_member("short", b'0', b"payload"),
                ]
                .concat(),
            ),
            (
                "GNU LongLink",
                [
                    raw_tar_member("././@LongLink", b'K', &long_name),
                    raw_tar_member("short", b'0', b"payload"),
                ]
                .concat(),
            ),
            (
                "PAX extended header",
                [
                    raw_tar_member("PaxHeader/short", b'x', &pax_record("comment", BOMB)),
                    raw_tar_member("short", b'0', b"payload"),
                ]
                .concat(),
            ),
        ];

        for (label, members) in &cases {
            let tar = gzip(&tar_end(members.clone()));
            let err = BackupService::extract_entries_bounded(&tar, tiny)
                .err()
                .unwrap_or_else(|| {
                    panic!("{label}: {BOMB} bytes must not be decompressed under a 1 KiB budget")
                });
            assert!(
                err.to_string().contains("decompression bomb"),
                "{label} got: {err}"
            );
        }

        // Control: the identical payload in a plain regular-file entry was
        // already refused, which is exactly why the extension-record escape was
        // invisible — the shape the tests covered was the shape that was bound.
        let plain = gzip(&raw_tar_with_entry_name("short", &long_name));
        assert!(
            BackupService::extract_entries_bounded(&plain, tiny).is_err(),
            "control: a plain entry of the same size must also be refused"
        );

        // And through the real entry point, at the DEFAULT limits, which is the
        // shape measured at 12.10 GiB on the first version of this fix.
        let over_floor = vec![b'a'; (MIN_DECOMPRESSED_BYTES + 1) as usize];
        let headline = gzip(&tar_end(
            [
                raw_tar_member("././@LongName", b'L', &over_floor),
                raw_tar_member("short", b'0', b"payload"),
            ]
            .concat(),
        ));
        let err = BackupService::extract_entries(&headline)
            .expect_err("the default limits must bound an extension record too");
        assert!(err.to_string().contains("decompression bomb"), "got: {err}");
    }

    /// A long path still round-trips: the budget bounds extension records, it
    /// does not reject them. `build_backup_tar` emits GNU LongLink for any
    /// artifact key over 100 characters (#758), so refusing the record type
    /// outright would break every backup that holds one.
    #[test]
    fn extract_entries_still_reads_a_long_path_written_as_an_extension_record() {
        let long_key = format!("artifacts/{}", "a/".repeat(70));
        assert!(
            long_key.len() > 100,
            "the test key must exceed the 100-char ustar name field"
        );
        let tar = create_test_tar_gz(&[(long_key.as_str(), b"artifact bytes")]);
        let entries = BackupService::extract_entries(&tar).expect("a long path must still extract");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.to_string_lossy(), long_key);
        assert_eq!(entries[0].1, b"artifact bytes");
    }

    #[test]
    fn extract_entries_accepts_a_plain_relative_path() {
        let tar = gzip(&raw_tar_with_entry_name("artifacts/normal/key", b"payload"));
        let entries = BackupService::extract_entries(&tar).expect("a plain path extracts");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"payload");
    }

    /// A `users` row shaped so `jsonb_populate_record` can insert it: every
    /// NOT NULL column is present. This is the row the issue describes — a
    /// crafted `database/users.json` carrying `is_admin: true`.
    fn crafted_admin_user_row(username: &str) -> serde_json::Value {
        serde_json::json!({
            "id": Uuid::new_v4(),
            "username": username,
            "email": format!("{username}@invalid.test"),
            "password_hash": "$2b$12$placeholder.not.a.real.hash.value.for.tests",
            "auth_provider": "local",
            "is_active": true,
            "is_admin": true,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
            "must_change_password": false,
            "totp_enabled": false,
            "is_service_account": false,
            "failed_login_attempts": 0,
            "password_changed_at": Utc::now(),
            "privileges_changed_at": Utc::now(),
        })
    }

    fn manifest_bytes_with_checksum(tables: &[&str], checksum: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "1.0",
            "backup_id": Uuid::new_v4(),
            "backup_type": "full",
            "created_at": Utc::now(),
            "database_tables": tables,
            "artifact_count": 0,
            "total_size_bytes": 0,
            "checksum": checksum,
        }))
        .expect("manifest serializes")
    }

    /// Register a crafted archive as a completed backup and return its id.
    async fn seed_archive_as_backup(
        pool: &PgPool,
        service: &BackupService,
        archive: Vec<u8>,
        payload_checksum: Option<&str>,
        record_size: bool,
    ) -> Uuid {
        let storage_path = format!("backups/3373/{}.tar.gz", Uuid::new_v4());
        let len = archive.len() as i64;
        service
            .archive_storage
            .put(&storage_path, Bytes::from(archive))
            .await
            .expect("write archive to storage");
        sqlx::query_scalar(
            "INSERT INTO backups (backup_type, status, storage_path, completed_at, \
             payload_checksum, size_bytes) \
             VALUES ('full', 'completed', $1, now(), $2, $3) RETURNING id",
        )
        .bind(&storage_path)
        .bind(payload_checksum)
        .bind(record_size.then_some(len))
        .fetch_one(pool)
        .await
        .expect("insert completed backup row")
    }

    async fn user_rows_named(pool: &PgPool, username: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(pool)
            .await
            .expect("count users")
    }

    /// The #3373 gap, end to end.
    ///
    /// On the parent commit this exact archive restored cleanly — `Ok`,
    /// `tables_restored = ["users"]`, `errors = []`, and the crafted
    /// `is_admin: true` row landed in `users`. Blanking one JSON field turned
    /// the integrity control off, which means the control did not meet its own
    /// threat model: the archive is the untrusted input, so it cannot also be
    /// the authority on whether it should be checked.
    #[tokio::test]
    async fn restore_refuses_an_archive_whose_manifest_checksum_was_blanked_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-3373-blank-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            dir.clone(),
        ))));
        let service = BackupService::new(pool.clone(), storage);

        let username = format!("ak3373-tamper-{}", Uuid::new_v4());
        let users_json = serde_json::to_vec(&vec![crafted_admin_user_row(&username)])
            .expect("users payload serializes");
        let archive = build_backup_tar(
            &[("users", users_json.as_slice())],
            &[],
            &manifest_bytes_with_checksum(&["users"], ""),
        )
        .expect("build crafted archive");

        // No recorded digest either: the row predates `payload_checksum`, which
        // is the weakest position the fix has to hold in.
        let backup_id = seed_archive_as_backup(&pool, &service, archive, None, false).await;

        let err = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect_err("an archive with no checkable digest must be refused");
        assert!(
            err.to_string().contains("integrity cannot be established"),
            "got: {err}"
        );
        assert_eq!(
            user_rows_named(&pool, &username).await,
            0,
            "the refusal must happen BEFORE any row is ingested"
        );

        // The operator can still restore it deliberately — that is an
        // affirmative decision recorded on the audit event, and it is not
        // something the archive can arrange for itself.
        let result = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: true,
                    actor: None,
                },
            )
            .await
            .expect("an explicit waiver still restores");
        assert_eq!(result.integrity_anchor, IntegrityAnchor::Waived);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("integrity was NOT verified")),
            "a waived restore must not report itself clean; got {:?}",
            result.errors
        );
        assert_eq!(user_rows_named(&pool, &username).await, 1);

        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&username)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The digest recorded on the `backups` row is the anchor a tamperer cannot
    /// reach: rewriting the archive so that it is internally consistent — new
    /// payload, new manifest checksum over that payload — passes every check
    /// that lives inside the archive and still fails this one.
    #[tokio::test]
    async fn restore_verifies_against_the_recorded_digest_not_the_archives_own_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-3373-anchor-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            dir.clone(),
        ))));
        let service = BackupService::new(pool.clone(), storage);

        // What the server captured: an empty `users` dump, and the digest it
        // recorded on the row for it.
        let honest: &[u8] = b"[]";
        let (_, recorded) = payload_summary([("users", honest)].into_iter());

        // What is on disk when the restore runs: a rewritten payload with a
        // manifest regenerated over it, so the archive agrees with itself.
        let username = format!("ak3373-anchor-{}", Uuid::new_v4());
        let rogue = serde_json::to_vec(&vec![crafted_admin_user_row(&username)])
            .expect("users payload serializes");
        let (_, self_consistent) = payload_summary([("users", rogue.as_slice())].into_iter());
        let tampered = build_backup_tar(
            &[("users", rogue.as_slice())],
            &[],
            &manifest_bytes_with_checksum(&["users"], &self_consistent),
        )
        .expect("build rewritten archive");

        // `size_bytes` left unrecorded so this test exercises the DIGEST anchor
        // specifically; the archive-length anchor has its own test below.
        let backup_id =
            seed_archive_as_backup(&pool, &service, tampered, Some(&recorded), false).await;

        let err = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect_err("the recorded digest must refuse a rewritten archive");
        assert!(err.to_string().contains("recorded"), "got: {err}");
        assert_eq!(user_rows_named(&pool, &username).await, 0);

        // The waiver does not reach a check that is possible and fails.
        let err = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: true,
                    actor: None,
                },
            )
            .await
            .expect_err("allow_unverified_archive must not waive a recorded-digest mismatch");
        assert!(err.to_string().contains("recorded"), "got: {err}");
        assert_eq!(user_rows_named(&pool, &username).await, 0);

        // Control: the archive the digest was recorded for still restores.
        let honest_archive = build_backup_tar(
            &[("users", honest)],
            &[],
            &manifest_bytes_with_checksum(&["users"], &recorded),
        )
        .expect("build honest archive");
        let honest_id =
            seed_archive_as_backup(&pool, &service, honest_archive, Some(&recorded), true).await;
        let result = service
            .restore(
                honest_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect("an untampered archive must still restore");
        assert_eq!(result.integrity_anchor, IntegrityAnchor::Recorded);
        assert!(result.tables_restored.iter().any(|t| t == "users"));

        let _ = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(&username)
            .execute(&pool)
            .await;
        for id in [backup_id, honest_id] {
            let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The archive's own length is recorded on the row too, so a swapped
    /// archive is refused before a byte of it is decompressed — which is what
    /// makes the bomb defence cheap for the normal case.
    #[tokio::test]
    async fn restore_refuses_an_archive_whose_length_does_not_match_the_record_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-3373-len-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            dir.clone(),
        ))));
        let service = BackupService::new(pool.clone(), storage);

        let honest: &[u8] = b"[]";
        let (_, checksum) = payload_summary([("users", honest)].into_iter());
        let archive = build_backup_tar(
            &[("users", honest)],
            &[],
            &manifest_bytes_with_checksum(&["users"], &checksum),
        )
        .expect("build archive");
        let backup_id =
            seed_archive_as_backup(&pool, &service, archive, Some(&checksum), true).await;

        // Someone swaps the object at rest for a longer one.
        let storage_path: String =
            sqlx::query_scalar("SELECT storage_path FROM backups WHERE id = $1")
                .bind(backup_id)
                .fetch_one(&pool)
                .await
                .expect("read storage path");
        let bomb = vec![0u8; 4 * 1024 * 1024];
        let swapped = create_test_tar_gz(&[("artifacts/bomb", bomb.as_slice())]);
        service
            .archive_storage
            .put(&storage_path, Bytes::from(swapped))
            .await
            .expect("swap the archive");

        let err = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: true,
                    actor: None,
                },
            )
            .await
            .expect_err("a length that disagrees with the record must be refused");
        assert!(
            err.to_string()
                .contains("bytes were read back from storage"),
            "got: {err}"
        );

        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real backup must record its payload digest on the row, or the anchor
    /// above never exists in production.
    #[tokio::test]
    async fn a_completed_backup_records_its_payload_checksum_on_the_row_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, repo_dir) = tdh::create_repo(&pool, "local", "generic").await;

        let (service, storage_dir) = service_with_empty_storage(pool.clone());
        let backup = service
            .create(full_backup_of(repo_id))
            .await
            .expect("create backup job");
        assert!(
            backup.payload_checksum.is_none(),
            "nothing is recorded before the archive exists"
        );

        service.execute(backup.id).await.expect("backup completes");

        let row = service.get_by_id(backup.id).await.expect("reload row");
        let recorded = row
            .payload_checksum
            .expect("a completed backup must record its payload digest (#3373)");
        assert_eq!(recorded.len(), 64, "a SHA-256 hex digest; got {recorded:?}");

        // And it must be the digest of what is actually in the archive, not
        // just some digest: restoring resolves against it and succeeds.
        let result = service
            .restore(
                backup.id,
                RestoreOptions {
                    restore_database: false,
                    restore_artifacts: true,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect("the archive this backup wrote must verify against its own record");
        assert_eq!(
            result.integrity_anchor,
            IntegrityAnchor::Recorded,
            "the row's digest, not the manifest's, must be the anchor used"
        );

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&repo_dir);
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    /// #3373: `target_repository_id` was accepted, stored on `RestoreOptions`
    /// and read by nothing, so a caller who scoped a restore to one repository
    /// got a full global ingest of the identity tables and a 200.
    #[tokio::test]
    async fn restore_refuses_the_target_repository_id_it_never_honored_3373() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::storage_service::FilesystemBackend;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let dir = std::env::temp_dir().join(format!("bk-3373-scope-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp storage dir");
        let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            dir.clone(),
        ))));
        let service = BackupService::new(pool.clone(), storage);

        let honest: &[u8] = b"[]";
        let (_, checksum) = payload_summary([("users", honest)].into_iter());
        let archive = build_backup_tar(
            &[("users", honest)],
            &[],
            &manifest_bytes_with_checksum(&["users"], &checksum),
        )
        .expect("build archive");
        let backup_id =
            seed_archive_as_backup(&pool, &service, archive, Some(&checksum), true).await;

        let err = service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: Some(Uuid::new_v4()),
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect_err("a scope this operation does not honor must not be accepted");
        assert!(
            err.to_string().contains("target_repository_id"),
            "got: {err}"
        );

        // Without it, the same restore runs.
        service
            .restore(
                backup_id,
                RestoreOptions {
                    restore_database: true,
                    restore_artifacts: false,
                    target_repository_id: None,
                    allow_unverified_archive: false,
                    actor: None,
                },
            )
            .await
            .expect("omitting the field restores normally");

        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
