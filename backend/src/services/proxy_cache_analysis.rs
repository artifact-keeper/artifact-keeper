//! Make proxy-cached packages eligible for Scan / SBOM.
//!
//! Upstream #1278 keeps proxy bodies out of `artifacts` on the hot cache
//! write path (storage-prefix bugs). Upstream #2227/#2292 then marked every
//! listing row `analyzable: false`, so the UI disabled Scan/SBOM even though
//! the bytes live in storage under `proxy-cache/<repo>/<path>/__content__`.
//!
//! On an explicit analysis request (or auto-scan-on-proxy for a meaningful
//! package) we materialize a thin `artifacts` row that **reuses** the existing
//! proxy-cache `storage_key` — no copy, no doubled prefix — so the existing
//! scanner / SBOM pipelines can resolve the object by the same deterministic
//! listing id the UI already shows.
//!
//! Queries use runtime `sqlx::query` (not `query!`) so CI with
//! `SQLX_OFFLINE=true` does not require regenerating `.sqlx` cache entries
//! for this module.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::proxy_catalog;
use crate::services::scan_eligibility::{
    is_scannable_package_path, proxy_cache_listing_id, proxy_listing_display_name,
};
use crate::services::scanner_service::ScannerService;
use crate::services::storage_service::StorageService;

/// Scanner handle for auto-scan after a successful proxy-cache write.
/// Registered once from `main` after both services exist — avoids threading
/// `ScannerService` through every `ProxyService` / `CachePersister` constructor.
static PROXY_AUTO_SCANNER: OnceLock<Arc<ScannerService>> = OnceLock::new();

/// Proxy-cache storage handle used to heal size-0 catalog placeholders from
/// the metadata sidecar (Scan/SBOM + auto-scan). Registered beside the scanner.
static PROXY_CACHE_STORAGE: OnceLock<Arc<StorageService>> = OnceLock::new();

/// How long / how often to wait for a just-written (or lazily backfilled)
/// `proxy_cache_artifacts` row with `size_bytes > 0` before giving up on
/// auto-scan. ~10s covers slow tee commits under storage backpressure.
const CATALOG_READY_ATTEMPTS: u32 = 40;
const CATALOG_READY_DELAY: Duration = Duration::from_millis(250);

/// Wire the process-wide scanner used by [`spawn_auto_scan_after_proxy_cache`].
/// Idempotent: the first registration wins.
pub fn register_scanner_for_proxy_auto_scan(scanner: Arc<ScannerService>) {
    let _ = PROXY_AUTO_SCANNER.set(scanner);
}

/// Wire the proxy-cache storage facade used to heal size-0 catalog placeholders.
/// Idempotent: the first registration wins.
pub fn register_storage_for_proxy_catalog_heal(storage: Arc<StorageService>) {
    let _ = PROXY_CACHE_STORAGE.set(storage);
}

fn proxy_storage() -> Option<&'static StorageService> {
    PROXY_CACHE_STORAGE.get().map(|s| s.as_ref())
}

struct ProxyCacheJoinRow {
    path: String,
    storage_key: String,
    metadata_key: String,
    size_bytes: i64,
    checksum_sha256: Option<String>,
    content_type: Option<String>,
    repository_id: Uuid,
    repo_key: String,
}

/// Resolve a UI listing id to an `artifacts.id`, materializing a row from
/// `proxy_cache_artifacts` when needed.
///
/// Returns:
/// - `Ok(Some(id))` when the id already refers to a hosted artifact, or a
///   scannable proxy-cache entry was successfully materialized
/// - `Ok(None)` when the id matches a proxy-cache entry that is **not**
///   scannable (sidecar / index) — caller should keep the honest
///   "not eligible" 404
/// - `Ok(None)` when no artifact and no proxy-cache entry match
///
/// Size-0 catalog placeholders are healed from the metadata sidecar when
/// [`register_storage_for_proxy_catalog_heal`] was called at boot (closes the
/// tee race where Scan/SBOM arrives before the streaming commit refines size).
pub async fn ensure_artifact_for_analysis(db: &PgPool, listing_id: Uuid) -> Result<Option<Uuid>> {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM artifacts WHERE id = $1 AND is_deleted = false")
            .bind(listing_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if existing.is_some() {
        return Ok(existing);
    }

    // O(1) lookup via migration 193 `listing_id`. Fall back to a bounded
    // legacy scan only when the column is still NULL (pre-migration rows
    // that have not been rewritten).
    let row = match fetch_catalog_by_listing_id(db, listing_id).await? {
        Some(row) => row,
        None => match fetch_catalog_by_listing_id_legacy_scan(db, listing_id).await? {
            Some(row) => row,
            None => return Ok(None),
        },
    };

    if !is_scannable_package_path(&row.path) {
        return Ok(None);
    }

    let row = maybe_heal_placeholder(db, proxy_storage(), row).await?;
    if row.size_bytes <= 0 {
        return Ok(None);
    }

    let name = proxy_listing_display_name(&row.path);
    let checksum = row
        .checksum_sha256
        .clone()
        .unwrap_or_else(|| "0".repeat(64));
    let content_type = row
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let id = upsert_proxy_artifact_row(
        db,
        listing_id,
        row.repository_id,
        &row.path,
        &name,
        row.size_bytes,
        &checksum,
        &content_type,
        &row.storage_key,
    )
    .await?;

    Ok(Some(id))
}

async fn fetch_catalog_by_listing_id(
    db: &PgPool,
    listing_id: Uuid,
) -> Result<Option<ProxyCacheJoinRow>> {
    let row = sqlx::query(
        r#"
        SELECT pca.path, pca.storage_key, pca.metadata_key, pca.size_bytes,
               pca.checksum_sha256, pca.content_type, pca.repository_id,
               r.key AS repo_key
        FROM proxy_cache_artifacts pca
        JOIN repositories r ON r.id = pca.repository_id
        WHERE pca.listing_id = $1
          AND r.repo_type = 'remote'
        LIMIT 1
        "#,
    )
    .bind(listing_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    row.map(parse_join_row).transpose()
}

/// Pre-migration rows (or writes that failed to set `listing_id`) — scan only
/// rows still missing `listing_id` so this stays bounded as the column fills.
async fn fetch_catalog_by_listing_id_legacy_scan(
    db: &PgPool,
    listing_id: Uuid,
) -> Result<Option<ProxyCacheJoinRow>> {
    let rows = sqlx::query(
        r#"
        SELECT pca.path, pca.storage_key, pca.metadata_key, pca.size_bytes,
               pca.checksum_sha256, pca.content_type, pca.repository_id,
               r.key AS repo_key
        FROM proxy_cache_artifacts pca
        JOIN repositories r ON r.id = pca.repository_id
        WHERE r.repo_type = 'remote'
          AND pca.listing_id IS NULL
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    for row in rows {
        let parsed = parse_join_row(row)?;
        if proxy_cache_listing_id(&parsed.repo_key, &parsed.path) == listing_id {
            // Best-effort: stamp listing_id so the next lookup is O(1).
            let _ = sqlx::query(
                "UPDATE proxy_cache_artifacts SET listing_id = $1 \
                 WHERE repository_id = $2 AND path = $3 AND listing_id IS NULL",
            )
            .bind(listing_id)
            .bind(parsed.repository_id)
            .bind(&parsed.path)
            .execute(db)
            .await;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn parse_join_row(row: sqlx::postgres::PgRow) -> Result<ProxyCacheJoinRow> {
    use sqlx::Row;
    Ok(ProxyCacheJoinRow {
        path: row
            .try_get("path")
            .map_err(|e| AppError::Database(e.to_string()))?,
        storage_key: row
            .try_get("storage_key")
            .map_err(|e| AppError::Database(e.to_string()))?,
        metadata_key: row
            .try_get("metadata_key")
            .map_err(|e| AppError::Database(e.to_string()))?,
        size_bytes: row
            .try_get("size_bytes")
            .map_err(|e| AppError::Database(e.to_string()))?,
        checksum_sha256: row
            .try_get("checksum_sha256")
            .map_err(|e| AppError::Database(e.to_string()))?,
        content_type: row
            .try_get("content_type")
            .map_err(|e| AppError::Database(e.to_string()))?,
        repository_id: row
            .try_get("repository_id")
            .map_err(|e| AppError::Database(e.to_string()))?,
        repo_key: row
            .try_get("repo_key")
            .map_err(|e| AppError::Database(e.to_string()))?,
    })
}

/// When the catalog still shows a size-0 download placeholder, try to refine
/// it from the on-disk metadata sidecar (positive entries only).
async fn maybe_heal_placeholder(
    db: &PgPool,
    storage: Option<&StorageService>,
    mut row: ProxyCacheJoinRow,
) -> Result<ProxyCacheJoinRow> {
    if row.size_bytes > 0 {
        return Ok(row);
    }
    let Some(storage) = storage else {
        return Ok(row);
    };
    let data = match storage.get(&row.metadata_key).await {
        Ok(data) => data,
        Err(_) => return Ok(row),
    };
    let meta: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Ok(row),
    };
    // Negative-cache sidecars must not heal into a positive catalog row.
    if meta
        .get("negative_cached_until")
        .and_then(|v| v.as_str())
        .is_some()
    {
        return Ok(row);
    }
    let size = meta.get("size_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    if size <= 0 {
        return Ok(row);
    }
    let checksum = meta
        .get("checksum_sha256")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let content_type = meta.get("content_type").and_then(|v| v.as_str());

    if let Err(e) = proxy_catalog::backfill_from_sidecar(
        db,
        row.repository_id,
        &row.repo_key,
        &row.path,
        &row.storage_key,
        &row.metadata_key,
        size,
        checksum,
        content_type,
    )
    .await
    {
        tracing::debug!(
            path = %row.path,
            error = %e,
            "failed to heal size-0 proxy catalog placeholder from sidecar"
        );
        return Ok(row);
    }

    row.size_bytes = size;
    if let Some(c) = checksum {
        row.checksum_sha256 = Some(c.to_string());
    }
    if let Some(ct) = content_type {
        row.content_type = Some(ct.to_string());
    }
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
async fn upsert_proxy_artifact_row(
    db: &PgPool,
    listing_id: Uuid,
    repository_id: Uuid,
    path: &str,
    name: &str,
    size_bytes: i64,
    checksum: &str,
    content_type: &str,
    storage_key: &str,
) -> Result<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, size_bytes,
            checksum_sha256, content_type, storage_key
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            name = EXCLUDED.name,
            storage_key = EXCLUDED.storage_key,
            size_bytes = EXCLUDED.size_bytes,
            checksum_sha256 = EXCLUDED.checksum_sha256,
            content_type = EXCLUDED.content_type,
            is_deleted = false,
            updated_at = NOW()
        RETURNING id
        "#,
    )
    .bind(listing_id)
    .bind(repository_id)
    .bind(path)
    .bind(name)
    .bind(size_bytes)
    .bind(checksum)
    .bind(content_type)
    .bind(storage_key)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(id)
}

/// Materialize a thin `artifacts` row for a known proxy-cache path (keyed
/// lookup — no full-table scan). Returns `None` for non-scannable paths or
/// when the catalog row is missing / still a size-0 placeholder that could
/// not be healed from the sidecar.
pub async fn ensure_artifact_for_proxy_path(
    db: &PgPool,
    repository_id: Uuid,
    repo_key: &str,
    path: &str,
) -> Result<Option<Uuid>> {
    if !is_scannable_package_path(path) {
        return Ok(None);
    }

    let listing_id = proxy_cache_listing_id(repo_key, path);
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM artifacts WHERE id = $1 AND is_deleted = false")
            .bind(listing_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if existing.is_some() {
        return Ok(existing);
    }

    let row = sqlx::query(
        r#"
        SELECT pca.path, pca.storage_key, pca.metadata_key, pca.size_bytes,
               pca.checksum_sha256, pca.content_type, pca.repository_id,
               $3::text AS repo_key
        FROM proxy_cache_artifacts pca
        WHERE pca.repository_id = $1 AND pca.path = $2
        LIMIT 1
        "#,
    )
    .bind(repository_id)
    .bind(path)
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(row) = row else {
        return Ok(None);
    };
    let row = parse_join_row(row)?;
    let row = maybe_heal_placeholder(db, proxy_storage(), row).await?;
    if row.size_bytes <= 0 {
        return Ok(None);
    }

    let name = proxy_listing_display_name(&row.path);
    let checksum = row.checksum_sha256.unwrap_or_else(|| "0".repeat(64));
    let content_type = row
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let id = upsert_proxy_artifact_row(
        db,
        listing_id,
        repository_id,
        &row.path,
        &name,
        row.size_bytes,
        &checksum,
        &content_type,
        &row.storage_key,
    )
    .await?;
    Ok(Some(id))
}

/// True when auto-scan-on-proxy should run for a cache-owning repository
/// (usually a Remote member).
///
/// Smoke / clients pull through Virtual repos, but proxy-cache rows are keyed
/// by the Remote member id. Operators commonly flip Security toggles on the
/// Virtual they use — so we OR the member's own config with any Virtual parent
/// that has `scan_enabled && scan_on_proxy` (same stricter-of-two spirit as
/// [`crate::api::handlers::proxy_helpers::effective_virtual_scan_policy`]).
pub(crate) fn effective_proxy_auto_scan_from_flags(
    member_scan_enabled: bool,
    member_scan_on_proxy: bool,
    virtual_parent_wants_proxy_scan: bool,
) -> bool {
    (member_scan_enabled && member_scan_on_proxy) || virtual_parent_wants_proxy_scan
}

async fn effective_proxy_auto_scan_enabled(db: &PgPool, repository_id: Uuid) -> bool {
    let member: Option<(bool, bool)> = sqlx::query_as(
        "SELECT scan_enabled, scan_on_proxy FROM scan_configs WHERE repository_id = $1",
    )
    .bind(repository_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let (member_enabled, member_on_proxy) = member.unwrap_or((false, false));

    let virtual_wants: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM virtual_repo_members vrm
            JOIN scan_configs sc ON sc.repository_id = vrm.virtual_repo_id
            WHERE vrm.member_repo_id = $1
              AND sc.scan_enabled = true
              AND sc.scan_on_proxy = true
        )
        "#,
    )
    .bind(repository_id)
    .fetch_one(db)
    .await
    .unwrap_or(false);

    effective_proxy_auto_scan_from_flags(member_enabled, member_on_proxy, virtual_wants)
}

/// After a successful proxy-cache write **or** a warm cache hit, enqueue a
/// hosted-pipeline scan for scannable package payloads when effective
/// scan-on-proxy policy is enabled.
///
/// Best-effort and never blocks the client fetch. Sidecars/indexes are
/// skipped. If the scanner was not registered (tests / minimal boot), this
/// is a no-op — callers may still log the historical #1274 warning.
///
/// Retries when the catalog row is not visible yet or still a size-0
/// placeholder (streaming write still committing, or lazy hit-backfill in
/// flight), healing from the sidecar when possible.
pub fn spawn_auto_scan_after_proxy_cache(db: PgPool, repository_id: Uuid, path: String) {
    if !is_scannable_package_path(&path) {
        return;
    }
    let Some(scanner) = PROXY_AUTO_SCANNER.get().cloned() else {
        return;
    };

    tokio::spawn(async move {
        if !effective_proxy_auto_scan_enabled(&db, repository_id).await {
            return;
        }

        let repo_key: Option<String> =
            sqlx::query_scalar("SELECT key FROM repositories WHERE id = $1")
                .bind(repository_id)
                .fetch_optional(&db)
                .await
                .ok()
                .flatten();
        let Some(repo_key) = repo_key else {
            return;
        };

        let mut artifact_id = None;
        for attempt in 0..CATALOG_READY_ATTEMPTS {
            match ensure_artifact_for_proxy_path(&db, repository_id, &repo_key, &path).await {
                Ok(Some(id)) => {
                    artifact_id = Some(id);
                    break;
                }
                Ok(None) => {
                    if attempt + 1 < CATALOG_READY_ATTEMPTS {
                        tokio::time::sleep(CATALOG_READY_DELAY).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        repository_id = %repository_id,
                        path = %path,
                        error = %e,
                        "proxy cache auto-scan materialize failed"
                    );
                    return;
                }
            }
        }

        let Some(artifact_id) = artifact_id else {
            tracing::debug!(
                repository_id = %repository_id,
                path = %path,
                "proxy cache auto-scan skipped: no catalog row yet"
            );
            return;
        };

        // `force=true`: the materialized row lives on the Remote member, but
        // the operator may have enabled scanning only on a Virtual parent.
        // We already validated effective policy above; do not re-gate on the
        // member's `scan_enabled` alone (that would silently no-op).
        if let Err(e) = scanner
            .scan_artifact_with_options(artifact_id, true, false)
            .await
        {
            tracing::warn!(
                repository_id = %repository_id,
                artifact_id = %artifact_id,
                path = %path,
                error = %e,
                "auto-scan after proxy cache failed"
            );
        }
    });
}

/// True when a process-wide scanner was registered for proxy auto-scan.
pub fn proxy_auto_scan_registered() -> bool {
    PROXY_AUTO_SCANNER.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_policy_honors_member_toggles() {
        assert!(effective_proxy_auto_scan_from_flags(true, true, false));
        assert!(!effective_proxy_auto_scan_from_flags(true, false, false));
        assert!(!effective_proxy_auto_scan_from_flags(false, true, false));
        assert!(!effective_proxy_auto_scan_from_flags(false, false, false));
    }

    #[test]
    fn effective_policy_honors_virtual_parent_when_member_off() {
        // Smoke hits Virtual; cache rows are owned by Remote. Toggles on the
        // Virtual alone must still schedule auto-scan.
        assert!(effective_proxy_auto_scan_from_flags(false, false, true));
        assert!(effective_proxy_auto_scan_from_flags(true, false, true));
        assert!(effective_proxy_auto_scan_from_flags(false, true, true));
    }
}
