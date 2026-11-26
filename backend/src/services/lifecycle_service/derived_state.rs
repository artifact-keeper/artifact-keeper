//! The per-artifact delete's remaining post-commit steps, batched for a
//! lifecycle sweep (#6469, the #6333 audit).
//!
//! A sweep soft-deletes in bulk SQL, so it never reaches
//! `ArtifactService::finish_delete` or the REST delete handler. Steps 1 to 3
//! of `execute_in_repository` already cover the catalog Latest, npm
//! dist-tags, the npm packument cache and `oci_tags`. This step covers the
//! rest of what a single delete does:
//!
//! * peers: the push tasks a delete supersedes are cancelled and a `delete`
//!   sync task is fanned out to every push/mirror subscriber, so peers stop
//!   advertising swept versions;
//! * audit: one `ARTIFACT_DELETED` row per artifact, written as one
//!   multi-row INSERT per batch;
//! * events: `artifact.deleted` per artifact, so webhooks and email
//!   subscriptions see retention deletes;
//! * search: the swept documents leave the OpenSearch index, one `_bulk`
//!   request per batch;
//! * Maven: the stored `maven-metadata.xml` documents `mvn deploy` uploaded
//!   (artifact level, and the SNAPSHOT version level) are dropped, once per
//!   GA and once per SNAPSHOT directory, so the next GET regenerates them
//!   from the live rows (#2845, #5667 on the sweep path);
//! * Cargo: the cached sparse-index files of swept crates, here and in every
//!   Virtual above, are dropped (they were cleared on publish only).
//!
//! Cost is bounded: the swept ids are read with one scan, then handled in
//! pages of [`PAGE_SIZE`], each page costing a fixed number of statements, at
//! most one search request, and Maven and Cargo work once per package in the
//! page, not per file.
//!
//! **Recoverable.** The sweep's own transaction records the work as owed, one
//! `lifecycle_sweep_fanouts` row (migration 424) keyed on the repository and
//! the sweep's `deleted_at` stamp. Each page then runs in one transaction that
//! locks that row (`FOR UPDATE SKIP LOCKED`, so two replicas never run the
//! same page), writes the page's peer tasks and audit rows, and advances
//! `done_through` to the page's last id. The row is deleted when every page is
//! done. A restart mid-sweep, or a page whose statements fail, leaves the row
//! behind; [`resume_pending_sweep_fanouts`] (run at the start of every
//! lifecycle tick) picks it up and continues after `done_through`. Peer tasks
//! and audit rows are therefore written exactly once per artifact. Events are
//! published before the page commits, so a crash between the two repeats one
//! page's events rather than losing them (at least once). Search, Maven and
//! Cargo steps are idempotent and stay best-effort, as on the per-artifact
//! path: a failed one is logged and does not hold the page back.
//!
//! **No external I/O waits under the page's locks.** The Maven storage
//! deletes and the Cargo cache invalidation run before the page transaction
//! opens, for the rows the page is about to handle; both are idempotent, and
//! a crash before the commit repeats them with the page. The wait for room on
//! the event bus also happens before the transaction opens. Inside it there
//! are only the page's statements, the in-memory event publish, and the
//! OpenSearch `_bulk` delete, which is bounded by [`SEARCH_DELETE_TIMEOUT`]:
//! a hung cluster costs at most that per page, the timeout is logged as a
//! failed best-effort step, and the page commits.
//!
//! **Nothing is resurrected or over-deleted.** Each page re-reads its rows
//! with `is_deleted = true AND deleted_at = <the sweep's stamp>` and locks them
//! `FOR SHARE` until the page commits. A row restored or re-uploaded (an
//! upload of the same path revives the row) before the page is left out of
//! every step: no peer delete, no audit row, no event, and its search document
//! stays. One revived during the page waits for the page to commit, so its own
//! re-index lands after the page's search delete. Rows another delete stamped
//! are left to that delete's own steps.
//!
//! **Events are paced.** Before each page, [`EventBus::wait_for_room`] waits
//! (at most 2 s) while the slowest subscriber still has a quarter of the
//! buffer queued; the page's events (at most [`PAGE_SIZE`], under half the
//! 1024-slot buffer) then fit without displacing anything. So a large sweep
//! does not make the webhook, email and search consumers drop events,
//! including other repositories' concurrent uploads. Each artifact still gets
//! its own event, as a single delete does; webhook payloads do not change.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::api::IndexCache;
use crate::services::event_bus::{DomainEvent, EventBus, Pacing};
use crate::services::opensearch_service::OpenSearchService;
use crate::storage::StorageRegistry;

/// Swept artifacts per page.
pub(super) const PAGE_SIZE: usize = 500;

/// A sweep whose step has failed this many times is left alone (and logged
/// at error level) instead of being retried on every tick.
pub(super) const MAX_ATTEMPTS: i32 = 20;

/// Pending sweeps resumed per lifecycle tick.
const RESUME_BATCH: i64 = 50;

/// The most a page's OpenSearch `_bulk` delete may take while the page holds
/// its locks. The search client sets no request timeout of its own.
pub(super) const SEARCH_DELETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Services the sweep needs to reach the derived state a delete changes.
/// Every field is optional; a missing one skips only its step (unit tests,
/// or a deployment without OpenSearch).
#[derive(Clone, Default)]
pub struct SweepDerivedState {
    storage_registry: Option<Arc<StorageRegistry>>,
    search_service: Option<Arc<OpenSearchService>>,
    event_bus: Option<Arc<EventBus>>,
    cargo_index_cache: Option<IndexCache>,
}

impl SweepDerivedState {
    pub fn new(
        storage_registry: Option<Arc<StorageRegistry>>,
        search_service: Option<Arc<OpenSearchService>>,
        event_bus: Option<Arc<EventBus>>,
        cargo_index_cache: Option<IndexCache>,
    ) -> Self {
        Self {
            storage_registry,
            search_service,
            event_bus,
            cargo_index_cache,
        }
    }

    /// Everything from the application state, as the request path has it.
    pub fn from_state(state: &crate::api::AppState) -> Self {
        Self::new(
            Some(state.storage_registry.clone()),
            state.search_service.clone(),
            Some(state.event_bus.clone()),
            Some(state.index_cache.clone()),
        )
    }
}

/// One swept artifact, as the steps need it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct SweptRow {
    id: Uuid,
    name: String,
    path: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    uploaded_by: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
struct RepoRow {
    key: String,
    format: String,
    storage_backend: String,
    storage_path: String,
}

/// What a run of [`finish_swept_deletes`] did, for logs and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct SweptFanout {
    pub artifacts: usize,
    pub pages: usize,
    pub peer_tasks: u64,
    pub maven_documents: usize,
    pub cargo_crates: usize,
    /// Every page is done and the sweep's pending row is gone.
    pub completed: bool,
}

/// Record, in the sweep's own transaction, that the derived-state step of
/// the sweep stamped `deleted_at` is owed. Idempotent.
pub(super) async fn record_pending_fanout(
    conn: &mut PgConnection,
    repository_id: Uuid,
    deleted_at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO lifecycle_sweep_fanouts (repository_id, deleted_at) VALUES ($1, $2) \
         ON CONFLICT (repository_id, deleted_at) DO NOTHING",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .execute(conn)
    .await
    .map(|_| ())
}

/// Run the per-artifact delete's remaining steps for every artifact the
/// sweep of `repository_id` soft-deleted in the transaction stamped
/// `deleted_at`, resuming after whatever an earlier run finished. A sweep
/// with no pending row (finished, or never recorded) is a no-op.
pub(super) async fn finish_swept_deletes(
    db: &PgPool,
    derived: &SweepDerivedState,
    repository_id: Uuid,
    deleted_at: DateTime<Utc>,
) -> SweptFanout {
    run_fanout(
        db,
        derived,
        repository_id,
        deleted_at,
        PageLimits::default(),
    )
    .await
}

/// Finish the derived-state step of every sweep a restart or a failure left
/// pending, oldest first, at most [`RESUME_BATCH`] per call. Returns how many
/// completed. Run at the start of each lifecycle tick, under its lease.
pub(super) async fn resume_pending_sweep_fanouts(
    db: &PgPool,
    derived: &SweepDerivedState,
) -> usize {
    resume_pending_in(db, derived, None).await
}

/// [`resume_pending_sweep_fanouts`], optionally for one repository only.
async fn resume_pending_in(
    db: &PgPool,
    derived: &SweepDerivedState,
    repository_id: Option<Uuid>,
) -> usize {
    let pending: Vec<(Uuid, DateTime<Utc>)> = match sqlx::query_as(
        "SELECT repository_id, deleted_at FROM lifecycle_sweep_fanouts \
         WHERE attempts < $1 AND ($3::uuid IS NULL OR repository_id = $3) \
         ORDER BY created_at LIMIT $2",
    )
    .bind(MAX_ATTEMPTS)
    .bind(RESUME_BATCH)
    .bind(repository_id)
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("Lifecycle: failed to list pending sweep fan-outs: {}", e);
            return 0;
        }
    };
    let mut completed = 0;
    for (repository_id, deleted_at) in pending {
        tracing::info!(
            repository_id = %repository_id,
            deleted_at = %deleted_at,
            "Lifecycle: resuming the derived-state step of an interrupted sweep"
        );
        if finish_swept_deletes(db, derived, repository_id, deleted_at)
            .await
            .completed
        {
            completed += 1;
        }
    }
    completed
}

/// One page's outcome.
#[derive(Debug, Default)]
struct PageStats {
    artifacts: usize,
    peer_tasks: u64,
    maven_documents: usize,
    cargo_crates: usize,
}

/// The knobs of [`run_fanout`]; tests shrink them.
#[derive(Debug, Clone, Copy)]
struct PageLimits {
    page_size: usize,
    /// Stop after this many pages, the way a restart would.
    max_pages: usize,
    search_timeout: std::time::Duration,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            page_size: PAGE_SIZE,
            max_pages: usize::MAX,
            search_timeout: SEARCH_DELETE_TIMEOUT,
        }
    }
}

/// [`finish_swept_deletes`] with explicit [`PageLimits`].
async fn run_fanout(
    db: &PgPool,
    derived: &SweepDerivedState,
    repository_id: Uuid,
    deleted_at: DateTime<Utc>,
    limits: PageLimits,
) -> SweptFanout {
    let mut out = SweptFanout::default();
    let done_through: Option<Uuid> = match sqlx::query_scalar(
        "SELECT done_through FROM lifecycle_sweep_fanouts \
         WHERE repository_id = $1 AND deleted_at = $2",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .fetch_optional(db)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Lifecycle: failed to read the pending fan-out of a sweep of repository {}: {}",
                repository_id,
                e
            );
            return out;
        }
    };
    let Some(done_through) = done_through else {
        // Nothing owed: finished already, or another run completed it.
        return out;
    };
    // Exactly this sweep's rows: the trigger stamps every row a transaction
    // soft-deletes with that transaction's NOW(), which is `deleted_at`.
    let ids: Vec<Uuid> = match sqlx::query_scalar(
        "SELECT id FROM artifacts \
         WHERE repository_id = $1 AND is_deleted = true AND deleted_at = $2 AND id > $3 \
         ORDER BY id",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .bind(done_through)
    .fetch_all(db)
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            note_failure(db, repository_id, deleted_at, &e).await;
            return out;
        }
    };
    let repo: Option<RepoRow> = if ids.is_empty() {
        None
    } else {
        sqlx::query_as(
            "SELECT key, format::text AS format, storage_backend, storage_path \
             FROM repositories WHERE id = $1",
        )
        .bind(repository_id)
        .fetch_optional(db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                "Lifecycle: failed to read repository {} after a sweep: {}",
                repository_id,
                e
            );
            None
        })
    };

    for (n, page) in ids.chunks(limits.page_size.max(1)).enumerate() {
        if n >= limits.max_pages {
            return out;
        }
        match run_page(
            db,
            derived,
            repository_id,
            repo.as_ref(),
            deleted_at,
            page,
            limits.search_timeout,
        )
        .await
        {
            Ok(Some(stats)) => {
                if stats.artifacts > 0 {
                    out.pages += 1;
                }
                out.artifacts += stats.artifacts;
                out.peer_tasks += stats.peer_tasks;
                out.maven_documents += stats.maven_documents;
                out.cargo_crates += stats.cargo_crates;
            }
            Ok(None) => {
                // Another runner holds the pending row (it finishes the
                // rest), or it completed meanwhile.
                return out;
            }
            Err(e) => {
                note_failure(db, repository_id, deleted_at, &e).await;
                return out;
            }
        }
    }

    match sqlx::query(
        "DELETE FROM lifecycle_sweep_fanouts WHERE repository_id = $1 AND deleted_at = $2",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .execute(db)
    .await
    {
        // A failed delete only means the next tick finds no rows past
        // `done_through` and deletes it then.
        Ok(_) => out.completed = true,
        Err(e) => tracing::warn!(
            "Lifecycle: failed to clear the finished fan-out of a sweep of repository {}: {}",
            repository_id,
            e
        ),
    }
    tracing::info!(
        repository_id = %repository_id,
        artifacts = out.artifacts,
        peer_tasks = out.peer_tasks,
        maven_documents = out.maven_documents,
        cargo_crates = out.cargo_crates,
        "Lifecycle: finished the derived-state steps of a sweep"
    );
    out
}

/// A page's rows still deleted by this sweep and past `done_through`.
macro_rules! swept_rows_sql {
    ($suffix:literal) => {
        concat!(
            "SELECT id, name, path, version, size_bytes, checksum_sha256, uploaded_by \
             FROM artifacts \
             WHERE id = ANY($1::uuid[]) AND id > $3 AND is_deleted = true AND deleted_at = $2 \
             ORDER BY id",
            $suffix
        )
    };
}

/// One page. First, with no lock held: the Maven and Cargo steps for the
/// page's still-deleted rows, and the wait for room on the event bus. Then
/// one transaction: lock the sweep's pending row and the page's still-deleted
/// rows, write the peer tasks and audit rows, remove the search documents
/// (bounded by `search_timeout`), publish the events, and advance
/// `done_through`.
/// `Ok(None)` when the pending row is locked by another runner or gone.
/// An `Err` rolls the page back; it is retried from `done_through`.
async fn run_page(
    db: &PgPool,
    derived: &SweepDerivedState,
    repository_id: Uuid,
    repo: Option<&RepoRow>,
    deleted_at: DateTime<Utc>,
    page: &[Uuid],
    search_timeout: std::time::Duration,
) -> sqlx::Result<Option<PageStats>> {
    use crate::services::artifact_service::{
        CANCEL_SUPERSEDED_PUSH_TASKS_BATCH_SQL, ENQUEUE_DELETE_SYNC_TASKS_BATCH_SQL,
    };
    use crate::services::audit_service::AuditService;
    let Some(last) = page.last().copied() else {
        return Ok(Some(PageStats::default()));
    };
    let mut stats = PageStats::default();

    // Outside the transaction (#6469 review): storage and cache I/O must not
    // hold the page's locks. Both steps are idempotent, and a row revived
    // since only costs it a regenerated document or a cache refill. A crash
    // before the commit below repeats them when the page is resumed.
    let cursor: Option<Uuid> = sqlx::query_scalar(
        "SELECT done_through FROM lifecycle_sweep_fanouts \
         WHERE repository_id = $1 AND deleted_at = $2",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .fetch_optional(db)
    .await?;
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let unlocked: Vec<SweptRow> = sqlx::query_as(swept_rows_sql!(""))
        .bind(page)
        .bind(deleted_at)
        .bind(cursor)
        .fetch_all(db)
        .await?;
    if let Some(repo) = repo.filter(|_| !unlocked.is_empty()) {
        let (maven_documents, cargo_crates) =
            clear_package_caches(db, derived, repository_id, repo, &unlocked).await;
        stats.maven_documents = maven_documents;
        stats.cargo_crates = cargo_crates;
    }
    if let Some(bus) = derived.event_bus.as_ref().filter(|_| !unlocked.is_empty()) {
        // Room for the whole page before any lock is taken; the publish
        // inside the transaction then never waits.
        bus.wait_for_room(Pacing::for_capacity(bus.capacity()))
            .await;
    }

    let mut tx = db.begin().await?;
    let cursor: Option<Uuid> = sqlx::query_scalar(
        "SELECT done_through FROM lifecycle_sweep_fanouts \
         WHERE repository_id = $1 AND deleted_at = $2 FOR UPDATE SKIP LOCKED",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    // Still deleted by this sweep, and not done by a run that got here
    // first. `FOR SHARE` holds a restore or a reviving re-upload of these
    // rows until the page commits (#6469 review: the search delete and the
    // events must not act on a row that is live again).
    let rows: Vec<SweptRow> = sqlx::query_as(swept_rows_sql!(" FOR SHARE"))
        .bind(page)
        .bind(deleted_at)
        .bind(cursor)
        .fetch_all(&mut *tx)
        .await?;

    let mut entries = Vec::new();
    if !rows.is_empty() {
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        // Exactly once: these commit with the page.
        sqlx::query(CANCEL_SUPERSEDED_PUSH_TASKS_BATCH_SQL)
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        stats.peer_tasks = sqlx::query(ENQUEUE_DELETE_SYNC_TASKS_BATCH_SQL)
            .bind(&ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        entries = audit_entries(repository_id, &rows);
        AuditService::insert_batch_rows_on(&mut *tx, &entries).await?;

        // Best-effort and idempotent, while the rows are locked, and bounded:
        // a hung cluster must not hold the locks.
        if let Some(search) = derived.search_service.as_ref() {
            match tokio::time::timeout(search_timeout, search.remove_artifacts(&ids)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(
                    "Lifecycle: failed to remove {} swept artifacts of repository {} from the search index: {}",
                    ids.len(),
                    repository_id,
                    e
                ),
                Err(_) => tracing::warn!(
                    "Lifecycle: removing {} swept artifacts of repository {} from the search index \
                     took longer than {:?}; left to the search index's own reconcile",
                    ids.len(),
                    repository_id,
                    search_timeout
                ),
            }
        }
        // Before the commit: a crash between the two repeats this page's
        // events on resume instead of losing them. In memory, no waiting:
        // the room was made above.
        if let Some(bus) = derived.event_bus.as_ref() {
            for row in &rows {
                bus.publish(DomainEvent::now_for_repo(
                    "artifact.deleted",
                    row.id.to_string(),
                    repository_id,
                    row.uploaded_by.map(|id| id.to_string()),
                ));
            }
        }
        stats.artifacts = rows.len();
    }

    sqlx::query(
        "UPDATE lifecycle_sweep_fanouts \
         SET done_through = GREATEST(done_through, $3), attempts = 0, last_error = NULL, \
             updated_at = NOW() \
         WHERE repository_id = $1 AND deleted_at = $2",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .bind(last)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // The SIEM copies, once the rows they mirror are committed.
    for entry in &entries {
        crate::services::audit_export::emit_entry(entry);
    }
    Ok(Some(stats))
}

/// The Maven metadata documents and Cargo index cache entries of `rows`'
/// packages. Returns (Maven documents cleared, Cargo crates invalidated).
async fn clear_package_caches(
    db: &PgPool,
    derived: &SweepDerivedState,
    repository_id: Uuid,
    repo: &RepoRow,
    rows: &[SweptRow],
) -> (usize, usize) {
    match repo.format.as_str() {
        "maven" => {
            let mut gas: BTreeSet<(String, String)> = BTreeSet::new();
            let mut snapshot_dirs: BTreeMap<String, String> = BTreeMap::new();
            for row in rows {
                if let Ok(coords) =
                    crate::formats::maven::MavenHandler::parse_coordinates(&row.path)
                {
                    gas.insert((coords.group_id, coords.artifact_id));
                }
                if let Some(dir) =
                    crate::api::handlers::maven::snapshot_version_metadata_dir_key(&row.path)
                {
                    snapshot_dirs.entry(dir).or_insert_with(|| row.path.clone());
                }
            }
            if gas.is_empty() && snapshot_dirs.is_empty() {
                return (0, 0);
            }
            (
                clear_maven(derived, repository_id, repo, &gas, &snapshot_dirs).await,
                0,
            )
        }
        "cargo" => {
            let Some(cache) = derived.cargo_index_cache.as_ref() else {
                return (0, 0);
            };
            let crates: Vec<String> = rows
                .iter()
                .map(|r| r.name.to_lowercase())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            crate::api::handlers::cargo::invalidate_crate_index_caches(
                db,
                cache,
                repository_id,
                &repo.key,
                &crates,
            )
            .await;
            (0, crates.len())
        }
        _ => (0, 0),
    }
}

/// Count a failed attempt on the sweep's pending row; the next tick retries
/// it from `done_through` until [`MAX_ATTEMPTS`].
async fn note_failure(
    db: &PgPool,
    repository_id: Uuid,
    deleted_at: DateTime<Utc>,
    err: &sqlx::Error,
) {
    let attempts: Option<i32> = sqlx::query_scalar(
        "UPDATE lifecycle_sweep_fanouts \
         SET attempts = attempts + 1, last_error = $3, updated_at = NOW() \
         WHERE repository_id = $1 AND deleted_at = $2 RETURNING attempts",
    )
    .bind(repository_id)
    .bind(deleted_at)
    .bind(err.to_string())
    .fetch_optional(db)
    .await
    .unwrap_or(None);
    if attempts.is_some_and(|a| a >= MAX_ATTEMPTS) {
        tracing::error!(
            repository_id = %repository_id,
            deleted_at = %deleted_at,
            "Lifecycle: the derived-state step of a sweep failed {} times and is no longer retried \
             (row in lifecycle_sweep_fanouts): {}",
            MAX_ATTEMPTS,
            err
        );
    } else {
        tracing::warn!(
            repository_id = %repository_id,
            deleted_at = %deleted_at,
            attempts = ?attempts,
            "Lifecycle: a page of a sweep's derived-state step failed; the next lifecycle tick resumes it: {}",
            err
        );
    }
}

/// One `ARTIFACT_DELETED` audit row per swept artifact, with the details the
/// per-artifact delete records. A sweep has no request principal, so the
/// actor is unset, as for any service-internal delete.
fn audit_entries(
    repository_id: Uuid,
    rows: &[SweptRow],
) -> Vec<crate::services::audit_service::AuditEntry> {
    use crate::services::audit_service::{AuditAction, AuditEntry, ResourceType};
    rows.iter()
        .map(|row| {
            AuditEntry::new(AuditAction::ArtifactDeleted, ResourceType::Artifact)
                .resource(row.id)
                .resource_name(row.path.clone())
                .details_typed(crate::services::audit_export::details::ArtifactDetails {
                    repository_id,
                    path: row.path.clone(),
                    name: row.name.clone(),
                    version: row.version.clone(),
                    size_bytes: u64::try_from(row.size_bytes).ok(),
                    digest: Some(format!("sha256:{}", row.checksum_sha256.trim())),
                    uploaded_by: row.uploaded_by,
                })
        })
        .collect()
}

/// Drop the stored Maven metadata documents of every swept GA and SNAPSHOT
/// directory. Returns how many documents were cleared (attempted).
async fn clear_maven(
    derived: &SweepDerivedState,
    repository_id: Uuid,
    repo: &RepoRow,
    gas: &BTreeSet<(String, String)>,
    snapshot_dirs: &BTreeMap<String, String>,
) -> usize {
    let storage = derived.storage_registry.as_ref().and_then(|registry| {
        let location = crate::storage::StorageLocation {
            backend: repo.storage_backend.clone(),
            path: repo.storage_path.clone(),
        };
        registry
            .backend_for(&location)
            .map_err(|e| {
                tracing::warn!(
                    "Lifecycle: storage of repository {} unavailable for the Maven metadata clear: {}",
                    repository_id,
                    e
                );
            })
            .ok()
    });
    for (group_id, artifact_id) in gas {
        crate::api::handlers::maven::clear_stored_maven_metadata_in(
            storage.as_deref(),
            repository_id,
            &repo.storage_backend,
            group_id,
            artifact_id,
        )
        .await;
    }
    if let Some(storage) = storage.as_deref() {
        for artifact_path in snapshot_dirs.values() {
            crate::api::handlers::maven::clear_stored_snapshot_version_metadata_in(
                storage,
                repository_id,
                &repo.storage_backend,
                artifact_path,
            )
            .await;
        }
    }
    gas.len() + snapshot_dirs.len()
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::lifecycle_service::{CreateLifecyclePolicyRequest, LifecycleService};
    use crate::services::peer_instance_service::{PeerInstanceService, ReplicationMode};
    use serde_json::json;

    async fn insert_artifact(
        pool: &PgPool,
        repository_id: Uuid,
        path: &str,
        name: &str,
        version: &str,
        days_ago: i32,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 7, repeat('b', 64), 'application/octet-stream', $2, \
                     NOW() - make_interval(days => $5::INT), NOW() - make_interval(days => $5::INT)) \
             RETURNING id",
        )
        .bind(repository_id)
        .bind(path)
        .bind(name)
        .bind(version)
        .bind(days_ago)
        .fetch_one(pool)
        .await
        .expect("insert artifact")
    }

    async fn push_peer(pool: &PgPool, repository_id: Uuid, tag: &str) -> Uuid {
        let peer = tdh::register_test_peer(pool, "sweep-6469", tag).await;
        PeerInstanceService::new(pool.clone())
            .assign_repository(
                peer,
                repository_id,
                true,
                Some(ReplicationMode::Push),
                None,
                None,
            )
            .await
            .expect("subscribe peer");
        peer
    }

    async fn delete_tasks(pool: &PgPool, peer: Uuid) -> Vec<Uuid> {
        sqlx::query_scalar(
            "SELECT artifact_id FROM sync_tasks \
             WHERE peer_instance_id = $1 AND task_type = 'delete' ORDER BY artifact_id",
        )
        .bind(peer)
        .fetch_all(pool)
        .await
        .expect("read sync tasks")
    }

    async fn audited(pool: &PgPool, ids: &[Uuid]) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log \
             WHERE action = 'ARTIFACT_DELETED' AND resource_id = ANY($1)",
        )
        .bind(ids)
        .fetch_one(pool)
        .await
        .expect("count audit rows")
    }

    async fn cleanup_peer(pool: &PgPool, peer: Uuid) {
        for sql in [
            "DELETE FROM sync_tasks WHERE peer_instance_id = $1",
            "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1",
            "DELETE FROM peer_instances WHERE id = $1",
        ] {
            let _ = sqlx::query(sql).bind(peer).execute(pool).await;
        }
    }

    async fn max_age_policy(service: &LifecycleService, repository_id: Uuid) -> Uuid {
        service
            .create_policy(CreateLifecyclePolicyRequest {
                applies_to_all: false,
                repository_ids: None,
                repository_id: Some(repository_id),
                name: format!("sweep-6469-{}", repository_id.simple()),
                description: None,
                policy_type: "max_age_days".to_string(),
                config: json!({"days": 7}),
                priority: None,
                cron_schedule: None,
                enabled: None,
            })
            .await
            .expect("create lifecycle policy")
            .id
    }

    /// #6469: a max_age sweep of a Maven repository does what a per-artifact
    /// delete does for each swept file: a delete task per push peer (none for
    /// the survivor), an audit row, an `artifact.deleted` event, and the
    /// stored group-level and SNAPSHOT-level `maven-metadata.xml` dropped. A
    /// GA the sweep did not touch keeps its document, and a second run, which
    /// removes nothing, adds nothing.
    #[tokio::test]
    async fn test_sweep_runs_the_per_artifact_delete_steps_for_maven_6469() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let peer = push_peer(&pool, repo, "maven").await;
        let old = insert_artifact(
            &pool,
            repo,
            "com/example/demo/1.0.0/demo-1.0.0.jar",
            "demo",
            "1.0.0",
            30,
        )
        .await;
        let snap = insert_artifact(
            &pool,
            repo,
            "com/example/demo/2.0-SNAPSHOT/demo-2.0-20260101.120000-1.jar",
            "demo",
            "2.0-SNAPSHOT",
            30,
        )
        .await;
        let live = insert_artifact(
            &pool,
            repo,
            "com/example/demo/1.1.0/demo-1.1.0.jar",
            "demo",
            "1.1.0",
            1,
        )
        .await;
        let other = insert_artifact(
            &pool,
            repo,
            "com/example/other/1.0.0/other-1.0.0.jar",
            "other",
            "1.0.0",
            1,
        )
        .await;
        let storage = fx.state.storage_for_repo(&crate::storage::StorageLocation {
            backend: "filesystem".into(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        });
        let storage = storage.expect("storage");
        let ga_doc = "maven/com/example/demo/maven-metadata.xml";
        let snap_doc = "maven/com/example/demo/2.0-SNAPSHOT/maven-metadata.xml";
        let other_doc = "maven/com/example/other/maven-metadata.xml";
        for key in [ga_doc, snap_doc, other_doc] {
            storage
                .put(key, bytes::Bytes::from_static(b"<metadata/>"))
                .await
                .expect("seed stored metadata");
        }

        let bus = fx.state.event_bus.clone();
        let mut events = bus.subscribe();
        let service = LifecycleService::new(pool.clone())
            .with_derived_state(SweepDerivedState::from_state(&fx.state));
        let policy = max_age_policy(&service, repo).await;
        let run = service.execute_policy(policy, false).await.expect("run");
        let mut deleted_events = BTreeSet::new();
        while let Ok(e) = events.try_recv() {
            if e.event_type == "artifact.deleted" {
                deleted_events.insert(e.entity_id);
            }
        }
        let tasks = delete_tasks(&pool, peer).await;
        let audit_rows = audited(&pool, &[old, snap, live, other]).await;
        let ga_left = storage.exists(ga_doc).await.unwrap();
        let snap_left = storage.exists(snap_doc).await.unwrap();
        let other_left = storage.exists(other_doc).await.unwrap();

        let rerun = service.execute_policy(policy, false).await.expect("rerun");
        let tasks_after_rerun = delete_tasks(&pool, peer).await;
        let audit_after_rerun = audited(&pool, &[old, snap, live, other]).await;

        cleanup_peer(&pool, peer).await;
        let _ = sqlx::query("DELETE FROM lifecycle_policies WHERE id = $1")
            .bind(policy)
            .execute(&pool)
            .await;
        fx.teardown().await;

        assert_eq!(run.artifacts_removed, 2);
        let mut swept = vec![old, snap];
        swept.sort();
        assert_eq!(
            tasks, swept,
            "one delete task per swept artifact, none for the live ones"
        );
        assert_eq!(
            audit_rows, 2,
            "one ARTIFACT_DELETED audit row per swept artifact"
        );
        assert_eq!(
            deleted_events,
            BTreeSet::from([old.to_string(), snap.to_string()]),
            "artifact.deleted per swept artifact"
        );
        assert!(!ga_left, "the stored GA maven-metadata.xml is dropped");
        assert!(
            !snap_left,
            "the stored SNAPSHOT maven-metadata.xml is dropped"
        );
        assert!(
            other_left,
            "a GA the sweep did not touch keeps its document"
        );
        assert_eq!(rerun.artifacts_removed, 0);
        assert_eq!(
            tasks_after_rerun, swept,
            "a run that removes nothing adds nothing"
        );
        assert_eq!(audit_after_rerun, 2);
    }

    /// #6469: a Cargo sweep drops the swept crate's cached sparse-index file
    /// (and leaves another crate's), and removes the swept documents from the
    /// search index in one `_bulk` request.
    #[tokio::test]
    async fn test_sweep_drops_cargo_index_cache_and_search_documents_6469() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let Some(fx) = tdh::Fixture::setup("local", "cargo").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let old = insert_artifact(
            &pool,
            repo,
            "democrate/0.1.0/democrate-0.1.0.crate",
            "democrate",
            "0.1.0",
            30,
        )
        .await;
        let _live = insert_artifact(
            &pool,
            repo,
            "democrate/0.2.0/democrate-0.2.0.crate",
            "democrate",
            "0.2.0",
            1,
        )
        .await;
        let cache = fx.state.index_cache.clone();
        for name in ["democrate", "othercrate"] {
            cache.write().await.insert(
                format!("{}:{}", fx.repo_key, name),
                (bytes::Bytes::from_static(b"{}"), std::time::Instant::now()),
            );
        }
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errors": false})))
            .mount(&server)
            .await;
        let search = Arc::new(OpenSearchService::new(&server.uri(), None, None, false).unwrap());
        let derived = SweepDerivedState::new(None, Some(search), None, Some(cache.clone()));
        let service = LifecycleService::new(pool.clone()).with_derived_state(derived);
        let policy = max_age_policy(&service, repo).await;
        let run = service.execute_policy(policy, false).await.expect("run");
        let swept_cached = cache
            .read()
            .await
            .contains_key(&format!("{}:democrate", fx.repo_key));
        let other_cached = cache
            .read()
            .await
            .contains_key(&format!("{}:othercrate", fx.repo_key));
        let requests = server.received_requests().await.unwrap_or_default();

        let _ = sqlx::query("DELETE FROM lifecycle_policies WHERE id = $1")
            .bind(policy)
            .execute(&pool)
            .await;
        fx.teardown().await;

        assert_eq!(run.artifacts_removed, 1);
        assert!(
            !swept_cached,
            "the swept crate's index file is no longer cached"
        );
        assert!(other_cached, "another crate's cached index file is kept");
        assert_eq!(requests.len(), 1, "one _bulk request for the page");
        let body = std::str::from_utf8(&requests[0].body).unwrap();
        assert!(requests[0].url.path().ends_with("/_bulk"));
        assert_eq!(body.lines().count(), 1);
        assert!(
            body.contains(&old.to_string()),
            "the swept id is deleted: {body}"
        );
    }

    /// #6469 guards: a row restored (or re-uploaded, which revives the row)
    /// after the sweep committed is left alone (no delete task, no audit
    /// row), and a row another transaction deleted is not this sweep's.
    #[tokio::test]
    async fn test_sweep_fanout_skips_restored_rows_and_other_deletes_6469() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let peer = push_peer(&pool, repo, "guards").await;
        let restored = insert_artifact(&pool, repo, "a/1/a.bin", "a", "1", 30).await;
        let swept = insert_artifact(&pool, repo, "c/1/c.bin", "c", "1", 30).await;
        let elsewhere = insert_artifact(&pool, repo, "d/1/d.bin", "d", "1", 30).await;

        let mut tx = pool.begin().await.unwrap();
        let deleted_at: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = ANY($1)")
            .bind(vec![restored, swept])
            .execute(&mut *tx)
            .await
            .unwrap();
        record_pending_fanout(&mut tx, repo, deleted_at)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(elsewhere)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE artifacts SET is_deleted = false WHERE id = $1")
            .bind(restored)
            .execute(&pool)
            .await
            .unwrap();

        let out =
            finish_swept_deletes(&pool, &SweepDerivedState::default(), repo, deleted_at).await;
        let tasks = delete_tasks(&pool, peer).await;
        let audit_others = audited(&pool, &[restored, elsewhere]).await;
        let audit_swept = audited(&pool, &[swept]).await;

        cleanup_peer(&pool, peer).await;
        fx.teardown().await;

        assert_eq!(out.artifacts, 1, "only this sweep's still-deleted rows");
        assert_eq!(out.peer_tasks, 1);
        assert_eq!(
            tasks,
            vec![swept],
            "no delete for a restored row or another delete's row"
        );
        assert_eq!(audit_others, 0);
        assert_eq!(audit_swept, 1);
    }

    async fn pending_row(
        pool: &PgPool,
        repo: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Option<(Uuid, i32)> {
        sqlx::query_as(
            "SELECT done_through, attempts FROM lifecycle_sweep_fanouts \
             WHERE repository_id = $1 AND deleted_at = $2",
        )
        .bind(repo)
        .bind(deleted_at)
        .fetch_optional(pool)
        .await
        .expect("read pending fan-out")
    }

    /// Soft-delete `ids` in one transaction, the way a sweep does, and
    /// record the fan-out as owed. Returns the sweep's stamp.
    async fn sweep_by_hand(pool: &PgPool, repo: Uuid, ids: &[Uuid]) -> DateTime<Utc> {
        let mut tx = pool.begin().await.unwrap();
        let deleted_at: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = ANY($1)")
            .bind(ids)
            .execute(&mut *tx)
            .await
            .unwrap();
        record_pending_fanout(&mut tx, repo, deleted_at)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        deleted_at
    }

    /// #6469 review: the step is recoverable. A run stopped after its first
    /// page (as a restart would stop it) leaves the sweep pending with
    /// `done_through` at that page; the next lifecycle tick's resume writes
    /// the remaining peer tasks, audit rows and events, exactly once per
    /// artifact, and clears the pending row. A second resume adds nothing.
    #[tokio::test]
    async fn test_interrupted_sweep_fanout_is_resumed_exactly_once_6469() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let peer = push_peer(&pool, repo, "resume").await;
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(
                insert_artifact(
                    &pool,
                    repo,
                    &format!("r/{i}/r.bin"),
                    "r",
                    &i.to_string(),
                    30,
                )
                .await,
            );
        }
        ids.sort();
        let deleted_at = sweep_by_hand(&pool, repo, &ids).await;
        let bus = Arc::new(EventBus::new(1024));
        let mut events = bus.subscribe();
        let derived = SweepDerivedState::new(None, None, Some(bus.clone()), None);

        // Interrupted after one page of two.
        let first = run_fanout(
            &pool,
            &derived,
            repo,
            deleted_at,
            PageLimits {
                page_size: 2,
                max_pages: 1,
                ..PageLimits::default()
            },
        )
        .await;
        let tasks_mid = delete_tasks(&pool, peer).await;
        let audit_mid = audited(&pool, &ids).await;
        let pending_mid = pending_row(&pool, repo, deleted_at).await;

        // A failed page counts an attempt and keeps the cursor.
        // Scoped to this test's rows, so parallel tests are unaffected.
        let constraint = format!("sweep_6469_block_{}", repo.simple());
        let listed = ids
            .iter()
            .map(|id| format!("'{id}'"))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE audit_log ADD CONSTRAINT {constraint} \
             CHECK (resource_id IS NULL OR resource_id NOT IN ({listed})) NOT VALID"
        )))
        .execute(&pool)
        .await
        .unwrap();
        let failed = run_fanout(
            &pool,
            &derived,
            repo,
            deleted_at,
            PageLimits {
                page_size: 2,
                ..PageLimits::default()
            },
        )
        .await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE audit_log DROP CONSTRAINT {constraint}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        let pending_failed = pending_row(&pool, repo, deleted_at).await;
        let tasks_failed = delete_tasks(&pool, peer).await;

        // The next tick resumes it.
        let resumed = resume_pending_in(&pool, &derived, Some(repo)).await;
        let tasks_end = delete_tasks(&pool, peer).await;
        let audit_end = audited(&pool, &ids).await;
        let pending_end = pending_row(&pool, repo, deleted_at).await;
        let again = finish_swept_deletes(&pool, &derived, repo, deleted_at).await;
        let audit_again = audited(&pool, &ids).await;
        let mut deleted_events: Vec<String> = Vec::new();
        while let Ok(e) = events.try_recv() {
            if e.event_type == "artifact.deleted" {
                deleted_events.push(e.entity_id);
            }
        }

        cleanup_peer(&pool, peer).await;
        fx.teardown().await;

        assert_eq!(first.artifacts, 2);
        assert!(!first.completed);
        assert_eq!(
            tasks_mid,
            ids[..2].to_vec(),
            "only the first page reached the peer"
        );
        assert_eq!(audit_mid, 2);
        assert_eq!(
            pending_mid,
            Some((ids[1], 0)),
            "pending, done through the first page"
        );

        assert_eq!(failed.artifacts, 0, "the failed page rolled back");
        assert_eq!(
            pending_failed,
            Some((ids[1], 1)),
            "one attempt counted, cursor kept"
        );
        assert_eq!(
            tasks_failed,
            ids[..2].to_vec(),
            "the rolled-back page wrote no peer task"
        );

        assert!(resumed >= 1, "the resume completed the sweep");
        assert_eq!(
            tasks_end, ids,
            "every swept artifact has its peer delete task"
        );
        assert_eq!(audit_end, 5, "one audit row per artifact, none repeated");
        assert_eq!(pending_end, None, "the pending row is cleared");
        assert_eq!(again, SweptFanout::default(), "a finished sweep is a no-op");
        assert_eq!(audit_again, 5);
        let mut expected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        expected.sort();
        deleted_events.sort();
        assert_eq!(
            deleted_events, expected,
            "one artifact.deleted per artifact"
        );
    }

    /// #6469 review: a page that another runner holds is left to it (no
    /// double write), and a row revived before the page is not removed from
    /// the search index and gets no event.
    #[tokio::test]
    async fn test_sweep_page_skips_a_held_sweep_and_a_revived_row_6469() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let gone = insert_artifact(&pool, repo, "g/1/g.bin", "g", "1", 30).await;
        let revived = insert_artifact(&pool, repo, "v/1/v.bin", "v", "1", 30).await;
        let deleted_at = sweep_by_hand(&pool, repo, &[gone, revived]).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errors": false})))
            .mount(&server)
            .await;
        let search = Arc::new(OpenSearchService::new(&server.uri(), None, None, false).unwrap());
        let bus = Arc::new(EventBus::new(64));
        let mut events = bus.subscribe();
        let derived = SweepDerivedState::new(None, Some(search), Some(bus.clone()), None);

        // Another runner holds the pending row: this one backs off.
        let mut holder = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM lifecycle_sweep_fanouts WHERE repository_id = $1 AND deleted_at = $2 FOR UPDATE",
        )
        .bind(repo)
        .bind(deleted_at)
        .execute(&mut *holder)
        .await
        .unwrap();
        let held = finish_swept_deletes(&pool, &derived, repo, deleted_at).await;
        holder.rollback().await.unwrap();
        let requests_held = server.received_requests().await.unwrap_or_default().len();

        sqlx::query("UPDATE artifacts SET is_deleted = false WHERE id = $1")
            .bind(revived)
            .execute(&pool)
            .await
            .unwrap();
        let out = finish_swept_deletes(&pool, &derived, repo, deleted_at).await;
        let requests = server.received_requests().await.unwrap_or_default();
        let mut deleted_events = Vec::new();
        while let Ok(e) = events.try_recv() {
            if e.event_type == "artifact.deleted" {
                deleted_events.push(e.entity_id);
            }
        }
        let audit_revived = audited(&pool, &[revived]).await;
        fx.teardown().await;

        assert_eq!(held.artifacts, 0, "a held sweep is left to its holder");
        assert!(!held.completed);
        assert_eq!(requests_held, 0);
        assert_eq!(out.artifacts, 1);
        assert!(out.completed);
        assert_eq!(requests.len(), 1);
        let body = std::str::from_utf8(&requests[0].body).unwrap();
        assert!(body.contains(&gone.to_string()));
        assert!(
            !body.contains(&revived.to_string()),
            "the revived row keeps its search document: {body}"
        );
        assert_eq!(deleted_events, vec![gone.to_string()]);
        assert_eq!(audit_revived, 0);
    }

    /// #6469 re-review: a hung search cluster does not hold the page. The
    /// `_bulk` delete is cut off at the timeout, logged, and the page still
    /// commits its peer task, audit row, event and `done_through`, so the
    /// locks are released and the sweep completes.
    #[tokio::test]
    async fn test_sweep_page_commits_when_search_hangs_6469() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pool = fx.pool.clone();
        let repo = fx.repo_id;
        let peer = push_peer(&pool, repo, "hang").await;
        let swept = insert_artifact(&pool, repo, "h/1/h.bin", "h", "1", 30).await;
        let deleted_at = sweep_by_hand(&pool, repo, &[swept]).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"errors": false}))
                    .set_delay(std::time::Duration::from_secs(60)),
            )
            .mount(&server)
            .await;
        let search = Arc::new(OpenSearchService::new(&server.uri(), None, None, false).unwrap());
        let bus = Arc::new(EventBus::new(64));
        let mut events = bus.subscribe();
        let derived = SweepDerivedState::new(None, Some(search), Some(bus.clone()), None);

        let started = std::time::Instant::now();
        let out = run_fanout(
            &pool,
            &derived,
            repo,
            deleted_at,
            PageLimits {
                search_timeout: std::time::Duration::from_millis(300),
                ..PageLimits::default()
            },
        )
        .await;
        let elapsed = started.elapsed();
        let requests = server.received_requests().await.unwrap_or_default().len();
        let tasks = delete_tasks(&pool, peer).await;
        let audit_rows = audited(&pool, &[swept]).await;
        let pending = pending_row(&pool, repo, deleted_at).await;
        // The row lock is gone: a restore does not wait.
        let restore = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sqlx::query("UPDATE artifacts SET is_deleted = false WHERE id = $1")
                .bind(swept)
                .execute(&pool),
        )
        .await;
        let mut deleted_events = Vec::new();
        while let Ok(e) = events.try_recv() {
            if e.event_type == "artifact.deleted" {
                deleted_events.push(e.entity_id);
            }
        }

        cleanup_peer(&pool, peer).await;
        fx.teardown().await;

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the page did not wait for the hung search request: {elapsed:?}"
        );
        assert_eq!(requests, 1, "the search delete was attempted");
        assert!(out.completed, "the page committed and the sweep completed");
        assert_eq!(out.artifacts, 1);
        assert_eq!(tasks, vec![swept]);
        assert_eq!(audit_rows, 1);
        assert_eq!(pending, None);
        assert_eq!(deleted_events, vec![swept.to_string()]);
        assert!(
            matches!(restore, Ok(Ok(_))),
            "the artifact row is not left locked"
        );
    }
}
