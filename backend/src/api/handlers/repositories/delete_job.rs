//! Repository delete as a background job (#4311).
//!
//! `DELETE /api/v1/repositories/{key}` records a [`repository_delete_jobs`]
//! row, renames the repository out of the way (so its key is free and every
//! by-key lookup misses at once) and answers `202` with the job. A worker
//! then, under a row claim that exactly one replica holds at a time:
//!
//! 1. **collect**: journals the keys that only the repository's own catalog
//!    rows can name (Maven row-less objects, OCI objects) and the in-flight
//!    OCI upload temp keys, before those rows go;
//! 2. **delete_rows**: deletes the repository's `artifacts` and
//!    `artifact_versions` rows in bounded batches, journaling each batch's
//!    storage keys into `oci_gc_candidates` in the same transaction, then the
//!    repository row itself (the rest cascades);
//! 3. **purge**: walks the journaled keys and deletes each object that no
//!    other repository references, re-checking immediately before each delete
//!    behind the upload commit guard ([`purge_key_unless_referenced`]);
//! 4. **cleanup**: the OCI upload temp objects and the proxy-cache subtree.
//!
//! Every phase is idempotent and recorded on the job row, so a job whose
//! replica died (its claim lapses) is resumed by another replica
//! ([`spawn_resumer`]) from the phase it reached.
//!
//! `GET /api/v1/repository-deletions/{id}` reports progress in the shape of a
//! migration job.

use axum::extract::{Extension, Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{is_deleting_key, DELETING_PREFIX};
use crate::storage::{StorageBackend, StorageLocation};

/// Rows deleted (and keys journaled) per batch transaction.
const DELETE_BATCH: i64 = 500;

/// Journaled keys examined per purge page.
const PURGE_PAGE: i64 = 500;

/// Claim lifetime; the renewal heartbeat extends it every third of this.
const CLAIM_TTL_SECS: f64 = 300.0;

/// A job that failed this many claimed runs in a row is marked `failed`.
const MAX_ATTEMPTS: i32 = 5;

/// How often each replica looks for pending jobs and lapsed claims.
const RESUME_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Prefix of the key a repository is renamed to while its delete job runs.
/// `~` is not a legal character of a repository key
/// (`validate_repository_key`), so no repository can be created under it.
/// Defined once in [`crate::models::repository`] and re-used by every by-key
/// resolution site so the delete rename and its central guard cannot drift.
pub(crate) fn deleting_key(job_id: Uuid) -> String {
    format!("{DELETING_PREFIX}{job_id}")
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct RepositoryDeleteJobRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub storage_backend: String,
    pub storage_path: String,
    pub status: String,
    pub phase: String,
    pub total_items: i32,
    pub completed_items: i32,
    pub failed_items: i32,
    pub skipped_items: i32,
    pub total_bytes: i64,
    pub deleted_bytes: i64,
    pub error_summary: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

const JOB_COLUMNS: &str = "id, repository_id, repository_key, storage_backend, storage_path, \
     status, phase, total_items, completed_items, failed_items, skipped_items, total_bytes, \
     deleted_bytes, error_summary, created_by, created_at, started_at, finished_at";

impl RepositoryDeleteJobRow {
    fn location(&self) -> StorageLocation {
        StorageLocation {
            backend: self.storage_backend.clone(),
            path: self.storage_path.clone(),
        }
    }
}

/// A repository delete job, in the shape of a migration job
/// (`GET /api/v1/migrations/{id}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryDeleteJobResponse {
    pub id: Uuid,
    /// Always `repository_delete`.
    pub job_type: String,
    /// `pending`, `running`, `completed` or `failed`.
    pub status: String,
    /// The step the job is in: `queued`, `collect`, `delete_rows`, `purge`,
    /// `cleanup` or `done`.
    pub phase: String,
    pub repository_id: Uuid,
    /// The key the repository had when its delete was requested.
    pub repository_key: String,
    /// Artifacts the repository held when the job started.
    pub total_items: i32,
    /// Artifact rows deleted so far.
    pub completed_items: i32,
    /// Stored objects whose delete failed; storage GC retries them.
    pub failed_items: i32,
    /// Stored objects kept because another repository still references them.
    pub skipped_items: i32,
    /// Bytes the repository's artifacts held when the job started.
    pub total_bytes: i64,
    /// Bytes of the artifact rows deleted so far.
    pub transferred_bytes: i64,
    pub progress_percent: f64,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub error_summary: Option<String>,
    /// Where to poll this job.
    pub status_url: String,
}

impl From<RepositoryDeleteJobRow> for RepositoryDeleteJobResponse {
    fn from(row: RepositoryDeleteJobRow) -> Self {
        let progress_percent = match row.status.as_str() {
            "completed" => 100.0,
            _ if row.total_items > 0 => {
                // Row deletion is the bulk of the work; the purge and cleanup
                // steps after it report 99 until the job completes.
                (f64::from(row.completed_items) * 100.0 / f64::from(row.total_items)).min(99.0)
            }
            _ => 0.0,
        };
        Self {
            status_url: status_url(row.id),
            id: row.id,
            job_type: "repository_delete".to_string(),
            status: row.status,
            phase: row.phase,
            repository_id: row.repository_id,
            repository_key: row.repository_key,
            total_items: row.total_items,
            completed_items: row.completed_items,
            failed_items: row.failed_items,
            skipped_items: row.skipped_items,
            total_bytes: row.total_bytes,
            transferred_bytes: row.deleted_bytes,
            progress_percent,
            started_at: row.started_at,
            finished_at: row.finished_at,
            created_at: row.created_at,
            error_summary: row.error_summary,
        }
    }
}

pub(crate) fn status_url(job_id: Uuid) -> String {
    format!("/api/v1/repository-deletions/{job_id}")
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

/// Record a delete job for `repo` and rename the repository to
/// [`deleting_key`] in one transaction. Returns the job, and `false` when a
/// job for the repository was already in flight (that job is returned).
pub(crate) async fn enqueue(
    db: &PgPool,
    repo: &crate::models::repository::Repository,
    requested_by: Uuid,
) -> Result<(RepositoryDeleteJobRow, bool)> {
    let mut tx = db.begin().await.map_err(db_err)?;
    // Serialise concurrent deletes of one repository on its row.
    let locked: Option<(String,)> =
        sqlx::query_as("SELECT key FROM repositories WHERE id = $1 FOR UPDATE")
            .bind(repo.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    if locked.is_none() {
        return Err(AppError::NotFound("Repository not found".to_string()));
    }
    let existing_sql = format!(
        "SELECT {JOB_COLUMNS} FROM repository_delete_jobs \
         WHERE repository_id = $1 AND status IN ('pending', 'running')"
    );
    if let Some(existing) =
        sqlx::query_as::<_, RepositoryDeleteJobRow>(sqlx::AssertSqlSafe(&*existing_sql))
            .bind(repo.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
    {
        return Ok((existing, false));
    }
    // A repository a failed job left renamed keeps the key it had when its
    // delete was first requested, so the new job still purges that key's
    // proxy-cache subtree and still answers a `DELETE` of that key.
    let original_key = if is_deleting_key(&repo.key) {
        sqlx::query_scalar::<_, String>(
            "SELECT repository_key FROM repository_delete_jobs \
              WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .unwrap_or_else(|| repo.key.clone())
    } else {
        repo.key.clone()
    };
    let insert_sql = format!(
        "INSERT INTO repository_delete_jobs \
             (repository_id, repository_key, storage_backend, storage_path, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING {JOB_COLUMNS}"
    );
    let location = repo.storage_location();
    let job = sqlx::query_as::<_, RepositoryDeleteJobRow>(sqlx::AssertSqlSafe(&*insert_sql))
        .bind(repo.id)
        .bind(&original_key)
        .bind(&location.backend)
        .bind(&location.path)
        .bind(requested_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE repositories SET key = $2, updated_at = NOW() WHERE id = $1")
        .bind(repo.id)
        .bind(deleting_key(job.id))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    // Virtual repositories resolve their members by id, not by key: drop the
    // repository from every virtual now, as the synchronous delete's cascade
    // did, so no virtual keeps serving the artifacts the job has not deleted
    // yet.
    sqlx::query("DELETE FROM virtual_repo_members WHERE member_repo_id = $1")
        .bind(repo.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok((job, true))
}

/// The repository a delete job is still working on, or that a failed job
/// left renamed, under the key it had when its delete was requested. A
/// repeated `DELETE` of that key then returns the job in flight, or starts a
/// new one after a failure, instead of answering 404 (#4311). `None` when no
/// such repository remains (the job completed, or none was ever requested).
pub(crate) async fn repository_awaiting_delete(
    db: &PgPool,
    original_key: &str,
) -> Result<Option<Uuid>> {
    sqlx::query_scalar(
        "SELECT j.repository_id FROM repository_delete_jobs j \
           JOIN repositories r ON r.id = j.repository_id \
          WHERE j.repository_key = $1 AND r.key = $2 || j.id::text \
          ORDER BY j.created_at DESC LIMIT 1",
    )
    .bind(original_key)
    .bind(DELETING_PREFIX)
    .fetch_optional(db)
    .await
    .map_err(db_err)
}

/// Load one job.
pub(crate) async fn load(db: &PgPool, job_id: Uuid) -> Result<Option<RepositoryDeleteJobRow>> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM repository_delete_jobs WHERE id = $1");
    sqlx::query_as::<_, RepositoryDeleteJobRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(job_id)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

/// A job this process holds the claim on.
struct ClaimedJob {
    row: RepositoryDeleteJobRow,
    token: Uuid,
}

/// Claim `job_id` (or, with `None`, the oldest claimable job): a pending job,
/// or a running one whose claim lapsed because its replica died.
async fn claim(db: &PgPool, job_id: Option<Uuid>) -> Result<Option<ClaimedJob>> {
    let token = Uuid::new_v4();
    let sql = format!(
        "UPDATE repository_delete_jobs SET \
             status = 'running', claim_token = $2, claimed_by = $3, \
             claim_expires_at = NOW() + make_interval(secs => $4), \
             started_at = COALESCE(started_at, NOW()), attempts = attempts + 1, \
             updated_at = NOW() \
         WHERE id = ( \
             SELECT id FROM repository_delete_jobs \
              WHERE (status = 'pending' \
                     OR (status = 'running' AND claim_expires_at < NOW())) \
                AND ($1::uuid IS NULL OR id = $1) \
              ORDER BY created_at \
              LIMIT 1 \
              FOR UPDATE SKIP LOCKED) \
         RETURNING {JOB_COLUMNS}"
    );
    let row = sqlx::query_as::<_, RepositoryDeleteJobRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(job_id)
        .bind(token)
        .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str())
        .bind(CLAIM_TTL_SECS)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    Ok(row.map(|row| ClaimedJob { row, token }))
}

const RENEW_SQL: &str = "UPDATE repository_delete_jobs \
     SET claim_expires_at = NOW() + make_interval(secs => $3) \
     WHERE id = $1 AND claim_token = $2 AND status = 'running'";

/// Record progress under the claim. `Ok(false)`: the claim was lost.
async fn set_phase(db: &PgPool, job: &ClaimedJob, phase: &str) -> Result<bool> {
    let done = sqlx::query(
        "UPDATE repository_delete_jobs SET phase = $3, updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2 AND status = 'running'",
    )
    .bind(job.row.id)
    .bind(job.token)
    .bind(phase)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

async fn add_counts(
    db: &PgPool,
    job: &ClaimedJob,
    completed: i64,
    deleted_bytes: i64,
    failed: i64,
    skipped: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE repository_delete_jobs SET \
             completed_items = completed_items + $3, deleted_bytes = deleted_bytes + $4, \
             failed_items = failed_items + $5, skipped_items = skipped_items + $6, \
             updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.row.id)
    .bind(job.token)
    .bind(completed as i32)
    .bind(deleted_bytes)
    .bind(failed as i32)
    .bind(skipped as i32)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Why a run stopped before the job finished.
enum Stop {
    /// Another replica owns the job now; leave it alone.
    LeaseLost,
    /// A step failed; release the claim so the job is retried.
    Failed(AppError),
}

impl From<AppError> for Stop {
    fn from(e: AppError) -> Self {
        Stop::Failed(e)
    }
}

fn check(lost: &CancellationToken) -> std::result::Result<(), Stop> {
    if lost.is_cancelled() {
        Err(Stop::LeaseLost)
    } else {
        Ok(())
    }
}

/// Spawn a worker for `job_id` now (the request that created it).
pub(crate) fn spawn_job(state: SharedState, job_id: Uuid) {
    tokio::spawn(async move {
        if let Err(e) = run_claimable(&state, Some(job_id)).await {
            tracing::warn!(job_id = %job_id, error = %e, "repository delete job could not start");
        }
    });
}

/// Spawn the per-replica loop that resumes pending jobs and jobs whose
/// claim lapsed (a replica that died mid-delete). Stops with `shutdown`.
pub fn spawn_resumer(state: SharedState, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RESUME_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            loop {
                match run_claimable(&state, None).await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "repository delete resumer could not claim a job");
                        break;
                    }
                }
            }
        }
    });
}

/// Claim and run one job. `Ok(false)` when nothing was claimable.
pub(crate) async fn run_claimable(state: &SharedState, job_id: Option<Uuid>) -> Result<bool> {
    let Some(job) = claim(&state.db, job_id).await? else {
        return Ok(false);
    };
    let job_id = job.row.id;
    let (renewal, lost) = crate::services::cluster_work::spawn_row_claim_renewal(
        state.db.clone(),
        format!("repository delete job {job_id}"),
        RENEW_SQL,
        job_id,
        job.token,
        CLAIM_TTL_SECS,
    );
    let outcome = run(state, &job, &lost).await;
    drop(renewal);
    match outcome {
        Ok(()) => {
            finish(&state.db, &job, "completed", None).await;
            state.event_bus.emit_repository_event(
                "repository.deleted",
                job.row.repository_id,
                None,
            );
            tracing::info!(
                job_id = %job_id,
                repository_key = %job.row.repository_key,
                "Repository delete job completed"
            );
        }
        Err(Stop::LeaseLost) => {
            tracing::warn!(job_id = %job_id, "repository delete job lost its claim; another replica continues it");
        }
        Err(Stop::Failed(e)) => {
            tracing::warn!(job_id = %job_id, error = %e, "repository delete job step failed");
            release_after_failure(&state.db, &job, &e.to_string()).await;
        }
    }
    Ok(true)
}

async fn finish(db: &PgPool, job: &ClaimedJob, status: &str, error: Option<&str>) {
    let _ = sqlx::query(
        "UPDATE repository_delete_jobs SET status = $3, phase = 'done', error_summary = $4, \
             finished_at = NOW(), claim_token = NULL, claim_expires_at = NULL, updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.row.id)
    .bind(job.token)
    .bind(status)
    .bind(error)
    .execute(db)
    .await;
}

/// Put a job whose step failed back to `pending` for the resumer, or mark it
/// `failed` once it has failed [`MAX_ATTEMPTS`] runs.
async fn release_after_failure(db: &PgPool, job: &ClaimedJob, error: &str) {
    let _ = sqlx::query(
        "UPDATE repository_delete_jobs SET \
             status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END, \
             finished_at = CASE WHEN attempts >= $3 THEN NOW() ELSE NULL END, \
             error_summary = $4, claim_token = NULL, claim_expires_at = NULL, updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.row.id)
    .bind(job.token)
    .bind(MAX_ATTEMPTS)
    .bind(error)
    .execute(db)
    .await;
}

const PHASES: [&str; 5] = ["queued", "collect", "delete_rows", "purge", "cleanup"];

fn phase_index(phase: &str) -> usize {
    PHASES.iter().position(|p| *p == phase).unwrap_or(0)
}

async fn run(
    state: &SharedState,
    job: &ClaimedJob,
    lost: &CancellationToken,
) -> std::result::Result<(), Stop> {
    let start = phase_index(&job.row.phase);
    let next = |phase: &'static str| async move {
        if set_phase(&state.db, job, phase).await? {
            Ok(())
        } else {
            Err(Stop::LeaseLost)
        }
    };
    if start <= phase_index("collect") {
        next("collect").await?;
        collect(state, job).await?;
    }
    check(lost)?;
    if start <= phase_index("delete_rows") {
        next("delete_rows").await?;
        delete_rows(state, job, lost).await?;
    }
    check(lost)?;
    if start <= phase_index("purge") {
        next("purge").await?;
        purge(state, job, lost).await?;
    }
    check(lost)?;
    next("cleanup").await?;
    cleanup(state, job).await;
    Ok(())
}

/// Journal what only the repository's own catalog rows can name, before any
/// of them goes: OCI objects (left to storage GC's candidate sweep, which
/// owns them), Maven row-less objects and, on filesystem, the Maven sidecars
/// derived from artifact keys (both purged below), and the in-flight OCI
/// upload temp keys (kept on the job row). Idempotent.
async fn collect(state: &SharedState, job: &ClaimedJob) -> std::result::Result<(), Stop> {
    let repo_id = job.row.repository_id;
    let location = job.row.location();
    // The original key is free from the moment the delete was accepted, so a
    // repository created under it must not find this one's cached upstream
    // content (#2047). Purge the subtree first, not only at the end of the
    // job; `cleanup` repeats it for anything cached meanwhile.
    purge_proxy_cache(state, job).await;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM repositories WHERE id = $1)")
            .bind(repo_id)
            .fetch_one(&state.db)
            .await
            .map_err(db_err)?;
    if !exists {
        // Resumed after the repository row went: nothing left to collect.
        return Ok(());
    }
    let (total_items, total_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    let temp_keys = super::collect_repo_oci_upload_temp_keys(state, repo_id).await;
    sqlx::query(
        "UPDATE repository_delete_jobs SET total_items = $3, total_bytes = $4, \
             oci_temp_keys = $5, updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.row.id)
    .bind(job.token)
    .bind(total_items as i32)
    .bind(total_bytes)
    .bind(serde_json::json!(temp_keys))
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    crate::services::storage_gc_service::record_oci_gc_candidates(&state.db, repo_id, &location)
        .await?;
    let mut keys = super::collect_repo_maven_flat_keys(state, repo_id).await;
    if location.backend == "filesystem" {
        keys.extend(super::collect_repo_maven_derived_keys(state, repo_id).await);
    }
    crate::services::storage_gc_service::journal_repository_delete_keys(
        &state.db, repo_id, &location, &keys,
    )
    .await?;
    Ok(())
}

/// Delete the repository's rows in bounded batches, journaling each batch's
/// storage keys in the same transaction, then the repository row.
async fn delete_rows(
    state: &SharedState,
    job: &ClaimedJob,
    lost: &CancellationToken,
) -> std::result::Result<(), Stop> {
    let repo_id = job.row.repository_id;
    let scope = crate::services::storage_gc_service::oci_gc_candidate_scope(&job.row.location());
    for table in ["artifacts", "artifact_versions"] {
        loop {
            check(lost)?;
            let (deleted, bytes) =
                delete_batch(&state.db, table, repo_id, &job.row.repository_key, &scope).await?;
            if table == "artifacts" {
                add_counts(&state.db, job, deleted, bytes, 0, 0).await?;
            }
            // Until a batch finds nothing: a row an upload committed
            // meanwhile is picked up (and journaled) by a later batch.
            if deleted == 0 {
                break;
            }
        }
    }
    check(lost)?;
    match state.create_repository_service().delete(repo_id).await {
        Ok(()) | Err(AppError::NotFound(_)) => {}
        Err(e) => return Err(Stop::Failed(e)),
    }
    Ok(())
}

/// One batch: journal the keys of up to [`DELETE_BATCH`] rows of `table` and
/// delete those rows, in one transaction. Returns `(rows, bytes)`.
///
/// For `artifacts`, the batch's rows are locked first and a delete task per
/// push/mirror peer is queued for them in the same transaction, addressed by
/// `repository_key` (the key the repository had before the job renamed it)
/// and path, so the peers lose the repository's contents too (#5624).
async fn delete_batch(
    db: &PgPool,
    table: &'static str,
    repo_id: Uuid,
    repository_key: &str,
    scope: &StorageLocation,
) -> Result<(i64, i64)> {
    let mut tx = db.begin().await.map_err(db_err)?;
    let ids: Option<Vec<Uuid>> = if table == "artifacts" {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM artifacts WHERE repository_id = $1 ORDER BY id LIMIT $2 FOR UPDATE",
        )
        .bind(repo_id)
        .bind(DELETE_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        crate::services::peer_instance_service::PeerInstanceService::queue_deletes_before_removal(
            &mut tx,
            repo_id,
            repository_key,
            &ids,
        )
        .await?;
        Some(ids)
    } else {
        None
    };
    let sql = format!(
        "WITH batch AS ( \
             SELECT id, storage_key, size_bytes FROM {table} \
              WHERE repository_id = $1 AND ($5::uuid[] IS NULL OR id = ANY($5)) \
              ORDER BY id LIMIT $4 FOR UPDATE), \
         journal AS ( \
             INSERT INTO oci_gc_candidates \
                 (storage_key, storage_backend, storage_path, source_repository_id) \
             SELECT DISTINCT b.storage_key, $2, $3, $1 FROM batch b \
              WHERE {purgeable} \
             ON CONFLICT (storage_backend, storage_path, storage_key) DO NOTHING), \
         gone AS ( \
             DELETE FROM {table} t USING batch b WHERE t.id = b.id RETURNING b.size_bytes) \
         SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)::BIGINT FROM gone",
        purgeable = super::purgeable_key_sql("b.storage_key"),
    );
    let (rows, bytes): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(repo_id)
        .bind(&scope.backend)
        .bind(&scope.path)
        .bind(DELETE_BATCH)
        .bind(ids)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok((rows, bytes))
}

/// Delete every journaled object of the repository that no other repository
/// references.
async fn purge(
    state: &SharedState,
    job: &ClaimedJob,
    lost: &CancellationToken,
) -> std::result::Result<(), Stop> {
    let location = job.row.location();
    let storage = state.storage_for_repo(&location).map_err(Stop::Failed)?;
    let scope = crate::services::storage_gc_service::oci_gc_candidate_scope(&location);
    let sql = format!(
        "SELECT id, storage_key FROM oci_gc_candidates \
          WHERE source_repository_id = $1 AND storage_backend = $2 AND storage_path = $3 \
            AND id > $4 AND {purgeable} \
          ORDER BY id LIMIT $5",
        purgeable = super::purgeable_key_sql("storage_key"),
    );
    let mut after = 0_i64;
    loop {
        check(lost)?;
        let page: Vec<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
            .bind(job.row.repository_id)
            .bind(&scope.backend)
            .bind(&scope.path)
            .bind(after)
            .bind(PURGE_PAGE)
            .fetch_all(&state.db)
            .await
            .map_err(db_err)?;
        let Some((last, _)) = page.last() else {
            return Ok(());
        };
        after = *last;
        let (mut failed, mut kept) = (0_i64, 0_i64);
        for (_, key) in &page {
            match purge_key_unless_referenced(
                &state.db,
                storage.as_ref(),
                &location,
                job.row.repository_id,
                key,
            )
            .await
            {
                PurgeOutcome::Deleted => {}
                PurgeOutcome::Kept => kept += 1,
                PurgeOutcome::Failed => failed += 1,
            }
        }
        add_counts(&state.db, job, 0, 0, failed, kept).await?;
        if (page.len() as i64) < PURGE_PAGE {
            return Ok(());
        }
    }
}

/// OCI upload temp objects and the proxy-cache subtree. Best-effort, like the
/// synchronous delete was.
async fn cleanup(state: &SharedState, job: &ClaimedJob) {
    let temp_keys: Vec<String> = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT oci_temp_keys FROM repository_delete_jobs WHERE id = $1",
    )
    .bind(job.row.id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|keys| serde_json::from_value(keys).ok())
    .unwrap_or_default();
    super::purge_oci_upload_temp_objects(
        state,
        job.row.repository_id,
        &job.row.location(),
        temp_keys,
    )
    .await;
    purge_proxy_cache(state, job).await;
}

/// Purge the proxy-cache subtree of the repository's original key, unless a
/// repository has been created under that key since: what is cached there is
/// then that repository's own. Best-effort, like the synchronous delete was.
async fn purge_proxy_cache(state: &SharedState, job: &ClaimedJob) {
    let key_reused: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM repositories WHERE key = $1)")
            .bind(&job.row.repository_key)
            .fetch_one(&state.db)
            .await
            .unwrap_or(true);
    if key_reused {
        return;
    }
    if let Some(proxy) = state.proxy_service.as_ref() {
        match proxy.purge_repo_cache(&job.row.repository_key).await {
            Ok(purged) if purged > 0 => tracing::info!(
                repo_id = %job.row.repository_id,
                repo_key = %job.row.repository_key,
                purged,
                "Purged proxy-cache storage objects for deleted repository"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                repo_id = %job.row.repository_id,
                repo_key = %job.row.repository_key,
                error = %e,
                "Failed to list proxy-cache objects to purge after repository delete"
            ),
        }
    }
}

/// What [`purge_key_unless_referenced`] did with one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PurgeOutcome {
    /// The object was deleted (or was already gone).
    Deleted,
    /// Another repository references the key; the object stays and its
    /// journal row is left for storage GC's candidate sweep.
    Kept,
    /// The delete failed; the journal row is left for the candidate sweep.
    Failed,
}

/// Delete the object at `key`, which repository `repo_id` (being deleted)
/// held, unless another repository references it.
///
/// The key's `oci_gc_candidates` row is the slot every upload commit takes
/// first (`artifact_service::begin_guarded_cas_commit`), so the reference
/// check runs immediately before the delete with the slot held:
///
/// 1. In one transaction: upsert the slot as a lease (`leased_at = NOW()`,
///    `source_repository_id` kept non-null). This waits for an upload commit
///    that holds the slot; then check references from repositories other than
///    `repo_id`. A reference keeps the object; the lease is cleared and the
///    row stays for the candidate sweep.
/// 2. Otherwise commit the lease, delete the object, then drop the row. An
///    upload of identical content that reaches the guard while the lease is
///    fresh waits for the row to go and writes its bytes again; one that
///    committed before step 1 is the reference that keeps the object.
///
/// A failed delete clears the lease so uploads are not held for its 15
/// minutes, and leaves the row for the candidate sweep.
pub(crate) async fn purge_key_unless_referenced(
    db: &PgPool,
    storage: &dyn StorageBackend,
    location: &StorageLocation,
    repo_id: Uuid,
    key: &str,
) -> PurgeOutcome {
    let scope = crate::services::storage_gc_service::oci_gc_candidate_scope(location);
    let leased = async {
        let mut tx = db.begin().await.map_err(db_err)?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO oci_gc_candidates \
                 (storage_key, storage_backend, storage_path, source_repository_id, leased_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (storage_backend, storage_path, storage_key) \
                 DO UPDATE SET recorded_at = NOW() \
             RETURNING id",
        )
        .bind(key)
        .bind(&scope.backend)
        .bind(&scope.path)
        .bind(repo_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        let sql = format!(
            "SELECT {}",
            super::key_held_by_another_repository_sql("$1", "$2", "$3", "$4")
        );
        let referenced: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(&*sql))
            .bind(key)
            .bind(&location.backend)
            .bind(&location.path)
            .bind(repo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        if referenced {
            sqlx::query("UPDATE oci_gc_candidates SET leased_at = NULL WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Result::Ok((id, referenced))
    }
    .await;
    let (id, referenced) = match leased {
        Ok(leased) => leased,
        Err(e) => {
            tracing::warn!(storage_key = %key, error = %e, "Could not lease an object for repository-delete purge; leaving it to storage GC");
            return PurgeOutcome::Failed;
        }
    };
    if referenced {
        return PurgeOutcome::Kept;
    }
    match storage.delete(key).await {
        Ok(()) | Err(AppError::NotFound(_)) => {
            let _ = sqlx::query("DELETE FROM oci_gc_candidates WHERE id = $1")
                .bind(id)
                .execute(db)
                .await;
            PurgeOutcome::Deleted
        }
        Err(e) => {
            tracing::warn!(storage_key = %key, error = %e, "Failed to purge artifact object for repository delete");
            let _ = sqlx::query("UPDATE oci_gc_candidates SET leased_at = NULL WHERE id = $1")
                .bind(id)
                .execute(db)
                .await;
            PurgeOutcome::Failed
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/repository-deletions/{id}
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new().route("/:id", get(get_repository_deletion))
}

/// Status of a repository delete job (#4311).
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/repository-deletions",
    tag = "repositories",
    params(("id" = Uuid, Path, description = "Delete job id returned by DELETE /api/v1/repositories/{key}")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The delete job", body = RepositoryDeleteJobResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "No such job, or not visible to the caller"),
    )
)]
pub async fn get_repository_deletion(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<RepositoryDeleteJobResponse>> {
    let auth = super::require_auth(auth)?;
    let job = load(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Repository delete job not found".to_string()))?;
    // The requester and instance admins see a job; anyone else gets the same
    // 404 as a job that does not exist.
    if !auth.is_admin && job.created_by != Some(auth.user_id) {
        return Err(AppError::NotFound(
            "Repository delete job not found".to_string(),
        ));
    }
    Ok(Json(job.into()))
}

#[cfg(test)]
pub(crate) async fn run_to_completion(state: &SharedState, job_id: Uuid) -> RepositoryDeleteJobRow {
    // The request spawned a worker that may hold the claim; claim it here if
    // it does not, and wait for whichever runs it.
    let _ = run_claimable(state, Some(job_id)).await;
    for _ in 0..600 {
        let job = load(&state.db, job_id).await.unwrap().expect("job row");
        if matches!(job.status.as_str(), "completed" | "failed") {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = run_claimable(state, Some(job_id)).await;
    }
    panic!("repository delete job {job_id} did not finish");
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    /// Seed `n` artifact rows in the fixture repository, the first `objects`
    /// of them with a stored object. Returns the stored keys.
    async fn seed(fx: &tdh::Fixture, n: i64, objects: usize) -> Vec<String> {
        let keys: Vec<String> = sqlx::query_scalar(
            "INSERT INTO artifacts \
                 (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             SELECT $1, 'bulk/' || g || '.bin', g || '.bin', 3, md5(g::text || $2), \
                    'application/octet-stream', 'bulk/' || md5(g::text || $2) \
               FROM generate_series(1, $3) g \
             RETURNING storage_key",
        )
        .bind(fx.repo_id)
        .bind(fx.repo_id.to_string())
        .bind(n)
        .fetch_all(&fx.pool)
        .await
        .expect("seed artifacts");
        let storage = fx
            .state
            .storage_for_repo(&StorageLocation {
                backend: "filesystem".to_string(),
                path: fx.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        for key in keys.iter().take(objects) {
            storage
                .put(key, bytes::Bytes::from_static(b"abc"))
                .await
                .expect("put");
        }
        keys.into_iter().take(objects).collect()
    }

    fn admin(fx: &tdh::Fixture) -> AuthExtension {
        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = true;
        auth
    }

    /// #4311: `DELETE /api/v1/repositories/{key}` answers 202 with the job at
    /// once; the key stops resolving; the job deletes the rows in batches,
    /// reclaims the objects and reports completion through the status
    /// endpoint in the migration-job shape.
    #[tokio::test]
    async fn delete_answers_202_and_the_job_reclaims_the_repository_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let stored = seed(&fx, DELETE_BATCH * 2 + 17, 3).await;
        let app = tdh::router_with_auth(super::super::router(), fx.state.clone(), admin(&fx));
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{}", fx.repo_key))
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, body, headers) = tdh::send_with_headers(app, req).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let location = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("Location");
        let accepted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let job_id: Uuid = accepted["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(location, format!("/api/v1/repository-deletions/{job_id}"));
        assert_eq!(accepted["job_type"], "repository_delete");
        assert_eq!(accepted["repository_key"], fx.repo_key);

        // The key is free at once.
        let lookup = fx
            .state
            .create_repository_service()
            .get_by_key(&fx.repo_key)
            .await;
        assert!(matches!(lookup, Err(AppError::NotFound(_))), "{lookup:?}");

        // The temporary key the job renames the repository to is not a
        // back door: every by-key resolution treats it as absent (#5002).
        let renamed = deleting_key(job_id);
        let renamed_lookup = fx
            .state
            .create_repository_service()
            .get_by_key(&renamed)
            .await;
        assert!(
            matches!(renamed_lookup, Err(AppError::NotFound(_))),
            "{renamed_lookup:?}"
        );
        assert!(is_deleting_key(&renamed));

        let job = run_to_completion(&fx.state, job_id).await;
        assert_eq!(job.status, "completed", "{job:?}");
        assert_eq!(job.total_items as i64, DELETE_BATCH * 2 + 17);
        assert_eq!(job.completed_items, job.total_items);
        let gone: bool =
            sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM repositories WHERE id = $1)")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert!(gone, "the repository row is deleted");
        for key in &stored {
            assert!(
                !fx.storage_dir.join(key).exists(),
                "object {key} must be purged"
            );
        }
        let journaled: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_gc_candidates WHERE source_repository_id = $1",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(journaled, 0, "purged keys leave no journal rows");

        let status_app = tdh::router_with_auth(super::router(), fx.state.clone(), admin(&fx));
        let (status, body) = tdh::send(status_app, tdh::get(format!("/{job_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        let polled: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(polled["status"], "completed");
        assert_eq!(polled["progress_percent"], 100.0);
        assert_eq!(polled["completed_items"], DELETE_BATCH * 2 + 17);

        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// #5624: deleting a repository removes its contents from its push and
    /// mirror peers too. Each batch queues a delete per subscriber and
    /// artifact before the rows go, addressed by the key the repository had
    /// before the job renamed it; the cascade used to drop even the deletes
    /// already queued, so the peers kept everything.
    #[tokio::test]
    async fn repository_delete_queues_peer_deletes_by_path_5624() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let n = DELETE_BATCH + 3;
        seed(&fx, n, 0).await;
        let mut peers = Vec::new();
        for mode in ["push", "mirror", "pull"] {
            let peer_id = tdh::register_test_peer(&fx.pool, "repo-delete", mode).await;
            sqlx::query(
                "INSERT INTO peer_repo_subscriptions \
                     (peer_instance_id, repository_id, sync_enabled, replication_mode) \
                 VALUES ($1, $2, true, $3::text::replication_mode)",
            )
            .bind(peer_id)
            .bind(fx.repo_id)
            .bind(mode)
            .execute(&fx.pool)
            .await
            .expect("subscribe peer");
            peers.push(peer_id);
        }
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let done = run_to_completion(&fx.state, job.id).await;
        let mut counts = Vec::new();
        for peer_id in &peers {
            let row: (i64, i64, i64) = sqlx::query_as(
                "SELECT COUNT(*), \
                        COUNT(*) FILTER (WHERE artifact_id IS NULL AND status = 'pending' \
                                           AND target_repository_key = $2 \
                                           AND target_path LIKE 'bulk/%'), \
                        COUNT(DISTINCT target_path) \
                 FROM sync_tasks WHERE peer_instance_id = $1 AND task_type = 'delete'",
            )
            .bind(peer_id)
            .bind(&fx.repo_key)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
            counts.push(row);
        }
        for peer_id in &peers {
            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer_id)
                .execute(&fx.pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert_eq!(done.status, "completed", "{done:?}");
        assert_eq!(
            counts[0],
            (n, n, n),
            "push peer: one addressed delete per artifact"
        );
        assert_eq!(
            counts[1],
            (n, n, n),
            "mirror peer: one addressed delete per artifact"
        );
        assert_eq!(counts[2], (0, 0, 0), "a pull peer gets no deletes");
    }

    /// #4311: a job whose replica died mid-delete (claim lapsed, phase
    /// recorded) is resumed by another replica's resumer from that phase.
    #[tokio::test]
    async fn a_job_whose_claim_lapsed_is_resumed_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        seed(&fx, 5, 0).await;
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, created) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        assert!(created);
        // Another replica claimed it, reached `delete_rows`, and died.
        sqlx::query(
            "UPDATE repository_delete_jobs SET status = 'running', phase = 'delete_rows', \
                 claim_token = gen_random_uuid(), claimed_by = 'dead-replica', \
                 claim_expires_at = NOW() - INTERVAL '1 second' \
             WHERE id = $1",
        )
        .bind(job.id)
        .execute(&fx.pool)
        .await
        .unwrap();
        // A live claim is not taken over.
        assert!(!run_claimable(&fx.state, Some(Uuid::new_v4()))
            .await
            .unwrap());
        assert!(run_claimable(&fx.state, Some(job.id)).await.unwrap());
        let done = load(&fx.pool, job.id).await.unwrap().unwrap();
        assert_eq!(done.status, "completed", "{done:?}");
        let gone: bool =
            sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM repositories WHERE id = $1)")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert!(gone);
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// #4311: while its job runs the repository is out of the listing, and a
    /// second delete of it returns the same job.
    #[tokio::test]
    async fn a_deleting_repository_is_unlisted_and_a_second_delete_returns_its_job_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let service = fx.state.create_repository_service();
        let repo = service.get_by_id(fx.repo_id).await.unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let renamed = service.get_by_id(fx.repo_id).await.unwrap();
        assert_eq!(renamed.key, deleting_key(job.id));
        let (again, created) = enqueue(&fx.pool, &renamed, fx.user_id).await.unwrap();
        assert!(!created);
        assert_eq!(again.id, job.id);
        let (listed, _) = service
            .list(
                0,
                1000,
                None,
                None,
                crate::services::repository_service::RepoVisibility::All,
                Some(&renamed.key),
                None,
            )
            .await
            .unwrap();
        assert!(
            listed.iter().all(|r| r.id != fx.repo_id),
            "a repository being deleted is not listed"
        );
        let finished = run_to_completion(&fx.state, job.id).await;
        assert_eq!(finished.status, "completed");
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    async fn delete_key(fx: &tdh::Fixture, key: &str) -> (StatusCode, serde_json::Value) {
        let app = tdh::router_with_auth(super::super::router(), fx.state.clone(), admin(fx));
        let req = axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/{key}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// #4311: a repeated `DELETE` of the key the repository had answers with
    /// the job in flight instead of 404; after a failed job it starts a new
    /// one that keeps the original key (whose proxy-cache subtree it purges
    /// and under which it is audited); once the job completed the key is
    /// simply gone.
    #[tokio::test]
    async fn a_repeated_delete_of_the_original_key_returns_or_restarts_its_job_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        seed(&fx, 3, 0).await;
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        // Recorded but not started, as if its worker had not run yet.
        let (first, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();

        let (status, again) = delete_key(&fx, &fx.repo_key).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{again}");
        assert_eq!(again["id"], first.id.to_string(), "the job in flight");

        sqlx::query(
            "UPDATE repository_delete_jobs SET status = 'failed', finished_at = NOW() \
             WHERE id = $1",
        )
        .bind(first.id)
        .execute(&fx.pool)
        .await
        .unwrap();
        let (status, restarted) = delete_key(&fx, &fx.repo_key).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{restarted}");
        let second: Uuid = restarted["id"].as_str().unwrap().parse().unwrap();
        assert_ne!(second, first.id, "a failed job is followed by a new one");
        assert_eq!(restarted["repository_key"], fx.repo_key);
        let finished = run_to_completion(&fx.state, second).await;
        assert_eq!(finished.status, "completed", "{finished:?}");
        assert_eq!(finished.repository_key, fx.repo_key);

        let (status, _) = delete_key(&fx, &fx.repo_key).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = ANY($1)")
            .bind(vec![first.id, second])
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// #4311: the job's own purge (not only the per-key helper) keeps an
    /// object that an identical upload into another repository on the same
    /// storage deduplicated against after the job deleted the rows and
    /// journaled the key.
    #[tokio::test]
    async fn the_job_purge_keeps_an_object_another_repository_took_meanwhile_4311() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (state, mem) = tdh::build_state_with_cloud(pool.clone(), "s3");
        let (user_id, _) = tdh::create_user(&pool).await;
        let (repo_a, _, dir_a) = tdh::create_repo(&pool, "local", "generic").await;
        let (repo_b, _, dir_b) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query(
            "UPDATE repositories SET storage_backend = 's3', storage_path = '' WHERE id = ANY($1)",
        )
        .bind(vec![repo_a, repo_b])
        .execute(&pool)
        .await
        .unwrap();
        let location = StorageLocation {
            backend: "s3".to_string(),
            path: String::new(),
        };
        let storage = state.storage_for_repo(&location).unwrap();
        let service = state.create_artifact_service(storage);
        let body = bytes::Bytes::from(format!("shared later {}", Uuid::new_v4()));
        let own = bytes::Bytes::from(format!("only in A {}", Uuid::new_v4()));
        let key = service
            .upload(
                repo_a,
                "a.bin",
                "a.bin",
                None,
                "application/octet-stream",
                body.clone(),
                Some(user_id),
            )
            .await
            .unwrap()
            .storage_key;
        let own_key = service
            .upload(
                repo_a,
                "own.bin",
                "own.bin",
                None,
                "application/octet-stream",
                own,
                Some(user_id),
            )
            .await
            .unwrap()
            .storage_key;

        let repo = state
            .create_repository_service()
            .get_by_id(repo_a)
            .await
            .unwrap();
        let (job, _) = enqueue(&pool, &repo, user_id).await.unwrap();
        let claimed = claim(&pool, Some(job.id)).await.unwrap().expect("claimed");
        let lost = CancellationToken::new();
        assert!(collect(&state, &claimed).await.is_ok());
        assert!(delete_rows(&state, &claimed, &lost).await.is_ok());

        let b = service
            .upload(
                repo_b,
                "b.bin",
                "b.bin",
                None,
                "application/octet-stream",
                body.clone(),
                Some(user_id),
            )
            .await
            .unwrap();
        assert_eq!(b.storage_key, key, "B deduplicates against A's object");

        assert!(purge(&state, &claimed, &lost).await.is_ok());
        finish(&pool, &claimed, "completed", None).await;
        let (kept, own_left) = {
            let objects = mem.objects.lock().unwrap();
            (objects.get(&key).cloned(), objects.contains_key(&own_key))
        };
        let downloaded = service.download(repo_b, "b.bin", None, None, None).await;
        let _ = sqlx::query("DELETE FROM oci_gc_candidates WHERE storage_key = ANY($1)")
            .bind(vec![key.clone(), own_key.clone()])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_b, user_id).await;
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        assert_eq!(
            kept.as_ref(),
            Some(&body),
            "B's object must survive A's purge"
        );
        assert!(
            downloaded.is_ok(),
            "B's artifact must download: {downloaded:?}"
        );
        assert!(!own_left, "an object only A held is purged");
    }

    /// #4311: a job one replica holds the claim on is not claimed by another
    /// until that claim lapses.
    #[tokio::test]
    async fn a_held_claim_is_not_taken_by_another_replica_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let held = claim(&fx.pool, Some(job.id)).await.unwrap();
        assert!(held.is_some(), "the first claim takes the job");
        assert!(
            claim(&fx.pool, Some(job.id)).await.unwrap().is_none(),
            "a held claim is not taken over"
        );
        assert!(
            !run_claimable(&fx.state, Some(job.id)).await.unwrap(),
            "no second worker runs the job"
        );
        sqlx::query(
            "UPDATE repository_delete_jobs SET claim_expires_at = NOW() - INTERVAL '1 second' \
             WHERE id = $1",
        )
        .bind(job.id)
        .execute(&fx.pool)
        .await
        .unwrap();
        let done = run_to_completion(&fx.state, job.id).await;
        assert_eq!(done.status, "completed", "{done:?}");
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// #4311: a repository being deleted leaves every virtual repository at
    /// once, as the synchronous delete's cascade made it leave, so no virtual
    /// serves the artifacts the job has not deleted yet.
    #[tokio::test]
    async fn a_deleting_repository_leaves_its_virtuals_at_once_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (virtual_id, _, virtual_dir) = tdh::create_repo(&fx.pool, "virtual", "generic").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let members: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM virtual_repo_members WHERE member_repo_id = $1",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert_eq!(members, 0, "the accepted delete removes the membership");
        run_to_completion(&fx.state, job.id).await;
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(&fx.pool)
            .await;
        let _ = std::fs::remove_dir_all(&virtual_dir);
        fx.teardown().await;
    }

    /// #4311: a repository delete journals the object of a manifest the
    /// repository knows only through its `oci_manifests` record (no tag, no
    /// index edge, no artifacts row), so storage GC's candidate sweep can
    /// reclaim it once the record cascades away instead of the object leaking.
    #[tokio::test]
    async fn a_delete_journals_a_manifest_known_only_through_oci_manifests_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let digest = format!(
            "sha256:{}",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                Uuid::new_v4().as_bytes()
            ))
        );
        sqlx::query(
            "INSERT INTO oci_manifests (repository_id, digest, content_type, size_bytes) \
             VALUES ($1, $2, 'application/vnd.oci.image.manifest.v1+json', 42)",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .execute(&fx.pool)
        .await
        .expect("untagged manifest record");
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let done = run_to_completion(&fx.state, job.id).await;
        assert_eq!(done.status, "completed", "{done:?}");
        let key = format!(
            "{}{digest}",
            crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX
        );
        let journaled: Option<Option<Uuid>> = sqlx::query_scalar(
            "SELECT source_repository_id FROM oci_gc_candidates WHERE storage_key = $1",
        )
        .bind(&key)
        .fetch_optional(&fx.pool)
        .await
        .unwrap();
        let _ = sqlx::query("DELETE FROM oci_gc_candidates WHERE storage_key = $1")
            .bind(&key)
            .execute(&fx.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
        assert_eq!(
            journaled,
            Some(Some(fx.repo_id)),
            "the manifest object is a waiting GC candidate after the delete"
        );
    }

    /// The status endpoint shows a job only to its requester and to admins.
    #[tokio::test]
    async fn status_is_visible_to_the_requester_and_admins_only_4311() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let repo = fx
            .state
            .create_repository_service()
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let (job, _) = enqueue(&fx.pool, &repo, fx.user_id).await.unwrap();
        let (other_id, other_name) = tdh::create_user(&fx.pool).await;
        let get = |auth: AuthExtension| {
            let app = tdh::router_with_auth(super::router(), fx.state.clone(), auth);
            tdh::send(app, tdh::get(format!("/{}", job.id)))
        };
        assert_eq!(
            get(tdh::make_auth(fx.user_id, &fx.username)).await.0,
            StatusCode::OK
        );
        assert_eq!(
            get(tdh::make_auth(other_id, &other_name)).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(tdh::admin_auth(other_id, &other_name)).await.0,
            StatusCode::OK
        );
        run_to_completion(&fx.state, job.id).await;
        let _ = sqlx::query("DELETE FROM repository_delete_jobs WHERE id = $1")
            .bind(job.id)
            .execute(&fx.pool)
            .await;
        tdh::cleanup_user(&fx.pool, other_id).await;
        fx.teardown().await;
    }
}
