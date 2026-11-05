//! Seed a Remote repository's proxy cache from a manifest (#5284).
//!
//! `POST /api/v1/repositories/{key}/cache/seed` records a
//! `proxy_cache_seed_jobs` row and one `proxy_cache_seed_items` row per
//! requested path (input order, duplicates dropped) and answers `202`. A
//! worker then fetches every pending item through the generic download
//! route's proxy entry, [`ProxyService::fetch_artifact_streaming`] on the
//! same synthesized repository and cache path
//! (`generic_remote_fetch_target`), so a seed passes the upstream filter, the
//! origin policy, the quota / cache-cap admission and the #4442 scan-on-proxy
//! refusal exactly where a client's download does. A seed is not a way around
//! curation.
//!
//! Each item ends `cached`, `already_cached` (a fresh cache entry existed, so
//! the upstream was not contacted), `refused` (a gate said no; nothing was
//! cached) or `failed` (the upstream or the cache write failed). The job row
//! carries a claim (`claim_token` / `claim_expires_at`), renewed while it
//! runs, so one replica runs a job at a time and a job whose replica died is
//! resumed by [`spawn_resumer`] from the items still `pending`.
//!
//! `GET .../cache/seed/{job_id}` returns the job and its inventory.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    generic_remote_fetch_target, generic_route_remote_decision, require_auth, require_repo_admin,
    require_repo_write_access, require_visible, GenericRouteProxyServe,
};
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::proxy_service::ProxyService;
use crate::services::repository_service::RepositoryService;

/// The only manifest kind this release implements.
pub(crate) const KIND_PATHS: &str = "paths";

/// Kinds the issue specifies that are not implemented yet (#5284).
const PLANNED_KINDS: [&str; 4] = [
    "pypi-requirements",
    "npm-lockfile",
    "oci-images",
    "hf-models",
];

/// Most items one seed request may list (after duplicates are dropped).
pub(crate) const MAX_ITEMS: usize = 10_000;

/// Longest path accepted in a manifest.
pub(crate) const MAX_PATH_LEN: usize = 4096;

pub(crate) const DEFAULT_CONCURRENCY: i32 = 4;
pub(crate) const MAX_CONCURRENCY: i32 = 16;

/// Claim lifetime; the renewal loop extends it every third of this.
const CLAIM_TTL_SECS: f64 = 300.0;

/// A job whose run failed (not an item: the run itself) this many times is
/// marked `failed`.
const MAX_ATTEMPTS: i32 = 5;

/// How often each replica looks for pending jobs and lapsed claims.
const RESUME_INTERVAL: Duration = Duration::from_secs(60);

/// How long an item waits, after its body was drained, for the proxy cache
/// to commit the entry it teed.
const COMMIT_WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/repositories/{key}/cache/seed`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CacheSeedRequest {
    /// Manifest kind. Only `paths` is implemented; `pypi-requirements`,
    /// `npm-lockfile`, `oci-images` and `hf-models` are planned (#5284) and
    /// answer 400 for now.
    #[schema(example = "paths")]
    pub kind: String,
    /// For `paths`: repository-relative paths, either as a JSON array of
    /// strings or as newline-separated text. Blank lines and `#` comment
    /// lines of the text form are skipped, a leading `/` is dropped and a
    /// repeated path is seeded once.
    #[schema(value_type = Object, example = json!(["org/acme/lib/1.0/lib-1.0.jar"]))]
    pub content: serde_json::Value,
    #[serde(default)]
    pub options: CacheSeedOptions,
}

/// Seed options. Unknown fields are ignored.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CacheSeedOptions {
    /// Items fetched at once (1 to 16, default 4).
    pub concurrency: Option<i32>,
    /// Stop fetching once this many bytes were fetched by the job; the
    /// remaining items are reported `refused`. Unbounded when absent.
    pub max_total_bytes: Option<i64>,
}

/// `202` answer of a seed request.
#[derive(Debug, Serialize, ToSchema)]
pub struct CacheSeedAcceptedResponse {
    pub job_id: Uuid,
    pub repository_key: String,
    pub kind: String,
    pub status: String,
    /// Items recorded for the job, after duplicates were dropped.
    pub total_items: i64,
    pub duplicates_ignored: i64,
    pub concurrency: i32,
    pub max_total_bytes: Option<i64>,
    /// Where to poll the job.
    pub status_url: String,
}

/// One inventory row of a seed job.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct CacheSeedItem {
    /// 0-based position in the request (duplicates dropped).
    pub position: i32,
    pub path: String,
    /// `pending`, `cached`, `already_cached`, `refused` or `failed`.
    pub state: String,
    /// Why the item was refused or failed.
    pub reason: Option<String>,
    /// For `failed`: the HTTP status a client would have been answered with
    /// (404 for an upstream miss, 503 for an upstream 5xx, ...).
    pub status: Option<i32>,
    pub size_bytes: Option<i64>,
    pub checksum_sha256: Option<String>,
}

/// Item counts of a seed job.
#[derive(Debug, Default, Serialize, ToSchema, sqlx::FromRow)]
pub struct CacheSeedSummary {
    pub pending: i64,
    pub cached: i64,
    pub already_cached: i64,
    pub refused: i64,
    pub failed: i64,
    /// Bytes of the items this job cached.
    pub cached_bytes: i64,
}

/// A seed job and its inventory, in input order.
#[derive(Debug, Serialize, ToSchema)]
pub struct CacheSeedJobResponse {
    pub job_id: Uuid,
    pub repository_key: String,
    pub kind: String,
    /// `pending`, `running`, `completed` or `failed`.
    pub status: String,
    pub concurrency: i32,
    pub max_total_bytes: Option<i64>,
    pub total_items: i64,
    pub summary: CacheSeedSummary,
    pub error_summary: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub items: Vec<CacheSeedItem>,
}

fn status_url(repo_key: &str, job_id: Uuid) -> String {
    format!("/api/v1/repositories/{repo_key}/cache/seed/{job_id}")
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

// ---------------------------------------------------------------------------
// Manifest parsing (pure)
// ---------------------------------------------------------------------------

/// The paths of a `paths` manifest, unique and in input order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PathsManifest {
    pub paths: Vec<String>,
    pub duplicates: usize,
}

/// Refuse every kind but `paths`, naming the issue for the planned ones.
pub(crate) fn check_kind(kind: &str) -> Result<()> {
    if kind == KIND_PATHS {
        return Ok(());
    }
    if PLANNED_KINDS.contains(&kind) {
        return Err(AppError::Validation(format!(
            "manifest kind '{kind}' is not implemented yet (#5284); use kind \"paths\""
        )));
    }
    Err(AppError::Validation(format!(
        "unknown manifest kind '{kind}'; expected \"paths\" (planned: {})",
        PLANNED_KINDS.join(", ")
    )))
}

/// Parse a `paths` manifest: a JSON array of strings or newline text.
pub(crate) fn parse_paths_manifest(content: &serde_json::Value) -> Result<PathsManifest> {
    let raw: Vec<&str> = match content {
        serde_json::Value::String(text) => text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect(),
        serde_json::Value::Array(entries) => entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                entry.as_str().ok_or_else(|| {
                    AppError::Validation(format!("content[{i}] must be a string path"))
                })
            })
            .collect::<Result<_>>()?,
        _ => {
            return Err(AppError::Validation(
                "content must be an array of paths or newline-separated text".to_string(),
            ))
        }
    };
    let mut seen = std::collections::HashSet::new();
    let mut paths = Vec::new();
    let mut duplicates = 0;
    for entry in raw {
        let path = entry.trim().trim_start_matches('/');
        if path.is_empty() {
            continue;
        }
        if path.len() > MAX_PATH_LEN {
            return Err(AppError::Validation(format!(
                "a manifest path is longer than {MAX_PATH_LEN} bytes"
            )));
        }
        if !seen.insert(path) {
            duplicates += 1;
            continue;
        }
        if paths.len() == MAX_ITEMS {
            return Err(AppError::Validation(format!(
                "a seed request may list at most {MAX_ITEMS} paths; split the manifest"
            )));
        }
        paths.push(path.to_string());
    }
    if paths.is_empty() {
        return Err(AppError::Validation(
            "the manifest lists no paths".to_string(),
        ));
    }
    Ok(PathsManifest { paths, duplicates })
}

/// Validate the options: `(concurrency, max_total_bytes)`.
pub(crate) fn resolve_options(options: &CacheSeedOptions) -> Result<(i32, Option<i64>)> {
    let concurrency = options.concurrency.unwrap_or(DEFAULT_CONCURRENCY);
    if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
        return Err(AppError::Validation(format!(
            "options.concurrency must be between 1 and {MAX_CONCURRENCY}"
        )));
    }
    if options.max_total_bytes.is_some_and(|b| b <= 0) {
        return Err(AppError::Validation(
            "options.max_total_bytes must be positive".to_string(),
        ));
    }
    Ok((concurrency, options.max_total_bytes))
}

// ---------------------------------------------------------------------------
// Item outcomes (pure)
// ---------------------------------------------------------------------------

/// What happened to one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemOutcome {
    Cached { size: i64, sha256: String },
    AlreadyCached { size: Option<i64>, sha256: String },
    Refused(String),
    Failed { status: Option<i32>, reason: String },
}

/// The item-row columns of an outcome: `(state, reason, status, size, sha256)`.
type OutcomeColumns<'a> = (
    &'static str,
    Option<&'a str>,
    Option<i32>,
    Option<i64>,
    Option<&'a str>,
);

impl ItemOutcome {
    fn columns(&self) -> OutcomeColumns<'_> {
        match self {
            Self::Cached { size, sha256 } => {
                ("cached", None, None, Some(*size), Some(sha256.as_str()))
            }
            Self::AlreadyCached { size, sha256 } => {
                ("already_cached", None, None, *size, Some(sha256.as_str()))
            }
            Self::Refused(reason) => ("refused", Some(reason.as_str()), None, None, None),
            Self::Failed { status, reason } => {
                ("failed", Some(reason.as_str()), *status, None, None)
            }
        }
    }
}

/// Classify a proxy error the way the client-facing mapping does: a gate's
/// refusal (origin policy, Package Age Policy hold, quota, a path the proxy
/// will not key) is `refused`; an upstream miss or failure is `failed` with
/// the status a client would have seen.
pub(crate) fn classify_fetch_error(e: &AppError) -> ItemOutcome {
    match e {
        AppError::Authorization(m) | AppError::Conflict(m) | AppError::QuotaExceeded(m) => {
            ItemOutcome::Refused(m.clone())
        }
        AppError::Validation(m) => ItemOutcome::Refused(format!("invalid path: {m}")),
        AppError::NotFound(_) => ItemOutcome::Failed {
            status: Some(404),
            reason: "not found upstream".to_string(),
        },
        AppError::ServiceUnavailable(m) => ItemOutcome::Failed {
            status: Some(503),
            reason: m.clone(),
        },
        other => ItemOutcome::Failed {
            status: Some(
                crate::services::proxy_service::upstream_refusal_status(other)
                    .map_or(502, |s| i32::from(s.as_u16())),
            ),
            reason: other.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Seed a Remote repository's proxy cache from a manifest (#5284).
///
/// Every item is fetched through the same proxy entry as a client download,
/// so the upstream filter, origin policy, quota / cache cap and scan-on-proxy
/// refusal apply to it. Requires repository admin, like `cache/invalidate`.
#[utoipa::path(
    post,
    path = "/{key}/cache/seed",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CacheSeedRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 202, description = "Seed job accepted", body = CacheSeedAcceptedResponse),
        (status = 400, description = "Not a remote repository, unsupported kind or invalid manifest"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin permission required"),
        (status = 404, description = "Repository not found"),
        (status = 503, description = "Proxy service not configured on this deployment"),
    )
)]
pub async fn start_cache_seed(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<CacheSeedRequest>,
) -> Result<(StatusCode, Json<CacheSeedAcceptedResponse>)> {
    let auth = require_auth(auth)?;
    auth.require_scope("write:repositories")?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &service).await?;
    // Seeding drives upstream fetches into the cache: the same supply-chain
    // tier as `cache/invalidate` and `cache-ttl`.
    require_repo_admin(&auth, repo.id, &state.permission_service).await?;
    require_seedable(&repo)?;
    if state.proxy_service.is_none() {
        return Err(AppError::ServiceUnavailable(
            "proxy service not configured".to_string(),
        ));
    }
    check_kind(&payload.kind)?;
    let manifest = parse_paths_manifest(&payload.content)?;
    let (concurrency, max_total_bytes) = resolve_options(&payload.options)?;

    let job_id = enqueue(
        &state.db,
        repo.id,
        &payload.kind,
        concurrency,
        max_total_bytes,
        auth.user_id,
        &manifest.paths,
    )
    .await?;
    spawn_job(state.clone(), job_id);

    Ok((
        StatusCode::ACCEPTED,
        Json(CacheSeedAcceptedResponse {
            job_id,
            status_url: status_url(&repo.key, job_id),
            repository_key: repo.key,
            kind: payload.kind,
            status: "pending".to_string(),
            total_items: manifest.paths.len() as i64,
            duplicates_ignored: manifest.duplicates as i64,
            concurrency,
            max_total_bytes,
        }),
    ))
}

/// Only a Remote with an upstream owns a cache to seed.
#[allow(clippy::result_large_err)]
fn require_seedable(repo: &Repository) -> Result<()> {
    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "cache seeding is only supported on remote (proxy) repositories; seeding a virtual \
             repository through its remote members is not implemented yet (#5284)"
                .to_string(),
        ));
    }
    if repo.upstream_url.is_none() {
        return Err(AppError::Validation(
            "the remote repository has no upstream_url".to_string(),
        ));
    }
    Ok(())
}

/// Read a seed job and its inventory.
#[utoipa::path(
    get,
    path = "/{key}/cache/seed/{job_id}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("job_id" = Uuid, Path, description = "Seed job id"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The seed job and its inventory", body = CacheSeedJobResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin permission required"),
        (status = 404, description = "Repository or job not found"),
    )
)]
pub async fn get_cache_seed(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, job_id)): Path<(String, Uuid)>,
) -> Result<Json<CacheSeedJobResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &service).await?;
    let auth = require_auth(auth)?;
    auth.require_scope("read:repositories")?;
    require_repo_admin(&auth, repo.id, &state.permission_service).await?;
    let job = load_job(&state.db, &repo, job_id)
        .await?
        .ok_or_else(|| AppError::NotFound("cache seed job not found".to_string()))?;
    Ok(Json(job))
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

async fn enqueue(
    db: &PgPool,
    repository_id: Uuid,
    kind: &str,
    concurrency: i32,
    max_total_bytes: Option<i64>,
    created_by: Uuid,
    paths: &[String],
) -> Result<Uuid> {
    let mut tx = db.begin().await.map_err(db_err)?;
    let job_id: Uuid = sqlx::query_scalar(
        "INSERT INTO proxy_cache_seed_jobs \
             (repository_id, kind, concurrency, max_total_bytes, created_by) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(repository_id)
    .bind(kind)
    .bind(concurrency)
    .bind(max_total_bytes)
    .bind(created_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO proxy_cache_seed_items (job_id, position, path) \
         SELECT $1, (t.ord - 1)::int, t.path \
           FROM UNNEST($2::text[]) WITH ORDINALITY AS t(path, ord)",
    )
    .bind(job_id)
    .bind(paths)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(job_id)
}

type JobRow = (
    String,
    String,
    i32,
    Option<i64>,
    Option<String>,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

async fn load_job(
    db: &PgPool,
    repo: &Repository,
    job_id: Uuid,
) -> Result<Option<CacheSeedJobResponse>> {
    let row: Option<JobRow> = sqlx::query_as(
        "SELECT kind, status, concurrency, max_total_bytes, error_summary, \
                created_at, started_at, finished_at \
           FROM proxy_cache_seed_jobs WHERE id = $1 AND repository_id = $2",
    )
    .bind(job_id)
    .bind(repo.id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    let Some((kind, status, concurrency, max_total_bytes, error_summary, created, started, done)) =
        row
    else {
        return Ok(None);
    };
    let items: Vec<CacheSeedItem> = sqlx::query_as(
        "SELECT position, path, state, reason, http_status AS status, size_bytes, \
                checksum_sha256 \
           FROM proxy_cache_seed_items WHERE job_id = $1 ORDER BY position",
    )
    .bind(job_id)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(Some(CacheSeedJobResponse {
        job_id,
        repository_key: repo.key.clone(),
        kind,
        status,
        concurrency,
        max_total_bytes,
        total_items: items.len() as i64,
        summary: load_summary(db, job_id).await?,
        error_summary,
        created_at: created,
        started_at: started,
        finished_at: done,
        items,
    }))
}

async fn load_summary(db: &PgPool, job_id: Uuid) -> Result<CacheSeedSummary> {
    sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE state = 'pending') AS pending, \
                COUNT(*) FILTER (WHERE state = 'cached') AS cached, \
                COUNT(*) FILTER (WHERE state = 'already_cached') AS already_cached, \
                COUNT(*) FILTER (WHERE state = 'refused') AS refused, \
                COUNT(*) FILTER (WHERE state = 'failed') AS failed, \
                COALESCE(SUM(size_bytes) FILTER (WHERE state = 'cached'), 0)::bigint \
                    AS cached_bytes \
           FROM proxy_cache_seed_items WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_one(db)
    .await
    .map_err(db_err)
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// A job this process holds the claim on.
struct SeedClaim {
    id: Uuid,
    repository_id: Uuid,
    kind: String,
    concurrency: i32,
    max_total_bytes: Option<i64>,
    created_by: Option<Uuid>,
    token: Uuid,
}

/// The claimed job's columns: id, repository, kind, concurrency, byte cap,
/// requester.
type ClaimedJobRow = (Uuid, Uuid, String, i32, Option<i64>, Option<Uuid>);

/// Claim `job_id` (or, with `None`, the oldest claimable job): a pending job
/// or a running one whose claim lapsed.
async fn claim(db: &PgPool, job_id: Option<Uuid>) -> Result<Option<SeedClaim>> {
    let token = Uuid::new_v4();
    let row: Option<ClaimedJobRow> = sqlx::query_as(
        "UPDATE proxy_cache_seed_jobs SET \
             status = 'running', claim_token = $2, claimed_by = $3, \
             claim_expires_at = NOW() + make_interval(secs => $4), \
             started_at = COALESCE(started_at, NOW()), attempts = attempts + 1, \
             updated_at = NOW() \
         WHERE id = ( \
             SELECT id FROM proxy_cache_seed_jobs \
              WHERE (status = 'pending' \
                     OR (status = 'running' AND claim_expires_at < NOW())) \
                AND ($1::uuid IS NULL OR id = $1) \
              ORDER BY created_at LIMIT 1 \
              FOR UPDATE SKIP LOCKED) \
         RETURNING id, repository_id, kind, concurrency, max_total_bytes, created_by",
    )
    .bind(job_id)
    .bind(token)
    .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str())
    .bind(CLAIM_TTL_SECS)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(row.map(
        |(id, repository_id, kind, concurrency, max_total_bytes, created_by)| SeedClaim {
            id,
            repository_id,
            kind,
            concurrency,
            max_total_bytes,
            created_by,
            token,
        },
    ))
}

const RENEW_CLAIM_SQL: &str = "UPDATE proxy_cache_seed_jobs \
     SET claim_expires_at = NOW() + make_interval(secs => $3) \
     WHERE id = $1 AND claim_token = $2 AND status = 'running'";

/// Why a run stopped before every item was settled.
enum Stop {
    /// Another replica holds the job now.
    LeaseLost,
    /// The run itself failed; the job is released for a retry.
    Failed(AppError),
}

impl From<AppError> for Stop {
    fn from(e: AppError) -> Self {
        Stop::Failed(e)
    }
}

/// Spawn a worker for the job a request just created.
fn spawn_job(state: SharedState, job_id: Uuid) {
    tokio::spawn(async move {
        if let Err(e) = run_claimable(&state, Some(job_id)).await {
            tracing::warn!(job_id = %job_id, error = %e, "cache seed job could not start");
        }
    });
}

/// Spawn the per-replica loop that resumes pending seed jobs and jobs whose
/// claim lapsed (their replica died or restarted). Stops with `shutdown`.
pub fn spawn_resumer(state: SharedState, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RESUME_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            // Jobs run one after another on this replica; other replicas
            // claim the rest.
            loop {
                let claimed = run_claimable(&state, None).await;
                if let Err(e) = &claimed {
                    tracing::warn!(error = %e, "cache seed resumer could not claim a job");
                }
                if !matches!(claimed, Ok(true)) {
                    break;
                }
            }
        }
    });
}

/// Claim and run one job. `Ok(false)` when nothing was claimable.
async fn run_claimable(state: &SharedState, job_id: Option<Uuid>) -> Result<bool> {
    let Some(job) = claim(&state.db, job_id).await? else {
        return Ok(false);
    };
    let (renewal, lost) = crate::services::cluster_work::spawn_row_claim_renewal(
        state.db.clone(),
        format!("cache seed job {}", job.id),
        RENEW_CLAIM_SQL,
        job.id,
        job.token,
        CLAIM_TTL_SECS,
    );
    let outcome = run(state, &job, &lost).await;
    drop(renewal);
    match outcome {
        Ok(()) => tracing::info!(job_id = %job.id, "cache seed job completed"),
        Err(Stop::LeaseLost) => {
            tracing::warn!(job_id = %job.id, "cache seed job lost its claim; another replica continues it");
        }
        Err(Stop::Failed(e)) => {
            tracing::warn!(job_id = %job.id, error = %e, "cache seed job run failed");
            release_after_failure(&state.db, &job, &e.to_string()).await;
        }
    }
    Ok(true)
}

/// Put a job whose run failed back to `pending`, or mark it `failed` after
/// [`MAX_ATTEMPTS`] runs. Settled items keep their results.
async fn release_after_failure(db: &PgPool, job: &SeedClaim, error: &str) {
    let _ = sqlx::query(
        "UPDATE proxy_cache_seed_jobs SET \
             status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END, \
             finished_at = CASE WHEN attempts >= $3 THEN NOW() ELSE NULL END, \
             error_summary = $4, claim_token = NULL, claim_expires_at = NULL, updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.id)
    .bind(job.token)
    .bind(MAX_ATTEMPTS)
    .bind(error)
    .execute(db)
    .await;
}

/// What every item of one run shares.
struct SeedRun {
    db: PgPool,
    proxy: std::sync::Arc<ProxyService>,
    repo: Repository,
    upstream_url: String,
    max_total_bytes: Option<i64>,
    /// Bytes fetched by the job so far (this run and earlier ones).
    fetched: AtomicI64,
}

async fn run(
    state: &SharedState,
    job: &SeedClaim,
    lost: &CancellationToken,
) -> std::result::Result<(), Stop> {
    let proxy = state
        .proxy_service
        .clone()
        .ok_or_else(|| AppError::ServiceUnavailable("proxy service not configured".to_string()))?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_id(job.repository_id)
        .await?;
    require_seedable(&repo)?;
    let upstream_url = repo.upstream_url.clone().unwrap_or_default();

    // Gates that hold for the whole repository, read once per run. The fetch
    // path re-runs the origin policy per item, so a policy attached mid-run
    // still applies.
    let mut run_refusal = match generic_route_remote_decision(&state.db, &repo).await {
        GenericRouteProxyServe::Stream => None,
        GenericRouteProxyServe::Refuse => Some(format!(
            "the repository scans on proxy, so its files are served only through the {} \
             format route, which this seed kind does not use (#4442, #5284)",
            repo.format.handler_key()
        )),
        GenericRouteProxyServe::ConfigUnreadable => {
            return Err(Stop::Failed(AppError::ServiceUnavailable(
                "scan-on-proxy configuration is temporarily unreadable".to_string(),
            )))
        }
    };
    if run_refusal.is_none() {
        match proxy.cache_origin_policy_gate(&repo.key).await {
            Ok(()) => {}
            Err(AppError::Authorization(m)) => run_refusal = Some(m),
            Err(e) => return Err(e.into()),
        }
    }

    let pending: Vec<(i32, String)> = sqlx::query_as(
        "SELECT position, path FROM proxy_cache_seed_items \
          WHERE job_id = $1 AND state = 'pending' ORDER BY position",
    )
    .bind(job.id)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    let ctx = SeedRun {
        db: state.db.clone(),
        proxy,
        upstream_url,
        max_total_bytes: job.max_total_bytes,
        fetched: AtomicI64::new(load_summary(&state.db, job.id).await?.cached_bytes),
        repo,
    };

    let ctx_ref = &ctx;
    let refusal = run_refusal.as_deref();
    let mut settled = futures::stream::iter(pending)
        .map(move |(position, path)| async move {
            let outcome = match refusal {
                Some(reason) => ItemOutcome::Refused(reason.to_string()),
                None => seed_one(ctx_ref, &path).await,
            };
            (position, outcome)
        })
        .buffer_unordered(job.concurrency.clamp(1, MAX_CONCURRENCY) as usize);
    while let Some((position, outcome)) = settled.next().await {
        if lost.is_cancelled() || !record_item(&state.db, job, position, &outcome).await? {
            return Err(Stop::LeaseLost);
        }
    }
    drop(settled);

    let finished = sqlx::query(
        "UPDATE proxy_cache_seed_jobs SET status = 'completed', finished_at = NOW(), \
             error_summary = NULL, claim_token = NULL, claim_expires_at = NULL, \
             updated_at = NOW() \
         WHERE id = $1 AND claim_token = $2",
    )
    .bind(job.id)
    .bind(job.token)
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    if finished.rows_affected() != 1 {
        return Err(Stop::LeaseLost);
    }
    audit_completed(&state.db, job, &ctx.repo).await;
    Ok(())
}

/// Write an item's outcome under the job's claim. `Ok(false)`: claim lost.
async fn record_item(
    db: &PgPool,
    job: &SeedClaim,
    position: i32,
    outcome: &ItemOutcome,
) -> Result<bool> {
    let (state, reason, status, size, sha256) = outcome.columns();
    let done = sqlx::query(
        "UPDATE proxy_cache_seed_items i SET state = $3, reason = $4, http_status = $5, \
             size_bytes = $6, checksum_sha256 = $7, updated_at = NOW() \
           FROM proxy_cache_seed_jobs j \
          WHERE i.job_id = $1 AND i.position = $2 AND j.id = i.job_id AND j.claim_token = $8",
    )
    .bind(job.id)
    .bind(position)
    .bind(state)
    .bind(reason)
    .bind(status)
    .bind(size)
    .bind(sha256)
    .bind(job.token)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// One `CACHE_SEEDED` summary row per completed job.
async fn audit_completed(db: &PgPool, job: &SeedClaim, repo: &Repository) {
    let summary = load_summary(db, job.id).await.unwrap_or_default();
    let mut entry = AuditEntry::new(AuditAction::CacheSeeded, ResourceType::Repository)
        .resource(repo.id)
        .resource_name(repo.key.clone())
        .details(serde_json::json!({
            "repository": repo.key,
            "repository_id": repo.id,
            "job_id": job.id,
            "kind": job.kind,
            "cached": summary.cached,
            "already_cached": summary.already_cached,
            "refused": summary.refused,
            "failed": summary.failed,
            "cached_bytes": summary.cached_bytes,
        }));
    if let Some(user_id) = job.created_by {
        entry = entry.user(user_id);
    }
    audit_fire_and_forget(db.clone(), entry).await;
}

/// Seed one path: report a fresh cache entry without contacting the upstream,
/// otherwise fetch it through the generic route's proxy entry and wait for
/// the cache commit.
async fn seed_one(ctx: &SeedRun, path: &str) -> ItemOutcome {
    let (fetch_path, format) = match generic_remote_fetch_target(&ctx.db, &ctx.repo, path).await {
        Ok(target) => target,
        Err(e) => return classify_fetch_error(&e),
    };
    if let Some(sha256) = ctx
        .proxy
        .fresh_cache_validator(&ctx.repo.key, &fetch_path)
        .await
    {
        return ItemOutcome::AlreadyCached {
            size: cached_size(ctx, &fetch_path).await,
            sha256,
        };
    }
    // The fetch runs this gate too (and answers a refusal like a 404); asking
    // first is what lets the inventory say `refused` rather than `failed`.
    match crate::services::upstream_filter::upstream_allows(
        &ctx.db,
        ctx.repo.id,
        &ctx.repo.key,
        &ctx.upstream_url,
        &fetch_path,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return ItemOutcome::Refused("excluded by the repository's upstream filter".to_string())
        }
        Err(e) => return classify_fetch_error(&e),
    }
    if let Some(cap) = ctx.max_total_bytes {
        if ctx.fetched.load(Ordering::SeqCst) >= cap {
            return ItemOutcome::Refused(format!("options.max_total_bytes ({cap}) reached"));
        }
    }
    let synthetic = proxy_helpers::build_remote_repo_with_format(
        ctx.repo.id,
        &ctx.repo.key,
        &ctx.upstream_url,
        format,
    );
    let mut body = match ctx
        .proxy
        .fetch_artifact_streaming(&synthetic, &fetch_path)
        .await
    {
        Ok(result) => result.body,
        Err(e) => return classify_fetch_error(&e),
    };
    // Drain the stream: the proxy tees it into the cache as it is read.
    let mut streamed = 0i64;
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(bytes) => streamed += bytes.len() as i64,
            Err(e) => {
                return ItemOutcome::Failed {
                    status: Some(502),
                    reason: format!("reading the upstream body failed: {e}"),
                }
            }
        }
    }
    drop(body);
    ctx.fetched.fetch_add(streamed, Ordering::SeqCst);
    await_commit(ctx, &fetch_path, streamed).await
}

async fn cached_size(ctx: &SeedRun, fetch_path: &str) -> Option<i64> {
    ctx.proxy
        .get_cache_metadata(&ctx.repo.key, fetch_path)
        .await
        .ok()
        .flatten()
        .map(|m| m.size_bytes)
}

/// Wait for the background cache writer to commit the drained entry.
async fn await_commit(ctx: &SeedRun, fetch_path: &str, streamed: i64) -> ItemOutcome {
    let deadline = tokio::time::Instant::now() + COMMIT_WAIT;
    let mut delay = Duration::from_millis(25);
    loop {
        if let Some(sha256) = ctx
            .proxy
            .fresh_cache_validator(&ctx.repo.key, fetch_path)
            .await
        {
            let size = cached_size(ctx, fetch_path).await.unwrap_or(streamed);
            return ItemOutcome::Cached { size, sha256 };
        }
        if ctx.proxy.served_without_cache(ctx.repo.id, fetch_path) {
            return ItemOutcome::Refused(
                "served without caching: larger than the repository's quota or proxy-cache cap"
                    .to_string(),
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return ItemOutcome::Failed {
                status: None,
                reason: "fetched, but the proxy cache did not commit the entry".to_string(),
            };
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(500));
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_an_array_dropping_blanks_slashes_and_duplicates() {
        let parsed = parse_paths_manifest(&json!(["a/b.jar", " /c/d.pom ", "", "a/b.jar"]))
            .expect("valid manifest");
        assert_eq!(parsed.paths, vec!["a/b.jar", "c/d.pom"]);
        assert_eq!(parsed.duplicates, 1);
    }

    #[test]
    fn parses_newline_text_skipping_comments() {
        let parsed =
            parse_paths_manifest(&json!("a\n\n# a comment\n b \r\na\n")).expect("valid manifest");
        assert_eq!(parsed.paths, vec!["a", "b"]);
        assert_eq!(parsed.duplicates, 1);
    }

    #[test]
    fn refuses_malformed_or_empty_manifests() {
        for content in [
            json!([1]),
            json!(42),
            json!({"a": 1}),
            json!([]),
            json!("\n# x\n"),
        ] {
            assert!(
                matches!(parse_paths_manifest(&content), Err(AppError::Validation(_))),
                "{content}"
            );
        }
        let long = "a".repeat(MAX_PATH_LEN + 1);
        assert!(parse_paths_manifest(&json!([long])).is_err());
    }

    #[test]
    fn bounds_the_number_of_items() {
        let at_limit: Vec<String> = (0..MAX_ITEMS).map(|i| format!("p/{i}")).collect();
        assert_eq!(
            parse_paths_manifest(&json!(at_limit)).unwrap().paths.len(),
            MAX_ITEMS
        );
        // Duplicates do not count against the limit.
        let mut with_dup = at_limit.clone();
        with_dup.push("p/0".to_string());
        assert_eq!(
            parse_paths_manifest(&json!(with_dup)).unwrap().duplicates,
            1
        );
        let mut over = at_limit;
        over.push("p/extra".to_string());
        assert!(parse_paths_manifest(&json!(over)).is_err());
    }

    #[test]
    fn only_the_paths_kind_is_implemented() {
        assert!(check_kind("paths").is_ok());
        for kind in PLANNED_KINDS {
            let err = check_kind(kind).unwrap_err().to_string();
            assert!(
                err.contains("not implemented yet") && err.contains("#5284"),
                "{err}"
            );
        }
        let err = check_kind("bogus").unwrap_err().to_string();
        assert!(err.contains("unknown manifest kind"), "{err}");
    }

    #[test]
    fn options_default_and_bounds() {
        assert_eq!(
            resolve_options(&CacheSeedOptions::default()).unwrap(),
            (DEFAULT_CONCURRENCY, None)
        );
        let opts = |concurrency, max_total_bytes| CacheSeedOptions {
            concurrency,
            max_total_bytes,
        };
        assert_eq!(
            resolve_options(&opts(Some(16), Some(1))).unwrap(),
            (16, Some(1))
        );
        assert!(resolve_options(&opts(Some(0), None)).is_err());
        assert!(resolve_options(&opts(Some(17), None)).is_err());
        assert!(resolve_options(&opts(None, Some(0))).is_err());
    }

    #[test]
    fn classifies_gate_refusals_and_upstream_failures() {
        let refused = |e: AppError| matches!(classify_fetch_error(&e), ItemOutcome::Refused(_));
        assert!(refused(AppError::Authorization("policy".into())));
        assert!(refused(AppError::Conflict("held".into())));
        assert!(refused(AppError::QuotaExceeded("quota".into())));
        assert!(refused(AppError::Validation("..".into())));
        let status = |e: AppError| match classify_fetch_error(&e) {
            ItemOutcome::Failed { status, .. } => status,
            other => panic!("expected failed, got {other:?}"),
        };
        assert_eq!(status(AppError::NotFound("x".into())), Some(404));
        assert_eq!(status(AppError::ServiceUnavailable("x".into())), Some(503));
        assert_eq!(status(AppError::BadGateway("timeout".into())), Some(502));
        assert_eq!(
            status(AppError::BadGateway(
                "Upstream returned error status 403 Forbidden".into()
            )),
            Some(403)
        );
    }

    #[test]
    fn outcome_columns() {
        let cached = ItemOutcome::Cached {
            size: 3,
            sha256: "ab".into(),
        };
        assert_eq!(
            cached.columns(),
            ("cached", None, None, Some(3), Some("ab"))
        );
        let already = ItemOutcome::AlreadyCached {
            size: None,
            sha256: "cd".into(),
        };
        assert_eq!(
            already.columns(),
            ("already_cached", None, None, None, Some("cd"))
        );
        let failed = ItemOutcome::Failed {
            status: Some(404),
            reason: "gone".into(),
        };
        assert_eq!(
            failed.columns(),
            ("failed", Some("gone"), Some(404), None, None)
        );
    }
}

/// DB-backed tests: a wiremock upstream behind a real `ProxyService`.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod db_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Bytes;
    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use sha2::Digest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn app(fx: &tdh::Fixture, state: &crate::api::SharedState) -> axum::Router {
        tdh::router_with_auth(
            super::super::router(),
            state.clone(),
            tdh::make_auth(fx.user_id, &fx.username),
        )
    }

    async fn post_seed(app: axum::Router, key: &str, body: Value) -> (StatusCode, Value) {
        let (status, bytes) = tdh::send(
            app,
            tdh::post(
                format!("/{key}/cache/seed"),
                "application/json",
                Bytes::from(body.to_string()),
            ),
        )
        .await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Poll the job until it settles.
    async fn settled_job(app: axum::Router, key: &str, job_id: &str) -> Value {
        for _ in 0..600 {
            let (status, bytes) =
                tdh::send(app.clone(), tdh::get(format!("/{key}/cache/seed/{job_id}"))).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{}",
                String::from_utf8_lossy(&bytes)
            );
            let job: Value = serde_json::from_slice(&bytes).expect("job JSON");
            if job["status"] == "completed" || job["status"] == "failed" {
                return job;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("seed job {job_id} did not settle");
    }

    async fn mount(server: &MockServer, at: &str, template: ResponseTemplate, times: u64) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(template)
            .expect(times)
            .mount(server)
            .await;
    }

    fn ok(body: &'static [u8]) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_bytes(body)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    #[tokio::test]
    async fn seed_caches_refuses_fails_and_rerun_is_already_cached() {
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let server = MockServer::start().await;
        // Each file is requested exactly once across BOTH runs.
        mount(&server, "/lib/a.jar", ok(b"aaaa"), 1).await;
        mount(&server, "/lib/b.pom", ok(b"bbbbbb"), 1).await;
        mount(&server, "/blocked/x.jar", ok(b"x"), 0).await;
        mount(&server, "/missing.jar", ResponseTemplate::new(404), 1).await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        tdh::grant_repo_admin(&fx.pool, fx.repo_id, fx.user_id).await;
        crate::services::upstream_filter::save_upstream_filter(
            &fx.pool,
            fx.repo_id,
            &crate::services::upstream_filter::UpstreamFilter {
                include_patterns: vec![],
                exclude_patterns: vec!["^blocked/".to_string()],
            },
        )
        .await
        .expect("save upstream filter");
        let key = fx.repo_key.clone();

        let (status, accepted) = post_seed(
            app(&fx, &state),
            &key,
            json!({
                "kind": "paths",
                "content": ["lib/a.jar", "lib/b.pom", "blocked/x.jar", "missing.jar", "lib/a.jar"],
                "options": {"concurrency": 2},
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
        assert_eq!(accepted["total_items"], 4);
        assert_eq!(accepted["duplicates_ignored"], 1);
        let first = settled_job(app(&fx, &state), &key, accepted["job_id"].as_str().unwrap()).await;

        let (status, rerun) = post_seed(
            app(&fx, &state),
            &key,
            json!({"kind": "paths", "content": "lib/a.jar\n\nlib/b.pom\n"}),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{rerun}");
        let second = settled_job(app(&fx, &state), &key, rerun["job_id"].as_str().unwrap()).await;
        let audits = tdh::audit_count_eventually(&fx.pool, fx.repo_id, "CACHE_SEEDED", 2).await;

        let _ =
            crate::services::upstream_filter::delete_upstream_filter(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
        server.verify().await;

        assert_eq!(first["status"], "completed", "{first}");
        let items = first["items"].as_array().expect("items");
        let states: Vec<&str> = items.iter().map(|i| i["state"].as_str().unwrap()).collect();
        assert_eq!(states, ["cached", "cached", "refused", "failed"], "{first}");
        assert_eq!(items[0]["path"], "lib/a.jar");
        assert_eq!(items[0]["size_bytes"], 4);
        assert_eq!(items[0]["checksum_sha256"], sha256_hex(b"aaaa"));
        assert_eq!(items[1]["checksum_sha256"], sha256_hex(b"bbbbbb"));
        assert!(
            items[2]["reason"]
                .as_str()
                .unwrap()
                .contains("upstream filter"),
            "{first}"
        );
        assert_eq!(items[3]["status"], 404);
        assert_eq!(first["summary"]["cached"], 2);
        assert_eq!(first["summary"]["cached_bytes"], 10);

        assert_eq!(second["status"], "completed", "{second}");
        for item in second["items"].as_array().expect("items") {
            assert_eq!(item["state"], "already_cached", "{second}");
        }
        assert_eq!(second["items"][0]["checksum_sha256"], sha256_hex(b"aaaa"));
        assert_eq!(second["items"][1]["size_bytes"], 6);
        assert_eq!(audits, 2);
    }

    #[tokio::test]
    async fn seed_is_admin_only_remote_only_and_paths_only() {
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let server = MockServer::start().await;
        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let key = fx.repo_key.clone();
        let body = json!({"kind": "paths", "content": ["a.jar"]});

        // A plain member is not a repository admin.
        let (member_status, _) = post_seed(app(&fx, &state), &key, body.clone()).await;

        tdh::grant_repo_admin(&fx.pool, fx.repo_id, fx.user_id).await;
        let (planned_status, planned) = post_seed(
            app(&fx, &state),
            &key,
            json!({"kind": "pypi-requirements", "content": "requests==2.32.3"}),
        )
        .await;
        let (unknown_status, _) = post_seed(
            app(&fx, &state),
            &key,
            json!({"kind": "bogus", "content": []}),
        )
        .await;
        let (bad_options, _) = post_seed(
            app(&fx, &state),
            &key,
            json!({"kind": "paths", "content": ["a.jar"], "options": {"concurrency": 99}}),
        )
        .await;
        let (missing_job, _) = tdh::send(
            app(&fx, &state),
            tdh::get(format!("/{key}/cache/seed/{}", uuid::Uuid::new_v4())),
        )
        .await;

        let (local_id, local_key, local_dir) = tdh::create_repo(&fx.pool, "local", "generic").await;
        tdh::grant_repo_access(&fx.pool, local_id, fx.user_id).await;
        tdh::grant_repo_admin(&fx.pool, local_id, fx.user_id).await;
        let (local_status, _) = post_seed(app(&fx, &state), &local_key, body).await;

        tdh::cleanup_member_repo(&fx.pool, local_id, &local_dir).await;
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(local_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert_eq!(member_status, StatusCode::FORBIDDEN);
        assert_eq!(planned_status, StatusCode::BAD_REQUEST);
        assert!(
            planned.to_string().contains("not implemented yet"),
            "{planned}"
        );
        assert_eq!(unknown_status, StatusCode::BAD_REQUEST);
        assert_eq!(bad_options, StatusCode::BAD_REQUEST);
        assert_eq!(missing_job, StatusCode::NOT_FOUND);
        assert_eq!(local_status, StatusCode::BAD_REQUEST);
        assert!(server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
    }
}
