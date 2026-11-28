//! Warm a conda Remote's proxy cache from an ingested lockfile (#4184).
//!
//! * `POST   /api/v1/conda/{repo}/warm` with `{"environmentId": "<id>",
//!   "platform": "linux-64"}`: start a warm run (202), or return the run
//!   already active for that environment and platform (200).
//! * `GET    /api/v1/conda/{repo}/warm`: recent runs.
//! * `GET    /api/v1/conda/{repo}/warm/{id}`: one run's progress.
//! * `DELETE /api/v1/conda/{repo}/warm/{id}`: cancel an active run.
//!
//! `{repo}` is a conda Remote, or a Virtual whose Remote members are warmed.
//! Every endpoint needs repository `write` (or admin) on `{repo}`; a caller
//! without read gets the unknown-key 404. Warming a Virtual also needs read
//! on each Remote member it fills, the rule a download through the Virtual
//! applies. The environment must be one the caller can read.
//!
//! The runner fetches each package through the Remote's own download path
//! ([`conda::warm_remote_package`]), at most `CONDA_WARM_CONCURRENCY` at a
//! time and `CONDA_WARM_UPSTREAM_RPS` started per second per process, and
//! skips a package whose fresh cache entry already records the pinned
//! sha256. It fills the cache and serves nothing, so every serve-time gate
//! still applies to the warmed entries. Persistence, resolution and metrics
//! are in [`crate::services::conda_warm_service`].

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Extension, Json, Router,
};
use futures::StreamExt;
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::conda;
use crate::api::handlers::proxy_helpers;
use crate::api::handlers::repositories::{
    hide_write_denial_from_non_readers, require_repo_action, require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};
use crate::services::conda_warm_service::{
    parse_package_url, record_fetch, record_item, record_running_jobs, resolve_channel,
    ClaimedItem, ItemStatus, JobStop, RemoteCandidate, Resolution, WarmConfig, WarmJob,
    WarmService, MAX_ATTEMPTS,
};
use crate::services::proxy_service::UpstreamByteMeter;
use crate::services::repository_service::RepositoryService;

/// Body of [`start_warm`].
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartWarmRequest {
    /// A stored environment's id (`POST /api/v1/repositories/{key}/environments`).
    #[serde(alias = "environment_id", alias = "lockfileId", alias = "lockfile_id")]
    pub environment_id: Uuid,
    /// Warm only this platform's packages (`linux-64`, ...). Default: every
    /// platform the lockfile resolves.
    pub platform: Option<String>,
}

/// Query for [`list_warms`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListWarmsQuery {
    /// Page size (1-100, default 20).
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// `{repo}` for a warm endpoint: a conda Remote or Virtual on which the caller
/// may write (a caller who cannot read it gets the unknown-key 404).
async fn authorized_repo(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<Repository> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(key).await?;
    let gate = require_repo_action(auth, repo.id, "write", &state.permission_service).await;
    hide_write_denial_from_non_readers(gate, auth, &repo, &repo_service).await?;
    if repo.format != RepositoryFormat::Conda {
        return Err(AppError::Validation(format!(
            "`{key}` is not a conda repository"
        )));
    }
    if !matches!(
        repo.repo_type,
        RepositoryType::Remote | RepositoryType::Virtual
    ) {
        return Err(AppError::Validation(format!(
            "`{key}` is a {} repository; a warm fills a Remote's proxy cache, so it takes \
             a Remote or a Virtual with Remote members",
            format!("{:?}", repo.repo_type).to_lowercase()
        )));
    }
    Ok(repo)
}

/// The Remotes a warm of `repo` fills, in priority order, and the keys of
/// its other (hosted) members.
async fn warm_targets(
    state: &SharedState,
    repo: &Repository,
) -> std::result::Result<(Vec<Repository>, Vec<String>), axum::response::Response> {
    if repo.repo_type == RepositoryType::Remote {
        return Ok((vec![repo.clone()], Vec::new()));
    }
    let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
    let (remotes, others): (Vec<_>, Vec<_>) = members
        .into_iter()
        .partition(|m| m.repo_type == RepositoryType::Remote && m.upstream_url.is_some());
    Ok((remotes, others.into_iter().map(|m| m.key).collect()))
}

fn response_error(resp: axum::response::Response) -> AppError {
    AppError::Internal(format!("virtual member lookup failed ({})", resp.status()))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Start warming a Remote's proxy cache from a stored environment (#4184).
#[utoipa::path(
    post,
    path = "/api/v1/conda/{key}/warm",
    tag = "conda",
    params(("key" = String, Path, description = "Conda Remote or Virtual repository key")),
    request_body = StartWarmRequest,
    responses(
        (status = 200, description = "A warm of this environment and platform is already active; that job", body = Object),
        (status = 202, description = "Warm job created and started", body = Object),
        (status = 400, description = "Not a conda Remote/Virtual, no Remote member, or too many packages", body = crate::api::openapi::ErrorResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository write permission (or read on a Remote member) required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or environment not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn start_warm(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Json(body): Json<StartWarmRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let repo = authorized_repo(&state, &auth, &key).await?;
    let (remotes, _) = warm_targets(&state, &repo).await.map_err(response_error)?;
    if remotes.is_empty() {
        return Err(AppError::Validation(format!(
            "`{key}` has no Remote member to warm"
        )));
    }
    if repo.repo_type == RepositoryType::Virtual {
        // A download through the Virtual is served only by members the
        // caller could read directly (#2073); a warm fills no member the
        // caller could not download from.
        let n = remotes.len();
        let readable =
            proxy_helpers::try_authorize_virtual_members(&state.db, Some(&auth), repo.id, remotes)
                .await
                .map_err(response_error)?;
        if readable.len() != n {
            return Err(AppError::Authorization(
                "warming this Virtual needs read access to each of its Remote members".to_string(),
            ));
        }
    }

    // The environment, through the reader's visibility rule.
    let repo_service = RepositoryService::new(state.db.clone());
    let env_repo: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM environments WHERE id = $1")
            .bind(body.environment_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let not_found = || AppError::NotFound("Environment not found".to_string());
    let env_repo = env_repo.ok_or_else(not_found)?;
    let env_repo = repo_service.get_by_id(env_repo).await?;
    require_visible(&env_repo, &Some(auth.clone()), &repo_service)
        .await
        .map_err(|_| not_found())?;
    if state.proxy_service.is_none() {
        return Err(AppError::ServiceUnavailable(
            "the proxy service is not running on this server".to_string(),
        ));
    }

    let platform = body.platform.as_deref().unwrap_or("").trim().to_string();
    let cfg = WarmConfig::from_env();
    let created = WarmService::new(state.db.clone())
        .create(
            repo.id,
            body.environment_id,
            &platform,
            auth.user_id,
            cfg.max_items,
        )
        .await?;
    spawn_job(state.clone(), created.job.id);
    let status = if created.created {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let envelope = job_envelope(&state, &repo, &created.job, false).await?;
    Ok((status, Json(envelope)))
}

/// Recent warm jobs of a repository, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/conda/{key}/warm",
    tag = "conda",
    params(ListWarmsQuery, ("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "Warm jobs, newest first", body = Object),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository write permission required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_warms(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Query(q): Query<ListWarmsQuery>,
) -> Result<Json<serde_json::Value>> {
    let repo = authorized_repo(&state, &auth, &key).await?;
    let jobs = WarmService::new(state.db.clone())
        .list(repo.id, q.limit.unwrap_or(20))
        .await?;
    let mut out = Vec::with_capacity(jobs.len());
    for job in &jobs {
        out.push(job_envelope(&state, &repo, job, false).await?);
    }
    Ok(Json(serde_json::json!({ "jobs": out })))
}

/// One warm job's progress, with the first items that did not warm.
#[utoipa::path(
    get,
    path = "/api/v1/conda/{key}/warm/{id}",
    tag = "conda",
    params(("key" = String, Path, description = "Repository key"), ("id" = Uuid, Path, description = "Warm job id")),
    responses(
        (status = 200, description = "Warm job progress", body = Object),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository write permission required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or job not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_warm(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let repo = authorized_repo(&state, &auth, &key).await?;
    let job = WarmService::new(state.db.clone()).get(repo.id, id).await?;
    Ok(Json(job_envelope(&state, &repo, &job, true).await?))
}

/// Cancel an active warm job. Items already warmed stay cached.
#[utoipa::path(
    delete,
    path = "/api/v1/conda/{key}/warm/{id}",
    tag = "conda",
    params(("key" = String, Path, description = "Repository key"), ("id" = Uuid, Path, description = "Warm job id")),
    responses(
        (status = 204, description = "Cancelled"),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Repository write permission required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or job not found", body = crate::api::openapi::ErrorResponse),
        (status = 409, description = "The job already finished", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn cancel_warm(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((key, id)): Path<(String, Uuid)>,
) -> Result<StatusCode> {
    let repo = authorized_repo(&state, &auth, &key).await?;
    let svc = WarmService::new(state.db.clone());
    let job = svc.get(repo.id, id).await?;
    if svc.cancel(repo.id, job.id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Conflict(format!(
            "warm job {} is already {}",
            job.id, job.status
        )))
    }
}

async fn job_envelope(
    state: &SharedState,
    repo: &Repository,
    job: &WarmJob,
    with_problems: bool,
) -> Result<serde_json::Value> {
    let svc = WarmService::new(state.db.clone());
    let progress = svc.progress(job.id).await?;
    let mut v = serde_json::json!({
        "id": job.id,
        "repository": repo.key,
        "environmentId": job.environment_id,
        "platform": if job.platform.is_empty() { None } else { Some(&job.platform) },
        "status": job.status,
        "total": job.total,
        "done": progress.done,
        "remaining": progress.remaining,
        "counts": progress.counts,
        "bytesFetched": progress.bytes_fetched,
        "skippedNoUrl": job.skipped_no_url,
        "createdAt": job.created_at,
        "startedAt": job.started_at,
        "finishedAt": job.finished_at,
    });
    if with_problems {
        v["problems"] = serde_json::to_value(svc.problems(job.id, 50).await?)
            .unwrap_or(serde_json::Value::Null);
    }
    Ok(v)
}

/// Routes nested at `/api/v1/conda` under the full-auth middleware.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:key/warm", get(list_warms).post(start_warm))
        .route("/:key/warm/:id", get(get_warm).delete(cancel_warm))
}

#[derive(OpenApi)]
#[openapi(
    paths(start_warm, list_warms, get_warm, cancel_warm),
    components(schemas(StartWarmRequest))
)]
pub struct CondaWarmApiDoc;

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

struct Budget {
    /// Package fetches in flight, across every job in this process.
    permits: Arc<Semaphore>,
    /// The next instant an upstream-bound fetch may start.
    next_start: tokio::sync::Mutex<Instant>,
    interval: Duration,
}

impl Budget {
    async fn pace(&self) {
        let at = {
            let mut next = self.next_start.lock().await;
            let now = Instant::now();
            let at = (*next).max(now);
            *next = at + self.interval;
            at
        };
        tokio::time::sleep_until(at.into()).await;
    }
}

fn budget() -> &'static Budget {
    static BUDGET: OnceLock<Budget> = OnceLock::new();
    BUDGET.get_or_init(|| {
        let cfg = WarmConfig::from_env();
        Budget {
            permits: Arc::new(Semaphore::new(cfg.concurrency)),
            next_start: tokio::sync::Mutex::new(Instant::now()),
            interval: Duration::from_secs_f64(1.0 / f64::from(cfg.upstream_rps.max(1))),
        }
    })
}

/// Jobs this process is running, so a job is never run twice in one process.
fn running() -> &'static Mutex<HashSet<Uuid>> {
    static RUNNING: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashSet::new()))
}

fn shutdown_token() -> &'static OnceLock<CancellationToken> {
    static TOKEN: OnceLock<CancellationToken> = OnceLock::new();
    &TOKEN
}

/// Attempts [`spawn_job`] gives a run that stops on an error (a database
/// outage) before it ends the job as `failed`.
const RUNNER_ATTEMPTS: u32 = 5;
/// The first pause between those attempts; it doubles, up to a minute.
const RUNNER_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Run `job_id` in this process unless it already is.
///
/// A run that stops on an error is retried with backoff; once it has failed
/// [`RUNNER_ATTEMPTS`] times the job is ended as `failed`, so it never stays
/// `running` with nothing running it. If even that write fails (the database
/// is down), the job stays active: the next start resumes it, and a repeat
/// `POST .../warm` returns it and starts a runner here again.
pub(crate) fn spawn_job(state: SharedState, job_id: Uuid) {
    {
        let mut set = running().lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(job_id) {
            return;
        }
    }
    tokio::spawn(async move {
        struct Release(Uuid);
        impl Drop for Release {
            fn drop(&mut self) {
                running()
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&self.0);
                record_running_jobs(-1.0);
            }
        }
        record_running_jobs(1.0);
        let _release = Release(job_id);
        let shutdown = shutdown_token().get().cloned().unwrap_or_default();
        let ran = run_with_retries(RUNNER_ATTEMPTS, RUNNER_RETRY_DELAY, &shutdown, |attempt| {
            let state = state.clone();
            async move {
                let r = run_job(&state, job_id).await;
                if let Err(e) = &r {
                    tracing::warn!(job = %job_id, attempt, error = %e, "conda warm job stopped on an error");
                }
                r
            }
        })
        .await;
        if ran == RunEnd::GaveUp {
            match WarmService::new(state.db.clone())
                .stop(job_id, JobStop::Failed)
                .await
            {
                Ok(_) => {
                    tracing::warn!(job = %job_id, "conda warm job failed after repeated errors")
                }
                Err(e) => {
                    tracing::warn!(job = %job_id, error = %e, "could not mark the conda warm job failed; it resumes on the next start or a repeat request")
                }
            }
        }
    });
}

/// How [`run_with_retries`] ended.
#[derive(Debug, PartialEq, Eq)]
enum RunEnd {
    Done,
    GaveUp,
    ShutDown,
}

/// Call `run` until it succeeds, at most `attempts` times, pausing `delay`
/// (doubling, at most a minute) between failures. A shutdown ends the wait.
async fn run_with_retries<F, Fut>(
    attempts: u32,
    delay: Duration,
    shutdown: &CancellationToken,
    mut run: F,
) -> RunEnd
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut delay = delay;
    for attempt in 1..=attempts {
        if run(attempt).await.is_ok() {
            return RunEnd::Done;
        }
        if attempt == attempts {
            break;
        }
        tokio::select! {
            _ = shutdown.cancelled() => return RunEnd::ShutDown,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(Duration::from_secs(60));
    }
    RunEnd::GaveUp
}

/// Resume every active warm job (startup). Detached: the shutdown token
/// stops the runners between batches; claims left open lapse after the item
/// lease and are taken over by the next runner.
pub fn spawn_resume(
    state: SharedState,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let _ = shutdown_token().set(shutdown.clone());
    tokio::spawn(async move {
        // Let startup finish before the first upstream request.
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
        match WarmService::new(state.db.clone()).active_job_ids().await {
            Ok(ids) => {
                if !ids.is_empty() {
                    tracing::info!(jobs = ids.len(), "resuming conda warm jobs");
                }
                for id in ids {
                    spawn_job(state.clone(), id);
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list conda warm jobs to resume"),
        }
    })
}

/// What one job's items are resolved against, loaded once per run.
struct JobContext {
    scope: Scope,
    remotes: Vec<Repository>,
}

/// The repository a job warms, as [`warm_item_with`] sees it.
struct Scope {
    repo_id: Uuid,
    repo_key: String,
    is_virtual: bool,
    candidates: Vec<RemoteCandidate>,
    other_member_keys: Vec<String>,
}

async fn run_job(state: &SharedState, job_id: Uuid) -> Result<()> {
    let cfg = WarmConfig::from_env();
    let svc = WarmService::new(state.db.clone());
    let Some(job) = svc.job_by_id(job_id).await? else {
        return Ok(());
    };
    if !matches!(job.status.as_str(), "pending" | "running") {
        return Ok(());
    }
    let repo = RepositoryService::new(state.db.clone())
        .get_by_id(job.repository_id)
        .await?;
    let (remotes, other_member_keys) = warm_targets(state, &repo).await.map_err(response_error)?;
    let candidates = remotes
        .iter()
        .map(|r| RemoteCandidate {
            id: r.id,
            key: r.key.clone(),
            upstream_url: r.upstream_url.clone().unwrap_or_default(),
        })
        .collect();
    let ctx = JobContext {
        scope: Scope {
            repo_id: repo.id,
            repo_key: repo.key.clone(),
            is_virtual: repo.repo_type == RepositoryType::Virtual,
            candidates,
            other_member_keys,
        },
        remotes,
    };
    svc.mark_running(job_id).await?;
    // The job's byte budget, counting what earlier runs already fetched. A
    // fetch increments it as upstream bytes arrive, not after the item settles.
    let used = Arc::new(AtomicU64::new(
        svc.bytes_fetched(job_id).await?.max(0) as u64
    ));
    let shutdown = shutdown_token().get().cloned().unwrap_or_default();
    let batch = (cfg.concurrency * 4) as i64;
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        // A cancel (or a completion by another replica) ends this runner.
        match svc.job_by_id(job_id).await? {
            Some(j) if matches!(j.status.as_str(), "pending" | "running") => {}
            _ => return Ok(()),
        }
        if used.load(Ordering::Relaxed) >= cfg.max_job_bytes {
            svc.stop(job_id, JobStop::BudgetExceeded).await?;
            tracing::warn!(
                job = %job_id,
                repository = %ctx.scope.repo_key,
                bytes = used.load(Ordering::Relaxed),
                budget = cfg.max_job_bytes,
                "conda warm job stopped: its byte budget (CONDA_WARM_MAX_JOB_BYTES) is spent"
            );
            return Ok(());
        }
        let items = svc.claim(job_id, batch, cfg.item_lease).await?;
        if items.is_empty() {
            if svc.complete_if_done(job_id).await? {
                tracing::info!(job = %job_id, repository = %ctx.scope.repo_key, "conda warm job completed");
                return Ok(());
            }
            // Another runner holds the open claims; wait for them or their lease.
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            continue;
        }
        futures::stream::iter(items)
            .for_each_concurrent(cfg.concurrency, |item| {
                let ctx = &ctx;
                let svc = &svc;
                let used = &used;
                async move {
                    let (status, remote, bytes, detail) =
                        if used.load(Ordering::Relaxed) >= cfg.max_job_bytes {
                            // The budget is spent: put the item back unfetched;
                            // the loop then ends the job.
                            (ItemStatus::Pending, None, None, Some("the job's byte budget is spent".to_string()))
                        } else {
                            let (status, remote, bytes, detail) =
                                warm_item(state, ctx, &item, cfg.item_timeout, used).await;
                            (settle(status, item.attempts), remote, bytes, detail)
                        };
                    if !status.is_open() {
                        record_item(status);
                    }
                    if let Err(e) = svc
                        .finish_item(item.id, status, remote, bytes, detail.as_deref())
                        .await
                    {
                        tracing::warn!(item = item.id, error = %e, "could not record a conda warm item; its claim lapses and it is retried");
                    }
                }
            })
            .await;
    }
}

type ItemOutcome = (ItemStatus, Option<Uuid>, Option<i64>, Option<String>);

/// A transient fault (`Pending`) on an item's last attempt is final.
fn settle(status: ItemStatus, attempts: i32) -> ItemStatus {
    if status == ItemStatus::Pending && attempts >= MAX_ATTEMPTS {
        ItemStatus::Failed
    } else {
        status
    }
}

/// The longest a drained fetch may take to appear in the cache.
const COMMIT_WAIT: Duration = Duration::from_secs(30);
/// The least commit wait an item gets when its deadline is nearly spent.
const MIN_COMMIT_WAIT: Duration = Duration::from_secs(2);

/// Wait up to `wait` for the background cache writer to commit a drained
/// fetch, as the generic cache seed does (#5284). `Err` names why the entry
/// is not there.
async fn await_commit(
    proxy: &crate::services::proxy_service::ProxyService,
    remote_id: Uuid,
    remote_key: &str,
    cache_key: &str,
    wait: Duration,
) -> std::result::Result<(), String> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut delay = Duration::from_millis(25);
    loop {
        if proxy
            .fresh_cache_redirect(remote_key, cache_key)
            .await
            .is_some()
        {
            return Ok(());
        }
        if proxy.served_without_cache(remote_id, cache_key) {
            return Err(
                "served without caching: larger than the repository's quota or proxy-cache cap"
                    .to_string(),
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("fetched, but the proxy cache did not commit the entry".to_string());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(500));
    }
}

/// A cache entry as [`warm_item_with`] sees it.
#[derive(Debug, Clone)]
struct CachedEntry {
    /// Inside its Package Age Policy hold.
    held: bool,
    /// The sha256 its sidecar records; empty when it records none.
    sha256: String,
}

/// The upstream bytes one fetch actually consumed, as an item's recorded size.
fn metered_bytes(meter: &UpstreamByteMeter) -> Option<i64> {
    let bytes = meter.bytes();
    (bytes > 0).then_some(bytes as i64)
}

/// Publish each attempt's bytes as soon as that attempt ends, rather than
/// waiting for the item to settle (#6488).
fn record_metered_fetch(meter: &UpstreamByteMeter, published: &mut u64) {
    let total = meter.bytes();
    if total > *published {
        record_fetch(total - *published);
        *published = total;
    }
}

/// The side effects of warming one item, so the decisions in
/// [`warm_item_with`] are testable without an upstream or a cache.
trait WarmOps {
    /// Whether the Virtual's allowlist admits the file. `Err` is the status
    /// of a failed lookup.
    async fn allowlist_admits(
        &self,
        virtual_id: Uuid,
        subdir: &str,
        filename: &str,
    ) -> std::result::Result<bool, StatusCode>;
    /// Whether a non-Remote (hosted) member of the Virtual owns `name`.
    async fn hosted_owns_name(
        &self,
        virtual_id: Uuid,
        name: &str,
    ) -> std::result::Result<bool, StatusCode>;
    /// The fresh cache entry `remote` holds under `cache_key`.
    async fn cached(&self, remote: &RemoteCandidate, cache_key: &str) -> Option<CachedEntry>;
    /// A process-wide fetch permit, after pacing. `None`: shutting down.
    async fn acquire(&self) -> Option<OwnedSemaphorePermit>;
    /// Fetch through the Remote's download path (and drain the body). The
    /// meter counts upstream bytes even when the status is not 2xx or the
    /// deadline cuts the body short (#6488).
    async fn fetch(
        &self,
        remote: &RemoteCandidate,
        via_virtual: Option<Uuid>,
        subdir: &str,
        filename: &str,
        meter: &UpstreamByteMeter,
    ) -> (StatusCode, Option<(String, u64)>);
    /// Wait up to `wait` for the fetched entry to be committed.
    async fn await_commit(
        &self,
        remote: &RemoteCandidate,
        cache_key: &str,
        wait: Duration,
    ) -> std::result::Result<(), String>;
    /// Remove the entry from `remote`'s proxy cache.
    async fn evict(
        &self,
        remote: &RemoteCandidate,
        cache_key: &str,
    ) -> std::result::Result<(), String>;
}

/// [`WarmOps`] against the running server.
struct LiveOps<'a> {
    state: &'a SharedState,
    proxy: &'a crate::services::proxy_service::ProxyService,
    remotes: &'a [Repository],
}

impl WarmOps for LiveOps<'_> {
    async fn allowlist_admits(
        &self,
        virtual_id: Uuid,
        subdir: &str,
        filename: &str,
    ) -> std::result::Result<bool, StatusCode> {
        conda::virtual_allowlist_admits(&self.state.db, virtual_id, subdir, filename)
            .await
            .map_err(|r| r.status())
    }

    async fn hosted_owns_name(
        &self,
        virtual_id: Uuid,
        name: &str,
    ) -> std::result::Result<bool, StatusCode> {
        proxy_helpers::virtual_non_remote_owns_name(&self.state.db, virtual_id, name, "conda")
            .await
            .map_err(|r| r.status())
    }

    async fn cached(&self, remote: &RemoteCandidate, cache_key: &str) -> Option<CachedEntry> {
        // The hold is read from the same sidecar the serve-time gate reads.
        let entry = self
            .proxy
            .fresh_cache_redirect(&remote.key, cache_key)
            .await?;
        Some(CachedEntry {
            held: entry.quarantine_gate().is_err(),
            sha256: entry.checksum_sha256().to_string(),
        })
    }

    async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        let permit = budget().permits.clone().acquire_owned().await.ok()?;
        budget().pace().await;
        Some(permit)
    }

    async fn fetch(
        &self,
        remote: &RemoteCandidate,
        via_virtual: Option<Uuid>,
        subdir: &str,
        filename: &str,
        meter: &UpstreamByteMeter,
    ) -> (StatusCode, Option<(String, u64)>) {
        let Some(repo) = self.remotes.iter().find(|r| r.id == remote.id) else {
            return (StatusCode::NOT_FOUND, None);
        };
        UpstreamByteMeter::scope(
            meter.clone(),
            conda::warm_remote_package(self.state, self.proxy, repo, via_virtual, subdir, filename),
        )
        .await
    }

    async fn await_commit(
        &self,
        remote: &RemoteCandidate,
        cache_key: &str,
        wait: Duration,
    ) -> std::result::Result<(), String> {
        await_commit(self.proxy, remote.id, &remote.key, cache_key, wait).await
    }

    async fn evict(
        &self,
        remote: &RemoteCandidate,
        cache_key: &str,
    ) -> std::result::Result<(), String> {
        self.proxy
            .invalidate_cache_by_key(&remote.key, cache_key)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Warm one item against the running server. `Pending` means a transient
/// fault: retried until [`MAX_ATTEMPTS`].
async fn warm_item(
    state: &SharedState,
    ctx: &JobContext,
    item: &ClaimedItem,
    item_timeout: Duration,
    job_bytes: &Arc<AtomicU64>,
) -> ItemOutcome {
    let Some(proxy) = state.proxy_service.as_deref() else {
        return (
            ItemStatus::Pending,
            None,
            None,
            Some("proxy service not running".into()),
        );
    };
    let ops = LiveOps {
        state,
        proxy,
        remotes: &ctx.remotes,
    };
    warm_item_with(&ops, &ctx.scope, item, item_timeout, job_bytes).await
}

/// The decisions for one item: resolve it to the Remote(s) that serve it,
/// apply the Virtual's own rules, skip what is cached, fetch under the
/// process-wide budget and an end-to-end deadline, and check the bytes
/// against the lockfile's pin.
async fn warm_item_with<O: WarmOps>(
    ops: &O,
    scope: &Scope,
    item: &ClaimedItem,
    item_timeout: Duration,
    job_bytes: &Arc<AtomicU64>,
) -> ItemOutcome {
    let Some(pkg) = parse_package_url(&item.url) else {
        return (
            ItemStatus::NotRemote,
            None,
            None,
            Some("not a conda package URL".into()),
        );
    };
    let ids = match resolve_channel(
        &pkg.channel,
        &scope.repo_key,
        &scope.candidates,
        &scope.other_member_keys,
    ) {
        Resolution::NotRemote => {
            return (
                ItemStatus::NotRemote,
                None,
                None,
                Some("the URL's channel is not a Remote of this repository".into()),
            )
        }
        Resolution::Remotes(ids) => ids,
    };
    let via_virtual = scope.is_virtual.then_some(scope.repo_id);
    if let Some(virtual_id) = via_virtual {
        // The Virtual serves what its merged index lists: not a name a
        // hosted member owns (#4555), not what its allowlist refuses.
        match ops
            .allowlist_admits(virtual_id, &pkg.subdir, &pkg.filename)
            .await
        {
            Ok(true) => {}
            Ok(false) => return (ItemStatus::NotAllowed, None, None, None),
            Err(code) => {
                return (
                    ItemStatus::Pending,
                    None,
                    None,
                    Some(format!("allowlist lookup: {code}")),
                )
            }
        }
        if let Some(name) = conda::conda_package_name(&pkg.filename) {
            match ops.hosted_owns_name(virtual_id, name).await {
                Ok(false) => {}
                Ok(true) => {
                    return (
                        ItemStatus::NotRemote,
                        None,
                        None,
                        Some(format!("a hosted member owns `{name}`")),
                    )
                }
                Err(code) => {
                    return (
                        ItemStatus::Pending,
                        None,
                        None,
                        Some(format!("member lookup: {code}")),
                    )
                }
            }
        }
    }

    let cache_key = conda::conda_package_cache_key(&pkg.subdir, &pkg.filename);
    let expected = item.expected_sha256.as_deref();
    // One meter for the item: every attempt contributes to it, including a
    // timed-out body and a non-2xx answer (#6488).
    let meter = UpstreamByteMeter::new(Some(Arc::clone(job_bytes)));
    let mut published_bytes = 0;
    let mut last_detail = None;
    for remote in ids
        .iter()
        .filter_map(|id| scope.candidates.iter().find(|r| r.id == *id))
    {
        // Idempotent: a fresh entry is not fetched again.
        if let Some(entry) = ops.cached(remote, &cache_key).await {
            if entry.held {
                return (ItemStatus::Held, Some(remote.id), None, None);
            }
            match expected {
                // A mismatch the commit left behind (or a client cached
                // earlier) is safe to remove now: this lookup proves the
                // entry is fully present (#6488).
                Some(want) if !entry.sha256.is_empty() && entry.sha256 != want => {
                    let evicted = match ops.evict(remote, &cache_key).await {
                        Ok(()) => "removed from the cache".to_string(),
                        Err(e) => format!("could not be removed from the cache: {e}"),
                    };
                    return (
                        ItemStatus::ChecksumMismatch,
                        Some(remote.id),
                        None,
                        Some(format!(
                            "cached sha256 {}, the lockfile pins {want}; {evicted}",
                            entry.sha256
                        )),
                    );
                }
                // The entry is already cached: its size is not bytes this job
                // fetched, so it must not reach the budget (#6488).
                _ if !entry.sha256.is_empty() => {
                    return (ItemStatus::Cached, Some(remote.id), None, None)
                }
                _ => {}
            }
        }
        // One deadline for the whole item: the wait for a permit is not
        // counted, the response, the body and the commit are.
        let Some(permit) = ops.acquire().await else {
            return (
                ItemStatus::Pending,
                None,
                None,
                Some("shutting down".into()),
            );
        };
        let deadline = tokio::time::Instant::now() + item_timeout;
        let fetched = tokio::time::timeout_at(
            deadline,
            ops.fetch(remote, via_virtual, &pkg.subdir, &pkg.filename, &meter),
        )
        .await;
        // The commit wait below holds no permit: it costs the upstream
        // nothing.
        drop(permit);
        let bytes = metered_bytes(&meter);
        let Ok((status, served)) = fetched else {
            record_metered_fetch(&meter, &mut published_bytes);
            return (
                ItemStatus::Pending,
                Some(remote.id),
                bytes,
                Some(format!(
                    "no complete response from {} within {}s; retried",
                    remote.key,
                    item_timeout.as_secs()
                )),
            );
        };
        record_metered_fetch(&meter, &mut published_bytes);
        let commit_wait = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .clamp(MIN_COMMIT_WAIT, COMMIT_WAIT);
        match status.as_u16() {
            200..=299 => {
                let (sha, _) = served.unwrap_or_default();
                // The streaming tee commits after the body is drained; the
                // item is warm only once the entry is there to serve.
                let committed = ops.await_commit(remote, &cache_key, commit_wait).await;
                if let Some(want) = expected.filter(|want| *want != sha) {
                    // Only evict once the commit is confirmed. If it is not,
                    // the next lookup sees the mismatched entry and removes
                    // it, so a late commit cannot escape the check (#6488).
                    let evicted = match &committed {
                        Ok(()) => match ops.evict(remote, &cache_key).await {
                            Ok(()) => "removed from the cache".to_string(),
                            Err(e) => format!("could not be removed from the cache: {e}"),
                        },
                        Err(_) => "commit not confirmed; removed on the next lookup".to_string(),
                    };
                    return (
                        ItemStatus::ChecksumMismatch,
                        Some(remote.id),
                        bytes,
                        Some(format!(
                            "upstream sha256 {sha}, the lockfile pins {want}; {evicted}"
                        )),
                    );
                }
                return match committed {
                    Ok(()) => (ItemStatus::Fetched, Some(remote.id), bytes, None),
                    Err(why) => (ItemStatus::Failed, Some(remote.id), bytes, Some(why)),
                };
            }
            409 => return (ItemStatus::Held, Some(remote.id), bytes, None),
            403 => {
                return (
                    ItemStatus::Blocked,
                    Some(remote.id),
                    bytes,
                    Some("refused by the repository's scan or origin policy".into()),
                )
            }
            // Not on this member: the next one, as a Virtual walk does.
            404 => last_detail = Some(format!("404 from {}", remote.key)),
            400 => {
                return (
                    ItemStatus::Failed,
                    Some(remote.id),
                    bytes,
                    Some("the file name is not a servable conda package path".into()),
                )
            }
            code => {
                return (
                    ItemStatus::Pending,
                    Some(remote.id),
                    bytes,
                    Some(format!("HTTP {code} from {}; retried", remote.key)),
                )
            }
        }
    }
    (
        ItemStatus::Failed,
        None,
        None,
        last_detail.or(Some("no Remote serves it".into())),
    )
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::conda_warm_service::DEFAULT_MAX_JOB_BYTES;

    #[test]
    fn request_accepts_both_spellings() {
        let id = Uuid::new_v4();
        for body in [
            format!(r#"{{"environmentId":"{id}"}}"#),
            format!(r#"{{"environment_id":"{id}","platform":"linux-64"}}"#),
            format!(r#"{{"lockfileId":"{id}"}}"#),
        ] {
            let r: StartWarmRequest = serde_json::from_str(&body).expect(&body);
            assert_eq!(r.environment_id, id);
        }
        assert!(serde_json::from_str::<StartWarmRequest>("{}").is_err());
    }

    #[tokio::test]
    async fn pacing_spaces_starts() {
        let b = Budget {
            permits: Arc::new(Semaphore::new(1)),
            next_start: tokio::sync::Mutex::new(Instant::now()),
            interval: Duration::from_millis(50),
        };
        let t0 = Instant::now();
        for _ in 0..5 {
            b.pace().await;
        }
        // The first start is immediate, the next four are 50 ms apart.
        assert!(
            t0.elapsed() >= Duration::from_millis(195),
            "{:?}",
            t0.elapsed()
        );
    }

    // -----------------------------------------------------------------
    // warm_item_with: every branch, against a scripted WarmOps.
    // -----------------------------------------------------------------

    const SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[derive(Default)]
    struct Fake {
        allowlist: Option<std::result::Result<bool, StatusCode>>,
        owns: Option<std::result::Result<bool, StatusCode>>,
        cached: std::collections::HashMap<Uuid, CachedEntry>,
        fetch: std::collections::HashMap<Uuid, (StatusCode, Option<(String, u64)>)>,
        fetch_takes: Option<Duration>,
        fetch_bytes: Option<u64>,
        commit: Option<std::result::Result<(), String>>,
        shutting_down: bool,
        permits: Option<Arc<Semaphore>>,
        fetched: Mutex<Vec<(Uuid, Option<Uuid>)>>,
        evicted: Mutex<Vec<(Uuid, String)>>,
        commit_saw_free_permit: Mutex<Option<bool>>,
        events: Mutex<Vec<&'static str>>,
    }

    impl WarmOps for Fake {
        async fn allowlist_admits(
            &self,
            _: Uuid,
            _: &str,
            _: &str,
        ) -> std::result::Result<bool, StatusCode> {
            self.allowlist.unwrap_or(Ok(true))
        }
        async fn hosted_owns_name(
            &self,
            _: Uuid,
            _: &str,
        ) -> std::result::Result<bool, StatusCode> {
            self.owns.unwrap_or(Ok(false))
        }
        async fn cached(&self, remote: &RemoteCandidate, _: &str) -> Option<CachedEntry> {
            self.cached.get(&remote.id).cloned()
        }
        async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
            if self.shutting_down {
                return None;
            }
            let sem = self
                .permits
                .clone()
                .unwrap_or_else(|| Arc::new(Semaphore::new(1)));
            sem.acquire_owned().await.ok()
        }
        async fn fetch(
            &self,
            remote: &RemoteCandidate,
            via_virtual: Option<Uuid>,
            _: &str,
            _: &str,
            meter: &UpstreamByteMeter,
        ) -> (StatusCode, Option<(String, u64)>) {
            self.fetched.lock().unwrap().push((remote.id, via_virtual));
            let outcome = self
                .fetch
                .get(&remote.id)
                .cloned()
                .unwrap_or((StatusCode::NOT_FOUND, None));
            let bytes = self
                .fetch_bytes
                .or_else(|| outcome.1.as_ref().map(|(_, size)| *size))
                .unwrap_or(0);
            meter.add(bytes as usize);
            if let Some(d) = self.fetch_takes {
                tokio::time::sleep(d).await;
            }
            outcome
        }
        async fn await_commit(
            &self,
            _: &RemoteCandidate,
            _: &str,
            _: Duration,
        ) -> std::result::Result<(), String> {
            self.events.lock().unwrap().push("commit");
            if let Some(sem) = &self.permits {
                *self.commit_saw_free_permit.lock().unwrap() = Some(sem.available_permits() == 1);
            }
            self.commit.clone().unwrap_or(Ok(()))
        }
        async fn evict(
            &self,
            remote: &RemoteCandidate,
            cache_key: &str,
        ) -> std::result::Result<(), String> {
            self.events.lock().unwrap().push("evict");
            self.evicted
                .lock()
                .unwrap()
                .push((remote.id, cache_key.to_string()));
            Ok(())
        }
    }

    fn cand(key: &str) -> RemoteCandidate {
        RemoteCandidate {
            id: Uuid::new_v4(),
            key: key.into(),
            upstream_url: format!("https://upstream.example/{key}"),
        }
    }

    /// A Remote `fleet` warmed directly.
    fn remote_scope() -> Scope {
        let r = RemoteCandidate {
            key: "fleet".into(),
            ..cand("fleet")
        };
        Scope {
            repo_id: r.id,
            repo_key: "fleet".into(),
            is_virtual: false,
            candidates: vec![r],
            other_member_keys: vec![],
        }
    }

    /// A Virtual `fleet` over Remotes `r1`, `r2` and a hosted `hosted`.
    fn virtual_scope() -> Scope {
        Scope {
            repo_id: Uuid::new_v4(),
            repo_key: "fleet".into(),
            is_virtual: true,
            candidates: vec![cand("r1"), cand("r2")],
            other_member_keys: vec!["hosted".into()],
        }
    }

    fn item(url: &str, sha: Option<&str>, attempts: i32) -> ClaimedItem {
        ClaimedItem {
            id: 1,
            url: url.into(),
            expected_sha256: sha.map(str::to_string),
            attempts,
        }
    }

    const URL: &str = "https://ak.example/conda/fleet/linux-64/a-1.0-h0_0.conda";
    const T: Duration = Duration::from_secs(60);

    fn ok(sha: &str) -> (StatusCode, Option<(String, u64)>) {
        (StatusCode::OK, Some((sha.to_string(), 42)))
    }

    fn job_bytes() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(0))
    }

    async fn run(fake: &Fake, scope: &Scope, sha: Option<&str>) -> ItemOutcome {
        warm_item_with(fake, scope, &item(URL, sha, 1), T, &job_bytes()).await
    }

    #[tokio::test]
    async fn not_remote_urls_are_not_fetched() {
        let fake = Fake::default();
        let s = remote_scope();
        for url in [
            "https://elsewhere.example/ch/linux-64/a-1.0-0.conda",
            "https://ak.example/conda/fleet/linux-64/README.md",
        ] {
            let out = warm_item_with(&fake, &s, &item(url, None, 1), T, &job_bytes()).await;
            assert_eq!(out.0, ItemStatus::NotRemote, "{url}");
        }
        // A URL on the route of the Virtual's hosted member.
        let v = virtual_scope();
        let out = warm_item_with(
            &fake,
            &v,
            &item(
                "https://ak.example/conda/hosted/linux-64/a-1.0-0.conda",
                None,
                1,
            ),
            T,
            &job_bytes(),
        )
        .await;
        assert_eq!(out.0, ItemStatus::NotRemote);
        assert!(fake.fetched.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn virtual_allowlist_and_hosted_names() {
        let v = virtual_scope();
        let refused = Fake {
            allowlist: Some(Ok(false)),
            ..Fake::default()
        };
        assert_eq!(run(&refused, &v, None).await.0, ItemStatus::NotAllowed);
        let lookup_failed = Fake {
            allowlist: Some(Err(StatusCode::SERVICE_UNAVAILABLE)),
            ..Fake::default()
        };
        let out = run(&lookup_failed, &v, None).await;
        assert_eq!(out.0, ItemStatus::Pending);
        assert!(out.3.unwrap().contains("allowlist"));
        let hosted = Fake {
            owns: Some(Ok(true)),
            ..Fake::default()
        };
        let out = run(&hosted, &v, None).await;
        assert_eq!(out.0, ItemStatus::NotRemote);
        assert!(out.3.unwrap().contains("hosted member owns `a`"));
        let owner_failed = Fake {
            owns: Some(Err(StatusCode::INTERNAL_SERVER_ERROR)),
            ..Fake::default()
        };
        assert_eq!(run(&owner_failed, &v, None).await.0, ItemStatus::Pending);
        for f in [&refused, &lookup_failed, &hosted, &owner_failed] {
            assert!(f.fetched.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn cached_entries_are_not_fetched() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let entry = |held: bool, sha: &str| Fake {
            cached: [(
                id,
                CachedEntry {
                    held,
                    sha256: sha.into(),
                },
            )]
            .into(),
            fetch: [(id, ok(SHA))].into(),
            ..Fake::default()
        };
        let held = entry(true, SHA);
        assert_eq!(run(&held, &s, Some(SHA)).await.0, ItemStatus::Held);
        let same = entry(false, SHA);
        let out = run(&same, &s, Some(SHA)).await;
        assert_eq!((out.0, out.2), (ItemStatus::Cached, None));
        // A mismatched entry left by a late commit (or a client's earlier
        // pull) is removed once a lookup confirms it is present. A cached
        // entry's own size never counts as fetched bytes.
        let other = entry(false, OTHER);
        let out = run(&other, &s, Some(SHA)).await;
        assert_eq!((out.0, out.2), (ItemStatus::ChecksumMismatch, None));
        assert!(out.3.unwrap().starts_with("cached sha256"));
        assert_eq!(other.evicted.lock().unwrap().len(), 1);
        for f in [&held, &same, &other] {
            assert!(f.fetched.lock().unwrap().is_empty());
        }
        // An entry that records no sha256 is fetched again to learn it.
        let unknown = entry(false, "");
        assert_eq!(run(&unknown, &s, Some(SHA)).await.0, ItemStatus::Fetched);
        assert_eq!(unknown.fetched.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_then_commit_without_holding_a_permit() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let fake = Fake {
            fetch: [(id, ok(SHA))].into(),
            permits: Some(Arc::new(Semaphore::new(1))),
            ..Fake::default()
        };
        let out = run(&fake, &s, Some(SHA)).await;
        assert_eq!(out, (ItemStatus::Fetched, Some(id), Some(42), None));
        assert_eq!(*fake.commit_saw_free_permit.lock().unwrap(), Some(true));
        assert_eq!(
            fake.fetched.lock().unwrap().as_slice(),
            &[(id, None)],
            "a direct warm uses the Remote's own scan policy"
        );
    }

    #[tokio::test]
    async fn a_mismatch_after_the_fetch_is_evicted() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let fake = Fake {
            fetch: [(id, ok(OTHER))].into(),
            ..Fake::default()
        };
        let out = run(&fake, &s, Some(SHA)).await;
        assert_eq!(out.0, ItemStatus::ChecksumMismatch);
        let detail = out.3.unwrap();
        assert!(detail.contains("removed from the cache"), "{detail}");
        let evicted = fake.evicted.lock().unwrap().clone();
        assert_eq!(
            evicted,
            vec![(
                id,
                conda::conda_package_cache_key("linux-64", "a-1.0-h0_0.conda")
            )]
        );
        assert_eq!(
            fake.events.lock().unwrap().as_slice(),
            &["commit", "evict"],
            "the mismatch is removed only after the commit is confirmed"
        );
        // No pin: any bytes are the right ones.
        let unpinned = Fake {
            fetch: [(id, ok(OTHER))].into(),
            ..Fake::default()
        };
        assert_eq!(run(&unpinned, &s, None).await.0, ItemStatus::Fetched);
        assert!(unpinned.evicted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_uncommitted_mismatch_is_not_evicted_early() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let fake = Fake {
            fetch: [(id, ok(OTHER))].into(),
            commit: Some(Err("no commit yet".into())),
            ..Fake::default()
        };
        let out = run(&fake, &s, Some(SHA)).await;
        assert_eq!(out.0, ItemStatus::ChecksumMismatch);
        assert!(out.3.unwrap().contains("next lookup"));
        assert!(fake.evicted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_upstream_byte_counts_toward_the_job_budget() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let job_bytes = job_bytes();
        let fake = Fake {
            fetch: [(id, (StatusCode::FORBIDDEN, None))].into(),
            fetch_bytes: Some(17),
            ..Fake::default()
        };
        let out = warm_item_with(&fake, &s, &item(URL, Some(SHA), 1), T, &job_bytes).await;
        assert_eq!((out.0, out.2), (ItemStatus::Blocked, Some(17)));
        assert_eq!(job_bytes.load(Ordering::Relaxed), 17);

        let retry_bytes = Arc::new(AtomicU64::new(0));
        let fake = Fake {
            fetch: [(id, (StatusCode::BAD_GATEWAY, None))].into(),
            fetch_bytes: Some(9),
            ..Fake::default()
        };
        let out = warm_item_with(&fake, &s, &item(URL, Some(SHA), 1), T, &retry_bytes).await;
        assert_eq!((out.0, out.2), (ItemStatus::Pending, Some(9)));
        assert_eq!(retry_bytes.load(Ordering::Relaxed), 9);
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_retry_counts_the_bytes_it_did_fetch() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let job_bytes = job_bytes();
        let fake = Fake {
            fetch: [(id, ok(SHA))].into(),
            fetch_bytes: Some(11),
            fetch_takes: Some(Duration::from_secs(3_600)),
            ..Fake::default()
        };
        let out = warm_item_with(
            &fake,
            &s,
            &item(URL, Some(SHA), 1),
            Duration::from_secs(5),
            &job_bytes,
        )
        .await;
        assert_eq!((out.0, out.2), (ItemStatus::Pending, Some(11)));
        assert_eq!(job_bytes.load(Ordering::Relaxed), 11);
    }

    #[tokio::test]
    async fn through_a_virtual_the_scan_gate_can_block() {
        let v = virtual_scope();
        let r1 = v.candidates[0].id;
        let fake = Fake {
            fetch: [(r1, (StatusCode::FORBIDDEN, None))].into(),
            ..Fake::default()
        };
        let out = run(&fake, &v, Some(SHA)).await;
        assert_eq!(out.0, ItemStatus::Blocked);
        assert_eq!(
            fake.fetched.lock().unwrap().as_slice(),
            &[(r1, Some(v.repo_id))],
            "the fetch is made under the Virtual's (stricter) scan policy"
        );
    }

    #[tokio::test]
    async fn a_404_walks_to_the_next_member() {
        let v = virtual_scope();
        let (r1, r2) = (v.candidates[0].id, v.candidates[1].id);
        let fake = Fake {
            fetch: [(r1, (StatusCode::NOT_FOUND, None)), (r2, ok(SHA))].into(),
            ..Fake::default()
        };
        let out = run(&fake, &v, Some(SHA)).await;
        assert_eq!((out.0, out.1), (ItemStatus::Fetched, Some(r2)));
        let nowhere = Fake::default();
        let out = run(&nowhere, &v, None).await;
        assert_eq!(out.0, ItemStatus::Failed);
        assert_eq!(out.3.as_deref(), Some("404 from r2"));
        assert_eq!(nowhere.fetched.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn statuses_map_to_outcomes() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        for (code, want) in [
            (StatusCode::CONFLICT, ItemStatus::Held),
            (StatusCode::BAD_REQUEST, ItemStatus::Failed),
            (StatusCode::BAD_GATEWAY, ItemStatus::Pending),
            (StatusCode::TOO_MANY_REQUESTS, ItemStatus::Pending),
        ] {
            let fake = Fake {
                fetch: [(id, (code, None))].into(),
                ..Fake::default()
            };
            assert_eq!(run(&fake, &s, None).await.0, want, "{code}");
        }
        let not_committed = Fake {
            fetch: [(id, ok(SHA))].into(),
            commit: Some(Err(
                "fetched, but the proxy cache did not commit the entry".into()
            )),
            ..Fake::default()
        };
        let out = run(&not_committed, &s, Some(SHA)).await;
        assert_eq!(out.0, ItemStatus::Failed);
        assert!(out.3.unwrap().contains("did not commit"));
        let stopping = Fake {
            shutting_down: true,
            ..Fake::default()
        };
        let out = run(&stopping, &s, None).await;
        assert_eq!(
            (out.0, out.3.as_deref()),
            (ItemStatus::Pending, Some("shutting down"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickling_upstream_hits_the_item_deadline() {
        let s = remote_scope();
        let id = s.candidates[0].id;
        let permits = Arc::new(Semaphore::new(1));
        let fake = Fake {
            fetch: [(id, ok(SHA))].into(),
            fetch_takes: Some(Duration::from_secs(3_600)),
            permits: Some(permits.clone()),
            ..Fake::default()
        };
        let out = warm_item_with(
            &fake,
            &s,
            &item(URL, Some(SHA), 1),
            Duration::from_secs(5),
            &job_bytes(),
        )
        .await;
        assert_eq!(out.0, ItemStatus::Pending);
        assert!(out.3.unwrap().contains("within 5s"));
        assert_eq!(permits.available_permits(), 1, "the permit is released");
    }

    #[test]
    fn transient_faults_become_final_at_max_attempts() {
        assert_eq!(settle(ItemStatus::Pending, 1), ItemStatus::Pending);
        assert_eq!(
            settle(ItemStatus::Pending, MAX_ATTEMPTS),
            ItemStatus::Failed
        );
        assert_eq!(
            settle(ItemStatus::Fetched, MAX_ATTEMPTS),
            ItemStatus::Fetched
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_run_is_retried_then_given_up() {
        let token = CancellationToken::new();
        let calls = std::sync::atomic::AtomicU32::new(0);
        let end = run_with_retries(5, Duration::from_secs(2), &token, |_| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(AppError::Database("down".into()))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!((end, calls.load(Ordering::SeqCst)), (RunEnd::Done, 3));
        let calls = std::sync::atomic::AtomicU32::new(0);
        let end = run_with_retries(3, Duration::from_secs(2), &token, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(AppError::Database("down".into())) }
        })
        .await;
        assert_eq!((end, calls.load(Ordering::SeqCst)), (RunEnd::GaveUp, 3));
        token.cancel();
        let end = run_with_retries(3, Duration::from_secs(2), &token, |_| async {
            Err(AppError::Database("down".into()))
        })
        .await;
        assert_eq!(end, RunEnd::ShutDown);
    }

    // -----------------------------------------------------------------
    // Database-backed: the scan policy, authorization and the runner.
    // -----------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    fn lock_for(key: &str) -> String {
        format!(
            "version: 6\nenvironments:\n  default:\n    channels:\n    - url: https://ak.example/conda/{key}/\n    packages:\n      linux-64:\n      - conda: https://ak.example/conda/{key}/linux-64/a-1.0-h0_0.conda\n      - conda: https://ak.example/conda/{key}/linux-64/b-1.0-h0_0.conda\npackages:\n- conda: https://ak.example/conda/{key}/linux-64/a-1.0-h0_0.conda\n  sha256: {SHA}\n  depends: []\n- conda: https://ak.example/conda/{key}/linux-64/b-1.0-h0_0.conda\n  sha256: {OTHER}\n  depends: []\n"
        )
    }

    async fn ingest(pool: &sqlx::PgPool, repo_id: Uuid, key: &str) -> Uuid {
        let env = crate::services::environment_lock::parse_named_lockfile(
            "pixi.lock",
            lock_for(key).as_bytes(),
        )
        .expect("lock parses");
        crate::services::environment_service::EnvironmentService::new(pool.clone())
            .ingest(repo_id, "warm-env", "sha", &env)
            .await
            .expect("ingest")
            .id
    }

    fn start(env: Uuid) -> Json<StartWarmRequest> {
        Json(StartWarmRequest {
            environment_id: env,
            platform: None,
        })
    }

    #[tokio::test]
    async fn a_virtual_warm_scans_under_the_virtual_policy() {
        let Some(fx) = tdh::Fixture::setup("remote", "conda").await else {
            return;
        };
        let (virt, _, vdir) = tdh::create_repo(&fx.pool, "virtual", "conda").await;
        sqlx::query(
            "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
                 scan_on_proxy, proxy_scan_action, block_on_policy_violation, severity_threshold) \
             VALUES ($1, true, false, true, 'fail_closed', true, 'high')",
        )
        .bind(virt)
        .execute(&fx.pool)
        .await
        .expect("seed scan_configs");
        let direct = conda::warm_scan_policy(&fx.pool, fx.repo_id, None)
            .await
            .expect("readable");
        let through = conda::warm_scan_policy(&fx.pool, fx.repo_id, Some(virt))
            .await
            .expect("readable");
        assert!(direct.is_none(), "the member alone does not scan");
        assert!(through.is_some(), "the Virtual scans, so its warm does");
        sqlx::query("DELETE FROM scan_configs WHERE repository_id = $1")
            .bind(virt)
            .execute(&fx.pool)
            .await
            .unwrap();
        tdh::cleanup_member_repo(&fx.pool, virt, &vdir).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn live_ops_reads_and_evicts_a_real_cache_entry() {
        let Some(fx) = tdh::Fixture::setup("remote", "conda").await else {
            return;
        };
        let (server, _ssrf) = tdh::non_loopback_mock_server().await;
        let filename = "a-1.0-h0_0.conda";
        let path = format!("/linux-64/{filename}");
        let body = b"warmed-conda-package".to_vec();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(path.as_str()))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(server.uri())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let scope = crate::services::proxy_cache_scope::ProxyCacheScope::unscoped();
        let (proxy, _backend) = tdh::build_scoped_presign_proxy(fx.pool.clone(), scope);
        let state = tdh::build_state_with_proxy(
            fx.pool.clone(),
            fx.storage_dir.to_str().unwrap(),
            proxy.clone(),
        );
        let repo = RepositoryService::new(fx.pool.clone())
            .get_by_id(fx.repo_id)
            .await
            .unwrap();
        let candidate = RemoteCandidate {
            id: repo.id,
            key: repo.key.clone(),
            upstream_url: repo.upstream_url.clone().unwrap(),
        };
        let remotes = [repo];
        let ops = LiveOps {
            state: &state,
            proxy: &proxy,
            remotes: &remotes,
        };
        let cache_key = conda::conda_package_cache_key("linux-64", filename);

        assert!(ops.cached(&candidate, &cache_key).await.is_none());
        let meter = UpstreamByteMeter::new(None);
        let (status, served) = ops
            .fetch(&candidate, None, "linux-64", filename, &meter)
            .await;
        assert!(status.is_success(), "{status}");
        let (sha, size) = served.expect("a successful warm returns the served digest");
        assert_eq!(size, body.len() as u64);
        assert_eq!(meter.bytes(), body.len() as u64);

        ops.await_commit(&candidate, &cache_key, Duration::from_secs(5))
            .await
            .expect("the warm fills the proxy cache");
        let entry = ops
            .cached(&candidate, &cache_key)
            .await
            .expect("LiveOps::cached sees the fetched entry");
        assert!(!entry.held);
        assert_eq!(entry.sha256, sha);

        ops.evict(&candidate, &cache_key)
            .await
            .expect("LiveOps::evict invalidates the cache entry");
        assert!(
            ops.cached(&candidate, &cache_key).await.is_none(),
            "the evicted entry is no longer fresh"
        );
        fx.teardown().await;
    }

    #[tokio::test]
    async fn start_refuses_unreadable_members_and_invisible_environments() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let (virt, vkey, vdir) = tdh::create_repo(&fx.pool, "virtual", "conda").await;
        let (member, _, mdir) = tdh::create_repo(&fx.pool, "remote", "conda").await;
        tdh::link_virtual_member(&fx.pool, virt, member, 1).await;
        tdh::grant_repo_actions(&fx.pool, virt, fx.user_id, &["read", "write"]).await;
        let visible_env = ingest(&fx.pool, fx.repo_id, &vkey).await;

        // Write on the Virtual, nothing on its private Remote member.
        let r = start_warm(
            State(fx.state.clone()),
            Extension(auth.clone()),
            Path(vkey.clone()),
            start(visible_env),
        )
        .await;
        assert!(matches!(r, Err(AppError::Authorization(_))), "{r:?}");

        // Readable member, but an environment in a repository the caller
        // cannot see: the unknown-environment 404.
        tdh::grant_repo_actions(&fx.pool, member, fx.user_id, &["read"]).await;
        let (hidden, hkey, hdir) = tdh::create_repo(&fx.pool, "local", "conda").await;
        let hidden_env = ingest(&fx.pool, hidden, &hkey).await;
        let r = start_warm(
            State(fx.state.clone()),
            Extension(auth.clone()),
            Path(vkey.clone()),
            start(hidden_env),
        )
        .await;
        assert!(matches!(r, Err(AppError::NotFound(_))), "{r:?}");
        let created: i64 =
            sqlx::query_scalar("SELECT count(*) FROM conda_warm_jobs WHERE repository_id = $1")
                .bind(virt)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(created, 0, "neither request created a job");

        for (id, dir) in [(hidden, &hdir), (member, &mdir), (virt, &vdir)] {
            sqlx::query("DELETE FROM permissions WHERE target_id = $1")
                .bind(id)
                .execute(&fx.pool)
                .await
                .unwrap();
            tdh::cleanup_member_repo(&fx.pool, id, dir).await;
        }
        fx.teardown().await;
    }

    #[tokio::test]
    async fn the_runner_stops_on_cancel_and_on_a_spent_budget() {
        let Some(fx) = tdh::Fixture::setup("remote", "conda").await else {
            return;
        };
        let env = ingest(&fx.pool, fx.repo_id, &fx.repo_key).await;
        let svc = WarmService::new(fx.pool.clone());
        let open = |job: Uuid| {
            let pool = fx.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM conda_warm_items WHERE job_id = $1 AND status = 'pending'",
                )
                .bind(job)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };

        // Cancelled while running: the runner ends before claiming anything.
        let job = svc
            .create(fx.repo_id, env, "", fx.user_id, 100)
            .await
            .unwrap()
            .job;
        svc.mark_running(job.id).await.unwrap();
        assert!(svc.cancel(fx.repo_id, job.id).await.unwrap());
        run_job(&fx.state, job.id).await.expect("run");
        assert_eq!(open(job.id).await, 2, "nothing was claimed");
        assert_eq!(
            svc.get(fx.repo_id, job.id).await.unwrap().status,
            "cancelled"
        );

        // An earlier run fetched past the byte budget: the next run stops
        // the job as budget_exceeded and fetches nothing more.
        let job = svc
            .create(fx.repo_id, env, "", fx.user_id, 100)
            .await
            .unwrap()
            .job;
        let first = svc
            .claim(job.id, 1, Duration::from_secs(600))
            .await
            .unwrap();
        svc.finish_item(
            first[0].id,
            ItemStatus::Fetched,
            Some(fx.repo_id),
            Some((DEFAULT_MAX_JOB_BYTES + 1) as i64),
            None,
        )
        .await
        .unwrap();
        run_job(&fx.state, job.id).await.expect("run");
        assert_eq!(
            svc.get(fx.repo_id, job.id).await.unwrap().status,
            "budget_exceeded"
        );
        assert_eq!(open(job.id).await, 1, "the rest is left unfetched");
        fx.teardown().await;
    }
}
