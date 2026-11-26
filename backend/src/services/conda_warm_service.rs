//! Warm a conda Remote's proxy cache from an ingested lockfile (#4184).
//!
//! A fleet of CI jobs installing one locked environment from a cold Remote
//! sends every job's first request for each package upstream at once. A warm
//! run fetches every pinned package of a stored environment (#4054) into the
//! Remote's proxy cache beforehand, so the fleet is served from the cache.
//!
//! This module is the persistence and the pure logic: the job and item rows
//! (migration 425), mapping a lockfile URL to the Remote that serves it, the
//! tunables and the metrics. The runner that performs the fetches lives with
//! the route (`api::handlers::conda_warm`), because a fetch goes through the
//! same handler-layer gates a client download does.
//!
//! * **Idempotent.** One active job per (repository, environment, platform
//!   filter): asking again returns the running job. An item whose fresh cache
//!   entry already records the pinned sha256 is `cached` without a fetch.
//! * **Resumable.** Items are claimed in batches with `FOR UPDATE SKIP
//!   LOCKED` under a lease. A restarted process resumes every active job at
//!   startup; a claim whose process died lapses after the lease and is
//!   claimed again, by any replica.
//! * **Gated.** A warm only fills the cache through the Remote's own fetch
//!   path; it never serves. A package inside its Package Age Policy hold is
//!   recorded `held` (and the cached entry stays held), one the scan or origin
//!   policy refuses is `blocked`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// `CONDA_WARM_CONCURRENCY`: package fetches in flight per process, across
/// every warm job. Small, so warming never competes with foreground serves.
pub const DEFAULT_CONCURRENCY: usize = 8;
/// `CONDA_WARM_UPSTREAM_RPS`: upstream fetches started per second per
/// process, across every warm job. Entries already cached cost nothing.
pub const DEFAULT_UPSTREAM_RPS: u32 = 20;
/// `CONDA_WARM_MAX_ITEMS`: the most package files one job may warm.
pub const DEFAULT_MAX_ITEMS: usize = 50_000;
/// `CONDA_WARM_ITEM_LEASE_SECS`: how long a claimed item stays claimed before
/// another runner (after a crash or restart) may take it over.
pub const DEFAULT_ITEM_LEASE_SECS: u64 = 600;
/// `CONDA_WARM_ITEM_TIMEOUT_SECS`: the most one item may take end to end
/// (upstream response, body and cache commit). An upstream that trickles
/// bytes cannot hold a fetch permit past it; the item is retried.
pub const DEFAULT_ITEM_TIMEOUT_SECS: u64 = 300;
/// `CONDA_WARM_MAX_JOB_BYTES`: the most bytes one job may fetch from
/// upstream (100 GiB). Checked before each fetch, so a job may overshoot by
/// the fetches already in flight; it then stops as `budget_exceeded`.
pub const DEFAULT_MAX_JOB_BYTES: u64 = 100 * 1024 * 1024 * 1024;
/// Attempts per item before a transient failure is final.
pub const MAX_ATTEMPTS: i32 = 3;

/// Warm tunables, read once from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarmConfig {
    pub concurrency: usize,
    pub upstream_rps: u32,
    pub max_items: usize,
    pub item_lease: Duration,
    pub item_timeout: Duration,
    pub max_job_bytes: u64,
}

impl Default for WarmConfig {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            upstream_rps: DEFAULT_UPSTREAM_RPS,
            max_items: DEFAULT_MAX_ITEMS,
            item_lease: Duration::from_secs(DEFAULT_ITEM_LEASE_SECS),
            item_timeout: Duration::from_secs(DEFAULT_ITEM_TIMEOUT_SECS),
            max_job_bytes: DEFAULT_MAX_JOB_BYTES,
        }
    }
}

impl WarmConfig {
    /// Parse the tunables through a lookup (`std::env::var` in production).
    /// Blank, zero or unparsable values keep the default; every value is
    /// clamped so no setting can make a warm unbounded.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        fn num<T: std::str::FromStr + PartialOrd + Default>(v: Option<String>) -> Option<T> {
            v.and_then(|s| s.trim().parse::<T>().ok())
                .filter(|n| *n > T::default())
        }
        let d = Self::default();
        Self {
            concurrency: num::<usize>(get("CONDA_WARM_CONCURRENCY"))
                .unwrap_or(d.concurrency)
                .min(64),
            upstream_rps: num::<u32>(get("CONDA_WARM_UPSTREAM_RPS"))
                .unwrap_or(d.upstream_rps)
                .min(1_000),
            max_items: num::<usize>(get("CONDA_WARM_MAX_ITEMS"))
                .unwrap_or(d.max_items)
                .min(1_000_000),
            item_lease: Duration::from_secs(
                num::<u64>(get("CONDA_WARM_ITEM_LEASE_SECS"))
                    .unwrap_or(DEFAULT_ITEM_LEASE_SECS)
                    .clamp(30, 86_400),
            ),
            item_timeout: Duration::from_secs(
                num::<u64>(get("CONDA_WARM_ITEM_TIMEOUT_SECS"))
                    .unwrap_or(DEFAULT_ITEM_TIMEOUT_SECS)
                    .clamp(10, 3_600),
            ),
            max_job_bytes: num::<u64>(get("CONDA_WARM_MAX_JOB_BYTES"))
                .unwrap_or(d.max_job_bytes)
                .max(1024 * 1024),
        }
    }

    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

/// Where an item stands. `pending` and `in_progress` are open; the rest are
/// final for this job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemStatus {
    Pending,
    InProgress,
    /// Fetched from upstream into the cache by this job.
    Fetched,
    /// Already in the cache (a fresh entry with the pinned sha256).
    Cached,
    /// Inside the Remote's Package Age Policy hold: cached under the hold,
    /// not served until it elapses or an admin releases it.
    Held,
    /// Refused by the scan or origin policy (403).
    Blocked,
    /// Upstream bytes differ from the sha256 the lockfile pins.
    ChecksumMismatch,
    /// The upstream answered 404, or a fault persisted past the retries.
    Failed,
    /// The URL resolves to no Remote of the repository (a hosted channel,
    /// another host, or a name a hosted member of the Virtual owns).
    NotRemote,
    /// The Virtual's allowlist does not admit the package.
    NotAllowed,
}

impl ItemStatus {
    pub const ALL: [ItemStatus; 10] = [
        ItemStatus::Pending,
        ItemStatus::InProgress,
        ItemStatus::Fetched,
        ItemStatus::Cached,
        ItemStatus::Held,
        ItemStatus::Blocked,
        ItemStatus::ChecksumMismatch,
        ItemStatus::Failed,
        ItemStatus::NotRemote,
        ItemStatus::NotAllowed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ItemStatus::Pending => "pending",
            ItemStatus::InProgress => "in_progress",
            ItemStatus::Fetched => "fetched",
            ItemStatus::Cached => "cached",
            ItemStatus::Held => "held",
            ItemStatus::Blocked => "blocked",
            ItemStatus::ChecksumMismatch => "checksum_mismatch",
            ItemStatus::Failed => "failed",
            ItemStatus::NotRemote => "not_remote",
            ItemStatus::NotAllowed => "not_allowed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    pub fn is_open(self) -> bool {
        matches!(self, ItemStatus::Pending | ItemStatus::InProgress)
    }
}

/// How [`WarmService::stop`] ends a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStop {
    /// The job fetched `CONDA_WARM_MAX_JOB_BYTES` from upstream.
    BudgetExceeded,
    /// The runner gave up after repeated errors (a database outage).
    Failed,
}

impl JobStop {
    pub fn as_str(self) -> &'static str {
        match self {
            JobStop::BudgetExceeded => "budget_exceeded",
            JobStop::Failed => "failed",
        }
    }
}

/// A package URL split into what the Remote serves it as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageUrl {
    /// Everything before `/<subdir>/<filename>`, without a trailing slash.
    pub channel: String,
    pub subdir: String,
    pub filename: String,
}

/// Split a lockfile package URL into channel, subdir and file name. Query
/// and fragment are dropped (an `@EXPLICIT` line carries `#<md5>`). `None`
/// when the last segment is not a conda package file or a segment is empty.
pub fn parse_package_url(url: &str) -> Option<PackageUrl> {
    let url = url.trim();
    let url = url.split(['#', '?']).next().unwrap_or(url);
    let (rest, filename) = url.rsplit_once('/')?;
    let (channel, subdir) = rest.rsplit_once('/')?;
    if filename.is_empty()
        || subdir.is_empty()
        || channel.is_empty()
        || !(filename.ends_with(".conda") || filename.ends_with(".tar.bz2"))
    {
        return None;
    }
    Some(PackageUrl {
        channel: channel.to_string(),
        subdir: subdir.to_string(),
        filename: filename.to_string(),
    })
}

/// The repository key a channel URL names on this server's conda route,
/// whatever host the lock recorded: `.../conda/<key>`, with the token
/// layouts `.../conda/t/<token>/<key>` and `.../t/<token>/conda/<key>`.
pub fn route_key_of_channel(channel: &str) -> Option<&str> {
    let path = match channel.find("://") {
        Some(i) => channel[i + 3..]
            .split_once('/')
            .map(|(_, p)| p)
            .unwrap_or(""),
        None => channel.trim_start_matches('/'),
    };
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let n = segs.len();
    if n >= 2 && segs[n - 2] == "conda" {
        return Some(segs[n - 1]);
    }
    if n >= 4 && segs[n - 4] == "conda" && segs[n - 3] == "t" {
        return Some(segs[n - 1]);
    }
    None
}

/// Normalise a channel or upstream URL for prefix comparison: no trailing
/// slash, scheme and host lower-cased.
pub fn normalize_channel(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    match url.find("://") {
        Some(i) => {
            let (scheme, rest) = url.split_at(i);
            let rest = &rest[3..];
            let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
            if path.is_empty() {
                format!(
                    "{}://{}",
                    scheme.to_ascii_lowercase(),
                    host.to_ascii_lowercase()
                )
            } else {
                format!(
                    "{}://{}/{}",
                    scheme.to_ascii_lowercase(),
                    host.to_ascii_lowercase(),
                    path
                )
            }
        }
        None => url.to_string(),
    }
}

/// A Remote a warm may fill, as the resolver sees it.
#[derive(Debug, Clone)]
pub struct RemoteCandidate {
    pub id: Uuid,
    pub key: String,
    pub upstream_url: String,
}

/// What a lockfile URL resolves to, for a warm of `requested_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Warm through these Remotes, in priority order; the first one that has
    /// the package fills its cache (a Virtual walk).
    Remotes(Vec<Uuid>),
    NotRemote,
}

/// Map a channel URL to the Remote(s) that would serve it.
///
/// * A URL on this server's conda route for the requested repository warms
///   its Remote(s): the repository itself when it is a Remote, every Remote
///   member in priority order when it is a Virtual.
/// * A URL on this server's route for one Remote member warms that member.
/// * A URL under a Remote's upstream URL (the lock was solved against the
///   upstream channel itself) warms that Remote.
/// * Anything else (a hosted member, another server) is `NotRemote`.
pub fn resolve_channel(
    channel: &str,
    requested_key: &str,
    remotes: &[RemoteCandidate],
    other_member_keys: &[String],
) -> Resolution {
    if let Some(key) = route_key_of_channel(channel) {
        if key == requested_key {
            return if remotes.is_empty() {
                Resolution::NotRemote
            } else {
                Resolution::Remotes(remotes.iter().map(|r| r.id).collect())
            };
        }
        if let Some(r) = remotes.iter().find(|r| r.key == key) {
            return Resolution::Remotes(vec![r.id]);
        }
        if other_member_keys.iter().any(|k| k == key) {
            return Resolution::NotRemote;
        }
    }
    let channel = normalize_channel(channel);
    let matched: Vec<Uuid> = remotes
        .iter()
        .filter(|r| {
            let up = normalize_channel(&r.upstream_url);
            !up.is_empty()
                && (channel == up
                    || channel
                        .strip_prefix(up.as_str())
                        .is_some_and(|rest| rest.starts_with('/')))
        })
        .map(|r| r.id)
        .collect();
    if matched.is_empty() {
        Resolution::NotRemote
    } else {
        Resolution::Remotes(matched)
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct WarmJob {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub environment_id: Uuid,
    pub platform: String,
    pub status: String,
    pub total: i32,
    pub skipped_no_url: i32,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// One claimed item.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedItem {
    pub id: i64,
    pub url: String,
    pub expected_sha256: Option<String>,
    pub attempts: i32,
}

/// An item that did not warm, for the progress report.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ItemProblem {
    pub url: String,
    pub status: String,
    pub detail: Option<String>,
}

/// Per-status counts and bytes for one job.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmProgress {
    pub counts: std::collections::BTreeMap<String, i64>,
    pub bytes_fetched: i64,
    pub done: i64,
    pub remaining: i64,
}

/// The result of [`WarmService::create`].
#[derive(Debug)]
pub struct Created {
    pub job: WarmJob,
    /// `false` when an active job for the same key already existed and was
    /// returned instead.
    pub created: bool,
}

/// The [`WarmJob`] columns, as a literal so every query stays a static
/// string (sqlx refuses dynamically built SQL).
macro_rules! job_columns {
    () => {
        "id, repository_id, environment_id, platform, status, total, \
         skipped_no_url, created_at, started_at, finished_at"
    };
}

pub struct WarmService {
    db: PgPool,
}

impl WarmService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create the job for (repository, environment, platform) with one item
    /// per distinct conda package URL the environment pins, or return the
    /// active job for that key. One transaction, so a resuming runner never
    /// sees a job without its items.
    pub async fn create(
        &self,
        repository_id: Uuid,
        environment_id: Uuid,
        platform: &str,
        requested_by: Uuid,
        max_items: usize,
    ) -> Result<Created> {
        if let Some(job) = self.active(repository_id, environment_id, platform).await? {
            return Ok(Created {
                job,
                created: false,
            });
        }
        let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
        // Distinct files; an environment lists a noarch file once per
        // platform scope. `sha256` is the pinned one when any scope pins it.
        let rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT url, max(sha256) FROM environment_packages \
             WHERE environment_id = $1 AND ecosystem = 'conda' \
               AND ($2 = '' OR scope_platform = $2) \
             GROUP BY url",
        )
        .bind(environment_id)
        .bind(platform)
        .fetch_all(&self.db)
        .await
        .map_err(db_err)?;
        let mut urls = Vec::with_capacity(rows.len());
        let mut shas = Vec::with_capacity(rows.len());
        let mut no_url = 0i32;
        for (url, sha) in rows {
            match url.filter(|u| !u.trim().is_empty()) {
                Some(u) => {
                    urls.push(u);
                    shas.push(sha);
                }
                None => no_url += 1,
            }
        }
        if urls.len() > max_items {
            return Err(AppError::Validation(format!(
                "the environment pins {} conda package files; a warm takes at most {} \
                 (CONDA_WARM_MAX_ITEMS)",
                urls.len(),
                max_items
            )));
        }
        let mut tx = self.db.begin().await.map_err(db_err)?;
        let inserted: Option<WarmJob> = sqlx::query_as(concat!(
            "INSERT INTO conda_warm_jobs \
               (repository_id, environment_id, platform, requested_by, total, skipped_no_url) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (repository_id, environment_id, platform) \
               WHERE status IN ('pending', 'running') DO NOTHING \
             RETURNING ",
            job_columns!(),
            ""
        ))
        .bind(repository_id)
        .bind(environment_id)
        .bind(platform)
        .bind(requested_by)
        .bind(urls.len() as i32)
        .bind(no_url)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        let Some(job) = inserted else {
            // Lost the race to a concurrent request: return its job.
            tx.rollback().await.map_err(db_err)?;
            let job = self
                .active(repository_id, environment_id, platform)
                .await?
                .ok_or_else(|| AppError::Conflict("warm job changed concurrently".into()))?;
            return Ok(Created {
                job,
                created: false,
            });
        };
        for (u, s) in urls.chunks(5_000).zip(shas.chunks(5_000)) {
            sqlx::query(
                "INSERT INTO conda_warm_items (job_id, url, expected_sha256) \
                 SELECT $1, u, s FROM UNNEST($2::text[], $3::text[]) AS t(u, s) \
                 ON CONFLICT (job_id, url) DO NOTHING",
            )
            .bind(job.id)
            .bind(u)
            .bind(s)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(Created { job, created: true })
    }

    pub async fn active(
        &self,
        repository_id: Uuid,
        environment_id: Uuid,
        platform: &str,
    ) -> Result<Option<WarmJob>> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM conda_warm_jobs \
             WHERE repository_id = $1 AND environment_id = $2 AND platform = $3 \
               AND status IN ('pending', 'running')"
        ))
        .bind(repository_id)
        .bind(environment_id)
        .bind(platform)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    pub async fn get(&self, repository_id: Uuid, job_id: Uuid) -> Result<WarmJob> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM conda_warm_jobs WHERE id = $1 AND repository_id = $2"
        ))
        .bind(job_id)
        .bind(repository_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Warm job not found".to_string()))
    }

    pub async fn job_by_id(&self, job_id: Uuid) -> Result<Option<WarmJob>> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM conda_warm_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    pub async fn list(&self, repository_id: Uuid, limit: i64) -> Result<Vec<WarmJob>> {
        sqlx::query_as(concat!(
            "SELECT ",
            job_columns!(),
            " FROM conda_warm_jobs WHERE repository_id = $1 \
             ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(repository_id)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Every job a runner should be working on (startup resume).
    pub async fn active_job_ids(&self) -> Result<Vec<Uuid>> {
        sqlx::query_scalar(
            "SELECT id FROM conda_warm_jobs WHERE status IN ('pending', 'running') \
             ORDER BY created_at",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Mark a job running (first claim) — a no-op once it is.
    pub async fn mark_running(&self, job_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE conda_warm_jobs SET status = 'running', \
               started_at = COALESCE(started_at, now()), updated_at = now() \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(job_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Claim up to `limit` items: pending ones, and in-progress ones whose
    /// lease lapsed (their runner died). Each claim counts an attempt.
    pub async fn claim(
        &self,
        job_id: Uuid,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<ClaimedItem>> {
        sqlx::query_as(
            "UPDATE conda_warm_items i SET status = 'in_progress', claimed_at = now(), \
               attempts = i.attempts + 1 \
             WHERE i.id IN ( \
               SELECT id FROM conda_warm_items \
               WHERE job_id = $1 AND (status = 'pending' \
                 OR (status = 'in_progress' AND claimed_at < now() - make_interval(secs => $3))) \
               ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) \
             RETURNING i.id, i.url, i.expected_sha256, i.attempts",
        )
        .bind(job_id)
        .bind(limit)
        .bind(lease.as_secs_f64())
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Record an item's final (or retry) state.
    pub async fn finish_item(
        &self,
        item_id: i64,
        status: ItemStatus,
        remote_id: Option<Uuid>,
        bytes: Option<i64>,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE conda_warm_items SET status = $2, remote_repository_id = $3, \
               bytes = $4, detail = $5, \
               finished_at = CASE WHEN $2 IN ('pending', 'in_progress') THEN NULL ELSE now() END, \
               claimed_at = CASE WHEN $2 = 'pending' THEN NULL ELSE claimed_at END \
             WHERE id = $1",
        )
        .bind(item_id)
        .bind(status.as_str())
        .bind(remote_id)
        .bind(bytes)
        .bind(detail.map(|d| truncate(d, 500)))
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Close the job when no item is open. Returns whether it is finished.
    pub async fn complete_if_done(&self, job_id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE conda_warm_jobs SET status = 'completed', finished_at = now(), \
               updated_at = now() \
             WHERE id = $1 AND status IN ('pending', 'running') \
               AND NOT EXISTS (SELECT 1 FROM conda_warm_items \
                 WHERE job_id = $1 AND status IN ('pending', 'in_progress'))",
        )
        .bind(job_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if r.rows_affected() > 0 {
            return Ok(true);
        }
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM conda_warm_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(!matches!(status.as_deref(), Some("pending" | "running")))
    }

    /// End an active job with a terminal `status` other than `completed`:
    /// `budget_exceeded` (its byte budget is spent) or `failed` (its runner
    /// could not continue). Open items stay open and are not fetched; a new
    /// request starts a new job. Returns whether it was active.
    pub async fn stop(&self, job_id: Uuid, status: JobStop) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE conda_warm_jobs SET status = $2, finished_at = now(), updated_at = now() \
             WHERE id = $1 AND status IN ('pending', 'running')",
        )
        .bind(job_id)
        .bind(status.as_str())
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(r.rows_affected() > 0)
    }

    /// Bytes this job has fetched from upstream so far (its budget use).
    pub async fn bytes_fetched(&self, job_id: Uuid) -> Result<i64> {
        sqlx::query_scalar(
            "SELECT COALESCE(sum(bytes), 0)::bigint FROM conda_warm_items \
             WHERE job_id = $1 AND status IN ('fetched', 'checksum_mismatch')",
        )
        .bind(job_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Cancel an active job: open items stay as they are (not fetched), the
    /// runner stops at its next claim. Returns whether it was active.
    pub async fn cancel(&self, repository_id: Uuid, job_id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE conda_warm_jobs SET status = 'cancelled', finished_at = now(), \
               updated_at = now() \
             WHERE id = $1 AND repository_id = $2 AND status IN ('pending', 'running')",
        )
        .bind(job_id)
        .bind(repository_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn progress(&self, job_id: Uuid) -> Result<WarmProgress> {
        let rows: Vec<(String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT status, count(*), sum(bytes)::bigint FROM conda_warm_items \
             WHERE job_id = $1 GROUP BY status",
        )
        .bind(job_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let mut p = WarmProgress::default();
        for s in ItemStatus::ALL {
            p.counts.insert(s.as_str().to_string(), 0);
        }
        for (status, n, bytes) in rows {
            let open = ItemStatus::parse(&status).is_some_and(|s| s.is_open());
            if open {
                p.remaining += n;
            } else {
                p.done += n;
            }
            if status == ItemStatus::Fetched.as_str() {
                p.bytes_fetched += bytes.unwrap_or(0);
            }
            p.counts.insert(status, n);
        }
        Ok(p)
    }

    /// The first items that did not warm, for the report.
    pub async fn problems(&self, job_id: Uuid, limit: i64) -> Result<Vec<ItemProblem>> {
        sqlx::query_as(
            "SELECT url, status, detail FROM conda_warm_items \
             WHERE job_id = $1 AND status NOT IN ('pending', 'in_progress', 'fetched', 'cached') \
             ORDER BY id LIMIT $2",
        )
        .bind(job_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// `ak_conda_warm_items_total{outcome}`: items finished, by final status.
pub fn record_item(status: ItemStatus) {
    metrics::counter!("ak_conda_warm_items_total", "outcome" => status.as_str()).increment(1);
}

/// `ak_conda_warm_upstream_fetches_total`: fetches a warm sent past the
/// cache check (each one may reach the upstream), and
/// `ak_conda_warm_bytes_total` the bytes they filled.
pub fn record_fetch(bytes: u64) {
    metrics::counter!("ak_conda_warm_upstream_fetches_total").increment(1);
    metrics::counter!("ak_conda_warm_bytes_total").increment(bytes);
}

/// `ak_conda_warm_jobs_running`: warm jobs this process is running.
pub fn record_running_jobs(delta: f64) {
    metrics::gauge!("ak_conda_warm_jobs_running").increment(delta);
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn remote(key: &str, up: &str) -> RemoteCandidate {
        RemoteCandidate {
            id: Uuid::new_v4(),
            key: key.into(),
            upstream_url: up.into(),
        }
    }

    #[test]
    fn config_defaults_clamps_and_garbage() {
        let none = WarmConfig::from_lookup(|_| None);
        assert_eq!(none, WarmConfig::default());
        assert_eq!(none.concurrency, 8);
        assert_eq!(none.upstream_rps, 20);
        let set = WarmConfig::from_lookup(|k| {
            Some(
                match k {
                    "CONDA_WARM_CONCURRENCY" => "500",
                    "CONDA_WARM_UPSTREAM_RPS" => "0",
                    "CONDA_WARM_MAX_ITEMS" => "abc",
                    "CONDA_WARM_ITEM_LEASE_SECS" => "1",
                    "CONDA_WARM_ITEM_TIMEOUT_SECS" => "1",
                    "CONDA_WARM_MAX_JOB_BYTES" => "10",
                    _ => "",
                }
                .to_string(),
            )
        });
        assert_eq!(set.concurrency, 64, "clamped");
        assert_eq!(
            set.upstream_rps, 20,
            "zero keeps the default: never unbounded"
        );
        assert_eq!(set.max_items, DEFAULT_MAX_ITEMS);
        assert_eq!(set.item_lease, Duration::from_secs(30));
        assert_eq!(set.item_timeout, Duration::from_secs(10), "clamped up");
        assert_eq!(set.max_job_bytes, 1024 * 1024, "at least 1 MiB");
        assert_eq!(none.item_timeout, Duration::from_secs(300));
        assert_eq!(none.max_job_bytes, DEFAULT_MAX_JOB_BYTES);
        assert_eq!(JobStop::BudgetExceeded.as_str(), "budget_exceeded");
        assert_eq!(JobStop::Failed.as_str(), "failed");
    }

    #[test]
    fn status_round_trips() {
        for s in ItemStatus::ALL {
            assert_eq!(ItemStatus::parse(s.as_str()), Some(s));
        }
        assert!(ItemStatus::Pending.is_open() && ItemStatus::InProgress.is_open());
        assert!(!ItemStatus::Held.is_open());
    }

    #[test]
    fn parses_package_urls() {
        let p = parse_package_url(
            "https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4-py312h_0.conda",
        )
        .unwrap();
        assert_eq!(p.channel, "https://conda.anaconda.org/conda-forge");
        assert_eq!(p.subdir, "linux-64");
        assert_eq!(p.filename, "numpy-1.26.4-py312h_0.conda");
        let e = parse_package_url("http://h/c/noarch/a-1-0.tar.bz2#0123abcd").unwrap();
        assert_eq!(e.filename, "a-1-0.tar.bz2");
        assert!(parse_package_url("http://h/c/noarch/repodata.json").is_none());
        assert!(parse_package_url("a-1-0.conda").is_none());
        assert!(parse_package_url("http://h/c/noarch/").is_none());
    }

    #[test]
    fn route_keys_from_any_host() {
        assert_eq!(
            route_key_of_channel("https://ak.example/conda/fleet"),
            Some("fleet")
        );
        assert_eq!(
            route_key_of_channel("http://10.0.0.1:8080/conda/r1"),
            Some("r1")
        );
        assert_eq!(
            route_key_of_channel("https://ak/conda/t/tok123/r1"),
            Some("r1")
        );
        assert_eq!(
            route_key_of_channel("https://ak/t/tok123/conda/r1"),
            Some("r1")
        );
        assert_eq!(
            route_key_of_channel("https://conda.anaconda.org/conda-forge"),
            None
        );
    }

    #[test]
    fn resolves_channels_to_remotes() {
        let a = remote("cf-proxy", "https://conda.anaconda.org/conda-forge/");
        let b = remote("bio-proxy", "https://conda.anaconda.org/bioconda");
        let remotes = vec![a.clone(), b.clone()];
        let hosted = vec!["internal".to_string()];
        // The virtual's own route: every Remote member, in priority order.
        assert_eq!(
            resolve_channel("https://ak/conda/fleet", "fleet", &remotes, &hosted),
            Resolution::Remotes(vec![a.id, b.id])
        );
        // One member's route: that member.
        assert_eq!(
            resolve_channel("https://ak/conda/bio-proxy", "fleet", &remotes, &hosted),
            Resolution::Remotes(vec![b.id])
        );
        // A hosted member's route: nothing to warm.
        assert_eq!(
            resolve_channel("https://ak/conda/internal", "fleet", &remotes, &hosted),
            Resolution::NotRemote
        );
        // Solved against the upstream itself: the Remote fronting it, with
        // host case and trailing slashes ignored.
        assert_eq!(
            resolve_channel(
                "HTTPS://Conda.Anaconda.org/conda-forge",
                "fleet",
                &remotes,
                &hosted
            ),
            Resolution::Remotes(vec![a.id])
        );
        // A prefix that is not a path boundary does not match.
        assert_eq!(
            resolve_channel(
                "https://conda.anaconda.org/conda-forge-extra",
                "fleet",
                &remotes,
                &hosted
            ),
            Resolution::NotRemote
        );
        assert_eq!(
            resolve_channel("https://elsewhere.example/ch", "fleet", &remotes, &hosted),
            Resolution::NotRemote
        );
        // A Remote warmed directly has no members: its own route is itself.
        assert_eq!(
            resolve_channel(
                "https://ak/conda/cf-proxy",
                "cf-proxy",
                std::slice::from_ref(&a),
                &[]
            ),
            Resolution::Remotes(vec![a.id])
        );
    }

    const LOCK: &str = r#"version: 6
environments:
  default:
    channels:
    - url: https://ak.example/conda/fleet/
    packages:
      linux-64:
      - conda: https://ak.example/conda/fleet/linux-64/a-1.0-h0_0.conda
      - conda: https://ak.example/conda/fleet/noarch/n-1.0-0.tar.bz2
      osx-arm64:
      - conda: https://ak.example/conda/fleet/osx-arm64/a-1.0-h1_0.conda
      - conda: https://ak.example/conda/fleet/noarch/n-1.0-0.tar.bz2
packages:
- conda: https://ak.example/conda/fleet/linux-64/a-1.0-h0_0.conda
  sha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  depends:
  - n >=1
- conda: https://ak.example/conda/fleet/osx-arm64/a-1.0-h1_0.conda
  sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  depends:
  - n >=1
- conda: https://ak.example/conda/fleet/noarch/n-1.0-0.tar.bz2
  sha256: not-a-digest
  depends: []
"#;

    /// Ingest stores the pinned URL and sha256 (#4184); a job has one item
    /// per distinct file; asking again returns the active job; claims are
    /// exclusive until their lease lapses; the job completes when no item
    /// is open.
    #[tokio::test]
    async fn job_lifecycle_idempotent_and_resumable() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::environment_service::EnvironmentService;
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let env =
            crate::services::environment_lock::parse_named_lockfile("pixi.lock", LOCK.as_bytes())
                .expect("lock parses");
        let ingested = EnvironmentService::new(fx.pool.clone())
            .ingest(fx.repo_id, "fleet-env", "sha", &env)
            .await
            .expect("ingest");
        let stored: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT scope_platform, url, sha256 FROM environment_packages \
             WHERE environment_id = $1 ORDER BY scope_platform, url",
        )
        .bind(ingested.id)
        .fetch_all(&fx.pool)
        .await
        .expect("stored rows");
        assert_eq!(stored.len(), 4, "{stored:?}");
        let a0 = stored
            .iter()
            .find(|r| r.1.as_deref().is_some_and(|u| u.ends_with("h0_0.conda")))
            .unwrap();
        assert_eq!(
            a0.2.as_deref(),
            Some("a".repeat(64).as_str()),
            "lower-cased"
        );
        let n = stored
            .iter()
            .find(|r| r.1.as_deref().is_some_and(|u| u.ends_with(".tar.bz2")))
            .unwrap();
        assert_eq!(n.2, None, "a malformed digest is not a pin");

        let svc = WarmService::new(fx.pool.clone());
        let user = fx.user_id;
        let all = svc
            .create(fx.repo_id, ingested.id, "", user, 100)
            .await
            .expect("create");
        assert!(all.created);
        assert_eq!(
            all.job.total, 3,
            "the noarch file is one item for both platforms"
        );
        let again = svc
            .create(fx.repo_id, ingested.id, "", user, 100)
            .await
            .expect("again");
        assert!(!again.created);
        assert_eq!(again.job.id, all.job.id);
        let linux = svc
            .create(fx.repo_id, ingested.id, "linux-64", user, 100)
            .await
            .expect("linux");
        assert!(linux.created && linux.job.total == 2, "{:?}", linux.job);
        assert!(matches!(
            svc.create(fx.repo_id, ingested.id, "osx-arm64", user, 1)
                .await,
            Err(AppError::Validation(_))
        ));

        let lease = Duration::from_secs(600);
        let first = svc.claim(all.job.id, 2, lease).await.expect("claim");
        assert_eq!(first.len(), 2);
        let second = svc.claim(all.job.id, 2, lease).await.expect("claim");
        assert_eq!(second.len(), 1, "claims are exclusive");
        assert!(svc.claim(all.job.id, 2, lease).await.unwrap().is_empty());
        assert!(
            !svc.complete_if_done(all.job.id).await.unwrap(),
            "items are open"
        );
        // The runner holding `first` dies: once the lease lapses they are
        // claimed again, as a second attempt.
        sqlx::query(
            "UPDATE conda_warm_items SET claimed_at = now() - interval '1 hour' WHERE id = ANY($1)",
        )
        .bind(first.iter().map(|i| i.id).collect::<Vec<_>>())
        .execute(&fx.pool)
        .await
        .unwrap();
        let resumed = svc.claim(all.job.id, 10, lease).await.expect("resume");
        assert_eq!(resumed.len(), 2);
        assert!(resumed.iter().all(|i| i.attempts == 2));
        for (item, status) in resumed.iter().chain(second.iter()).zip([
            ItemStatus::Fetched,
            ItemStatus::Held,
            ItemStatus::Cached,
        ]) {
            svc.finish_item(item.id, status, None, Some(10), None)
                .await
                .unwrap();
        }
        assert!(svc.complete_if_done(all.job.id).await.unwrap());
        let job = svc.get(fx.repo_id, all.job.id).await.unwrap();
        assert_eq!(job.status, "completed");
        let p = svc.progress(all.job.id).await.unwrap();
        assert_eq!((p.done, p.remaining, p.bytes_fetched), (3, 0, 10));
        assert_eq!(p.counts["held"], 1);
        let problems = svc.problems(all.job.id, 10).await.unwrap();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].status, "held");
        // Completed: a new request starts a new job.
        let next = svc
            .create(fx.repo_id, ingested.id, "", user, 100)
            .await
            .unwrap();
        assert!(next.created && next.job.id != all.job.id);
        assert!(svc.cancel(fx.repo_id, next.job.id).await.unwrap());
        assert!(
            !svc.cancel(fx.repo_id, next.job.id).await.unwrap(),
            "already cancelled"
        );
        let active = svc.active_job_ids().await.unwrap();
        assert!(active.contains(&linux.job.id) && !active.contains(&next.job.id));
        assert_eq!(svc.bytes_fetched(all.job.id).await.unwrap(), 10);
        // A spent budget (or a runner that gave up) ends the job; it is no
        // longer active, so a new request starts a new one.
        assert!(svc
            .stop(linux.job.id, JobStop::BudgetExceeded)
            .await
            .unwrap());
        assert!(!svc.stop(linux.job.id, JobStop::Failed).await.unwrap());
        assert_eq!(
            svc.get(fx.repo_id, linux.job.id).await.unwrap().status,
            "budget_exceeded"
        );
        let failed = svc
            .create(fx.repo_id, ingested.id, "linux-64", user, 100)
            .await
            .unwrap();
        assert!(failed.created);
        assert!(svc.stop(failed.job.id, JobStop::Failed).await.unwrap());
        assert_eq!(
            svc.get(fx.repo_id, failed.job.id).await.unwrap().status,
            "failed"
        );
        fx.teardown().await;
    }

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
