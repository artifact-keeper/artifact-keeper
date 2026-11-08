//! The introspection job queue (#5253, Phase 2/3).
//!
//! The backend never talks to an MCP server. It only records which server
//! versions should be introspected (`mcp_introspection_jobs`) and hands those
//! jobs to the separate `ak-mcp-introspector` worker, which claims them over
//! the HTTP API (`/api/v1/mcp/introspection/jobs/*`), runs them in its own
//! process (remote probe) or sandbox (stdio run), and posts the result back.
//!
//! Two job kinds:
//!
//! * `remote_probe`: one per `remotes[]` entry of transport
//!   `streamable-http` with a concrete `https`/`http` URL (no `{template}`).
//!   Queued when the repository's `mcp_probe_remotes` allows it: `all`
//!   everywhere, `hosted_only` only on Local/Staging repositories, `off`
//!   never. Re-queued by the scheduler once the previous probe is older than
//!   `max(ttlMs, 6 h)`, because a remote can change what it advertises
//!   without a version bump: for the server's latest version and versions
//!   published in the last [`REPROBE_RECENT_DAYS`] days only.
//! * `sandbox_run`: one per stdio `packages[]` entry of type `npm`, `pypi`
//!   or `oci` that has an AK pin (`own-repos` resolved it to a backing
//!   repository), when `mcp_sandbox_introspection = on`. Never re-queued: the
//!   bytes are version pinned.
//!
//! Claims follow the `RowClaimedQueue` pattern (`FOR UPDATE SKIP LOCKED`, a
//! random per-claim token whose hash is stored, a lease the reaper returns to
//! `pending`). Every scheduler step is DB-only and idempotent
//! (`IdempotentDbOnly`): the partial unique index allows one open job per
//! target, so concurrent replicas cannot double-queue.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::formats::mcp::{PackagePin, StoredVersion};
use crate::models::access_scope::AccessScope;
use crate::services::mcp_capabilities::{
    self as caps, AuthState, CapabilitySet, NewSnapshot, Outcome, Source,
};

/// Minimum interval between two probes of the same remote.
pub const MIN_REPROBE_SECS: i64 = 6 * 3600;
/// How long a claim lasts before the reaper hands the job out again. Longer
/// than the sandbox's 120 s wall clock plus install time.
pub const LEASE_SECS: i64 = 600;
/// Jobs re-queued per scheduler tick.
pub const REPROBE_BATCH: i64 = 100;
/// A remote is re-probed only for its server's latest version
/// (`registry.isLatest`) or a version published within this many days
/// (`registry.publishedAt`, else the artifact's creation time). Older
/// versions keep their last snapshot and can still be probed on demand
/// (`POST .../capabilities/probe`) (#5386).
pub const REPROBE_RECENT_DAYS: i32 = 30;
/// Attempts of a `sandbox_run` job whose runs time out: one retry.
pub const SANDBOX_TIMEOUT_ATTEMPTS: i32 = 2;
/// Package types the reference sandbox runner can install from AK.
pub const SANDBOX_REGISTRY_TYPES: &[&str] = &["npm", "pypi", "oci"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    RemoteProbe,
    SandboxRun,
}

impl JobKind {
    pub const ALL: [JobKind; 2] = [JobKind::RemoteProbe, JobKind::SandboxRun];

    pub fn as_str(self) -> &'static str {
        match self {
            JobKind::RemoteProbe => "remote_probe",
            JobKind::SandboxRun => "sandbox_run",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn source(self) -> Source {
        match self {
            JobKind::RemoteProbe => Source::RemoteProbe,
            JobKind::SandboxRun => Source::SandboxRun,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure policy
// ---------------------------------------------------------------------------

/// Whether `mcp_probe_remotes = mode` lets a repository of `repo_type` queue
/// probes.
pub fn probe_allowed(mode: Option<&str>, repo_type: &str) -> bool {
    match mode {
        Some("all") => repo_type != "virtual",
        Some("hosted_only") => matches!(repo_type, "local" | "staging"),
        _ => false,
    }
}

pub fn sandbox_allowed(mode: Option<&str>, repo_type: &str) -> bool {
    mode == Some("on") && repo_type != "virtual"
}

/// A concrete probe URL: `http(s)` with a host, no `{template}` variables,
/// no userinfo. (The worker additionally runs `validate_outbound_url`.)
pub fn probeable_url(url: &str) -> bool {
    if url.contains('{') || url.contains('}') {
        return false;
    }
    match url::Url::parse(url) {
        Ok(u) => {
            matches!(u.scheme(), "https" | "http")
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.username().is_empty()
                && u.password().is_none()
        }
        Err(_) => false,
    }
}

/// `(target_key, url)` for every probeable remote of a server document.
pub fn remote_targets(server: &Value) -> Vec<(String, String)> {
    server
        .get("remotes")
        .and_then(|r| r.as_array())
        .map(|remotes| {
            remotes
                .iter()
                .enumerate()
                .filter(|(_, r)| r.get("type").and_then(|t| t.as_str()) == Some("streamable-http"))
                .filter_map(|(i, r)| {
                    let url = r.get("url")?.as_str()?;
                    probeable_url(url).then(|| (format!("remote:{i}"), url.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Target keys of every package the sandbox may run: a stdio package of a
/// supported type that `own-repos` pinned to an AK repository.
pub fn sandbox_targets(server: &Value, pins: &[PackagePin]) -> Vec<String> {
    let Some(packages) = server.get("packages").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    packages
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            let stdio = p.pointer("/transport/type").and_then(|t| t.as_str()) == Some("stdio");
            let kind = p.get("registryType").and_then(|t| t.as_str()).unwrap_or("");
            stdio
                && SANDBOX_REGISTRY_TYPES.contains(&kind)
                && pins
                    .iter()
                    .any(|pin| pin.index == *i && pin.registry_type == kind)
        })
        .map(|(i, _)| format!("package:{i}"))
        .collect()
}

fn target_index(key: &str, prefix: &str) -> Option<usize> {
    key.strip_prefix(prefix)?.parse().ok()
}

/// Why a claimed job cannot be handed out any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unrunnable {
    /// The target entry no longer exists or is no longer eligible.
    TargetGone,
}

/// The `target` member of a claimed job, from the version as stored and
/// served now. `served_server` is the server document rewritten for serve
/// with the base URL the worker reached the backend on, so a sandbox run
/// installs from exactly the `registryBaseUrl`/identifier AK serves.
pub fn job_target(
    kind: JobKind,
    target_key: &str,
    stored: &StoredVersion,
    served_server: &Value,
) -> Result<Value, Unrunnable> {
    match kind {
        JobKind::RemoteProbe => {
            let idx = target_index(target_key, "remote:").ok_or(Unrunnable::TargetGone)?;
            let (_, url) = remote_targets(&stored.server)
                .into_iter()
                .find(|(k, _)| k == target_key)
                .ok_or(Unrunnable::TargetGone)?;
            // Never hand the worker the publisher's `headers[]`: the probe is
            // unauthenticated by construction.
            Ok(json!({
                "type": "remote",
                "index": idx,
                "transport": "streamable-http",
                "url": url,
            }))
        }
        JobKind::SandboxRun => {
            let idx = target_index(target_key, "package:").ok_or(Unrunnable::TargetGone)?;
            if !sandbox_targets(&stored.server, &stored.pins)
                .iter()
                .any(|k| k == target_key)
            {
                return Err(Unrunnable::TargetGone);
            }
            let package = served_server
                .pointer(&format!("/packages/{idx}"))
                .cloned()
                .ok_or(Unrunnable::TargetGone)?;
            Ok(json!({
                "type": "package",
                "index": idx,
                "registryType": package.get("registryType"),
                "package": package,
            }))
        }
    }
}

/// When a remote probed at `completed_at` with `ttl_ms` is due again.
pub fn reprobe_due_at(completed_at: DateTime<Utc>, ttl_ms: Option<i64>) -> DateTime<Utc> {
    let ttl_secs = ttl_ms.unwrap_or(0).max(0) / 1000;
    completed_at + chrono::Duration::seconds(ttl_secs.max(MIN_REPROBE_SECS))
}

/// Outcomes worth another attempt (until `max_attempts`). `start_failed`
/// is the worker's sandbox (engine, runtime, network, image pull) or the
/// connection failing, not the server's answer: retried, never stored as
/// the server's state on the first attempt.
pub fn is_transient(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::RateLimited | Outcome::Timeout | Outcome::Error | Outcome::StartFailed
    )
}

/// How many attempts a job of `kind` gets when an attempt ends in `outcome`.
/// A `sandbox_run` timeout already held a worker for the sandbox's whole wall
/// clock (120 s), so it is retried once at most instead of up to
/// `max_attempts` times (#5387).
pub fn attempts_allowed(kind: JobKind, outcome: Outcome, max_attempts: i32) -> i32 {
    match (kind, outcome) {
        (JobKind::SandboxRun, Outcome::Timeout) => max_attempts.min(SANDBOX_TIMEOUT_ATTEMPTS),
        _ => max_attempts,
    }
}

/// The delay before the next attempt: the server's `Retry-After`/`ttlMs`
/// hint for a 429 (clamped to 1 min .. 24 h), else 2^attempts minutes.
pub fn retry_delay_secs(outcome: Outcome, attempts: i32, retry_after_ms: Option<i64>) -> i64 {
    if outcome == Outcome::RateLimited {
        if let Some(ms) = retry_after_ms {
            return (ms / 1000).clamp(60, 24 * 3600);
        }
    }
    60 * (1i64 << attempts.clamp(0, 10))
}

// ---------------------------------------------------------------------------
// Worker result
// ---------------------------------------------------------------------------

/// What the worker posts to `.../jobs/{id}/complete`.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerResult {
    pub claim_token: String,
    pub outcome: String,
    #[serde(default)]
    pub auth_state: Option<String>,
    #[serde(default)]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ttl_ms: Option<i64>,
    #[serde(default)]
    pub cache_scope: Option<String>,
    #[serde(default)]
    pub tools: Option<Value>,
    #[serde(default)]
    pub resources: Option<Value>,
    #[serde(default)]
    pub prompts: Option<Value>,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub worker_version: Option<String>,
    #[serde(default)]
    pub retry_after_ms: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub details: Option<Value>,
}

/// A validated worker result.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedResult {
    pub outcome: Outcome,
    pub auth_state: AuthState,
    pub set: CapabilitySet,
}

pub fn parse_result(r: &WorkerResult) -> Result<ParsedResult, caps::CapError> {
    let outcome = Outcome::parse(&r.outcome)
        .ok_or_else(|| caps::CapError::new("outcome", "unknown outcome"))?;
    let auth_state = match r.auth_state.as_deref() {
        None => match outcome {
            Outcome::AuthRequired => AuthState::AuthRequired,
            _ => AuthState::None,
        },
        Some(s) => AuthState::parse(s)
            .ok_or_else(|| caps::CapError::new("authState", "unknown auth state"))?,
    };
    let doc = json!({
        "tools": r.tools, "resources": r.resources, "prompts": r.prompts,
        "instructions": r.instructions,
    });
    let set = CapabilitySet::from_doc(&doc)?;
    if outcome != Outcome::Ok && set != CapabilitySet::default() {
        return Err(caps::CapError::new(
            "outcome",
            "a failed attempt carries no capabilities",
        ));
    }
    Ok(ParsedResult {
        outcome,
        auth_state,
        set,
    })
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub artifact_id: Uuid,
    pub kind: String,
    pub target_key: String,
    pub status: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub not_before: DateTime<Utc>,
    pub claimed_by: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub claim_token_hash: Option<String>,
    pub last_error: Option<String>,
    pub snapshot_id: Option<Uuid>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const JOB_COLUMNS: &str = "id, repository_id, artifact_id, kind, target_key, status, attempts, \
     max_attempts, not_before, claimed_by, lease_expires_at, claim_token_hash, last_error, \
     snapshot_id, completed_at, created_at";

impl JobRow {
    pub fn kind(&self) -> Option<JobKind> {
        JobKind::parse(&self.kind)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.kind,
            "target": self.target_key,
            "status": self.status,
            "attempts": self.attempts,
            "maxAttempts": self.max_attempts,
            "notBefore": self.not_before,
            "claimedBy": self.claimed_by,
            "leaseExpiresAt": self.lease_expires_at,
            "lastError": self.last_error,
            "snapshotId": self.snapshot_id,
            "completedAt": self.completed_at,
            "createdAt": self.created_at,
        })
    }
}

fn db_err(e: sqlx::Error) -> crate::error::AppError {
    crate::error::AppError::Database(e.to_string())
}

/// The effective introspection settings of a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modes {
    pub probe: String,
    pub sandbox: String,
    pub repo_type: String,
}

impl Modes {
    pub fn probe_enabled(&self) -> bool {
        probe_allowed(Some(&self.probe), &self.repo_type)
    }
    pub fn sandbox_enabled(&self) -> bool {
        sandbox_allowed(Some(&self.sandbox), &self.repo_type)
    }
}

pub async fn modes(db: &PgPool, repo_id: Uuid) -> crate::error::Result<Modes> {
    let repo_type: String =
        sqlx::query_scalar("SELECT repo_type::text FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(db)
            .await
            .map_err(db_err)?;
    let s = crate::services::mcp_settings::load(db, repo_id, &repo_type).await?;
    Ok(Modes {
        probe: s.mcp_probe_remotes.unwrap_or_else(|| "off".into()),
        sandbox: s.mcp_sandbox_introspection.unwrap_or_else(|| "off".into()),
        repo_type,
    })
}

async fn insert_job(
    db: &PgPool,
    repo_id: Uuid,
    artifact_id: Uuid,
    kind: JobKind,
    target_key: &str,
    requested_by: Option<Uuid>,
) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar(
        "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, target_key, \
           requested_by) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (artifact_id, kind, target_key) WHERE status IN ('pending', 'claimed') \
         DO NOTHING RETURNING id",
    )
    .bind(repo_id)
    .bind(artifact_id)
    .bind(kind.as_str())
    .bind(target_key)
    .bind(requested_by)
    .fetch_optional(db)
    .await
}

/// Queue every job the repository's settings allow for one server version.
/// Idempotent: a target with an open job is skipped. Returns the new job ids.
pub async fn enqueue_for_artifact(
    db: &PgPool,
    artifact_id: Uuid,
    requested_by: Option<Uuid>,
) -> crate::error::Result<Vec<Uuid>> {
    let Some(v) = caps::version_ref(db, artifact_id).await.map_err(db_err)? else {
        return Ok(Vec::new());
    };
    let modes = modes(db, v.repository_id).await?;
    let Some(stored) = StoredVersion::from_metadata(&v.metadata) else {
        return Ok(Vec::new());
    };
    let mut targets: Vec<(JobKind, String)> = Vec::new();
    if modes.probe_enabled() {
        targets.extend(
            remote_targets(&stored.server)
                .into_iter()
                .map(|(k, _)| (JobKind::RemoteProbe, k)),
        );
    }
    if modes.sandbox_enabled() {
        targets.extend(
            sandbox_targets(&stored.server, &stored.pins)
                .into_iter()
                .map(|k| (JobKind::SandboxRun, k)),
        );
    }
    let mut ids = Vec::new();
    for (kind, key) in targets {
        if let Some(id) = insert_job(db, v.repository_id, artifact_id, kind, &key, requested_by)
            .await
            .map_err(db_err)?
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// A claimed job and the raw claim token (returned to the worker once).
#[derive(Debug, Clone)]
pub struct Claim {
    pub job: JobRow,
    pub token: String,
}

fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The repository authorization every claim and every completion checks
/// (#5460), as a SQL predicate on the job row aliased `j` with the worker
/// credential's repository allowlist bound at `$n` (`NULL`: a token with no
/// repository restriction; an empty list matches nothing). It holds when the
/// job's repository is in that allowlist AND the job is bound to it: the
/// server version the job introspects belongs to that same repository.
/// Claim and completion use this one predicate, so their checks cannot drift
/// apart, and possession of a claim token never stands in for it.
fn repo_authorized(j: &str, n: u8) -> String {
    format!(
        "(${n}::uuid[] IS NULL OR {j}.repository_id = ANY(${n}::uuid[])) \
         AND EXISTS (SELECT 1 FROM artifacts ra WHERE ra.id = {j}.artifact_id \
                     AND ra.repository_id = {j}.repository_id)"
    )
}

/// Claim a due job of `kinds`, fairly across repositories (#5387): the job
/// comes from the repository with the fewest jobs claimed right now, and is
/// that repository's oldest due job. One publisher queueing many versions
/// therefore cannot hold every worker while other repositories' jobs wait.
/// A single statement: `FOR UPDATE SKIP LOCKED` keeps concurrent claims from
/// handing out one job twice.
///
/// Only jobs of repositories `scope` covers are candidates (#5460): a worker
/// credential restricted to repository A is never handed repository B's job,
/// and B's job is left exactly as it was.
pub async fn claim(
    db: &PgPool,
    kinds: &[JobKind],
    worker_id: &str,
    scope: &AccessScope,
) -> crate::error::Result<Option<Claim>> {
    let kinds: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let token = new_token();
    let sql = format!(
        "WITH busy AS ( \
           SELECT repository_id, COUNT(*) AS claimed FROM mcp_introspection_jobs \
           WHERE status = 'claimed' GROUP BY repository_id), \
         next AS ( \
           SELECT p.id FROM mcp_introspection_jobs p \
           LEFT JOIN busy b ON b.repository_id = p.repository_id \
           WHERE p.status = 'pending' AND p.not_before <= NOW() AND p.kind = ANY($1) \
             AND {} \
           ORDER BY COALESCE(b.claimed, 0), p.not_before, p.created_at \
           LIMIT 1 FOR UPDATE OF p SKIP LOCKED) \
         UPDATE mcp_introspection_jobs j SET status = 'claimed', attempts = j.attempts + 1, \
           claimed_by = $2, claimed_at = NOW(), \
           lease_expires_at = NOW() + make_interval(secs => $3), claim_token_hash = $4, \
           updated_at = NOW() \
         FROM next WHERE j.id = next.id RETURNING {}",
        repo_authorized("p", 5),
        JOB_COLUMNS
            .split(", ")
            .map(|c| format!("j.{c}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let job: Option<JobRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&kinds)
        .bind(caps_truncate(worker_id, 128))
        .bind(LEASE_SECS as f64)
        .bind(caps::sha256_hex(token.as_bytes()))
        .bind(scope.as_allowed_repo_ids())
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    Ok(job.map(|job| Claim { job, token }))
}

fn caps_truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub async fn get_job(db: &PgPool, id: Uuid) -> crate::error::Result<Option<JobRow>> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM mcp_introspection_jobs WHERE id = $1");
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

pub async fn list_jobs(
    db: &PgPool,
    artifact_id: Uuid,
    limit: i64,
) -> crate::error::Result<Vec<JobRow>> {
    let sql = format!(
        "SELECT {JOB_COLUMNS} FROM mcp_introspection_jobs WHERE artifact_id = $1 \
         ORDER BY created_at DESC LIMIT $2"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(artifact_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(db_err)
}

/// Whether `token` proves the current claim of `job`.
pub fn token_matches(job: &JobRow, token: &str) -> bool {
    use subtle_eq::ct_eq;
    job.status == "claimed"
        && job
            .claim_token_hash
            .as_deref()
            .is_some_and(|h| ct_eq(h.as_bytes(), caps::sha256_hex(token.as_bytes()).as_bytes()))
}

mod subtle_eq {
    /// Constant-time byte comparison (equal lengths are hex digests here).
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// End a claim: `status` is `completed`, `failed`, `cancelled` or (a retry)
/// `pending` with `not_before`. Only the current claim can be ended.
async fn finish(
    db: impl sqlx::PgExecutor<'_>,
    job: &JobRow,
    status: &str,
    not_before: Option<DateTime<Utc>>,
    snapshot_id: Option<Uuid>,
    error: Option<&str>,
) -> crate::error::Result<bool> {
    let done = sqlx::query(
        "UPDATE mcp_introspection_jobs SET status = $3, \
           not_before = COALESCE($4, not_before), snapshot_id = COALESCE($5, snapshot_id), \
           last_error = $6, claim_token_hash = NULL, lease_expires_at = NULL, \
           completed_at = CASE WHEN $3 IN ('completed', 'failed', 'cancelled') THEN NOW() END, \
           updated_at = NOW() \
         WHERE id = $1 AND status = 'claimed' AND claim_token_hash = $2",
    )
    .bind(job.id)
    .bind(&job.claim_token_hash)
    .bind(status)
    .bind(not_before)
    .bind(snapshot_id)
    .bind(error.map(|e| caps_truncate(e, 1000)))
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// Cancel a claimed job that cannot run (target gone, version held).
pub async fn cancel(db: &PgPool, job: &JobRow, reason: &str) -> crate::error::Result<bool> {
    finish(db, job, "cancelled", None, None, Some(reason)).await
}

/// What completing a job did.
#[derive(Debug, Clone)]
// Built once per worker result and matched immediately; boxing the row buys
// nothing.
#[allow(clippy::large_enum_variant)]
pub enum Completed {
    /// A snapshot was stored (and drift raised when `drift_scan` is set).
    Stored {
        snapshot: caps::SnapshotRow,
        drift_scan: Option<Uuid>,
    },
    /// A transient failure: the job goes back to the queue.
    Retry { not_before: DateTime<Utc> },
    /// The claim was no longer current when the result arrived (completed
    /// by a concurrent or duplicate request, reaped, re-claimed): nothing was
    /// stored. `409 mcp_claim_invalid` (#5389).
    ClaimLost,
    /// The worker credential does not cover the job's repository (or the job
    /// is not bound to its server version's repository) at completion time:
    /// nothing was stored and the claim was left as it was.
    /// `403 mcp_forbidden` (#5460).
    Forbidden,
}

/// Lock the current claim of `job` in the transaction that will end it, and
/// re-check the repository authorization ([`repo_authorized`]) under that
/// same lock: `None` when the claim is no longer current (#5389),
/// `Some(false)` when `scope` does not authorize the job's repository
/// (#5460), `Some(true)` when the transaction may end the claim.
async fn lock_claim(
    tx: &mut sqlx::PgConnection,
    job: &JobRow,
    scope: &AccessScope,
) -> crate::error::Result<Option<bool>> {
    let sql = format!(
        "SELECT {} FROM mcp_introspection_jobs j \
         WHERE j.id = $1 AND j.status = 'claimed' AND j.claim_token_hash = $2 FOR UPDATE OF j",
        repo_authorized("j", 3)
    );
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(job.id)
        .bind(&job.claim_token_hash)
        .bind(scope.as_allowed_repo_ids())
        .fetch_optional(tx)
        .await
        .map_err(db_err)
}

/// Record a worker result for a claimed job (token already checked by the
/// caller, but the claim may end concurrently), as a worker whose credential
/// carries repository `scope`.
///
/// The claim check and end and the snapshot insert run in one transaction
/// (the job row is locked with its token hash and `claimed` status), so of
/// two completions of one claim exactly one stores a snapshot; the other, and
/// one racing the reaper or a re-claim, gets [`Completed::ClaimLost`]. The
/// audit, lint and drift side effects run after the commit, and only for a
/// newly stored snapshot (#5389). Under that same row lock the worker's
/// repository scope and the job's repository binding are re-checked, for a
/// retry as for a result, so a credential that does not (or no longer)
/// covers the job's repository gets [`Completed::Forbidden`] and changes
/// nothing (#5460).
pub async fn complete(
    db: &PgPool,
    job: &JobRow,
    result: &WorkerResult,
    parsed: ParsedResult,
    scope: &AccessScope,
) -> crate::error::Result<Completed> {
    let kind = job
        .kind()
        .ok_or_else(|| crate::error::AppError::Internal("unknown job kind".into()))?;
    let mut tx = db.begin().await.map_err(db_err)?;
    match lock_claim(&mut tx, job, scope).await? {
        None => return Ok(Completed::ClaimLost),
        Some(false) => return Ok(Completed::Forbidden),
        Some(true) => {}
    }
    if is_transient(parsed.outcome)
        && job.attempts < attempts_allowed(kind, parsed.outcome, job.max_attempts)
    {
        let delay = retry_delay_secs(parsed.outcome, job.attempts, result.retry_after_ms);
        let not_before = Utc::now() + chrono::Duration::seconds(delay);
        // The row is locked and matched above, so this ends the claim.
        if !finish(
            &mut *tx,
            job,
            "pending",
            Some(not_before),
            None,
            Some(result.error.as_deref().unwrap_or(parsed.outcome.as_str())),
        )
        .await?
        {
            return Ok(Completed::ClaimLost);
        }
        tx.commit().await.map_err(db_err)?;
        return Ok(Completed::Retry { not_before });
    }
    let v = caps::version_ref(db, job.artifact_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| crate::error::AppError::NotFound("server version deleted".into()))?;
    let mut details = result.details.clone().unwrap_or_else(|| json!({}));
    if let (Some(o), Some(e)) = (details.as_object_mut(), result.error.as_deref()) {
        o.insert("error".into(), json!(caps_truncate(e, 1000)));
    }
    if let Some(o) = details.as_object_mut() {
        o.insert("jobId".into(), json!(job.id));
        o.insert("target".into(), json!(job.target_key));
    }
    let source = kind.source();
    let snap = NewSnapshot {
        repository_id: v.repository_id,
        artifact_id: v.artifact_id,
        server_name: v.name,
        server_version: v.version,
        source,
        provenance: source.default_provenance().to_string(),
        origin: Some(job.target_key.clone()),
        reported_by: None,
        auth_state: parsed.auth_state,
        outcome: parsed.outcome,
        protocol_version: result.protocol_version.clone(),
        observed_at: result.observed_at.unwrap_or_else(Utc::now),
        ttl_ms: result.ttl_ms.filter(|t| *t >= 0),
        cache_scope: result.cache_scope.clone(),
        set: parsed.set,
        worker_version: result
            .worker_version
            .clone()
            .or_else(|| job.claimed_by.clone()),
        details,
    };
    let status = if matches!(parsed.outcome, Outcome::Error | Outcome::StartFailed) {
        "failed"
    } else {
        "completed"
    };
    let ins = caps::insert_snapshot_in(&mut tx, &snap)
        .await
        .map_err(db_err)?;
    // The row is locked and matched above, so this ends the claim.
    if !finish(
        &mut *tx,
        job,
        status,
        None,
        Some(ins.snapshot.id),
        result.error.as_deref(),
    )
    .await?
    {
        return Ok(Completed::ClaimLost);
    }
    tx.commit().await.map_err(db_err)?;
    let drift_scan = caps::record_stored(db, &snap, &ins, &v.repository_key).await?;
    Ok(Completed::Stored {
        snapshot: ins.snapshot,
        drift_scan,
    })
}

/// Return expired claims to the queue (or fail them after `max_attempts`).
pub async fn reap_expired(db: &PgPool) -> crate::error::Result<u64> {
    let r = sqlx::query(
        "UPDATE mcp_introspection_jobs SET \
           status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END, \
           completed_at = CASE WHEN attempts >= max_attempts THEN NOW() END, \
           last_error = 'claim lease expired', claim_token_hash = NULL, \
           lease_expires_at = NULL, updated_at = NOW() \
         WHERE status = 'claimed' AND lease_expires_at < NOW()",
    )
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(r.rows_affected())
}

/// Queue the next probe of every remote whose last probe is due again, for
/// the latest version of each server and versions published within
/// [`REPROBE_RECENT_DAYS`] (#5386). The version filter is in the query, so an
/// old version never takes a slot of the batch.
pub async fn requeue_due_probes(db: &PgPool) -> crate::error::Result<usize> {
    let due: Vec<(Uuid, String, DateTime<Utc>, Option<i64>)> = sqlx::query_as(
        "SELECT DISTINCT ON (j.artifact_id, j.target_key) j.artifact_id, j.target_key, \
                j.completed_at, s.ttl_ms \
         FROM mcp_introspection_jobs j \
         JOIN artifacts a ON a.id = j.artifact_id AND a.is_deleted = false \
         JOIN artifact_metadata m ON m.artifact_id = a.id AND m.format = 'mcp' \
         LEFT JOIN mcp_capability_snapshots s ON s.id = j.snapshot_id \
         WHERE j.kind = 'remote_probe' AND j.status IN ('completed', 'failed') \
           AND j.completed_at < NOW() - make_interval(secs => $1) \
           AND (m.metadata->'registry'->>'isLatest' = 'true' \
                OR COALESCE((m.metadata->'registry'->>'publishedAt')::timestamptz, a.created_at) \
                   > NOW() - make_interval(days => $3)) \
           AND NOT EXISTS (SELECT 1 FROM mcp_introspection_jobs o \
                           WHERE o.artifact_id = j.artifact_id AND o.kind = j.kind \
                             AND o.target_key = j.target_key \
                             AND (o.status IN ('pending', 'claimed') OR o.created_at > j.created_at)) \
         ORDER BY j.artifact_id, j.target_key, j.completed_at DESC LIMIT $2",
    )
    .bind(MIN_REPROBE_SECS as f64)
    .bind(REPROBE_BATCH)
    .bind(REPROBE_RECENT_DAYS)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    let mut queued = 0;
    for (artifact_id, target_key, completed_at, ttl_ms) in due {
        if reprobe_due_at(completed_at, ttl_ms) > Utc::now() {
            continue;
        }
        // Settings may have changed since: the probe stays opt-in.
        let Some(v) = caps::version_ref(db, artifact_id).await.map_err(db_err)? else {
            continue;
        };
        if !modes(db, v.repository_id).await?.probe_enabled() {
            continue;
        }
        let still_listed = StoredVersion::from_metadata(&v.metadata).is_some_and(|s| {
            remote_targets(&s.server)
                .iter()
                .any(|(k, _)| *k == target_key)
        });
        if !still_listed {
            continue;
        }
        if insert_job(
            db,
            v.repository_id,
            artifact_id,
            JobKind::RemoteProbe,
            &target_key,
            None,
        )
        .await
        .map_err(db_err)?
        .is_some()
        {
            queued += 1;
        }
    }
    Ok(queued)
}

/// One scheduler pass (`IdempotentDbOnly`).
pub async fn scheduler_tick(db: &PgPool) {
    match reap_expired(db).await {
        Ok(n) if n > 0 => tracing::info!(reaped = n, "MCP introspection claims expired"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "MCP introspection reaper failed"),
    }
    match requeue_due_probes(db).await {
        Ok(n) if n > 0 => tracing::info!(queued = n, "MCP remote probes re-queued"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "MCP re-probe scheduling failed"),
    }
    match caps::prune_snapshots(db).await {
        Ok(n) if n > 0 => tracing::info!(pruned = n, "MCP capability snapshots pruned"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "MCP capability snapshot retention failed"),
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::mcp::{PackagePolicy, RegistryState, ResolvedPin, SubmittedRef};

    fn pin(index: usize, registry_type: &str) -> PackagePin {
        PackagePin {
            index,
            registry_type: registry_type.into(),
            submitted: SubmittedRef {
                identifier: "x".into(),
                version: None,
            },
            resolved: ResolvedPin {
                repository: "npm-local".into(),
                repository_id: Uuid::nil(),
                artifact_ids: vec![],
                sha256: None,
                name: None,
                tag: None,
                digest: None,
                media_type: None,
                children: vec![],
                gate_digest: None,
                resolved_at: Utc::now(),
                warnings: vec![],
                cache_path: None,
                download_path: None,
            },
            drift: None,
        }
    }

    fn server() -> Value {
        json!({
            "name": "com.acme/x", "version": "1.0.0",
            "remotes": [
                {"type": "streamable-http", "url": "https://mcp.acme.test/mcp",
                 "headers": [{"name": "Authorization", "value": "secret"}]},
                {"type": "sse", "url": "https://mcp.acme.test/sse"},
                {"type": "streamable-http", "url": "https://{tenant}.acme.test/mcp"},
                {"type": "streamable-http", "url": "https://u:p@acme.test/mcp"},
            ],
            "packages": [
                {"registryType": "npm", "identifier": "@acme/x", "transport": {"type": "stdio"}},
                {"registryType": "npm", "identifier": "@acme/y", "transport": {"type": "streamable-http", "url": "http://localhost"}},
                {"registryType": "cargo", "identifier": "x", "transport": {"type": "stdio"}},
                {"registryType": "pypi", "identifier": "x", "transport": {"type": "stdio"}},
            ],
        })
    }

    #[test]
    fn policy_matrix() {
        assert!(!probe_allowed(None, "local"));
        assert!(!probe_allowed(Some("off"), "local"));
        assert!(probe_allowed(Some("hosted_only"), "local"));
        assert!(probe_allowed(Some("hosted_only"), "staging"));
        assert!(!probe_allowed(Some("hosted_only"), "remote"));
        assert!(probe_allowed(Some("all"), "remote"));
        assert!(!probe_allowed(Some("all"), "virtual"));
        assert!(sandbox_allowed(Some("on"), "remote"));
        assert!(!sandbox_allowed(Some("off"), "local"));
        assert!(!sandbox_allowed(Some("on"), "virtual"));
        for k in JobKind::ALL {
            assert_eq!(JobKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(JobKind::parse("x"), None);
        assert_eq!(JobKind::SandboxRun.source(), Source::SandboxRun);
    }

    #[test]
    fn targets_from_a_server() {
        assert_eq!(
            remote_targets(&server()),
            vec![(
                "remote:0".to_string(),
                "https://mcp.acme.test/mcp".to_string()
            )]
        );
        assert!(remote_targets(&json!({})).is_empty());
        assert!(!probeable_url("ftp://x.test"));
        assert!(!probeable_url("not a url"));
        assert!(probeable_url("http://x.test:8080/mcp"));
        let pins = vec![pin(0, "npm"), pin(1, "npm"), pin(2, "cargo")];
        assert_eq!(sandbox_targets(&server(), &pins), vec!["package:0"]);
        assert_eq!(
            sandbox_targets(&server(), &[pin(3, "pypi")]),
            vec!["package:3"]
        );
        assert!(
            sandbox_targets(&server(), &[]).is_empty(),
            "unpinned never runs"
        );
        assert!(sandbox_targets(&json!({}), &pins).is_empty());
    }

    fn stored(pins: Vec<PackagePin>) -> StoredVersion {
        StoredVersion {
            server: server(),
            registry: RegistryState::new_active(Utc::now()),
            policy: PackagePolicy::OwnRepos,
            pins,
            upstream: None,
            resolving: false,
        }
    }

    #[test]
    fn job_target_shapes() {
        let s = stored(vec![pin(0, "npm")]);
        let mut served = server();
        served["packages"][0]["registryBaseUrl"] = json!("https://ak.test/npm/npm-local");
        let t = job_target(JobKind::RemoteProbe, "remote:0", &s, &served).unwrap();
        assert_eq!(t["url"], "https://mcp.acme.test/mcp");
        assert!(
            t.get("headers").is_none(),
            "publisher headers never reach the worker"
        );
        assert_eq!(
            job_target(JobKind::RemoteProbe, "remote:1", &s, &served),
            Err(Unrunnable::TargetGone)
        );
        assert_eq!(
            job_target(JobKind::RemoteProbe, "bogus", &s, &served),
            Err(Unrunnable::TargetGone)
        );
        let t = job_target(JobKind::SandboxRun, "package:0", &s, &served).unwrap();
        assert_eq!(
            t["package"]["registryBaseUrl"],
            "https://ak.test/npm/npm-local"
        );
        assert_eq!(t["registryType"], "npm");
        assert_eq!(
            job_target(JobKind::SandboxRun, "package:2", &s, &served),
            Err(Unrunnable::TargetGone)
        );
    }

    #[test]
    fn sandbox_timeout_is_retried_once() {
        assert_eq!(
            attempts_allowed(JobKind::SandboxRun, Outcome::Timeout, 3),
            2
        );
        assert_eq!(
            attempts_allowed(JobKind::SandboxRun, Outcome::Timeout, 1),
            1
        );
        assert_eq!(attempts_allowed(JobKind::SandboxRun, Outcome::Error, 3), 3);
        assert_eq!(
            attempts_allowed(JobKind::RemoteProbe, Outcome::Timeout, 3),
            3
        );
    }

    #[test]
    fn retry_and_reprobe_timing() {
        let t = DateTime::from_timestamp(1_000_000, 0).unwrap();
        assert_eq!(
            reprobe_due_at(t, None),
            t + chrono::Duration::seconds(MIN_REPROBE_SECS)
        );
        assert_eq!(
            reprobe_due_at(t, Some(48 * 3600 * 1000)),
            t + chrono::Duration::hours(48)
        );
        assert_eq!(reprobe_due_at(t, Some(-5)), reprobe_due_at(t, None));
        assert!(is_transient(Outcome::Timeout) && is_transient(Outcome::RateLimited));
        assert!(!is_transient(Outcome::AuthRequired) && !is_transient(Outcome::Ok));
        // A sandbox that could not start is retried; a server that would
        // not start unconfigured is its own state.
        assert!(is_transient(Outcome::StartFailed) && !is_transient(Outcome::NeedsConfig));
        assert_eq!(retry_delay_secs(Outcome::RateLimited, 1, Some(5_000)), 60);
        assert_eq!(
            retry_delay_secs(Outcome::RateLimited, 1, Some(7_200_000)),
            7200
        );
        assert_eq!(
            retry_delay_secs(Outcome::RateLimited, 1, Some(i64::MAX)),
            24 * 3600
        );
        assert_eq!(retry_delay_secs(Outcome::Timeout, 1, None), 120);
        assert_eq!(retry_delay_secs(Outcome::Error, 3, Some(1)), 480);
    }

    #[test]
    fn worker_result_parsing() {
        let ok = WorkerResult {
            claim_token: "t".into(),
            outcome: "ok".into(),
            tools: Some(json!([{"name": "a"}])),
            ..Default::default()
        };
        let p = parse_result(&ok).unwrap();
        assert_eq!(p.auth_state, AuthState::None);
        assert_eq!(p.set.tools.len(), 1);
        let auth = WorkerResult {
            outcome: "auth_required".into(),
            ..Default::default()
        };
        assert_eq!(
            parse_result(&auth).unwrap().auth_state,
            AuthState::AuthRequired
        );
        let bad = [
            WorkerResult {
                outcome: "nope".into(),
                ..Default::default()
            },
            WorkerResult {
                outcome: "ok".into(),
                auth_state: Some("x".into()),
                ..Default::default()
            },
            WorkerResult {
                outcome: "timeout".into(),
                tools: Some(json!([{"name": "a"}])),
                ..Default::default()
            },
            WorkerResult {
                outcome: "ok".into(),
                tools: Some(json!({})),
                ..Default::default()
            },
        ];
        for b in bad {
            assert!(parse_result(&b).is_err(), "{b:?}");
        }
    }

    #[test]
    fn token_check() {
        let job = JobRow {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            kind: "remote_probe".into(),
            target_key: "remote:0".into(),
            status: "claimed".into(),
            attempts: 1,
            max_attempts: 3,
            not_before: Utc::now(),
            claimed_by: None,
            lease_expires_at: None,
            claim_token_hash: Some(caps::sha256_hex(b"tok")),
            last_error: None,
            snapshot_id: None,
            completed_at: None,
            created_at: Utc::now(),
        };
        assert!(token_matches(&job, "tok"));
        assert!(!token_matches(&job, "other"));
        let done = JobRow {
            status: "completed".into(),
            ..job.clone()
        };
        assert!(!token_matches(&done, "tok"));
        assert_eq!(job.to_json()["target"], "remote:0");
        assert_eq!(job.kind(), Some(JobKind::RemoteProbe));
        assert_eq!(new_token().len(), 64);
    }
}
