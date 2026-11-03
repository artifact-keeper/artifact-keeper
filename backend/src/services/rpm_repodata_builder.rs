//! Precomputed hosted RPM repodata (#4544).
//!
//! A hosted RPM repository used to render a root's repodata on the request
//! path: the fingerprint cache ([`super::rpm_repodata_cache`]) made repeat
//! requests cheap, but every change made the next request on every replica
//! pay a full render (about 35 s of CPU on a 2,500-package root), and a bulk
//! import changes the root on every insert.
//!
//! In the default `repodata_mode` (`precomputed`) the documents are built in
//! the background instead and served from storage:
//!
//! 1. **Dirty at the persistence boundary.** Triggers on `artifacts` and
//!    `artifact_metadata` (migration 308) mark the changed root, using
//!    migration 247's root derivation. A writer only appends a row to
//!    `rpm_repodata_dirty` (migration 309), and only when the root is not
//!    already marked, so writers never lock a shared row: a bulk import does
//!    not queue, and two writers touching two roots in opposite order cannot
//!    deadlock. The builder folds the marks into
//!    `rpm_repodata_roots.dirty_since` ([`fold_marks`]), dropping marks that
//!    predate the current revision's claim: they are already in its
//!    snapshot, and applying them late would ask for a redundant rebuild.
//! 2. **Debounced builder.** Every replica ticks; a dirty root is built once
//!    it has been quiet for [`BuilderSettings::quiet`] or dirty for
//!    [`BuilderSettings::max_delay`], under a [`ClusterLock`] lease per root
//!    so one replica builds it. The heal (#3801) runs first, outside any
//!    snapshot; the render then reads one snapshot without storage reads
//!    ([`rpm::RenderHeal::Before`]) and streams the gzipped documents into
//!    spool files, which go to `put_stream` (through `put_file`) under
//!    [`revision_prefix`]. One `UPDATE` makes the new revision current.
//! 3. **Serve from storage.** `repomd.xml` comes from the row, the `*.xml.gz`
//!    documents stream from the current revision, `repomd.xml.asc` is signed
//!    per request over the stored `repomd.xml` (so key rotation, #1329, keeps
//!    working). The bytes are the ones the on-request render produces for the
//!    same rows.
//! 4. **Fallback and GC.** A root that has never been built renders on request
//!    (once per state per replica, through the in-process cache) until its
//!    first build. The previous revision is kept so a download in flight
//!    during a swap completes; older ones are deleted. A root with no
//!    packages is not stored at all.
//!
//! Consistency: the builder clears `dirty_since` before it opens its
//! snapshot, so a write committed after that re-dirties the root. Writers
//! hold a shared advisory lock on the root (`ak_rpm_repodata_fence`) until
//! they commit, and the builder clears the flag under the exclusive lock, so
//! a write whose trigger saw the root still dirty has committed (and is in
//! the snapshot) by the time the flag is cleared. The claim also sets
//! `retry_at` to a deadline, so a build that dies before its swap is retried.
//! As a safety net, [`reconcile`] compares built fingerprints with the live
//! ones every [`BuilderSettings::maintenance_every`].
//!
//! Virtual repositories stay on request: their documents depend on which
//! members the caller may read (#4346).

use std::collections::HashMap;
use std::io::BufWriter;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api::handlers::rpm;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::cluster_lock::{lease_object_id, ClusterLease, ClusterLock, PgAdvisoryLock};
use crate::services::rpm_repodata_cache::{revision_prefix, StoredRepodata};
use crate::storage::StorageLocation;

/// Advisory-lock class (`classid`) for building one RPM repodata root.
pub const RPM_REPODATA_BUILD_LOCK_CLASS: i32 = 0x4544;

/// `repository_config` key of the per-repository repodata mode.
pub const MODE_KEY: &str = "repodata_mode";

/// How a hosted RPM repository's repodata is produced.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RepodataMode {
    /// Built in the background and served from storage (the default).
    #[default]
    Precomputed,
    /// Rendered on the request path, validated against the repository state
    /// on every request (read-your-writes; the pre-1.12 behaviour).
    OnRequest,
}

impl RepodataMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Precomputed => "precomputed",
            Self::OnRequest => "on_request",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "precomputed" => Some(Self::Precomputed),
            "on_request" => Some(Self::OnRequest),
            _ => None,
        }
    }
}

/// SQL predicate (over `repositories r`) for a repository whose roots are
/// precomputed: hosted RPM, no active curated publication (that serves its
/// own frozen repodata), not being deleted (#4311), and not opted out.
const PRECOMPUTED_REPO_SQL: &str = "r.format = 'rpm' AND r.repo_type = 'local' \
     AND r.active_publication_id IS NULL \
     AND NOT EXISTS (SELECT 1 FROM repository_delete_jobs j \
                     WHERE j.repository_id = r.id AND j.status IN ('pending', 'running')) \
     AND NOT EXISTS (SELECT 1 FROM repository_config c \
                     WHERE c.repository_id = r.id AND c.key = 'repodata_mode' \
                       AND c.value = 'on_request')";

/// Builder timing, read once from the environment at start.
#[derive(Clone, Debug)]
pub struct BuilderSettings {
    /// How often a replica looks for dirty roots
    /// (`RPM_REPODATA_BUILD_INTERVAL_SECS`, default 2).
    pub interval: Duration,
    /// A dirty root is built once no package changed for this long
    /// (`RPM_REPODATA_BUILD_QUIET_SECS`, default 3).
    pub quiet: Duration,
    /// ... or once it has been dirty this long, even while writes continue
    /// (`RPM_REPODATA_BUILD_MAX_DELAY_SECS`, default 60).
    pub max_delay: Duration,
    /// Rebuild after a build that missed some package's dependency data for
    /// a transient reason (#3801).
    pub retry_incomplete: Duration,
    /// Back-off after a failed build.
    pub failure_backoff: Duration,
    /// How often the fingerprint reconcile and the revision GC run.
    pub maintenance_every: Duration,
    /// A claimed build that has not swapped by then (its replica died) is
    /// retried.
    pub build_deadline: Duration,
    /// Longest the builder waits for in-flight writers of a root before it
    /// clears the root's dirty flag; past it the root is skipped this tick.
    pub fence_timeout: Duration,
    /// Roots looked at per tick.
    pub batch: i64,
}

impl Default for BuilderSettings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            quiet: Duration::from_secs(3),
            max_delay: Duration::from_secs(60),
            retry_incomplete: Duration::from_secs(60),
            failure_backoff: Duration::from_secs(30),
            maintenance_every: Duration::from_secs(60),
            build_deadline: Duration::from_secs(15 * 60),
            fence_timeout: Duration::from_millis(500),
            batch: 16,
        }
    }
}

impl BuilderSettings {
    pub fn from_env() -> Self {
        let secs = |name: &str, default: Duration| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(default)
        };
        let d = Self::default();
        Self {
            interval: secs("RPM_REPODATA_BUILD_INTERVAL_SECS", d.interval)
                .max(Duration::from_secs(1)),
            quiet: secs("RPM_REPODATA_BUILD_QUIET_SECS", d.quiet),
            max_delay: secs("RPM_REPODATA_BUILD_MAX_DELAY_SECS", d.max_delay),
            ..d
        }
    }
}

/// Spawn the builder loop on this replica. Detached: its lifetime is the
/// shutdown token.
pub fn spawn(state: SharedState, shutdown: CancellationToken) {
    let settings = BuilderSettings::from_env();
    info!(
        interval_secs = settings.interval.as_secs(),
        quiet_secs = settings.quiet.as_secs(),
        max_delay_secs = settings.max_delay.as_secs(),
        "RPM repodata builder started (#4544)"
    );
    sweep_spool_files(
        &crate::api::handlers::incus::staging_root(&state.config.storage_path),
        settings.build_deadline,
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(settings.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_maintenance: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            run_tick(&state, &settings).await;
            if last_maintenance.is_none_or(|t| t.elapsed() >= settings.maintenance_every) {
                last_maintenance = Some(tokio::time::Instant::now());
                if let Err(e) = reconcile(&state.db).await {
                    warn!(error = %e, "RPM repodata reconcile failed");
                }
                if let Err(e) = collect_garbage(&state).await {
                    warn!(error = %e, "RPM repodata revision GC failed");
                }
            }
        }
    });
}

/// Delete spool files a build left behind when its process died: older
/// than any build may run. Best effort.
fn sweep_spool_files(dir: &std::path::Path, older_than: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .file_name()
            .to_string_lossy()
            .starts_with(SPOOL_PREFIX)
            && entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > older_than);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// File name prefix of the builder's spool files.
const SPOOL_PREFIX: &str = "ak-rpm-repodata-";

/// One pass over the roots due for a build. Returns how many were built.
pub async fn run_tick(state: &SharedState, settings: &BuilderSettings) -> usize {
    let candidates = match due_roots(&state.db, settings).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "RPM repodata builder: listing dirty roots failed");
            return 0;
        }
    };
    let mut built = 0;
    for (repo_id, root) in candidates {
        match try_build(state, repo_id, &root, settings).await {
            Ok(BuildOutcome::Built { .. }) => built += 1,
            Ok(_) => {}
            Err(e) => warn!(%repo_id, root, error = %e, "RPM repodata build failed"),
        }
    }
    built
}

/// Advisory lock (single-key space) serializing [`fold_marks`] across
/// replicas.
const FOLD_LOCK_KEY: i64 = 0x4544_0309;

/// Move the dirty marks writers queued in `rpm_repodata_dirty` (migration
/// 309) into `rpm_repodata_roots.dirty_since`. Writers never lock a root
/// row, so two uploads touching two roots in opposite order cannot
/// deadlock; the builder takes the row locks here instead, one replica at a
/// time and in key order. Marks at or before the current revision's claim
/// (`built_from_at`) are dropped: that build's snapshot already includes
/// them, and applying one late would ask for a redundant rebuild (#5128).
/// Returns the roots marked.
pub async fn fold_marks(db: &PgPool) -> Result<u64> {
    fold_marks_inner(db, false).await
}

/// [`fold_marks`], but waiting for another replica's fold instead of
/// skipping (tests read `dirty_since` right after a write).
#[cfg(test)]
pub(crate) async fn fold_marks_waiting(db: &PgPool) -> Result<u64> {
    fold_marks_inner(db, true).await
}

async fn fold_marks_inner(db: &PgPool, wait: bool) -> Result<u64> {
    let mut tx = db.begin().await?;
    if wait {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(FOLD_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
    } else {
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(FOLD_LOCK_KEY)
            .fetch_one(&mut *tx)
            .await?;
        if !got {
            return Ok(0);
        }
    }
    // Never stall every replica's fold behind one blocked root row: give up
    // and retry at the next tick.
    sqlx::query("SET LOCAL lock_timeout = '1s'")
        .execute(&mut *tx)
        .await?;
    // Consume the queue first, then lock the roots: a build's claim deletes
    // marks and then updates the root, in the same order, so neither can
    // deadlock the other. Park the marks in a transaction-local table so the
    // next statement can read each root's latest `built_from_at` after
    // waiting for a claim that is already in progress. Filtering in the same
    // statement as the DELETE would use the pre-claim snapshot, see the
    // previous build's instant, and re-dirty a root the claim just cleared
    // (#5128).
    sqlx::query(
        "CREATE TEMP TABLE ak_rpm_repodata_fold \
             (repository_id uuid NOT NULL, root text NOT NULL, \
              marked_at timestamptz NOT NULL) ON COMMIT DROP",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "WITH moved AS (DELETE FROM rpm_repodata_dirty \
                         RETURNING repository_id, root, marked_at) \
         INSERT INTO ak_rpm_repodata_fold SELECT repository_id, root, marked_at FROM moved",
    )
    .execute(&mut *tx)
    .await?;
    let folded = sqlx::query(
        "WITH locked AS ( \
             SELECT rr.repository_id, rr.root, rr.built_from_at \
               FROM rpm_repodata_roots rr \
              WHERE (rr.repository_id, rr.root) IN \
                    (SELECT repository_id, root FROM ak_rpm_repodata_fold) \
              ORDER BY rr.repository_id, rr.root FOR UPDATE) \
         INSERT INTO rpm_repodata_roots (repository_id, root, dirty_since) \
         SELECT f.repository_id, f.root, MIN(f.marked_at) \
           FROM ak_rpm_repodata_fold f \
           LEFT JOIN locked l \
             ON l.repository_id = f.repository_id AND l.root = f.root \
          WHERE l.built_from_at IS NULL OR f.marked_at >= l.built_from_at \
          GROUP BY f.repository_id, f.root ORDER BY f.repository_id, f.root \
         ON CONFLICT (repository_id, root) DO UPDATE \
            SET dirty_since = COALESCE(rpm_repodata_roots.dirty_since, EXCLUDED.dirty_since)",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(folded)
}

/// Roots whose build is due: dirty and debounced, or past their retry time.
async fn due_roots(db: &PgPool, settings: &BuilderSettings) -> Result<Vec<(Uuid, String)>> {
    // A fold that timed out only delays marks to the next tick; the roots
    // already marked are still due.
    if let Err(e) = fold_marks(db).await {
        debug!(error = %e, "RPM repodata: folding dirty marks failed; retried next tick");
    }
    let sql = format!(
        "SELECT rr.repository_id, rr.root FROM rpm_repodata_roots rr \
           JOIN repositories r ON r.id = rr.repository_id \
          WHERE (rr.dirty_since IS NOT NULL OR rr.retry_at IS NOT NULL) \
            AND {PRECOMPUTED_REPO_SQL} \
            AND ((rr.dirty_since IS NOT NULL \
                  AND (rr.last_error IS NULL OR rr.retry_at IS NULL OR rr.retry_at <= now()) \
                  AND (rr.dirty_since <= now() - make_interval(secs => $1) \
                       OR GREATEST(rr.dirty_since, ( \
                              SELECT MAX(a.updated_at) FROM artifacts a \
                               WHERE a.repository_id = rr.repository_id \
                                 AND a.is_deleted = false AND a.path LIKE '%.rpm' \
                                 AND starts_with(a.path, \
                                     CASE WHEN rr.root = '' THEN '' ELSE rr.root || '/' END))) \
                          <= now() - make_interval(secs => $2))) \
                 OR (rr.dirty_since IS NULL AND rr.retry_at <= now())) \
          ORDER BY COALESCE(rr.dirty_since, rr.retry_at) \
          LIMIT $3"
    );
    let rows: Vec<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(settings.max_delay.as_secs_f64())
        .bind(settings.quiet.as_secs_f64())
        .bind(settings.batch)
        .fetch_all(db)
        .await?;
    Ok(rows)
}

/// What one build attempt did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildOutcome {
    /// A new revision is current.
    Built { revision: i64, packages: i64 },
    /// The root has no packages: nothing is stored and it renders on request.
    Empty,
    /// Another replica holds the root's lease.
    Busy,
    /// A writer transaction on the root outlasted
    /// [`BuilderSettings::fence_timeout`]; the root stays dirty and is not
    /// tried again for [`BuilderSettings::failure_backoff`], so a long import
    /// does not have new uploads queue behind the builder every tick.
    WritersBusy,
    /// The repository is not precomputed (opted out, virtual, publication, or
    /// gone).
    NotPrecomputed,
}

fn lease_key(repo_id: Uuid, root: &str) -> String {
    format!("rpm-repodata:{repo_id}:{root}")
}

fn root_prefix(root: &str) -> String {
    if root.is_empty() {
        String::new()
    } else {
        format!("{root}/")
    }
}

/// Build `root` now if no other replica is building it.
pub async fn try_build(
    state: &SharedState,
    repo_id: Uuid,
    root: &str,
    settings: &BuilderSettings,
) -> Result<BuildOutcome> {
    let lease = PgAdvisoryLock::new(state.db.clone())
        .try_acquire(
            RPM_REPODATA_BUILD_LOCK_CLASS,
            lease_object_id(&lease_key(repo_id, root)),
        )
        .await?;
    let Some(lease) = lease else {
        return Ok(BuildOutcome::Busy);
    };
    build_leased(state, repo_id, root, settings, lease).await
}

/// Build `root` now, waiting up to `wait` for a build another replica is
/// running to finish first. Used by the rebuild endpoint (`wait=true`). When
/// the current revision already includes every committed write (the root
/// is clean, and no claimed build is outstanding: `retry_at` is only left
/// set by a claim that never swapped or an incomplete build), it is
/// returned instead of building again, so concurrent callers and retries
/// share one build.
///
/// `slots` caps the builds this replica runs synchronously; a permit is
/// taken only once the lease is held, so waiting on another replica's build
/// does not occupy one. No free permit is a 503.
pub async fn build_waiting(
    state: &SharedState,
    repo_id: Uuid,
    root: &str,
    wait: Duration,
    slots: &'static tokio::sync::Semaphore,
) -> Result<BuildOutcome> {
    let lease = PgAdvisoryLock::new(state.db.clone())
        .acquire_blocking(
            RPM_REPODATA_BUILD_LOCK_CLASS,
            lease_object_id(&lease_key(repo_id, root)),
            wait,
        )
        .await?;
    let Some(lease) = lease else {
        return Ok(BuildOutcome::Busy);
    };
    let current: Option<(i64, i64)> = sqlx::query_as(
        "SELECT built_revision, built_count FROM rpm_repodata_roots \
          WHERE repository_id = $1 AND root = $2 AND dirty_since IS NULL \
            AND retry_at IS NULL AND built_revision IS NOT NULL \
            AND NOT EXISTS (SELECT 1 FROM rpm_repodata_dirty d \
                            WHERE d.repository_id = $1 AND d.root = $2)",
    )
    .bind(repo_id)
    .bind(root)
    .fetch_optional(&state.db)
    .await?;
    if let Some((revision, packages)) = current {
        lease.release().await;
        return Ok(BuildOutcome::Built { revision, packages });
    }
    let Ok(_permit) = slots.try_acquire() else {
        lease.release().await;
        return Err(AppError::ServiceUnavailable(
            "Too many synchronous repodata rebuilds in progress; retry".into(),
        ));
    };
    build_leased(state, repo_id, root, &BuilderSettings::from_env(), lease).await
}

/// Ask for a build of `root` at the next tick, without the debounce. A root
/// backing off after a failed build keeps its back-off.
pub async fn request_build(db: &PgPool, repo_id: Uuid, root: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO rpm_repodata_roots (repository_id, root, dirty_since) \
         VALUES ($1, $2, 'epoch') \
         ON CONFLICT (repository_id, root) DO UPDATE SET dirty_since = 'epoch', \
             retry_at = CASE WHEN rpm_repodata_roots.last_error IS NULL THEN NULL \
                             ELSE rpm_repodata_roots.retry_at END",
    )
    .bind(repo_id)
    .bind(root)
    .execute(db)
    .await?;
    Ok(())
}

async fn build_leased(
    state: &SharedState,
    repo_id: Uuid,
    root: &str,
    settings: &BuilderSettings,
    lease: ClusterLease,
) -> Result<BuildOutcome> {
    let started = std::time::Instant::now();
    let result = build_root(state, repo_id, root, settings).await;
    let label = match &result {
        Ok(BuildOutcome::Built { .. }) => "built",
        Ok(BuildOutcome::Empty) => "empty",
        Ok(BuildOutcome::Busy) => "busy",
        Ok(BuildOutcome::WritersBusy) => "writers_busy",
        Ok(BuildOutcome::NotPrecomputed) => "skipped",
        Err(_) => "failed",
    };
    metrics::counter!("ak_rpm_repodata_builds_total", "result" => label).increment(1);
    if matches!(result, Ok(BuildOutcome::Built { .. })) {
        metrics::histogram!("ak_rpm_repodata_build_seconds")
            .record(started.elapsed().as_secs_f64());
    }
    if let Err(e) = &result {
        // Keep the root dirty and back off; a later tick retries.
        let _ = sqlx::query(
            "UPDATE rpm_repodata_roots \
                SET dirty_since = COALESCE(dirty_since, now()), \
                    retry_at = now() + make_interval(secs => $3), last_error = $4 \
              WHERE repository_id = $1 AND root = $2",
        )
        .bind(repo_id)
        .bind(root)
        .bind(settings.failure_backoff.as_secs_f64())
        .bind(e.to_string())
        .execute(&state.db)
        .await;
    }
    lease.release().await;
    result
}

/// The repository's storage location when it is precomputed.
pub async fn precomputed_location(db: &PgPool, repo_id: Uuid) -> Result<Option<StorageLocation>> {
    let sql = format!(
        "SELECT r.storage_backend, r.storage_path FROM repositories r \
          WHERE r.id = $1 AND {PRECOMPUTED_REPO_SQL}"
    );
    let row: Option<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|(backend, path)| StorageLocation { backend, path }))
}

/// A spool file for one compressed document, in the upload staging
/// directory (`AK_UPLOAD_STAGING_DIR`, default `<STORAGE_PATH>/.incoming`):
/// a deployment-sized disk, unlike a memory-backed `/tmp`.
struct Spool {
    file: tempfile::NamedTempFile,
}

impl Spool {
    fn new(dir: &std::path::Path) -> Result<(Self, BufWriter<std::fs::File>)> {
        std::fs::create_dir_all(dir)
            .map_err(|e| AppError::Internal(format!("repodata spool directory: {e}")))?;
        let file = tempfile::Builder::new()
            .prefix(SPOOL_PREFIX)
            .tempfile_in(dir)
            .map_err(|e| AppError::Internal(format!("repodata spool file: {e}")))?;
        let writer = file
            .reopen()
            .map_err(|e| AppError::Internal(format!("repodata spool file: {e}")))?;
        Ok((Self { file }, BufWriter::new(writer)))
    }
}

async fn build_root(
    state: &SharedState,
    repo_id: Uuid,
    root: &str,
    settings: &BuilderSettings,
) -> Result<BuildOutcome> {
    let started = std::time::Instant::now();
    let Some(location) = precomputed_location(&state.db, repo_id).await? else {
        return Ok(BuildOutcome::NotPrecomputed);
    };
    let depth = crate::services::rpm_layout::depth(&state.db, repo_id).await?;
    if crate::services::rpm_layout::validate_root(root, depth).is_err() {
        // A root of an earlier layout: the depth can only change once the
        // repository holds no artifacts, so nothing lives there any more.
        drop_root(state, repo_id, root).await?;
        sqlx::query("DELETE FROM rpm_repodata_roots WHERE repository_id = $1 AND root = $2")
            .bind(repo_id)
            .bind(root)
            .execute(&state.db)
            .await?;
        return Ok(BuildOutcome::Empty);
    }
    let prefix = root_prefix(root);

    // 1. Heal first, outside any snapshot: its storage reads and writes do
    //    not hold the render's snapshot (and the vacuum horizon) open, and
    //    the render needs no second connection. Its writes are heal
    //    bookkeeping (migration 308 ignores them) or, for a row without
    //    metadata, land before the dirty flag is cleared below.
    let healed = rpm::heal_root(state, repo_id, &prefix)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // 2. Claim a revision number and clear the dirty flag, under the
    //    exclusive fence: writers whose trigger saw the root dirty (and so
    //    did not touch the row) hold the shared fence until they commit, so
    //    once the clear commits every such write is visible to the snapshot
    //    below, and any later write re-dirties the root. `retry_at` is the
    //    deadline after which a build that never swapped is retried. The
    //    storage location is recorded now so the GC can find this revision's
    //    objects even if the build fails before it becomes current.
    let Some(revision) = claim(state, repo_id, root, &location, settings).await? else {
        // An upsert: a root whose marks have not been folded yet has no row,
        // and its back-off must not be lost.
        sqlx::query(
            "INSERT INTO rpm_repodata_roots (repository_id, root, retry_at, last_error) \
             VALUES ($1, $2, now() + make_interval(secs => $3), \
                     'writers held the root past the fence timeout') \
             ON CONFLICT (repository_id, root) DO UPDATE \
                SET retry_at = EXCLUDED.retry_at, last_error = EXCLUDED.last_error",
        )
        .bind(repo_id)
        .bind(root)
        .bind(settings.failure_backoff.as_secs_f64())
        .execute(&state.db)
        .await?;
        return Ok(BuildOutcome::WritersBusy);
    };

    // 3. Render one snapshot into spool files.
    let spool_dir = crate::api::handlers::incus::staging_root(&state.config.storage_path);
    let (primary, primary_w) = Spool::new(&spool_dir)?;
    let (filelists, filelists_w) = Spool::new(&spool_dir)?;
    let (other, other_w) = Spool::new(&spool_dir)?;
    let render = rpm::render_repodata_snapshot(
        state,
        &[repo_id],
        &prefix,
        rpm::RPM_REPODATA_RENDER_BATCH_BYTES,
        rpm::RPM_REPODATA_DOC_SPILL_BYTES,
        [primary_w, filelists_w, other_w],
        rpm::RenderHeal::Before,
    )
    .await
    .map_err(|resp| AppError::Internal(format!("repodata render failed ({})", resp.status())))?;

    if render.count == 0 {
        drop_root(state, repo_id, root).await?;
        return Ok(BuildOutcome::Empty);
    }

    let docs = render.docs;
    let mut sizes = HashMap::new();
    let mut uploads = Vec::with_capacity(3);
    for (name, doc, spool) in [
        ("primary.xml.gz", docs.primary, primary),
        ("filelists.xml.gz", docs.filelists, filelists),
        ("other.xml.gz", docs.other, other),
    ] {
        doc.sink
            .into_inner()
            .map_err(|e| AppError::Internal(format!("repodata spool flush: {}", e.error())))?
            .sync_all()
            .map_err(|e| AppError::Internal(format!("repodata spool flush: {e}")))?;
        sizes.insert(name.to_string(), doc.size as u64);
        uploads.push((name, spool));
    }
    let repomd = Bytes::from(docs.repomd_xml);
    sizes.insert("repomd.xml".to_string(), repomd.len() as u64);

    // 4. Store the revision.
    let storage = state.storage_for_repo(&location)?;
    let key_prefix = revision_prefix(repo_id, root, revision);
    for (name, spool) in &uploads {
        storage
            .put_file(&format!("{key_prefix}/{name}"), spool.file.path())
            .await?;
    }
    storage
        .put(&format!("{key_prefix}/repomd.xml"), repomd.clone())
        .await?;
    drop(uploads);

    // 5. Make it current. A heal retry deadline or an incomplete heal asks
    //    for another build later, as the on-request cache would re-render.
    let retry_at: Option<DateTime<Utc>> = {
        let incomplete = (!(healed && render.heal_complete)).then(|| {
            Utc::now() + chrono::Duration::from_std(settings.retry_incomplete).unwrap_or_default()
        });
        let due = render.valid_until.map(|until| {
            Utc::now()
                + chrono::Duration::from_std(
                    until.saturating_duration_since(std::time::Instant::now()),
                )
                .unwrap_or_default()
        });
        match (incomplete, due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    };
    let swapped: Option<(Option<i64>, i64)> = sqlx::query_as(
        "UPDATE rpm_repodata_roots \
            SET built_revision = $3, previous_revision = built_revision, \
                built_count = $4, built_latest = $5, built_at = now(), \
                built_repomd = $6, built_sizes = $7, \
                storage_backend = $8, storage_path = $9, \
                retry_at = $10, last_error = NULL \
          WHERE repository_id = $1 AND root = $2 \
            AND (built_revision IS NULL OR built_revision < $3) \
          RETURNING previous_revision, gc_floor",
    )
    .bind(repo_id)
    .bind(root)
    .bind(revision)
    .bind(render.count)
    .bind(render.latest_update)
    .bind(repomd.as_ref())
    .bind(serde_json::to_value(&sizes).unwrap_or_default())
    .bind(&location.backend)
    .bind(&location.path)
    .bind(retry_at)
    .fetch_optional(&state.db)
    .await?;
    let Some((previous, gc_floor)) = swapped else {
        // The row went (the root emptied meanwhile) or a newer revision is
        // already current: this one is not reachable.
        delete_revision(storage.as_ref(), repo_id, root, revision).await;
        return Ok(BuildOutcome::Built {
            revision,
            packages: render.count,
        });
    };

    // 6. Safety net: the fence already puts every write that skipped the
    //    dirty mark into the snapshot; if the live fingerprint moved anyway,
    //    build again.
    mark_dirty_if_moved(&state.db, repo_id, root).await?;

    // 7. Keep the previous revision so a download in flight during the swap
    //    completes; delete the rest.
    let keep = previous.unwrap_or(revision);
    for old in gc_floor..revision {
        if Some(old) != previous {
            delete_revision(storage.as_ref(), repo_id, root, old).await;
        }
    }
    sqlx::query(
        "UPDATE rpm_repodata_roots SET gc_floor = GREATEST(gc_floor, $3) \
          WHERE repository_id = $1 AND root = $2",
    )
    .bind(repo_id)
    .bind(root)
    .bind(keep)
    .execute(&state.db)
    .await?;

    info!(
        %repo_id,
        root,
        revision,
        packages = render.count,
        batches = render.stats.batches,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "RPM repodata built"
    );
    Ok(BuildOutcome::Built {
        revision,
        packages: render.count,
    })
}

/// Step 2 of [`build_root`]: `None` when in-flight writers did not finish
/// within [`BuilderSettings::fence_timeout`]. Returns the claimed revision;
/// the claim instant is recorded as `built_from_at` on the root row.
async fn claim(
    state: &SharedState,
    repo_id: Uuid,
    root: &str,
    location: &StorageLocation,
    settings: &BuilderSettings,
) -> Result<Option<i64>> {
    let mut tx = state.db.begin().await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET LOCAL lock_timeout = '{}ms'",
        settings.fence_timeout.as_millis().max(1)
    )))
    .execute(&mut *tx)
    .await?;
    let fenced = sqlx::query("SELECT pg_advisory_xact_lock(ak_rpm_repodata_fence($1, $2))")
        .bind(repo_id)
        .bind(root)
        .execute(&mut *tx)
        .await;
    match fenced {
        Ok(_) => {}
        Err(e)
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "55P03" || c == "57014") =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }
    // Taken after the exclusive fence: every writer that queued a mark has
    // committed by now, so its `marked_at` is at or before this instant and
    // the build's snapshot will include it. `fold_marks` uses this to drop a
    // mark that a concurrent fold read before the claim cleared the queue
    // (#5128). `now()` would be the transaction start, before the fence
    // wait, and could discard a write that committed while we waited.
    //
    // Stored with the claim, not at the swap: a fold that races the build
    // must see it as soon as the claim commits. If it were written only when
    // the revision became current, the fold could compare against the
    // previous build and re-dirty the row the claim just cleared.
    let built_from_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    // Queued marks first, then the row: the same order as `fold_marks`, so
    // the two never wait on each other in a cycle.
    let consumed =
        sqlx::query("DELETE FROM rpm_repodata_dirty WHERE repository_id = $1 AND root = $2")
            .bind(repo_id)
            .bind(root)
            .execute(&mut *tx)
            .await;
    match consumed {
        Ok(_) => {}
        Err(e)
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "55P03" || c == "57014") =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }
    let revision: i64 = sqlx::query_scalar(
        "INSERT INTO rpm_repodata_roots \
             (repository_id, root, next_revision, retry_at, storage_backend, storage_path, \
              built_from_at) \
         VALUES ($1, $2, 1, now() + make_interval(secs => $5), $3, $4, $6) \
         ON CONFLICT (repository_id, root) DO UPDATE SET dirty_since = NULL, \
             retry_at = now() + make_interval(secs => $5), \
             next_revision = rpm_repodata_roots.next_revision + 1, \
             storage_backend = COALESCE(rpm_repodata_roots.storage_backend, $3), \
             storage_path = COALESCE(rpm_repodata_roots.storage_path, $4), \
             built_from_at = $6 \
         RETURNING next_revision",
    )
    .bind(repo_id)
    .bind(root)
    .bind(&location.backend)
    .bind(&location.path)
    .bind(settings.build_deadline.as_secs_f64())
    .bind(built_from_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(revision))
}

/// Set `dirty_since` when the live fingerprint of the root no longer matches
/// the one its current revision was built from.
async fn mark_dirty_if_moved(db: &PgPool, repo_id: Uuid, root: &str) -> Result<()> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE rpm_repodata_roots rr SET dirty_since = now() \
          WHERE rr.repository_id = $1 AND rr.root = $2 AND {MOVED_SQL}"
    )))
    .bind(repo_id)
    .bind(root)
    .execute(db)
    .await?;
    Ok(())
}

/// SQL predicate (over `rpm_repodata_roots rr`): a clean, built root whose
/// live `.rpm` count or latest `updated_at` differs from its build's.
/// `retry_at` excludes a root whose build is in flight (the claim sets it)
/// or already scheduled: its snapshot is not current yet, so "moved" only
/// means the build has not swapped (#5128).
const MOVED_SQL: &str = "rr.dirty_since IS NULL AND rr.retry_at IS NULL \
     AND rr.built_revision IS NOT NULL \
     AND (SELECT (COUNT(*), MAX(a.updated_at)) FROM artifacts a \
           WHERE a.repository_id = rr.repository_id AND a.is_deleted = false \
             AND a.path LIKE '%.rpm' \
             AND starts_with(a.path, CASE WHEN rr.root = '' THEN '' ELSE rr.root || '/' END)) \
         IS DISTINCT FROM (rr.built_count, rr.built_latest)";

/// SQL predicate (over `rpm_repodata_roots rr`): a clean root that has
/// never been built (or was dropped while empty) but lists packages, with no
/// build pending.
const UNBUILT_POPULATED_SQL: &str = "rr.dirty_since IS NULL AND rr.built_revision IS NULL \
     AND rr.retry_at IS NULL \
     AND EXISTS (SELECT 1 FROM artifacts a \
           WHERE a.repository_id = rr.repository_id AND a.is_deleted = false \
             AND a.path LIKE '%.rpm' \
             AND starts_with(a.path, CASE WHEN rr.root = '' THEN '' ELSE rr.root || '/' END))";

/// Mark dirty every clean built root whose packages moved without the
/// triggers marking it, and every unbuilt root that has packages. A safety
/// net: the fence and the claim deadline already cover the known races.
/// Returns the count.
pub async fn reconcile(db: &PgPool) -> Result<u64> {
    let moved = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE rpm_repodata_roots rr SET dirty_since = now() \
          WHERE ({MOVED_SQL}) OR ({UNBUILT_POPULATED_SQL})"
    )))
    .execute(db)
    .await?
    .rows_affected();
    if moved > 0 {
        debug!(moved, "RPM repodata reconcile marked roots dirty");
    }
    Ok(moved)
}

/// Delete one revision's objects. Best effort: an object already gone is
/// fine, and a failure only leaves an unreachable object behind.
async fn delete_revision(
    storage: &dyn crate::storage::StorageBackend,
    repo_id: Uuid,
    root: &str,
    revision: i64,
) {
    let prefix = revision_prefix(repo_id, root, revision);
    for file in crate::services::rpm_repodata_cache::STORED_REPODATA_FILES {
        match storage.delete(&format!("{prefix}/{file}")).await {
            Ok(()) | Err(AppError::NotFound(_)) => {}
            Err(e) => warn!(%repo_id, root, revision, error = %e, "RPM repodata GC: delete failed"),
        }
    }
}

/// Stop serving a stored revision of `root` and delete every revision. The
/// row stays (it keeps `next_revision`, so numbers are never reused) and
/// renders on request until the next build.
async fn drop_root(state: &SharedState, repo_id: Uuid, root: &str) -> Result<()> {
    let row: Option<(i64, i64, Option<String>, Option<String>)> = sqlx::query_as(
        "WITH old AS ( \
             SELECT repository_id, root, gc_floor FROM rpm_repodata_roots \
              WHERE repository_id = $1 AND root = $2 FOR UPDATE) \
         UPDATE rpm_repodata_roots rr SET built_revision = NULL, previous_revision = NULL, \
             built_repomd = NULL, built_sizes = NULL, built_count = NULL, built_latest = NULL, \
             retry_at = NULL, gc_floor = rr.next_revision + 1 \
           FROM old WHERE rr.repository_id = old.repository_id AND rr.root = old.root \
          RETURNING old.gc_floor, rr.next_revision, rr.storage_backend, rr.storage_path",
    )
    .bind(repo_id)
    .bind(root)
    .fetch_optional(&state.db)
    .await?;
    if let Some((old_floor, last, Some(backend), Some(path))) = row {
        if let Ok(storage) = state.storage_for_repo(&StorageLocation { backend, path }) {
            for revision in old_floor..=last {
                delete_revision(storage.as_ref(), repo_id, root, revision).await;
            }
        }
    }
    Ok(())
}

/// Delete the stored revisions of roots that are no longer precomputed: the
/// repository was deleted (its rows outlive it for this), opted out with
/// `repodata_mode: on_request`, or got an active publication. A deleted
/// repository's rows go as well; the others keep tracking dirtiness so a
/// switch back starts from a fresh build.
pub async fn collect_garbage(state: &SharedState) -> Result<u64> {
    let sql = format!(
        "SELECT rr.repository_id, rr.root, (r.id IS NULL) FROM rpm_repodata_roots rr \
           LEFT JOIN repositories r ON r.id = rr.repository_id \
          WHERE r.id IS NULL OR (rr.built_revision IS NOT NULL AND NOT ({PRECOMPUTED_REPO_SQL})) \
          LIMIT 64"
    );
    let rows: Vec<(Uuid, String, bool)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(&state.db)
        .await?;
    let mut collected = 0;
    for (repo_id, root, gone) in rows {
        let Some(lease) = PgAdvisoryLock::new(state.db.clone())
            .try_acquire(
                RPM_REPODATA_BUILD_LOCK_CLASS,
                lease_object_id(&lease_key(repo_id, &root)),
            )
            .await?
        else {
            continue;
        };
        // Recheck under the lease: the repository may have switched back to
        // precomputed and been built since the listing.
        let still: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS (SELECT 1 FROM rpm_repodata_roots rr \
               LEFT JOIN repositories r ON r.id = rr.repository_id \
              WHERE rr.repository_id = $1 AND rr.root = $2 \
                AND (r.id IS NULL OR NOT ({PRECOMPUTED_REPO_SQL})))"
        )))
        .bind(repo_id)
        .bind(&root)
        .fetch_one(&state.db)
        .await?;
        if !still {
            lease.release().await;
            continue;
        }
        let result = drop_root(state, repo_id, &root).await;
        if gone && result.is_ok() {
            let _ = sqlx::query(
                "DELETE FROM rpm_repodata_roots WHERE repository_id = $1 AND root = $2",
            )
            .bind(repo_id)
            .bind(&root)
            .execute(&state.db)
            .await;
        }
        lease.release().await;
        result?;
        collected += 1;
    }
    Ok(collected)
}

/// The revision `root` of `repo_id` serves, when the repository is
/// precomputed and the root has been built.
pub async fn stored_revision(
    db: &PgPool,
    repo_id: Uuid,
    root: &str,
) -> Result<Option<StoredRepodata>> {
    let sql = format!(
        "SELECT rr.built_revision, rr.built_repomd, rr.built_sizes, \
                rr.storage_backend, rr.storage_path \
           FROM rpm_repodata_roots rr JOIN repositories r ON r.id = rr.repository_id \
          WHERE rr.repository_id = $1 AND rr.root = $2 AND rr.built_revision IS NOT NULL \
            AND {PRECOMPUTED_REPO_SQL}"
    );
    type Row = (
        i64,
        Option<Vec<u8>>,
        Option<serde_json::Value>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo_id)
        .bind(root)
        .fetch_optional(db)
        .await?;
    let Some((revision, Some(repomd), sizes, Some(backend), Some(path))) = row else {
        return Ok(None);
    };
    let sizes: HashMap<String, u64> = sizes
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    Ok(Some(StoredRepodata {
        revision,
        repomd_xml: Bytes::from(repomd),
        location: StorageLocation { backend, path },
        key_prefix: revision_prefix(repo_id, root, revision),
        sizes,
    }))
}

/// Mark `root` dirty (a stored document was unreadable): the next tick
/// rebuilds it.
pub async fn mark_dirty(db: &PgPool, repo_id: Uuid, root: &str) -> Result<()> {
    sqlx::query(
        "UPDATE rpm_repodata_roots SET dirty_since = COALESCE(dirty_since, now()) \
          WHERE repository_id = $1 AND root = $2",
    )
    .bind(repo_id)
    .bind(root)
    .execute(db)
    .await?;
    Ok(())
}

/// Why a `repodata_mode` cannot be set on a repository.
pub const MODE_UNSUPPORTED: &str = "repodata_mode applies to hosted (local) RPM repositories only";

/// Store `mode` for `repo_id` on the writer's connection. `precomputed`, the
/// default, is stored as the absence of the key. Switching to `on_request`
/// takes effect on the next request; the builder's maintenance pass then
/// deletes the stored revisions.
pub async fn set_mode(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    mode: RepodataMode,
) -> Result<()> {
    match mode {
        RepodataMode::Precomputed => {
            let switched =
                sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key = $2")
                    .bind(repo_id)
                    .bind(MODE_KEY)
                    .execute(&mut *conn)
                    .await?
                    .rows_affected();
            if switched == 0 {
                return Ok(());
            }
            // Build afresh: a revision built before an opt-out is stale.
            // Append marks rather than update the roots: this runs inside the
            // caller's repository transaction, which must not hold root row
            // locks the builder's fold takes in another order.
            sqlx::query(
                "INSERT INTO rpm_repodata_dirty (repository_id, root) \
                 SELECT repository_id, root FROM rpm_repodata_roots WHERE repository_id = $1",
            )
            .bind(repo_id)
            .execute(&mut *conn)
            .await?;
        }
        RepodataMode::OnRequest => {
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (repository_id, key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(repo_id)
            .bind(MODE_KEY)
            .bind(mode.as_str())
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// The modes of the hosted RPM repositories among `ids` (other repositories
/// are absent from the map).
pub async fn modes(db: &PgPool, ids: &[Uuid]) -> Result<HashMap<Uuid, RepodataMode>> {
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT r.id, c.value FROM repositories r \
           LEFT JOIN repository_config c ON c.repository_id = r.id AND c.key = 'repodata_mode' \
          WHERE r.id = ANY($1) AND r.format = 'rpm' AND r.repo_type = 'local'",
    )
    .bind(ids)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, value)| {
            (
                id,
                value
                    .as_deref()
                    .and_then(RepodataMode::parse)
                    .unwrap_or_default(),
            )
        })
        .collect())
}

/// Whether a rebuild may name `root` of `repo_id`: it lists a package, or
/// it is already tracked (it had packages, so a build that empties it must
/// be possible). A made-up root is neither.
pub async fn root_is_known(db: &PgPool, repo_id: Uuid, root: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM rpm_repodata_roots \
                         WHERE repository_id = $1 AND root = $3) \
             OR EXISTS (SELECT 1 FROM artifacts a \
          WHERE a.repository_id = $1 AND a.is_deleted = false AND a.path LIKE '%.rpm' \
            AND starts_with(a.path, $2))",
    )
    .bind(repo_id)
    .bind(root_prefix(root))
    .bind(root)
    .fetch_one(db)
    .await?)
}

/// Deserialize a present `repodata_mode`, refusing `null` (omit the field to
/// keep the current mode).
pub fn deserialize_mode<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<RepodataMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <RepodataMode as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// The repository's repodata mode (`repodata_mode` in `repository_config`;
/// absent means [`RepodataMode::Precomputed`]).
pub async fn mode(db: &PgPool, repo_id: Uuid) -> Result<RepodataMode> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(MODE_KEY)
    .fetch_optional(db)
    .await?;
    Ok(value
        .as_deref()
        .and_then(RepodataMode::parse)
        .unwrap_or_default())
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests;
