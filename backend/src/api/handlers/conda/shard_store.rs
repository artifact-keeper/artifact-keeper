//! Write-time CEP-16 shards and per-subdir revisions of hosted conda
//! channels (#4173, #4174).
//!
//! The tables (migration `conda_shard_index`) hold, per `(repository,
//! subdir)`, one encoded shard per package name and a revision counter. The
//! catalog triggers put every `(repository, subdir, name)` a write touches
//! into `conda_shard_dirty` in the writer's own transaction, whichever code
//! path writes (an upload here, a generic delete, a scanner verdict, the
//! quarantine console). Marks are append-only (#4978): each is a new row
//! with its own sequence value, so writers never lock a shared key and two
//! writers marking the same names in different orders cannot deadlock.
//! This module turns dirty keys back into shards:
//!
//! * [`materialise`] rebuilds the dirty keys of a repository (or one subdir
//!   of it) in bounded batches, each batch one transaction under a
//!   per-repository advisory lock: it reads only the rows of the dirty names,
//!   rewrites only the shards whose bytes changed, deletes the marks it saw
//!   (a mark added meanwhile survives), bumps the revision of every
//!   subdir it touched and announces the change on the conda invalidation
//!   channel. The conda write paths call it right after their write; every
//!   reader calls it, through [`subdir_state`], before it serves, so nothing
//!   built from an older catalog state is ever served after the catalog moved.
//! * A hold that lapses (`quarantine_until` passes) makes a package visible
//!   with no write. `conda_channel_state.next_hold_expiry` keeps the earliest
//!   pending expiry; the first read after it marks the lapsed rows dirty.
//!   Visibility is always decided against the database clock, the same
//!   instant the expiry check uses, so an application clock behind the
//!   database can never strand a lapsed hold.
//! * [`run_backfill`] fills the tables for repositories that held packages
//!   before the migration: batches of [`BACKFILL_BATCH_NAMES`] names in name
//!   order, the cursor saved with each batch, so it is bounded per
//!   transaction and resumes where it stopped. Until a repository's backfill
//!   finishes its shard endpoints keep the per-request walk.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    artifacts_for_subdir, build_shard, encode_shard, group_artifacts_by_name, is_conda_package,
    is_withdrawn, shard_address, CondaArtifact, CondaArtifactRow,
};

/// Advisory-lock class (`classid`) of the per-repository materialisation
/// lock. Two-argument advisory locks live in their own key space, apart from
/// the proxy-hydration class `0x1609`.
const MATERIALISE_LOCK_CLASS: i32 = 0x4173;

/// Dirty keys rebuilt per transaction. Bounds the rows read and the shards
/// encoded while the repository's materialisation lock is held.
const MATERIALISE_BATCH_KEYS: i64 = 256;

/// Package names per backfill transaction (#4173). A name is usually a
/// handful of rows, so a batch reads a few thousand rows and encodes 500
/// small shards: well under a second on the reference host, short enough
/// that a writer waiting on the lock is not held up for long.
pub(crate) const BACKFILL_BATCH_NAMES: i64 = 500;

/// Pause between backfill batches, so a large channel's backfill does not
/// hold a database connection busy back to back.
const BACKFILL_BATCH_PAUSE: Duration = Duration::from_millis(50);

/// How long the backfill loop waits before retrying a repository it could
/// not finish (locked by another replica, or a database error).
const BACKFILL_RETRY: Duration = Duration::from_secs(30);

/// Upper bound on materialise passes one read makes before it gives up and
/// answers 503: a channel receiving writes faster than they can be rebuilt.
const MAX_READ_PASSES: usize = 64;

/// The state of one hosted subdir after its dirty keys were rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubdirState {
    /// Bumped by every rebuild of the subdir; 0 for a subdir never built.
    pub revision: i64,
    /// Whether the repository's stored shards are complete (backfill done).
    pub backfilled: bool,
    /// The database clock at the check: visibility for this state is
    /// decided at this instant.
    pub now: DateTime<Utc>,
}

/// The state of a whole hosted repository after its dirty keys were rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RepoState {
    /// Sum of the repository's subdir revisions. Every rebuild raises it.
    pub revision: i64,
    pub backfilled: bool,
    pub now: DateTime<Utc>,
}

fn db_unavailable(context: &str, e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "conda shard store: {context}");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

/// Longest a reader waits for a rebuild of its repository that another
/// session is running before it answers 503 (#4978 item 5).
const READER_WAIT: Duration = Duration::from_secs(10);
/// First and longest pause between a waiting reader's looks at the state.
const READER_POLL_MIN: Duration = Duration::from_millis(10);
const READER_POLL_MAX: Duration = Duration::from_millis(200);
/// Stripes of the per-process reader turn ([`reader_turn`]).
const READER_TURN_STRIPES: usize = 64;

/// The turn a reader of `repo_id` takes before it rebuilds dirty keys
/// (#4978 item 5): one reader per repository (stripe) per process rebuilds,
/// the others wait here holding no database connection, then find the state
/// clean. Across processes the rebuild lock is only ever TRIED by a reader,
/// so a reader never holds a pooled connection while it waits for a rebuild
/// another session runs either.
fn reader_turn(repo_id: Uuid) -> &'static tokio::sync::Mutex<()> {
    static TURNS: std::sync::OnceLock<Vec<tokio::sync::Mutex<()>>> = std::sync::OnceLock::new();
    let turns = TURNS.get_or_init(|| {
        (0..READER_TURN_STRIPES)
            .map(|_| tokio::sync::Mutex::new(()))
            .collect()
    });
    let stripe = repo_id.as_u128() as usize % READER_TURN_STRIPES;
    &turns[stripe]
}

/// One look at a scope's state: `(revision, dirty, expired, backfilled,
/// now)`.
type StateRow = (i64, bool, bool, bool, DateTime<Utc>);

/// Read the state of `(repo_id, subdir)`, or of the whole repository when
/// `subdir` is `None` (the sum of its subdir revisions).
async fn read_state(
    db: &PgPool,
    repo_id: Uuid,
    subdir: Option<&str>,
) -> Result<StateRow, Response> {
    let row = match subdir {
        Some(subdir) => sqlx::query(
            "SELECT \
               COALESCE((SELECT revision FROM conda_subdir_revisions \
                          WHERE repository_id = $1 AND subdir = $2), 0) AS revision, \
               EXISTS (SELECT 1 FROM conda_shard_dirty \
                        WHERE repository_id = $1 AND subdir = $2) AS dirty, \
               COALESCE((SELECT next_hold_expiry <= NOW() FROM conda_channel_state \
                          WHERE repository_id = $1), false) AS expired, \
               COALESCE((SELECT backfill_done_at IS NOT NULL FROM conda_channel_state \
                          WHERE repository_id = $1), true) AS backfilled, \
               NOW() AS now",
        )
        .bind(repo_id)
        .bind(subdir),
        None => sqlx::query(
            "SELECT \
               COALESCE((SELECT SUM(revision) FROM conda_subdir_revisions \
                          WHERE repository_id = $1), 0)::BIGINT AS revision, \
               EXISTS (SELECT 1 FROM conda_shard_dirty WHERE repository_id = $1) AS dirty, \
               COALESCE((SELECT next_hold_expiry <= NOW() FROM conda_channel_state \
                          WHERE repository_id = $1), false) AS expired, \
               COALESCE((SELECT backfill_done_at IS NOT NULL FROM conda_channel_state \
                          WHERE repository_id = $1), true) AS backfilled, \
               NOW() AS now",
        )
        .bind(repo_id),
    }
    .fetch_one(db)
    .await
    .map_err(|e| db_unavailable("reading conda channel state", e))?;
    Ok((
        row.get("revision"),
        row.get("dirty"),
        row.get("expired"),
        row.get("backfilled"),
        row.get("now"),
    ))
}

/// Rebuild what is dirty in the scope (`subdir`, or the whole repository)
/// and return its clean state: `(revision, backfilled, now)`.
///
/// A reader holds a pooled connection only for its own statements, never
/// while it waits for a rebuild (#4978 item 5): it waits for its turn in this
/// process ([`reader_turn`]) with no connection, and it only TRIES the
/// repository's rebuild lock, so when another session holds it the reader
/// gives the connection back, pauses and looks again. It answers 503 after
/// [`READER_WAIT`] or [`MAX_READ_PASSES`] rebuilds of its own.
async fn clean_state(
    db: &PgPool,
    repo_id: Uuid,
    subdir: Option<&str>,
) -> Result<(i64, bool, DateTime<Utc>), Response> {
    let deadline = tokio::time::Instant::now() + READER_WAIT;
    let mut passes = 0;
    let mut pause = READER_POLL_MIN;
    loop {
        let (revision, dirty, expired, backfilled, now) = read_state(db, repo_id, subdir).await?;
        if !dirty && !expired {
            return Ok((revision, backfilled, now));
        }
        let Ok(turn) = tokio::time::timeout_at(deadline, reader_turn(repo_id).lock()).await else {
            return Err(busy());
        };
        // Another reader of this process may have rebuilt it meanwhile.
        let (revision, dirty, expired, backfilled, now) = read_state(db, repo_id, subdir).await?;
        if !dirty && !expired {
            return Ok((revision, backfilled, now));
        }
        let mut done = true;
        if expired {
            done = mark_lapsed_holds(db, repo_id, false)
                .await
                .map_err(|e| db_unavailable("marking lapsed holds", e))?;
        }
        if done {
            done = materialise_with(db, repo_id, subdir, false)
                .await
                .map_err(|e| db_unavailable("rebuilding shards", e))?
                .is_some();
        }
        drop(turn);
        if done {
            passes += 1;
            if passes >= MAX_READ_PASSES {
                return Err(busy());
            }
            continue;
        }
        // Another session holds the rebuild lock: look again shortly.
        if tokio::time::Instant::now() + pause > deadline {
            return Err(busy());
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(READER_POLL_MAX);
    }
}

/// Rebuild what is dirty in `(repo_id, subdir)` and return its state.
pub(crate) async fn subdir_state(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
) -> Result<SubdirState, Response> {
    let (revision, backfilled, now) = clean_state(db, repo_id, Some(subdir)).await?;
    Ok(SubdirState {
        revision,
        backfilled,
        now,
    })
}

/// Rebuild everything dirty in `repo_id` and return its state.
pub(crate) async fn repo_state(db: &PgPool, repo_id: Uuid) -> Result<RepoState, Response> {
    let (revision, backfilled, now) = clean_state(db, repo_id, None).await?;
    Ok(RepoState {
        revision,
        backfilled,
        now,
    })
}

fn busy() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        "Conda channel metadata is being rebuilt; retry shortly",
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("1"),
    );
    response
}

/// Take the per-repository materialisation lock for the rest of `tx`.
async fn lock_repo(tx: &mut Transaction<'_, Postgres>, repo_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(MATERIALISE_LOCK_CLASS)
        .bind(crate::services::cluster_lock::lease_object_id(
            &repo_id.to_string(),
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// [`lock_repo`] without waiting: `false` when another session holds it.
async fn try_lock_repo(tx: &mut Transaction<'_, Postgres>, repo_id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(MATERIALISE_LOCK_CLASS)
        .bind(crate::services::cluster_lock::lease_object_id(
            &repo_id.to_string(),
        ))
        .fetch_one(&mut **tx)
        .await
}

/// Mark the rows whose hold lapsed since the last check, and record the next
/// pending expiry. With `wait` false, `Ok(false)` when another session holds
/// the repository's rebuild lock (nothing is done).
async fn mark_lapsed_holds(db: &PgPool, repo_id: Uuid, wait: bool) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    if !take_lock(&mut tx, repo_id, wait).await? {
        tx.rollback().await?;
        return Ok(false);
    }
    let since: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT next_hold_expiry FROM conda_channel_state \
          WHERE repository_id = $1 AND next_hold_expiry <= NOW()",
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    if let Some(since) = since {
        sqlx::query(
            "SELECT conda_mark_artifact_dirty(a.repository_id, a.id, a.path, a.name) \
               FROM artifacts a \
              WHERE a.repository_id = $1 AND a.is_deleted = false \
                AND a.quarantine_status = 'quarantined' \
                AND a.quarantine_until >= $2 AND a.quarantine_until <= NOW()",
        )
        .bind(repo_id)
        .bind(since)
        .execute(&mut *tx)
        .await?;
        refresh_next_hold_expiry(&mut tx, repo_id).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// [`lock_repo`] when `wait`, else [`try_lock_repo`].
async fn take_lock(
    tx: &mut Transaction<'_, Postgres>,
    repo_id: Uuid,
    wait: bool,
) -> sqlx::Result<bool> {
    if wait {
        lock_repo(tx, repo_id).await?;
        Ok(true)
    } else {
        try_lock_repo(tx, repo_id).await
    }
}

/// Store the earliest pending hold expiry of `repo_id`.
async fn refresh_next_hold_expiry(
    tx: &mut Transaction<'_, Postgres>,
    repo_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO conda_channel_state (repository_id, backfill_done_at, next_hold_expiry) \
         VALUES ($1, NOW(), (SELECT MIN(a.quarantine_until) FROM artifacts a \
                              WHERE a.repository_id = $1 AND a.is_deleted = false \
                                AND a.quarantine_status = 'quarantined' \
                                AND a.quarantine_until > NOW())) \
         ON CONFLICT (repository_id) DO UPDATE \
            SET next_hold_expiry = EXCLUDED.next_hold_expiry, updated_at = NOW()",
    )
    .bind(repo_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `(subdir, package name)`.
type ShardKey = (String, String);

/// A dirty key as read: `(subdir, package name, mark)`.
type DirtyKey = (String, String, i64);

/// Rebuild the dirty keys of `repo_id` (only those of `subdir` when given)
/// until none is left. Returns the number of keys rebuilt.
pub(crate) async fn materialise(
    db: &PgPool,
    repo_id: Uuid,
    subdir: Option<&str>,
) -> sqlx::Result<usize> {
    Ok(materialise_with(db, repo_id, subdir, true)
        .await?
        .unwrap_or_default())
}

/// [`materialise`]; with `wait` false the rebuild lock is only tried, and
/// `Ok(None)` means another session held it before anything was rebuilt (a
/// batch already rebuilt is kept and its count returned).
async fn materialise_with(
    db: &PgPool,
    repo_id: Uuid,
    subdir: Option<&str>,
    wait: bool,
) -> sqlx::Result<Option<usize>> {
    let mut total = 0;
    let mut batches = 0;
    loop {
        let mut tx = db.begin().await?;
        if !take_lock(&mut tx, repo_id, wait).await? {
            tx.rollback().await?;
            return Ok((batches > 0).then_some(total));
        }
        // Every mark of the first `MATERIALISE_BATCH_KEYS` keys: marks are
        // append-only (#4978), so a key can carry several.
        let dirty: Vec<DirtyKey> = sqlx::query_as(
            "SELECT d.subdir, d.package_name, d.mark FROM conda_shard_dirty d \
               JOIN (SELECT subdir, package_name FROM conda_shard_dirty \
                      WHERE repository_id = $1 AND ($2::TEXT IS NULL OR subdir = $2) \
                      GROUP BY subdir, package_name \
                      ORDER BY subdir, package_name LIMIT $3) k \
                 USING (subdir, package_name) \
              WHERE d.repository_id = $1 \
              ORDER BY d.subdir, d.package_name, d.mark",
        )
        .bind(repo_id)
        .bind(subdir)
        .bind(MATERIALISE_BATCH_KEYS)
        .fetch_all(&mut *tx)
        .await?;
        if dirty.is_empty() {
            tx.commit().await?;
            return Ok(Some(total));
        }
        total += dirty.len();
        batches += 1;
        rebuild_keys(&mut tx, repo_id, &dirty).await?;
        tx.commit().await?;
    }
}

/// Rebuild `keys` inside `tx` (which holds the repository lock): rewrite the
/// shards whose bytes changed, drop the marks seen, bump the touched
/// subdirs' revisions, refresh the hold expiry and announce the change.
async fn rebuild_keys(
    tx: &mut Transaction<'_, Postgres>,
    repo_id: Uuid,
    keys: &[DirtyKey],
) -> sqlx::Result<()> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&mut **tx)
        .await?;
    let names: Vec<String> = keys
        .iter()
        .map(|(_, name, _)| name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let rows = rows_for_names(tx, repo_id, &names).await?;
    let built = build_key_shards(&rows, keys, now);

    for (subdir, name) in built.removed {
        sqlx::query(
            "DELETE FROM conda_shard_index \
              WHERE repository_id = $1 AND subdir = $2 AND package_name = $3",
        )
        .bind(repo_id)
        .bind(subdir)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    }
    for ((subdir, name), shard) in built.present {
        let hash = shard.as_ref().map(|s| shard_address(s).to_vec());
        // Rewrites only a shard whose bytes changed (#4173: one upload
        // rewrites exactly one shard and one index row).
        sqlx::query(
            "INSERT INTO conda_shard_index \
                 (repository_id, subdir, package_name, shard_hash, shard, origin) \
             VALUES ($1, $2, $3, $4, $5, 'hosted') \
             ON CONFLICT (repository_id, subdir, package_name) DO UPDATE \
                SET shard_hash = EXCLUDED.shard_hash, shard = EXCLUDED.shard, \
                    origin = 'hosted', updated_at = NOW() \
              WHERE conda_shard_index.shard_hash IS DISTINCT FROM EXCLUDED.shard_hash",
        )
        .bind(repo_id)
        .bind(&subdir)
        .bind(&name)
        .bind(hash)
        .bind(shard)
        .execute(&mut **tx)
        .await?;
    }

    let subdirs: Vec<&str> = keys.iter().map(|(s, _, _)| s.as_str()).collect();
    let key_names: Vec<&str> = keys.iter().map(|(_, n, _)| n.as_str()).collect();
    let marks: Vec<i64> = keys.iter().map(|(_, _, m)| *m).collect();
    sqlx::query(
        "DELETE FROM conda_shard_dirty d \
          USING UNNEST($2::TEXT[], $3::TEXT[], $4::BIGINT[]) AS seen(subdir, package_name, mark) \
          WHERE d.repository_id = $1 AND d.subdir = seen.subdir \
            AND d.package_name = seen.package_name AND d.mark = seen.mark",
    )
    .bind(repo_id)
    .bind(&subdirs)
    .bind(&key_names)
    .bind(&marks)
    .execute(&mut **tx)
    .await?;

    let touched: Vec<String> = keys
        .iter()
        .map(|(s, _, _)| s.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // Always bump, even when no shard changed: `repodata.json`'s `removed`
    // array also moves with deletes of rows that were already withdrawn.
    sqlx::query(
        "INSERT INTO conda_subdir_revisions (repository_id, subdir, revision) \
         SELECT $1, s, 1 FROM UNNEST($2::TEXT[]) AS s \
         ON CONFLICT (repository_id, subdir) DO UPDATE \
            SET revision = conda_subdir_revisions.revision + 1, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(&touched)
    .execute(&mut **tx)
    .await?;
    refresh_next_hold_expiry(tx, repo_id).await?;

    let payload =
        crate::services::cache_invalidation::conda_repodata_invalidation_payload(repo_id, &touched);
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(crate::services::cache_invalidation::CONDA_REPODATA_INVALIDATION_CHANNEL)
        .bind(payload)
        .execute(&mut **tx)
        .await?;
    super::repodata_cache::invalidate_local(repo_id, &touched).await;
    Ok(())
}

/// Live rows (any visibility) of `repo_id` that can belong to the shard of
/// one of the package names `names` (as the keys spell them), newest first.
///
/// A row belongs to the shard its METADATA name names
/// ([`super::group_artifacts_by_name`]), which is not always its
/// `artifacts.name` (#4978 item 3): the upload route writes them equal, but
/// any other writer may not. So a row is read when either its row name
/// matches case-insensitively (the `LOWER(name)` index) or its metadata
/// `name` is exactly one of `names` (the metadata GIN index, `@>`).
async fn rows_for_names(
    tx: &mut Transaction<'_, Postgres>,
    repo_id: Uuid,
    names: &[String],
) -> sqlx::Result<Vec<CondaArtifactRow>> {
    let lowered: Vec<String> = names
        .iter()
        .map(|n| n.to_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let by_metadata: Vec<serde_json::Value> = names
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|n| serde_json::json!({ "name": n }))
        .collect();
    sqlx::query_as::<_, CondaArtifactRow>(
        "SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                a.storage_key, am.metadata, a.quarantine_status, a.quarantine_until, \
                a.created_at \
           FROM artifacts a \
           LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
          WHERE a.id IN ( \
                  SELECT n.id FROM artifacts n \
                   WHERE n.repository_id = $1 AND n.is_deleted = false \
                     AND LOWER(n.name) = ANY($2) \
                  UNION \
                  SELECT m.artifact_id \
                    FROM UNNEST($3::JSONB[]) AS q(doc) \
                    JOIN artifact_metadata m ON m.metadata @> q.doc \
                    JOIN artifacts r ON r.id = m.artifact_id \
                   WHERE r.repository_id = $1 AND r.is_deleted = false) \
          ORDER BY a.created_at DESC",
    )
    .bind(repo_id)
    .bind(&lowered)
    .bind(&by_metadata)
    .fetch_all(&mut **tx)
    .await
}

/// What a rebuild writes: per key either a shard (`None` when the name has
/// live rows but none visible) or removal of the index row.
#[derive(Default)]
struct BuiltKeys {
    present: Vec<(ShardKey, Option<Vec<u8>>)>,
    removed: Vec<ShardKey>,
}

/// Build the shard of every key in `keys` from `rows`, the live rows of the
/// keys' names, deciding visibility at `now`. A row belongs to a key by the
/// rules of [`artifacts_for_subdir`] and [`group_artifacts_by_name`], so the
/// shard is byte-identical to the one the per-request walk builds.
fn build_key_shards(rows: &[CondaArtifactRow], keys: &[DirtyKey], now: DateTime<Utc>) -> BuiltKeys {
    let wanted: BTreeSet<(&str, &str)> = keys
        .iter()
        .map(|(s, n, _)| (s.as_str(), n.as_str()))
        .collect();
    let all: Vec<CondaArtifact> = rows.iter().map(row_to_artifact).collect();
    let visible: HashSet<uuid::Uuid> = rows
        .iter()
        .filter(|r| !is_withdrawn(r.quarantine_status.as_deref(), r.quarantine_until, now))
        .map(|r| r.id)
        .collect();
    let mut out = BuiltKeys::default();
    let subdirs: BTreeSet<&str> = wanted.iter().map(|(s, _)| *s).collect();
    for subdir in subdirs {
        let in_subdir = artifacts_for_subdir(&all, subdir);
        // First row per filename wins (newest first), as the per-request
        // walk deduplicates.
        let mut seen = HashSet::new();
        let packages: Vec<&CondaArtifact> = in_subdir
            .into_iter()
            .filter(|a| {
                let filename = a.path.rsplit('/').next().unwrap_or(&a.path);
                is_conda_package(filename) && seen.insert(filename.to_string())
            })
            .collect();
        let live = group_artifacts_by_name(&packages);
        for (key_subdir, name) in wanted.iter().filter(|(s, _)| *s == subdir) {
            match live.get(*name) {
                None => out.removed.push((key_subdir.to_string(), name.to_string())),
                Some(artifacts) => {
                    let shown: Vec<&CondaArtifact> = artifacts
                        .iter()
                        .copied()
                        .filter(|a| visible.contains(&a.id))
                        .collect();
                    let shard = if shown.is_empty() {
                        None
                    } else {
                        // Encoding a shard built from stored rows cannot
                        // fail (msgpack into memory, then zstd); a failure
                        // keeps the name out of the index rather than
                        // serving a broken shard.
                        encode_shard(&build_shard(subdir, &shown)).ok()
                    };
                    out.present
                        .push(((key_subdir.to_string(), name.to_string()), shard));
                }
            }
        }
    }
    out
}

fn row_to_artifact(r: &CondaArtifactRow) -> CondaArtifact {
    CondaArtifact {
        id: r.id,
        path: r.path.clone(),
        name: r.name.clone(),
        version: r.version.clone(),
        size_bytes: r.size_bytes,
        checksum_sha256: r.checksum_sha256.clone(),
        storage_key: r.storage_key.clone(),
        metadata: r.metadata.clone(),
        indexed_at: Some(r.created_at),
    }
}

/// The stored shard index of `(repo_id, subdir)`: package name to address.
pub(crate) async fn stored_index(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
) -> Result<BTreeMap<String, Vec<u8>>, Response> {
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT package_name, shard_hash FROM conda_shard_index \
          WHERE repository_id = $1 AND subdir = $2 AND shard_hash IS NOT NULL",
    )
    .bind(repo_id)
    .bind(subdir)
    .fetch_all(db)
    .await
    .map_err(|e| db_unavailable("reading the shard index", e))?;
    Ok(rows.into_iter().collect())
}

/// The stored shard at `address` in `(repo_id, subdir)`, if it is listed.
/// The bytes are checked against the address before they are returned
/// (#4829): a stored row that does not hash to its address is never served.
pub(crate) async fn stored_shard(
    db: &PgPool,
    repo_id: Uuid,
    subdir: &str,
    address: &[u8],
) -> Result<Option<Vec<u8>>, Response> {
    let shard: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT shard FROM conda_shard_index \
          WHERE repository_id = $1 AND subdir = $2 AND shard_hash = $3 LIMIT 1",
    )
    .bind(repo_id)
    .bind(subdir)
    .bind(address)
    .fetch_optional(db)
    .await
    .map_err(|e| db_unavailable("reading a shard", e))?
    .flatten();
    match shard {
        Some(bytes) if shard_address(&bytes).as_slice() == address => Ok(Some(bytes)),
        Some(_) => {
            tracing::error!(
                repo_id = %repo_id,
                subdir,
                address = %hex::encode(address),
                "stored conda shard does not hash to its address; refusing to serve it"
            );
            Ok(None)
        }
        None => Ok(None),
    }
}

/// Backfill one batch of `repo_id`: `Ok(Some(true))` when the repository
/// is done, `Ok(Some(false))` when more batches follow, `Ok(None)` when
/// another session holds the repository's lock.
pub(crate) async fn backfill_batch(db: &PgPool, repo_id: Uuid) -> sqlx::Result<Option<bool>> {
    backfill_batch_sized(db, repo_id, BACKFILL_BATCH_NAMES).await
}

/// [`backfill_batch`] with `batch_names` names per batch.
pub(crate) async fn backfill_batch_sized(
    db: &PgPool,
    repo_id: Uuid,
    batch_names: i64,
) -> sqlx::Result<Option<bool>> {
    let mut tx = db.begin().await?;
    if !try_lock_repo(&mut tx, repo_id).await? {
        return Ok(None);
    }
    let cursor: Option<Option<String>> = sqlx::query_scalar(
        "SELECT backfill_cursor FROM conda_channel_state \
          WHERE repository_id = $1 AND backfill_done_at IS NULL",
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(cursor) = cursor else {
        tx.commit().await?;
        return Ok(Some(true));
    };
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT LOWER(name) AS n FROM artifacts \
          WHERE repository_id = $1 AND is_deleted = false AND LOWER(name) > $2 \
          ORDER BY n LIMIT $3",
    )
    .bind(repo_id)
    .bind(cursor.as_deref().unwrap_or(""))
    .bind(batch_names)
    .fetch_all(&mut *tx)
    .await?;
    let Some(last) = names.last().cloned() else {
        // Every subdir any row (deleted ones included) names gets a revision,
        // so for a backfilled repository revision 0 means "no row ever named
        // this subdir", the same as for one created after the migration.
        sqlx::query(
            "INSERT INTO conda_subdir_revisions (repository_id, subdir, revision) \
             SELECT DISTINCT $1::UUID, s, 1 FROM ( \
               SELECT COALESCE( \
                        CASE WHEN jsonb_typeof(am.metadata -> 'subdir') = 'string' \
                             THEN am.metadata ->> 'subdir' END, \
                        CASE WHEN position('/' IN a.path) > 0 \
                             THEN split_part(a.path, '/', 1) END) AS s \
                 FROM artifacts a \
                 LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
                WHERE a.repository_id = $1) named \
              WHERE s IS NOT NULL \
             ON CONFLICT (repository_id, subdir) DO UPDATE \
                SET revision = conda_subdir_revisions.revision + 1, updated_at = NOW()",
        )
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE conda_channel_state SET backfill_done_at = NOW(), updated_at = NOW() \
              WHERE repository_id = $1",
        )
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        tracing::info!(repo_id = %repo_id, "conda shard backfill finished");
        return Ok(Some(true));
    };
    // Mark every key the batch's rows contribute to, exactly as the
    // triggers would, then rebuild those keys in the same transaction.
    sqlx::query(
        "SELECT conda_mark_artifact_dirty(a.repository_id, a.id, a.path, a.name) \
           FROM artifacts a \
          WHERE a.repository_id = $1 AND a.is_deleted = false AND LOWER(a.name) = ANY($2)",
    )
    .bind(repo_id)
    .bind(&names)
    .execute(&mut *tx)
    .await?;
    let dirty: Vec<DirtyKey> = sqlx::query_as(
        "SELECT subdir, package_name, mark FROM conda_shard_dirty \
          WHERE repository_id = $1 AND LOWER(package_name) = ANY($2)",
    )
    .bind(repo_id)
    .bind(&names)
    .fetch_all(&mut *tx)
    .await?;
    if !dirty.is_empty() {
        rebuild_keys(&mut tx, repo_id, &dirty).await?;
    }
    sqlx::query(
        "UPDATE conda_channel_state SET backfill_cursor = $2, updated_at = NOW() \
          WHERE repository_id = $1",
    )
    .bind(repo_id)
    .bind(&last)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(false))
}

/// Backfill every repository that still needs it, batch by batch. Returns the
/// number of repositories left unfinished (locked elsewhere or failed).
pub(crate) async fn backfill_pass(db: &PgPool) -> usize {
    let pending: Vec<Uuid> = match sqlx::query_scalar(
        "SELECT repository_id FROM conda_channel_state WHERE backfill_done_at IS NULL",
    )
    .fetch_all(db)
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(error = %e, "conda shard backfill: listing repositories failed");
            return 1;
        }
    };
    let mut unfinished = 0;
    for repo_id in pending {
        loop {
            match backfill_batch(db, repo_id).await {
                Ok(Some(true)) => break,
                Ok(Some(false)) => tokio::time::sleep(BACKFILL_BATCH_PAUSE).await,
                Ok(None) => {
                    unfinished += 1;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        repo_id = %repo_id,
                        error = %e,
                        "conda shard backfill batch failed; it resumes from its cursor"
                    );
                    unfinished += 1;
                    break;
                }
            }
        }
    }
    unfinished
}

/// Run [`backfill_pass`] until nothing is left (#4173). Spawned once at
/// startup; a repository another replica is backfilling is retried later.
pub fn spawn_backfill(db: PgPool, shutdown: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        loop {
            let left = tokio::select! {
                left = backfill_pass(&db) => left,
                _ = shutdown.cancelled() => return,
            };
            if left == 0 {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(BACKFILL_RETRY) => {}
                _ = shutdown.cancelled() => return,
            }
        }
    });
}

/// The stored shards of several hosted repositories (the hosted members of a
/// virtual, in priority order) for `subdir`: name to `(member position,
/// address)` for a name only one member lists, and the names more than one
/// lists, whose shard the caller merges from rows.
pub(crate) struct MemberIndexes {
    pub single: BTreeMap<String, (usize, Vec<u8>)>,
    pub shared: BTreeSet<String>,
}

pub(crate) async fn member_indexes(
    db: &PgPool,
    repo_ids: &[Uuid],
    subdir: &str,
) -> Result<MemberIndexes, Response> {
    let mut by_name: HashMap<String, Vec<(usize, Vec<u8>)>> = HashMap::new();
    for (position, repo_id) in repo_ids.iter().enumerate() {
        for (name, hash) in stored_index(db, *repo_id, subdir).await? {
            by_name.entry(name).or_default().push((position, hash));
        }
    }
    let mut out = MemberIndexes {
        single: BTreeMap::new(),
        shared: BTreeSet::new(),
    };
    for (name, mut listed) in by_name {
        if listed.len() == 1 {
            out.single.insert(name, listed.remove(0));
        } else {
            out.shared.insert(name);
        }
    }
    Ok(out)
}

/// The live rows of `names` in each of `repo_ids`, for merging a shard
/// several hosted members publish.
pub(crate) async fn member_rows_for_names(
    db: &PgPool,
    repo_ids: &[Uuid],
    names: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<Vec<CondaArtifact>>, Response> {
    let mut out = Vec::with_capacity(repo_ids.len());
    for repo_id in repo_ids {
        let mut tx = db
            .begin()
            .await
            .map_err(|e| db_unavailable("reading member rows", e))?;
        let rows = rows_for_names(&mut tx, *repo_id, names)
            .await
            .map_err(|e| db_unavailable("reading member rows", e))?;
        tx.commit()
            .await
            .map_err(|e| db_unavailable("reading member rows", e))?;
        out.push(
            rows.iter()
                .filter(|r| !is_withdrawn(r.quarantine_status.as_deref(), r.quarantine_until, now))
                .map(row_to_artifact)
                .collect(),
        );
    }
    Ok(out)
}

/// The revision of each hosted repository of `repo_ids` (the sum of its
/// subdir revisions), in order, after every dirty key of it was rebuilt: the
/// fingerprint the virtual dependency-confusion guard keeps its owned-name
/// set under (#4978 item 1). One statement for all of them; a repository
/// with dirty keys is rebuilt first ([`repo_state`]).
pub(crate) async fn member_revisions(
    db: &PgPool,
    repo_ids: &[Uuid],
) -> Result<Vec<(Uuid, i64)>, Response> {
    let rows: Vec<(Uuid, i64, bool)> = sqlx::query_as(
        "SELECT m.id, \
                COALESCE((SELECT SUM(r.revision) FROM conda_subdir_revisions r \
                           WHERE r.repository_id = m.id), 0)::BIGINT, \
                EXISTS (SELECT 1 FROM conda_shard_dirty d WHERE d.repository_id = m.id) \
           FROM UNNEST($1::UUID[]) WITH ORDINALITY AS m(id, ord) \
          ORDER BY m.ord",
    )
    .bind(repo_ids)
    .fetch_all(db)
    .await
    .map_err(|e| db_unavailable("reading member revisions", e))?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, revision, dirty) in rows {
        let revision = if dirty {
            repo_state(db, id).await?.revision
        } else {
            revision
        };
        out.push((id, revision));
    }
    Ok(out)
}
