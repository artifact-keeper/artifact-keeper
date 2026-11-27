//! When an artifact became visible in its repository's index: the server-set
//! publish time CEP 47 calls `indexed_timestamp` (#6525, #6527).
//!
//! A client cooldown (`exclude-newer`) trusts this value, so it must be the
//! moment the package could first be installed from the channel, not the
//! moment its bytes arrived. A package held by the upload quarantine, blocked
//! by a scan policy or restored from the trash becomes visible later than it
//! was stored. Serving its upload time let it skip a cooldown on its first
//! fetch.
//!
//! Two columns on `artifacts` (migration 426) carry it:
//!
//! * `indexed_at`: set once, the first time an index build lists the row, and
//!   never recomputed after that (CEP 47: "MUST preserve that value across
//!   subsequent indexing runs"). NULL on rows from before the migration,
//!   which keep being served with `created_at` ([`served`]).
//! * `index_pending`: the row has not been listed yet. Writers that make a
//!   row that is not visible at once set it (a hosted conda upload that is
//!   held or under a scan policy, a trash restore; an upload visible at once
//!   is indexed at its `created_at`). The index build that first finds the row visible stamps
//!   it ([`stamp_first_listed`]). A hold that lapses, a release, a scan policy
//!   that stops refusing the row and a restore all end the same way, so no
//!   release path needs to know about the column.
//!
//! The listing queries read both columns with the row, so a build with no
//! pending row (every build once a package has been listed) runs no extra
//! statement.

use std::collections::HashMap;

use axum::http::HeaderMap;
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Header a peer replication PUT carries the source row's [`served`] time in
/// (RFC 3339). Optional: a peer that does not send it, or does not read it,
/// falls back to the receiving row's own time (#6527).
pub const INDEXED_AT_HEADER: &str = "X-Artifact-Indexed-At";

/// The time a listed row is served with: its stamp, or for a row from before
/// migration 426, its creation time (CEP 47 lets a server seed artifacts that
/// predate the field from a server-side signal).
pub fn served(indexed_at: Option<DateTime<Utc>>, created_at: DateTime<Utc>) -> DateTime<Utc> {
    indexed_at.unwrap_or(created_at)
}

/// The SQL expression for the time a replication sends for the row aliased
/// `a`: its [`served`] time, or NULL while it was never listed on the source
/// (the receiving peer then stamps its own).
pub const REPLICATED_INDEXED_AT_SQL: &str =
    "CASE WHEN a.index_pending THEN NULL ELSE COALESCE(a.indexed_at, a.created_at) END";

/// `SET` assignments for a trash restore, which shows a row again with the
/// same bytes it had: a row that was already listed keeps its `indexed_at`
/// (CEP 47: preserved once set, and clients already saw that value), and a
/// row never listed, or one from before migration 426, waits for its next
/// listing, so it is indexed at the time it is visible again (#6525). Only a
/// hosted conda row waits: no other format stamps `indexed_at` yet.
pub const RELIST_SET_SQL: &str = "index_pending = indexed_at IS NULL AND EXISTS ( \
         SELECT 1 FROM repositories ir \
          WHERE ir.id = artifacts.repository_id \
            AND ir.format::text IN ('conda', 'conda_native') \
            AND ir.repo_type::text IN ('local', 'staging')) \
         AND (artifacts.path LIKE '%.conda' OR artifacts.path LIKE '%.tar.bz2')";

/// Format `at` for [`INDEXED_AT_HEADER`] and the replication session body:
/// microseconds, the precision Postgres stores, so both peers hold the same
/// value.
pub fn format_replicated(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Read [`INDEXED_AT_HEADER`]. An absent or unparseable value is `None`.
pub fn header_value(headers: &HeaderMap) -> Option<DateTime<Utc>> {
    headers
        .get(INDEXED_AT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| DateTime::parse_from_rfc3339(v.trim()).ok())
        .map(|v| v.with_timezone(&Utc))
}

/// How long a first-listing stamp waits for a row another build is stamping.
/// A build that cannot get it in time serves without the row this once.
const STAMP_LOCK_TIMEOUT: &str = "500ms";

/// Stamp the rows `ids`, which an index build is about to list for the first
/// time, and return each row's `indexed_at`. Idempotent and race-free: a row
/// another build stamped first keeps that value (`COALESCE`), so every build
/// and every replica serves the same instant, taken from the database clock
/// (`clock_timestamp()`, the moment of the stamp rather than the start of a
/// transaction).
///
/// Runs in a short transaction of its own on `db`, never inside a caller's
/// longer one: the rows are locked in id order (two builds stamping
/// overlapping sets cannot deadlock), for at most [`STAMP_LOCK_TIMEOUT`],
/// and only until this commit. An error leaves the rows pending; callers
/// log it, count it ([`record_stamp_failure`]), leave the rows out of what
/// they serve, and the next build stamps them.
///
/// With `mark_dirty`, the rows' stored conda shards are marked for rebuild:
/// a build other than the shard store (the policy-filtered listing) stamped
/// a row the stored shard may have left out while it was pending.
pub async fn stamp_first_listed(
    db: &PgPool,
    ids: &[Uuid],
    mark_dirty: bool,
) -> sqlx::Result<HashMap<Uuid, DateTime<Utc>>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut tx = db.begin().await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET LOCAL lock_timeout = '{STAMP_LOCK_TIMEOUT}'"
    )))
    .execute(&mut *tx)
    .await?;
    let stamped: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "WITH locked AS ( \
             SELECT id FROM artifacts WHERE id = ANY($1) ORDER BY id FOR UPDATE) \
         UPDATE artifacts a \
            SET indexed_at = COALESCE(a.indexed_at, clock_timestamp()), index_pending = false \
           FROM locked l WHERE a.id = l.id \
         RETURNING a.id, a.indexed_at",
    )
    .bind(ids)
    .fetch_all(&mut *tx)
    .await?;
    if mark_dirty {
        mark_conda_rows_dirty(&mut tx, ids).await?;
    }
    tx.commit().await?;
    Ok(stamped.into_iter().collect())
}

/// Log and count a first-listing stamp that failed; `site` names the build.
pub fn record_stamp_failure(site: &'static str, error: &sqlx::Error) {
    tracing::warn!(site, error = %error, "conda first-listing stamp failed; the rows wait for the next build");
    crate::services::metrics_service::record_conda_index_stamp_failure(site);
}

/// Decide a hosted conda row's index state in the transaction that wrote it
/// (#6525): an upload, a chunked commit, a generic PUT, a promotion copy.
/// Nothing changes for a row of any other repository.
///
/// * `hold_until`: the upload hold the repository's quarantine config asks
///   for. It is applied here, in the writer's transaction, so no index build
///   can list (and stamp) the row in the instant between the commit and the
///   hold. The same guard as `quarantine_service::set_quarantine` keeps a
///   stronger state (an administrator's hold, a rejection); the post-commit
///   `apply_upload_hold` then finds the row held and changes nothing.
/// * A row that already has an `indexed_at` keeps it: the writers' upserts
///   keep it for the same bytes (a re-upload or revive of an identical
///   package) and drop it for other bytes, which are a new indexing.
/// * Otherwise, held or under a scan policy: pending, stamped by its first
///   listing. Visible at once: indexed now, which for a new row is its
///   `created_at`.
pub async fn settle_written_row(
    conn: &mut PgConnection,
    artifact_id: Uuid,
    hold_until: Option<DateTime<Utc>>,
) -> sqlx::Result<()> {
    sqlx::query(
        "WITH t AS ( \
             SELECT a.id, \
                    (a.path LIKE '%.conda' OR a.path LIKE '%.tar.bz2') AS conda, \
                    $2::timestamptz IS NOT NULL \
                      AND (a.quarantine_status IS NULL \
                           OR a.quarantine_status IN ('clean', 'flagged', 'unscanned', 'released')) \
                      AS hold, \
                    EXISTS (SELECT 1 FROM scan_policies p \
                             WHERE p.is_enabled \
                               AND (p.repository_id = a.repository_id OR p.repository_id IS NULL)) \
                      AS policy \
               FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
              WHERE a.id = $1 AND a.is_deleted = false \
                AND r.format::text IN ('conda', 'conda_native') \
                AND r.repo_type::text IN ('local', 'staging')) \
         UPDATE artifacts a SET \
             quarantine_status = CASE WHEN t.hold THEN 'quarantined' ELSE a.quarantine_status END, \
             quarantine_until = CASE WHEN t.hold THEN $2 ELSE a.quarantine_until END, \
             quarantine_source = CASE WHEN t.hold THEN 'upload' ELSE a.quarantine_source END, \
             index_pending = a.indexed_at IS NULL AND ($2::timestamptz IS NOT NULL OR t.policy), \
             indexed_at = CASE \
                 WHEN a.indexed_at IS NOT NULL THEN a.indexed_at \
                 WHEN $2::timestamptz IS NOT NULL OR t.policy THEN NULL \
                 ELSE GREATEST(a.created_at, NOW()) END \
           FROM t WHERE a.id = t.id AND t.conda",
    )
    .bind(artifact_id)
    .bind(hold_until)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Write the indexing time a trusted peer replication carried onto the row it
/// committed (#6527), so both peers serve the same `indexed_timestamp`. The
/// row is no longer pending: the source already listed it. A value in the
/// future (a peer's clock ahead) is clamped to this server's now.
pub async fn adopt_replicated(
    conn: &mut PgConnection,
    artifact_id: Uuid,
    at: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE artifacts SET indexed_at = LEAST($2, clock_timestamp()), index_pending = false \
          WHERE id = $1",
    )
    .bind(artifact_id)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    // `indexed_at` is not a column the conda dirty-mark trigger watches, and
    // a stored shard or a cached repodata render may already hold the row.
    mark_conda_rows_dirty(conn, &[artifact_id]).await
}

/// Delay before [`remark_after_failure`] marks the rows again.
const REMARK_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// After a stamp failed: mark the shards of the package rows among `ids` for
/// rebuild, best-effort, [`REMARK_DELAY`] later and off the request. The rows
/// were left out of what was built; the mark makes a later read rebuild (and
/// stamp) them instead of serving that build until the channel next changes.
/// Not at once: a reader serves only a clean channel, so a mark written while
/// the lock that failed the stamp is still held would only send the readers
/// round the rebuild again.
pub fn remark_after_failure(db: &PgPool, ids: &[Uuid]) {
    let db = db.clone();
    let ids = ids.to_vec();
    tokio::spawn(async move {
        tokio::time::sleep(REMARK_DELAY).await;
        if let Ok(mut conn) = db.acquire().await {
            let _ = mark_conda_rows_dirty(&mut conn, &ids).await;
        }
    });
}

/// Mark the stored conda shards of the package rows among `ids` for rebuild.
/// A no-op for rows of any other repository (the function checks).
async fn mark_conda_rows_dirty(conn: &mut PgConnection, ids: &[Uuid]) -> sqlx::Result<()> {
    sqlx::query(
        "SELECT conda_mark_artifact_dirty(a.repository_id, a.id, a.path, a.name) \
           FROM artifacts a \
          WHERE a.id = ANY($1) AND (a.path LIKE '%.conda' OR a.path LIKE '%.tar.bz2')",
    )
    .bind(ids)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// After a scan policy was created, changed or deleted: mark the stored shard
/// of every pending hosted conda row for rebuild. The shard store leaves a
/// pending row out while a policy applies to its repository (it cannot tell a
/// refused row from an allowed one), and serves its stored shards again once
/// none does, so without this a row the policy no longer refuses would stay
/// out of a sharded client's view until something else touched its shard.
/// Pending rows are few (each is cleared the first time it is listed).
/// Best-effort: a failure is logged.
pub async fn mark_pending_conda_rows_dirty(db: PgPool) {
    // A pending row under a hold or a rejection is left alone: the policy edit
    // cannot make it visible, and its release writes the row (which marks it).
    // So the set is the rows a scan policy alone keeps out, found through
    // the `idx_artifacts_index_pending` partial index (migration 428).
    let result = sqlx::query(
        "SELECT conda_mark_artifact_dirty(a.repository_id, a.id, a.path, a.name) \
           FROM artifacts a \
           JOIN repositories r ON r.id = a.repository_id \
          WHERE a.index_pending AND a.is_deleted = false \
            AND NOT (COALESCE(a.quarantine_status IN ('quarantined', 'rejected'), false) \
                     AND (a.quarantine_until IS NULL OR a.quarantine_until > NOW())) \
            AND r.format::text IN ('conda', 'conda_native') \
            AND r.repo_type::text IN ('local', 'staging')",
    )
    .execute(&db)
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not mark pending conda rows for a shard rebuild");
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn served_prefers_the_stamp_and_falls_back_to_creation() {
        let created = Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();
        let listed = Utc.timestamp_millis_opt(1_700_000_600_000).unwrap();
        assert_eq!(served(Some(listed), created), listed);
        assert_eq!(served(None, created), created);
    }

    #[test]
    fn header_round_trips_at_microsecond_precision() {
        let at = Utc.timestamp_micros(1_700_000_000_123_456).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(INDEXED_AT_HEADER, format_replicated(at).parse().unwrap());
        assert_eq!(header_value(&headers), Some(at));
    }

    #[test]
    fn header_absent_or_garbage_is_none() {
        assert_eq!(header_value(&HeaderMap::new()), None);
        let mut headers = HeaderMap::new();
        headers.insert(INDEXED_AT_HEADER, "yesterday".parse().unwrap());
        assert_eq!(header_value(&headers), None);
    }
}
