//! First-class OCI manifest existence registry (`oci_manifests`), first slice
//! of artifact-keeper#1683 (#4433).
//!
//! The registry historically had no record of a manifest as such: existence
//! and media type were reconstructed from `oci_tags` (plus the children of a
//! tagged index in `oci_manifest_refs`). Migration 268 adds `oci_manifests`,
//! one row per `(repository_id, digest)`, independent of any tag.
//!
//! This module owns every write to that table:
//!
//! * [`upsert_in_tx`] — called from
//!   [`persist_tag_and_refs_in_tx`](crate::api::handlers::oci_v2::persist_tag_and_refs_in_tx)
//!   in the same transaction as the `oci_tags` upsert, so every path that
//!   commits a manifest (push, proxy cache, migration import) records it, and a
//!   rolled-back push leaves no row behind.
//! * [`delete_in_tx`] — called from the manifest-delete unwind once the digest
//!   is no longer tagged, for a delete that names the manifest by digest or a
//!   last-tag delete that leaves it unaddressable ([`delete_removes_record`]).
//! * [`run_backfill`] — a one-shot, idempotent, best-effort startup pass that
//!   records manifests committed before migration 268.
//! * [`run_reconcile`]: the repair pass (#1683): the backfill's additions plus
//!   removal of rows whose manifest is no longer addressable (no tag, no live
//!   index edge, no live `artifacts` row). Rows go stale in ways the dual-write
//!   cannot see: a pre-268 replica's delete during a rolling upgrade, a
//!   lifecycle tag prune, the startup orphan-tag reconciliation. [`run_maintenance`]
//!   runs it at startup and every `OCI_MANIFESTS_RECONCILE_INTERVAL_SECS`.
//!
//! Readers (#1683, third slice): manifest GET/HEAD/DELETE by digest on a
//! hosted repository resolve through [`content_type_of`], the referrers API
//! lists only referrers that have a row, and the storage GC
//! keeps an `oci-manifests/<digest>` object while any repository on its
//! backend records the digest. The #1681 content-addressable fallback that
//! inferred existence from edge rows is gone. A 1.11 replica in the same
//! fleet still derives existence from tags and edges; the stale predicate
//! keeps every row such a replica would still serve, so the two answer the
//! same once the reconcile has run (docs/operations/oci-manifests-reconcile.md).

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::api::handlers::oci_digest::compute_sha256;
use crate::api::handlers::oci_v2::{
    classify_manifest, extract_manifest_subject, manifest_storage_key, stored_media_type_for,
};
use crate::services::cluster_lock::{ClusterLock, PgAdvisoryLock};
use crate::services::manifest_blob_refs_backfill::check_manifest_size;
use crate::storage::{StorageLocation, StorageRegistry};

/// Media type recorded when neither the recorded value nor the body says
/// what a manifest is. Matches the push handler's default for an absent
/// `Content-Type`.
const DEFAULT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The values one `oci_manifests` row carries, derived from a manifest body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestRecord {
    pub content_type: String,
    pub size_bytes: i64,
    pub subject_digest: Option<String>,
}

impl ManifestRecord {
    /// Build the row values for `body` stored under media type
    /// `content_type` (already content-classified by the caller). Pure.
    pub(crate) fn from_body(content_type: &str, body: &[u8]) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes: i64::try_from(body.len()).unwrap_or(i64::MAX),
            subject_digest: extract_manifest_subject(body, content_type).map(|s| s.subject_digest),
        }
    }
}

/// Record (or refresh) a committed manifest. Runs inside the caller's
/// transaction. A re-commit of the same digest refreshes the media type and
/// `last_referenced_at`; `created_at` keeps the first commit time.
pub(crate) async fn upsert_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
    record: &ManifestRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO oci_manifests
            (repository_id, digest, content_type, size_bytes, subject_digest)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (repository_id, digest) DO UPDATE SET
            content_type = EXCLUDED.content_type,
            size_bytes = EXCLUDED.size_bytes,
            subject_digest = EXCLUDED.subject_digest,
            last_referenced_at = NOW()
        "#,
    )
    .bind(repo_id)
    .bind(digest)
    .bind(&record.content_type)
    .bind(record.size_bytes)
    .bind(&record.subject_digest)
    .execute(conn)
    .await?;
    Ok(())
}

/// The recorded media type of `digest` in repository `repo_id`, or `None`
/// when the repository holds no such manifest (#1683 readers: manifest
/// GET/HEAD/DELETE by digest and the referrers API key on this row).
pub(crate) async fn content_type_of<'e, E>(
    executor: E,
    repo_id: Uuid,
    digest: &str,
) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT content_type FROM oci_manifests WHERE repository_id = $1 AND digest = $2",
    )
    .bind(repo_id)
    .bind(digest)
    .fetch_optional(executor)
    .await
}

// ---------------------------------------------------------------------------
// Digest-keyed download gate (#5457)
// ---------------------------------------------------------------------------
//
// A manifest's quarantine and rejection state lives on its `artifacts` rows,
// and one stored manifest can have several: the tag-path row a push writes
// (`v2/<name>/manifests/<tag>`, rewritten in place when the tag moves), the
// digest-path row an MCP pin or a by-digest push writes
// (`v2/<name>/manifests/<digest>`), and further tags. The download decision
// for a digest is therefore taken over EVERY live alias in the repository
// (any refusal refuses; repository-wide rather than per image name, so it
// fails closed), and a tag move carries a hold on the rewritten row over to
// the bytes it named instead of handing it to the new digest.

/// The hold strength of the row aliased `$t`: rejected (4) over a permanent
/// quarantine (3) over an explicit release (2) over a live timed quarantine
/// (1) over anything else, an expired timed hold included (0). A release
/// outranks a timed hold so an upload hold carried from another alias cannot
/// undo an administrator's release; a permanent hold outranks it (fail
/// closed).
macro_rules! hold_rank_sql {
    ($t:literal) => {
        concat!(
            "(CASE WHEN ",
            $t,
            ".quarantine_status = 'rejected' THEN 4 WHEN ",
            $t,
            ".quarantine_status = 'quarantined' AND ",
            $t,
            ".quarantine_until IS NULL THEN 3 WHEN ",
            $t,
            ".quarantine_status = 'released' THEN 2 WHEN ",
            $t,
            ".quarantine_status = 'quarantined' AND ",
            $t,
            ".quarantine_until > NOW() THEN 1 ELSE 0 END)"
        )
    };
}

/// Whether the hold of `EXCLUDED` (the carried one) is stronger than the
/// hold of the existing `artifacts` row: a higher rank, or the later expiry
/// of two live timed holds.
macro_rules! carried_is_stronger_sql {
    () => {
        concat!(
            "(",
            $crate::services::oci_manifests::hold_rank_sql!("EXCLUDED"),
            " > ",
            $crate::services::oci_manifests::hold_rank_sql!("artifacts"),
            " OR (",
            $crate::services::oci_manifests::hold_rank_sql!("artifacts"),
            " = 1 AND ",
            $crate::services::oci_manifests::hold_rank_sql!("EXCLUDED"),
            " = 1 AND EXCLUDED.quarantine_until > artifacts.quarantine_until))"
        )
    };
}

/// One quarantine column of the carried row on conflict: the carried value
/// when its hold is the stronger one, else the existing row's.
macro_rules! stronger_hold_column_sql {
    ($c:literal) => {
        concat!(
            $c,
            " = CASE WHEN ",
            $crate::services::oci_manifests::carried_is_stronger_sql!(),
            " THEN EXCLUDED.",
            $c,
            " ELSE artifacts.",
            $c,
            " END, "
        )
    };
}

/// The `WITH` clause `upsert_manifest_artifact` runs ahead of its upsert, so
/// a tag move cannot leave the bytes the tag named behind a clean alias.
///
/// When the row at the upserted path is under a hold that still refuses (a
/// rejection, a permanent quarantine, or a timed one that has not expired)
/// and names other bytes than the upsert writes (the tag moved), the hold is
/// carried to the old digest's digest-path row (`sha256:` plus the row's
/// checksum, whatever its storage key). That row is created when missing (a
/// tag push writes only the tag-path row). When it exists, live or
/// soft-deleted, it keeps the stronger of its own hold and the carried one
/// (a soft-deleted row is revived, so the bytes stay refused by digest). The
/// upsert itself then clears the rewritten row's hold, which described the
/// old bytes. The new bytes get their own upload hold after commit, and any
/// hold another alias of theirs carries still refuses them through
/// [`alias_rows`].
///
/// A carried scan-policy hold is recorded as an administrator's: the
/// digest-path row has no scan of its own, so the acknowledgement release
/// (which re-evaluates a `scan_policy` hold against the row's scans, and
/// passes a row with none) would otherwise lift it with the findings still
/// open. An administrator releases it.
///
/// One statement with the upsert, so the carry commits or rolls back with it.
/// The upsert must read `carried` before it writes (`WHERE (SELECT COUNT(*)
/// FROM carried) >= 0`): that runs the carry first, so `locked` locks the row
/// before the upsert rewrites it. Left to run after the upsert, it would skip
/// the row the same statement had already modified.
///
/// `locked` selects the row by its key alone and `moved` filters on the hold
/// afterwards (#5618). Under READ COMMITTED a `FOR UPDATE` that waits for a
/// concurrent writer re-checks its `WHERE` and returns the row's newest
/// version, but only for a row that matched in the statement's snapshot. With
/// the hold test in the locking `WHERE`, a row an administrator was holding
/// in a transaction still open when this statement started did not match, was
/// never locked or re-read, and the upsert (which does see the committed hold
/// once it gets the lock) cleared it: the hold was lost on every alias.
/// Locking by key first makes the carry decide from the row the upsert then
/// rewrites.
/// Binds, shared with the upsert: `$1` repository, `$2` the upserted path,
/// `$6` the new sha256 hex, `$11` the image name.
macro_rules! carry_moved_hold_cte {
    () => {
        concat!(
            "WITH locked AS ( \
                 SELECT a.size_bytes, a.checksum_sha256, a.content_type, a.storage_key, \
                        a.uploaded_by, a.quarantine_status, a.quarantine_until, \
                        a.quarantine_reason, a.quarantine_source, a.is_deleted \
                 FROM artifacts a \
                 WHERE a.repository_id = $1 AND a.path = $2 \
                 FOR UPDATE \
             ), moved AS ( \
                 SELECT a.size_bytes, a.checksum_sha256, a.content_type, a.storage_key, \
                        a.uploaded_by, a.quarantine_status, a.quarantine_until, \
                        a.quarantine_reason, \
                        CASE WHEN a.quarantine_source = 'scan_policy' THEN 'admin' \
                             ELSE a.quarantine_source END AS quarantine_source, \
                        'sha256:' || a.checksum_sha256 AS digest \
                 FROM locked a \
                 WHERE a.is_deleted = false \
                   AND a.checksum_sha256 <> $6::bpchar \
                   AND (a.quarantine_status = 'rejected' \
                        OR (a.quarantine_status = 'quarantined' \
                            AND (a.quarantine_until IS NULL OR a.quarantine_until > NOW()))) \
             ), carried AS ( \
                 INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                                        checksum_sha256, content_type, storage_key, uploaded_by, \
                                        quarantine_status, quarantine_until, quarantine_reason, \
                                        quarantine_source) \
                 SELECT $1, 'v2/' || $11::text || '/manifests/' || m.digest, \
                        $11::text || ':' || m.digest, m.digest, m.size_bytes, m.checksum_sha256, \
                        m.content_type, m.storage_key, m.uploaded_by, m.quarantine_status, \
                        m.quarantine_until, m.quarantine_reason, m.quarantine_source \
                 FROM moved m \
                 WHERE 'v2/' || $11::text || '/manifests/' || m.digest <> $2 \
                 ON CONFLICT (repository_id, path) DO UPDATE SET ",
            $crate::services::oci_manifests::stronger_hold_column_sql!("quarantine_status"),
            $crate::services::oci_manifests::stronger_hold_column_sql!("quarantine_until"),
            $crate::services::oci_manifests::stronger_hold_column_sql!("quarantine_reason"),
            $crate::services::oci_manifests::stronger_hold_column_sql!("quarantine_source"),
            "is_deleted = false, \
                     updated_at = NOW() \
                 WHERE artifacts.is_deleted OR ",
            $crate::services::oci_manifests::carried_is_stronger_sql!(),
            " RETURNING artifacts.id \
             ) "
        )
    };
}
pub(crate) use carried_is_stronger_sql;
pub(crate) use carry_moved_hold_cte;
pub(crate) use hold_rank_sql;
pub(crate) use stronger_hold_column_sql;

/// One live `artifacts` row naming a manifest digest: a tag-path or a
/// digest-path alias of the same stored manifest (#5457).
#[derive(Debug, Clone)]
pub(crate) struct AliasRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub checksum: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub quarantine_status: Option<String>,
    pub quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl AliasRow {
    /// The row as the download gate evaluates it.
    pub(crate) fn gate_row(&self) -> crate::services::quarantine_service::GateRow<'_> {
        crate::services::quarantine_service::GateRow {
            artifact_id: self.id,
            repository_id: self.repository_id,
            quarantine_status: self.quarantine_status.as_deref(),
            quarantine_until: self.quarantine_until,
        }
    }
}

type AliasRowTuple = (
    Uuid,
    Uuid,
    String,
    chrono::DateTime<chrono::Utc>,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// The columns and ordering both alias lookups select: rejected rows first,
/// then held ones, so the refusal a gate reports is the strongest.
macro_rules! alias_rows_sql {
    ($from_where:literal) => {
        concat!(
            "SELECT a.id, a.repository_id, a.checksum_sha256::text, a.created_at, \
                    a.quarantine_status, a.quarantine_until ",
            $from_where,
            " AND a.is_deleted = false AND ",
            crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
            " ORDER BY CASE a.quarantine_status WHEN 'rejected' THEN 0 \
                       WHEN 'quarantined' THEN 1 ELSE 2 END, a.path"
        )
    };
}

fn alias_row(t: AliasRowTuple) -> AliasRow {
    AliasRow {
        id: t.0,
        repository_id: t.1,
        checksum: t.2,
        created_at: t.3,
        quarantine_status: t.4,
        quarantine_until: t.5,
    }
}

/// Every live manifest-shaped `artifacts` row of `repo_id` carrying one of
/// `digests`, whatever path (tag or digest) it sits at. The rows the native
/// manifest gate and the MCP backing gate both evaluate (#5457): the decision
/// follows the stored bytes, not one alias. The checksum is compared as
/// `bpchar` so `idx_artifacts_checksum` serves the lookup (#4426).
pub(crate) async fn alias_rows(
    db: impl sqlx::PgExecutor<'_>,
    repo_id: Uuid,
    digests: &[&str],
) -> Result<Vec<AliasRow>, sqlx::Error> {
    let hexes: Vec<&str> = digests
        .iter()
        .map(|d| d.split_once(':').map_or(*d, |(_, hex)| hex))
        .collect();
    let rows: Vec<AliasRowTuple> = sqlx::query_as(alias_rows_sql!(
        "FROM artifacts a WHERE a.repository_id = $1 AND a.checksum_sha256 = ANY($2::bpchar[])"
    ))
    .bind(repo_id)
    .bind(&hexes)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(alias_row).collect())
}

/// Whether `path` has the shape of an OCI manifest row (the same shape
/// [`alias_rows`] selects), so a path-addressed download gates the digest.
pub(crate) fn is_manifest_path(path: &str) -> bool {
    path.contains("/manifests/")
        || path.ends_with("/manifest.json")
        || path.ends_with("/list.manifest.json")
}

/// The download gate of the live artifact at `(repository_id, path)`, for a
/// route that addresses an artifact by path (the generic download, the tree
/// content read). An OCI manifest row is gated with every alias of its
/// digest, as the native pull is (#5457); anything else, or a path with no
/// live row, is [`enforce_download_gate`] of that row as before.
///
/// [`enforce_download_gate`]: crate::services::quarantine_service::enforce_download_gate
pub(crate) async fn enforce_path_download_gate(
    db: &PgPool,
    artifact_id: Uuid,
    path: &str,
) -> crate::error::Result<()> {
    use crate::services::quarantine_service as qs;
    if is_manifest_path(path) {
        let rows: Vec<AliasRowTuple> = sqlx::query_as(alias_rows_sql!(
            "FROM artifacts r JOIN artifacts a ON a.repository_id = r.repository_id \
               AND a.checksum_sha256 = r.checksum_sha256 \
             WHERE r.id = $1 AND r.is_deleted = false"
        ))
        .bind(artifact_id)
        .fetch_all(db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
        let rows: Vec<AliasRow> = rows.into_iter().map(alias_row).collect();
        if rows.iter().any(|r| r.id == artifact_id) {
            let gate: Vec<_> = rows.iter().map(AliasRow::gate_row).collect();
            return qs::enforce_download_gate_rows(db, &gate)
                .await
                .map_err(|(_, e)| e);
        }
    }
    qs::enforce_download_gate(db, artifact_id).await
}

/// Whether a manifest delete that has just removed the digest's last tag also
/// deletes the manifest itself (and so its `oci_manifests` row).
///
/// * A content-addressed delete, and a named delete whose reference IS the
///   digest (the REST delete of a by-digest artifact), name the manifest, not
///   a tag: always.
/// * A tag-name delete that removed the LAST tag (#4449): only when no live
///   manifest-shaped `artifacts` row for the digest survives the delete
///   (`live_manifest_row_remains`). Until the #1683 reader slice serves
///   manifests from this table, a manifest is addressable by digest only
///   through such a row (or a live parent index edge, which [`delete_in_tx`]
///   checks), so once the last of them goes the manifest 404s by digest and
///   its record must go with it. When a row does remain (the image was also
///   pushed by digest, or a migrated row the reindex will index), the record
///   stays.
pub(crate) fn delete_removes_record(
    content_addressed: bool,
    reference: &str,
    digest: &str,
    live_manifest_row_remains: bool,
) -> bool {
    content_addressed || reference == digest || !live_manifest_row_remains
}

/// Live manifest-shaped `artifacts` rows of the digest other than the one the
/// delete removes (`$1` repository id, `$2` sha256 hex, `$3` the deleted
/// row's path). Same path shape as the reindex candidate scan.
const LIVE_MANIFEST_ROW_REMAINS_SQL: &str = concat!(
    r#"
    SELECT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.checksum_sha256 = $2
          AND a.path <> $3
          AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
    )
    "#
);

/// Whether a live manifest-shaped `artifacts` row for `digest` survives a
/// delete of the row at `deleted_path` (#4449). Read-only, inside the caller's
/// transaction, so it takes no row lock and leaves the #4441 lock order
/// (index rows, then `oci_manifests`, then `artifacts`) unchanged. A
/// non-`sha256:` digest can never match `checksum_sha256`: `false`.
pub(crate) async fn live_manifest_row_remains_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
    deleted_path: &str,
) -> Result<bool, sqlx::Error> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Ok(false);
    };
    sqlx::query_scalar(LIVE_MANIFEST_ROW_REMAINS_SQL)
        .bind(repo_id)
        .bind(hex)
        .bind(deleted_path)
        .fetch_one(conn)
        .await
}

/// Lock a manifest's row (if any) for the rest of the caller's transaction,
/// before a delete decides whether to remove it (#4449). Takes the row in the
/// #4441 order: after the delete's `oci_tags` rows, before any `artifacts` row.
pub(crate) async fn lock_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1 FROM oci_manifests WHERE repository_id = $1 AND digest = $2 FOR UPDATE")
        .bind(repo_id)
        .bind(digest)
        .execute(conn)
        .await?;
    Ok(())
}

/// After `DELETE /v2/<name>/manifests/<digest>` has removed the image's tags
/// and trashed its manifest rows (#1683): forget the manifest even when a
/// live index still references it, once nothing else in the repository holds
/// it (no tag under any image name, no live manifest-shaped `artifacts` row).
/// [`delete_in_tx`] keeps the row of a live index's child, which is right for
/// a tag delete, but a delete by digest names the manifest itself, and the
/// spec answers 404 for it afterwards. Without this, a child pushed only
/// under a tag and then deleted by digest stayed pullable through its row
/// while its index was tagged. The index's edge and the child's blob refs
/// stay (the tagged index still names it), exactly as on 1.11.
const FORGET_AFTER_DIGEST_DELETE_SQL: &str = concat!(
    r#"
    DELETE FROM oci_manifests om
    WHERE om.repository_id = $1
      AND om.digest = $2
      AND NOT EXISTS (
            SELECT 1 FROM oci_tags ot
            WHERE ot.repository_id = $1 AND ot.manifest_digest = $2
      )
      AND NOT (
            $2 LIKE 'sha256:%'
            AND EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = $1
                  AND a.is_deleted = false
                  AND a.checksum_sha256 = SUBSTRING($2 FROM 8)::bpchar
                  AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
            )
      )
    "#
);

/// See [`FORGET_AFTER_DIGEST_DELETE_SQL`]. Runs in the delete's transaction,
/// after its `artifacts` soft-delete; the row was locked by [`lock_in_tx`]
/// earlier in the same transaction, so the #4441 lock order holds.
pub(crate) async fn forget_after_digest_delete_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(FORGET_AFTER_DIGEST_DELETE_SQL)
        .bind(repo_id)
        .bind(digest)
        .execute(conn)
        .await?;
    Ok(())
}

/// Forget a deleted manifest (see [`delete_removes_record`]). Runs inside the
/// caller's transaction, after its tag rows and stale index edges are gone.
///
/// A manifest that is still the child of a live index (`oci_manifest_refs`
/// edge kept because the parent is still tagged, #1642) still exists by the
/// registry's rules — it is pullable through the parent — so its row stays.
///
/// The referrers of a removed manifest are left alone: the referrers API
/// lists a manifest whose `subject` names the digest for as long as that
/// referrer itself exists, whether or not the subject does (the distribution
/// spec lets referrers be pushed before their subject), so re-pushing a
/// deleted subject lists its referrers again.
pub(crate) async fn delete_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM oci_manifests om
        WHERE om.repository_id = $1
          AND om.digest = $2
          AND NOT EXISTS (
                SELECT 1 FROM oci_manifest_refs omr
                WHERE omr.repository_id = $1 AND omr.child_digest = $2
          )
        "#,
    )
    .bind(repo_id)
    .bind(digest)
    .execute(conn)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Startup backfill
// ---------------------------------------------------------------------------

/// Advisory-lock class for the backfill (two-int form, its own key space; see
/// `cluster_lock`). One replica runs the pass at a time, so N replicas starting
/// together do not each read the whole manifest corpus from storage.
const BACKFILL_LOCK_CLASS: i32 = 0x1683;

/// Candidates fetched per keyset page, so memory stays bounded on a large
/// first-boot corpus.
const BACKFILL_PAGE_SIZE: i64 = 1000;

/// Result of a backfill pass, for tracing and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BackfillStats {
    /// Manifests without an `oci_manifests` row that the pass tried to record.
    pub candidates_scanned: usize,
    /// Rows inserted. Lower than `candidates_scanned - candidates_failed` when
    /// a live push recorded the manifest first, or it was deleted mid-pass.
    pub rows_inserted: usize,
    /// Candidates skipped (body missing or unreadable, oversized, digest
    /// mismatch, DB error). Logged at WARN and retried on the next start.
    pub candidates_failed: usize,
}

impl BackfillStats {
    fn record(&mut self, outcome: &Result<bool, String>) {
        match outcome {
            Ok(true) => self.rows_inserted += 1,
            Ok(false) => {}
            Err(_) => self.candidates_failed += 1,
        }
    }
}

/// Repositories that can hold manifests, in id order. `$1` optionally scopes
/// the pass to one repository (tests). A repository with no tag and no
/// manifest edge has no candidate in any arm below.
const REPOSITORIES_SQL: &str = r#"
    SELECT r.id, r.storage_backend, r.storage_path
    FROM repositories r
    WHERE ($1::uuid IS NULL OR r.id = $1)
      AND (
            EXISTS (SELECT 1 FROM oci_tags ot WHERE ot.repository_id = r.id)
         OR EXISTS (SELECT 1 FROM manifest_blob_refs mbr WHERE mbr.repository_id = r.id)
         OR EXISTS (SELECT 1 FROM oci_manifest_refs omr WHERE omr.repository_id = r.id)
      )
    ORDER BY r.id
"#;

/// One keyset page (`digest > $2`, `LIMIT $3`) of manifests in repository `$1`
/// the registry already knows about but has no `oci_manifests` row for. Three
/// arms, mirroring what the 1.11 readers serve (#1642, #1681):
///
/// 1. every digest an `oci_tags` row points at — the tag is this repository's
///    proof that it committed the body;
/// 2. children of an index (`oci_manifest_refs.child_digest`) that have a live
///    `artifacts` row in the SAME repository at `oci-manifests/<digest>`. A
///    bare child edge only proves the parent *references* the digest; on a
///    shared cloud namespace reading `oci-manifests/<digest>` could pick up
///    another repository's body, and a proxy cache normally holds only the
///    architectures actually pulled. The artifacts row is the locality proof,
///    exactly as in `manifest_blob_refs_backfill`'s live set (#3285);
/// 3. manifests this repository recorded edges FOR: an image manifest's
///    `manifest_blob_refs` rows or an index's `oci_manifest_refs` parent rows,
///    written per repository at push time and kept across a tag overwrite.
///    They are the proof the #1681 content-addressable fallback accepts, so
///    a manifest whose tag moved before migration 268 is still pullable by
///    digest on a 1.11 replica and needs its row before the readers move to
///    this table. Not when every manifest-shaped `artifacts` row of the
///    digest is in the trash (a delete or a lifecycle expiry; the readers
///    treat that as deleted, #4525), the same exception as arm 4 of
///    [`ROW_IS_STALE_SQL`].
///
/// `recorded_type` is the best media type the database already holds (the
/// tag's, else the artifact's); the body decides when it is empty. Timestamps
/// carry the earliest/latest known commit so a backfilled row is not dated to
/// the upgrade. Every arm filters on `repository_id` so each page reads one
/// repository's rows through its index, not the whole table.
const CANDIDATE_PAGE_SQL: &str = concat!(
    r#"
    SELECT c.digest,
           MAX(NULLIF(c.recorded_type, '')) AS recorded_type,
           MIN(c.first_seen) AS first_seen,
           MAX(c.last_seen) AS last_seen
    FROM (
        SELECT ot.manifest_digest AS digest,
               ot.manifest_content_type AS recorded_type,
               ot.created_at AS first_seen, ot.updated_at AS last_seen
        FROM oci_tags ot
        WHERE ot.repository_id = $1 AND ot.manifest_digest > $2
        UNION ALL
        SELECT omr.child_digest AS digest,
               a.content_type AS recorded_type,
               a.created_at AS first_seen, a.updated_at AS last_seen
        FROM oci_manifest_refs omr
        JOIN artifacts a
          ON a.repository_id = omr.repository_id
         AND a.storage_key = 'oci-manifests/' || omr.child_digest
         AND a.is_deleted = false
        WHERE omr.repository_id = $1 AND omr.child_digest > $2
        UNION ALL
        SELECT e.digest, NULL AS recorded_type,
               NULL::timestamptz AS first_seen, NULL::timestamptz AS last_seen
        FROM (
            SELECT DISTINCT mbr.manifest_digest AS digest
            FROM manifest_blob_refs mbr
            WHERE mbr.repository_id = $1 AND mbr.manifest_digest > $2
            UNION
            SELECT DISTINCT own.parent_digest AS digest
            FROM oci_manifest_refs own
            WHERE own.repository_id = $1 AND own.parent_digest > $2
        ) e
        WHERE NOT (
            e.digest LIKE 'sha256:%'
            AND EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = $1
                  AND a.is_deleted = true
                  AND a.checksum_sha256 = SUBSTRING(e.digest FROM 8)::bpchar
                  AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
            )
            AND NOT EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = $1
                  AND a.is_deleted = false
                  AND a.checksum_sha256 = SUBSTRING(e.digest FROM 8)::bpchar
            )
        )
    ) c
    WHERE NOT EXISTS (
            SELECT 1 FROM oci_manifests om
            WHERE om.repository_id = $1 AND om.digest = c.digest
      )
    GROUP BY c.digest
    ORDER BY c.digest
    LIMIT $3
"#
);

/// Insert-time re-check of arm 1, locking the tag row against a concurrent
/// delete (`FOR KEY SHARE` conflicts with `DELETE FROM oci_tags`).
const STILL_TAGGED_SQL: &str = r#"
    SELECT 1 AS present FROM oci_tags
    WHERE repository_id = $1 AND manifest_digest = $2
    LIMIT 1
    FOR KEY SHARE
"#;

/// Insert-time re-check of arm 2. `FOR SHARE` (not `KEY SHARE`) on both rows,
/// because the artifact soft-delete is an UPDATE of a non-key column.
const STILL_LOCAL_CHILD_SQL: &str = r#"
    SELECT 1 AS present
    FROM oci_manifest_refs omr
    JOIN artifacts a
      ON a.repository_id = omr.repository_id
     AND a.storage_key = 'oci-manifests/' || omr.child_digest
     AND a.is_deleted = false
    WHERE omr.repository_id = $1 AND omr.child_digest = $2
    LIMIT 1
    FOR SHARE
"#;

/// Insert-time re-check of arm 3: the repository still holds its proof of the
/// push. `FOR KEY SHARE` conflicts with the delete unwind's `DELETE` of the
/// edge rows, so a delete either commits first or waits for the insert and
/// then removes the row itself. The trash exception is re-checked without a
/// lock: a lifecycle expiry racing the insert leaves a row the reconcile
/// removes on its next pass.
const STILL_EVIDENCED_SQL: &str = concat!(
    r#"
    SELECT 1 AS present
    FROM (
        SELECT 1 FROM manifest_blob_refs mbr
        WHERE mbr.repository_id = $1 AND mbr.manifest_digest = $2
        LIMIT 1
        FOR KEY SHARE
    ) proof
    WHERE NOT (
        $2 LIKE 'sha256:%'
        AND EXISTS (
            SELECT 1 FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = true
              AND a.checksum_sha256 = SUBSTRING($2 FROM 8)::bpchar
              AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
        )
        AND NOT EXISTS (
            SELECT 1 FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.checksum_sha256 = SUBSTRING($2 FROM 8)::bpchar
        )
    )
"#
);

/// [`STILL_EVIDENCED_SQL`] for an index's parent edges.
const STILL_EVIDENCED_INDEX_SQL: &str = concat!(
    r#"
    SELECT 1 AS present
    FROM (
        SELECT 1 FROM oci_manifest_refs own
        WHERE own.repository_id = $1 AND own.parent_digest = $2
        LIMIT 1
        FOR KEY SHARE
    ) proof
    WHERE NOT (
        $2 LIKE 'sha256:%'
        AND EXISTS (
            SELECT 1 FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = true
              AND a.checksum_sha256 = SUBSTRING($2 FROM 8)::bpchar
              AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
        )
        AND NOT EXISTS (
            SELECT 1 FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.checksum_sha256 = SUBSTRING($2 FROM 8)::bpchar
        )
    )
"#
);

// Pin the `oci-manifests/` literals above to the key the read builds.
const _: () = assert!(crate::storage::keys::prefix_matches("oci-manifests/"));

#[derive(Debug, Clone)]
struct Candidate {
    repository_id: Uuid,
    digest: String,
    recorded_type: Option<String>,
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    location: StorageLocation,
}

/// Run the backfill over every repository. Never fails at the boundary:
/// errors are logged and counted, because startup must not depend on one
/// unreadable manifest. Idempotent — once every manifest has a row the
/// candidate pages come back empty. Skipped when another replica holds the
/// backfill lock (that replica does the work).
pub async fn run_backfill(db: &PgPool, registry: Arc<StorageRegistry>) -> BackfillStats {
    let lease = match PgAdvisoryLock::new(db.clone())
        .try_acquire(BACKFILL_LOCK_CLASS, 0)
        .await
    {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            tracing::info!("oci_manifests backfill: another replica is running it; skipping");
            return BackfillStats::default();
        }
        Err(e) => {
            tracing::warn!(error = %e, "oci_manifests backfill: lock unavailable; skipping");
            return BackfillStats::default();
        }
    };
    let stats = run_backfill_scoped(db, &registry, None, BACKFILL_PAGE_SIZE).await;
    lease.release().await;
    stats
}

async fn run_backfill_scoped(
    db: &PgPool,
    registry: &StorageRegistry,
    repository_id: Option<Uuid>,
    page_size: i64,
) -> BackfillStats {
    let mut stats = BackfillStats::default();
    let repos = match sqlx::query(REPOSITORIES_SQL)
        .bind(repository_id)
        .fetch_all(db)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "oci_manifests backfill: failed to list repositories; skipping");
            return stats;
        }
    };
    for repo in repos {
        let (Ok(repo_id), Ok(backend), Ok(path)) = (
            repo.try_get::<Uuid, _>("id"),
            repo.try_get::<String, _>("storage_backend"),
            repo.try_get::<String, _>("storage_path"),
        ) else {
            continue;
        };
        let location = StorageLocation { backend, path };
        backfill_repository(db, registry, repo_id, &location, page_size, &mut stats).await;
    }
    if stats.candidates_scanned > 0 {
        tracing::info!(
            candidates_scanned = stats.candidates_scanned,
            rows_inserted = stats.rows_inserted,
            candidates_failed = stats.candidates_failed,
            "oci_manifests backfill: complete"
        );
    }
    stats
}

/// Walk one repository's candidates page by page. The cursor advances past
/// failures, so an unreadable manifest is retried on the next start, not
/// re-fetched forever within this pass.
async fn backfill_repository(
    db: &PgPool,
    registry: &StorageRegistry,
    repo_id: Uuid,
    location: &StorageLocation,
    page_size: i64,
    stats: &mut BackfillStats,
) {
    let mut cursor = String::new();
    loop {
        let page = match select_page(db, repo_id, location, &cursor, page_size).await {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!(
                    repository_id = %repo_id,
                    error = %e,
                    "oci_manifests backfill: failed to scan candidates; skipping repository"
                );
                return;
            }
        };
        let Some(last) = page.last() else {
            return;
        };
        cursor = last.digest.clone();
        stats.candidates_scanned += page.len();
        for candidate in &page {
            let outcome = process_candidate(db, registry, candidate).await;
            if let Err(e) = &outcome {
                tracing::warn!(
                    digest = candidate.digest.as_str(),
                    repository_id = %candidate.repository_id,
                    error = %e,
                    "oci_manifests backfill: skipped manifest"
                );
            }
            stats.record(&outcome);
        }
    }
}

async fn select_page(
    db: &PgPool,
    repo_id: Uuid,
    location: &StorageLocation,
    after: &str,
    page_size: i64,
) -> sqlx::Result<Vec<Candidate>> {
    let rows = sqlx::query(CANDIDATE_PAGE_SQL)
        .bind(repo_id)
        .bind(after)
        .bind(page_size)
        .fetch_all(db)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Candidate {
                repository_id: repo_id,
                digest: r.try_get("digest")?,
                recorded_type: r.try_get("recorded_type")?,
                first_seen: r.try_get("first_seen")?,
                last_seen: r.try_get("last_seen")?,
                location: location.clone(),
            })
        })
        .collect()
}

/// Validate a manifest body read back from storage before it is recorded:
/// bounded size, and (for sha256 digests, the only kind the registry
/// computes) the bytes must hash to the digest the row will claim. A body
/// that fails either check is not evidence that the manifest exists.
fn verify_body(digest: &str, body: &[u8]) -> Result<(), String> {
    check_manifest_size(body.len())?;
    if digest.starts_with("sha256:") {
        let actual = compute_sha256(body);
        if actual != digest {
            return Err(format!("stored body hashes to {actual}, not {digest}"));
        }
    }
    Ok(())
}

/// The media type a backfilled row records, derived the way the push handler
/// derives it: the recorded value (tag or artifact content type), else the
/// body's own `mediaType`, else the OCI image default — then canonicalized by
/// content so an index is never recorded with an image type or vice versa.
fn backfill_content_type(recorded: Option<&str>, body: &[u8]) -> String {
    let body_media_type = || {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("mediaType")?.as_str().map(str::to_string))
    };
    let declared = recorded
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(body_media_type)
        .unwrap_or_else(|| DEFAULT_MANIFEST_MEDIA_TYPE.to_string());
    stored_media_type_for(&classify_manifest(body), &declared)
}

/// Whether the manifest is still known (tagged, a locally stored child of an
/// index, or still proven by its own edge rows) at insert time, taking row locks that make a concurrent delete
/// wait for this transaction — so a delete either commits first (and this
/// returns false) or runs after the insert (and removes the row itself).
async fn still_known_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<bool, sqlx::Error> {
    for sql in [
        STILL_TAGGED_SQL,
        STILL_LOCAL_CHILD_SQL,
        STILL_EVIDENCED_SQL,
        STILL_EVIDENCED_INDEX_SQL,
    ] {
        let hit = sqlx::query(sql)
            .bind(repo_id)
            .bind(digest)
            .fetch_optional(&mut *conn)
            .await?;
        if hit.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read one manifest body, verify it, then — in a short transaction that
/// re-checks the candidate predicate under lock — insert its row. `Ok(true)`
/// when a row was inserted; `Ok(false)` when a live push recorded it first or
/// it was deleted after the candidate scan. Storage I/O stays outside the
/// transaction.
async fn process_candidate(
    db: &PgPool,
    registry: &StorageRegistry,
    candidate: &Candidate,
) -> Result<bool, String> {
    let storage = registry
        .backend_for(&candidate.location)
        .map_err(|e| format!("resolve storage backend: {e}"))?;
    let body = storage
        .get(&manifest_storage_key(&candidate.digest))
        .await
        .map_err(|e| format!("read manifest from storage: {e}"))?;
    verify_body(&candidate.digest, &body)?;

    let content_type = backfill_content_type(candidate.recorded_type.as_deref(), &body);
    let record = ManifestRecord::from_body(&content_type, &body);
    insert_if_still_known(db, candidate, &record)
        .await
        .map_err(|e| format!("insert oci_manifests row: {e}"))
}

async fn insert_if_still_known(
    db: &PgPool,
    candidate: &Candidate,
    record: &ManifestRecord,
) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    if !still_known_in_tx(&mut tx, candidate.repository_id, &candidate.digest).await? {
        return Ok(false);
    }
    // DO NOTHING, not an upsert: a live push that raced the backfill wrote the
    // authoritative row and must win.
    let res = sqlx::query(
        r#"
        INSERT INTO oci_manifests
            (repository_id, digest, content_type, size_bytes, subject_digest,
             created_at, last_referenced_at)
        VALUES ($1, $2, $3, $4, $5, COALESCE($6, NOW()), COALESCE($7, NOW()))
        ON CONFLICT (repository_id, digest) DO NOTHING
        "#,
    )
    .bind(candidate.repository_id)
    .bind(&candidate.digest)
    .bind(&record.content_type)
    .bind(record.size_bytes)
    .bind(&record.subject_digest)
    .bind(candidate.first_seen)
    .bind(candidate.last_seen)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Reconcile (#1683): repair rows the dual-write cannot keep exact
// ---------------------------------------------------------------------------

/// Advisory-lock object id of the maintenance pass (backfill plus
/// reconcile), in [`BACKFILL_LOCK_CLASS`]. The standalone startup backfill
/// keeps object `0`; a maintenance pass holds both so the two never overlap.
const RECONCILE_LOCK_OBJ: i32 = 1;

/// Rows younger than this are never removed by the reconcile (#1683). Every
/// writer records a row in the same transaction as the reference that keeps
/// it (`oci_tags`, an index edge, the `artifacts` row), so a just-written row
/// with no reference is not expected; the window is margin against a
/// reference written by a later statement of a push that is still running.
const RECONCILE_MIN_ROW_AGE_SECS: i64 = 600;

/// Default seconds between scheduled reconcile passes
/// (`OCI_MANIFESTS_RECONCILE_INTERVAL_SECS`; `0` disables the schedule but
/// keeps the startup pass).
pub const RECONCILE_INTERVAL_SECS_DEFAULT: u64 = 6 * 60 * 60;

/// SQL boolean over an `oci_manifests` row aliased `om`: the row no longer
/// records a manifest the registry can serve (#1683, #4449), because
///
/// 1. no tag in its repository points at it;
/// 2. no live index edge names it as a child: an `oci_manifest_refs` edge
///    counts only while its parent is itself tagged, has a live `artifacts`
///    row, or still has its own `oci_manifests` row. The last arm is what
///    keeps the child of an index of indexes (the middle index is untagged
///    and kept only by its own parent's edge) and the child of a pre-#2457
///    migrated index (kept only by checksum, so no key match): the parent's
///    row is kept by the same predicate, so liveness follows the edges down
///    one pass at a time. An edge whose parent is gone is the stale edge GC
///    prunes, not a reason for the child to exist;
/// 3. no live `artifacts` row of its repository stores it, by the canonical
///    `oci-manifests/<digest>` key or, for a pre-#2457 migrated manifest kept
///    under a generic CAS key, by its sha256 checksum; and
/// 4. the repository holds none of the per-repository records that the 1.11
///    readers accept as proof of a manifest pushed here (#1681): a
///    `manifest_blob_refs` row of an image manifest or an `oci_manifest_refs`
///    parent row of an index. They outlive a tag overwrite, so an image
///    whose tag moved stays pullable by digest on a 1.11 replica until the
///    storage GC prunes its blob refs (which retires the row with them, see
///    [`retire_rows_if_stale`]). The proof does not count once every
///    manifest-shaped `artifacts` row of the digest is in the trash, which
///    is what a lifecycle expiry and a delete leave and what the readers
///    treat as deleted (#4525).
///
/// These are the ways the registry addresses a manifest (the same ones
/// `delete_in_tx` and `live_manifest_row_remains_in_tx` consult on the write
/// side). Anything that keeps a manifest pullable, on this release or on a
/// 1.11 replica during a rolling upgrade, keeps its row.
const ROW_IS_STALE_SQL: &str = concat!(
    r#"
    NOT EXISTS (
        SELECT 1 FROM oci_tags ot
        WHERE ot.repository_id = om.repository_id
          AND ot.manifest_digest = om.digest
    )
    AND NOT EXISTS (
        SELECT 1 FROM oci_manifest_refs omr
        WHERE omr.repository_id = om.repository_id
          AND omr.child_digest = om.digest
          AND (
                EXISTS (
                    SELECT 1 FROM oci_tags pt
                    WHERE pt.repository_id = omr.repository_id
                      AND pt.manifest_digest = omr.parent_digest
                )
             OR EXISTS (
                    SELECT 1 FROM oci_manifests pm
                    WHERE pm.repository_id = omr.repository_id
                      AND pm.digest = omr.parent_digest
                )
             OR EXISTS (
                    SELECT 1 FROM artifacts pa
                    WHERE pa.repository_id = omr.repository_id
                      AND pa.is_deleted = false
                      AND pa.storage_key = 'oci-manifests/' || omr.parent_digest
                )
          )
    )
    AND NOT EXISTS (
        SELECT 1 FROM artifacts a
        WHERE a.repository_id = om.repository_id
          AND a.is_deleted = false
          AND a.storage_key = 'oci-manifests/' || om.digest
    )
    AND NOT (
        om.digest LIKE 'sha256:%'
        AND EXISTS (
            -- `checksum_sha256` is CHAR(64). Comparing it with the TEXT that
            -- SUBSTRING returns casts the column instead, which rules out
            -- idx_artifacts_checksum and turns this arm into a scan of every
            -- artifacts row per oci_manifests row. Cast the digest instead.
            SELECT 1 FROM artifacts a
            WHERE a.repository_id = om.repository_id
              AND a.is_deleted = false
              AND a.checksum_sha256 = SUBSTRING(om.digest FROM 8)::bpchar
        )
    )
    AND NOT (
        (
            EXISTS (
                SELECT 1 FROM manifest_blob_refs mbr
                WHERE mbr.manifest_digest = om.digest
                  AND mbr.repository_id = om.repository_id
            )
            OR EXISTS (
                SELECT 1 FROM oci_manifest_refs own
                WHERE own.parent_digest = om.digest
                  AND own.repository_id = om.repository_id
            )
        )
        AND NOT (
            om.digest LIKE 'sha256:%'
            AND EXISTS (
                SELECT 1 FROM artifacts a
                WHERE a.repository_id = om.repository_id
                  AND a.is_deleted = true
                  AND a.checksum_sha256 = SUBSTRING(om.digest FROM 8)::bpchar
                  AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
            )
        )
    )
"#
);

/// Result of a reconcile pass, for tracing, metrics and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileStats {
    /// The add half: the backfill's candidate scan (manifests the registry
    /// knows but has no row for, such as pushes served by a pre-268 replica).
    pub added: BackfillStats,
    /// Stale rows found by the scan.
    pub stale_found: usize,
    /// Stale rows removed (after the locked re-check).
    pub rows_removed: usize,
    /// Removals that failed (logged at WARN, retried next pass).
    pub remove_failed: usize,
}

/// One keyset page (`(repository_id, digest) > ($1, $2)`, `LIMIT $3`) of stale
/// rows older than `$4` seconds, optionally in repository `$5` only (tests).
fn stale_page_sql() -> String {
    format!(
        r#"
        SELECT om.repository_id, om.digest
        FROM oci_manifests om
        WHERE (om.repository_id, om.digest) > ($1, $2)
          AND ($5::uuid IS NULL OR om.repository_id = $5)
          AND om.last_referenced_at < NOW() - make_interval(secs => $4::BIGINT)
          AND {ROW_IS_STALE_SQL}
        ORDER BY om.repository_id, om.digest
        LIMIT $3
        "#
    )
}

/// Remove one stale row if it is still stale, under its row lock. The lock
/// serializes with a push re-tagging the digest (its `upsert_in_tx` takes the
/// same row), and the re-check runs as a new statement after the lock is
/// held, so it sees a reference that push committed. `Ok(true)` when removed.
async fn remove_if_still_stale(db: &PgPool, repo_id: Uuid, digest: &str) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let locked = sqlx::query(
        "SELECT 1 AS present FROM oci_manifests \
         WHERE repository_id = $1 AND digest = $2 FOR UPDATE",
    )
    .bind(repo_id)
    .bind(digest)
    .fetch_optional(&mut *tx)
    .await?;
    if locked.is_none() {
        return Ok(false);
    }
    let sql = format!(
        "DELETE FROM oci_manifests om \
         WHERE om.repository_id = $1 AND om.digest = $2 \
           AND om.last_referenced_at < NOW() - make_interval(secs => $3::BIGINT) \
           AND {ROW_IS_STALE_SQL}"
    );
    let removed = sqlx::query(sqlx::AssertSqlSafe(&*sql))
        .bind(repo_id)
        .bind(digest)
        .bind(RECONCILE_MIN_ROW_AGE_SECS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(removed > 0)
}

/// Most removal sweeps one reconcile pass runs. A row kept only by its
/// parent's row (arm 2 of [`ROW_IS_STALE_SQL`]) goes stale once that parent's
/// row is removed, so a dead index of indexes needs one sweep per level;
/// index nesting deeper than this is finished by the next pass.
const RECONCILE_MAX_SWEEPS: usize = 8;

/// The remove half of the reconcile: sweep every stale row page by page, and
/// sweep again while the previous sweep removed something (a removed parent
/// can leave its children stale), up to [`RECONCILE_MAX_SWEEPS`].
async fn remove_stale_rows(
    db: &PgPool,
    repository_id: Option<Uuid>,
    page_size: i64,
    stats: &mut ReconcileStats,
) {
    for _ in 0..RECONCILE_MAX_SWEEPS {
        let before = stats.rows_removed;
        remove_stale_rows_once(db, repository_id, page_size, stats).await;
        if stats.rows_removed == before {
            return;
        }
    }
}

/// Remove the rows of `candidates` that are stale ([`ROW_IS_STALE_SQL`]) and
/// older than the reconcile's minimum row age, each under its row lock with
/// the same re-check the reconcile uses. The storage GC calls this for the
/// manifests whose `manifest_blob_refs` it has just pruned (#1683): those
/// rows were kept only by that proof, and retiring them in the same GC run
/// keeps a manifest from being served by digest after its blobs became
/// reclaimable. Errors are logged and the row is left for the reconcile.
/// Returns the number of rows removed.
pub(crate) async fn retire_rows_if_stale(db: &PgPool, candidates: &[(Uuid, String)]) -> usize {
    let mut removed = 0;
    for (repo_id, digest) in candidates {
        match remove_if_still_stale(db, *repo_id, digest).await {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(
                repository_id = %repo_id,
                digest = digest.as_str(),
                error = %e,
                "oci_manifests: failed to retire the row of a manifest whose blob refs were pruned"
            ),
        }
    }
    if removed > 0 {
        metrics::counter!("ak_oci_manifests_reconcile_rows_removed_total")
            .increment(removed as u64);
    }
    removed
}

/// One removal sweep over every stale row, page by page.
async fn remove_stale_rows_once(
    db: &PgPool,
    repository_id: Option<Uuid>,
    page_size: i64,
    stats: &mut ReconcileStats,
) {
    let sql = stale_page_sql();
    let mut cursor = (Uuid::nil(), String::new());
    loop {
        let page = match sqlx::query(sqlx::AssertSqlSafe(&*sql))
            .bind(cursor.0)
            .bind(&cursor.1)
            .bind(page_size)
            .bind(RECONCILE_MIN_ROW_AGE_SECS)
            .bind(repository_id)
            .fetch_all(db)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "oci_manifests reconcile: stale-row scan failed");
                return;
            }
        };
        let rows: Vec<(Uuid, String)> = page
            .iter()
            .filter_map(|r| Some((r.try_get("repository_id").ok()?, r.try_get("digest").ok()?)))
            .collect();
        let Some(last) = rows.last().cloned() else {
            return;
        };
        stats.stale_found += rows.len();
        for (repo_id, digest) in &rows {
            match remove_if_still_stale(db, *repo_id, digest).await {
                Ok(true) => {
                    stats.rows_removed += 1;
                    tracing::debug!(
                        repository_id = %repo_id,
                        digest = digest.as_str(),
                        "oci_manifests reconcile: removed row of an unaddressable manifest"
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    stats.remove_failed += 1;
                    tracing::warn!(
                        repository_id = %repo_id,
                        digest = digest.as_str(),
                        error = %e,
                        "oci_manifests reconcile: failed to remove stale row"
                    );
                }
            }
        }
        if (rows.len() as i64) < page_size {
            return;
        }
        cursor = last;
    }
}

/// One reconcile pass, without the cluster lock (tests, and the locked
/// wrapper below): add missing rows, then remove stale ones. `repository_id`
/// scopes the pass to one repository (tests); production passes `None`.
async fn reconcile_unlocked(
    db: &PgPool,
    registry: &StorageRegistry,
    repository_id: Option<Uuid>,
    page_size: i64,
) -> ReconcileStats {
    let mut stats = ReconcileStats {
        added: run_backfill_scoped(db, registry, repository_id, page_size).await,
        ..ReconcileStats::default()
    };
    remove_stale_rows(db, repository_id, page_size, &mut stats).await;
    metrics::counter!("ak_oci_manifests_reconcile_rows_added_total")
        .increment(stats.added.rows_inserted as u64);
    metrics::counter!("ak_oci_manifests_reconcile_rows_removed_total")
        .increment(stats.rows_removed as u64);
    metrics::counter!("ak_oci_manifests_reconcile_failures_total")
        .increment((stats.added.candidates_failed + stats.remove_failed) as u64);
    if stats.added.rows_inserted > 0 || stats.rows_removed > 0 || stats.remove_failed > 0 {
        tracing::info!(
            rows_added = stats.added.rows_inserted,
            rows_removed = stats.rows_removed,
            stale_found = stats.stale_found,
            failures = stats.added.candidates_failed + stats.remove_failed,
            "oci_manifests reconcile: complete"
        );
    }
    stats
}

/// Reconcile `oci_manifests` with what the registry can actually serve
/// (#1683): record manifests that have no row (the backfill's candidates, so
/// pushes a pre-268 replica served during a rolling upgrade get theirs), and
/// remove rows for manifests that are no longer addressable
/// ([`ROW_IS_STALE_SQL`]), such as rows a pre-268 replica's delete or a
/// lifecycle tag prune left behind.
///
/// Must have run clean before any reader (GET/HEAD/DELETE by digest, the
/// referrers API, the GC orphan predicate) trusts the table. Idempotent,
/// best-effort, and skipped when another replica holds the lock.
pub async fn run_reconcile(db: &PgPool, registry: Arc<StorageRegistry>) -> Option<ReconcileStats> {
    run_reconcile_scoped(db, &registry, None).await
}

/// [`run_reconcile`] optionally scoped to one repository (tests).
async fn run_reconcile_scoped(
    db: &PgPool,
    registry: &StorageRegistry,
    repository_id: Option<Uuid>,
) -> Option<ReconcileStats> {
    let locks = PgAdvisoryLock::new(db.clone());
    let backfill_lease = match locks.try_acquire(BACKFILL_LOCK_CLASS, 0).await {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            tracing::info!("oci_manifests reconcile: another replica holds the lock; skipping");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "oci_manifests reconcile: lock unavailable; skipping");
            return None;
        }
    };
    let lease = match locks
        .try_acquire(BACKFILL_LOCK_CLASS, RECONCILE_LOCK_OBJ)
        .await
    {
        Ok(Some(lease)) => lease,
        _ => {
            backfill_lease.release().await;
            return None;
        }
    };
    let stats = reconcile_unlocked(db, registry, repository_id, BACKFILL_PAGE_SIZE).await;
    lease.release().await;
    backfill_lease.release().await;
    Some(stats)
}

/// Parse `OCI_MANIFESTS_RECONCILE_INTERVAL_SECS`: seconds between scheduled
/// passes; unset or unparsable means the default, `0` disables the schedule.
pub(crate) fn parse_reconcile_interval(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(RECONCILE_INTERVAL_SECS_DEFAULT)
}

/// Startup and scheduled maintenance of `oci_manifests` (#1683): one
/// reconcile at startup (which includes the backfill), then one every
/// `OCI_MANIFESTS_RECONCILE_INTERVAL_SECS`. Never returns while the schedule
/// is enabled; spawn it.
pub async fn run_maintenance(db: PgPool, registry: Arc<StorageRegistry>) {
    let interval = parse_reconcile_interval(
        std::env::var("OCI_MANIFESTS_RECONCILE_INTERVAL_SECS")
            .ok()
            .as_deref(),
    );
    run_maintenance_every(db, registry, interval).await;
}

/// [`run_maintenance`] with the interval given: one pass now, then one every
/// `interval_secs` seconds; returns after the first pass when it is `0`.
async fn run_maintenance_every(db: PgPool, registry: Arc<StorageRegistry>, interval: u64) {
    run_reconcile(&db, registry.clone()).await;
    if interval == 0 {
        return;
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        run_reconcile(&db, registry.clone()).await;
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::oci_v2::{
        delete_oci_manifest_and_artifacts, persist_tag_and_refs, ManifestClass, OciIndexDeleteScope,
    };
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::storage::StorageBackend;

    type Ts = chrono::DateTime<chrono::Utc>;

    const IMAGE: &str = "application/vnd.oci.image.manifest.v1+json";
    const INDEX: &str = "application/vnd.oci.image.index.v1+json";
    const DOCKER_IMAGE: &str = "application/vnd.docker.distribution.manifest.v2+json";

    fn image_body(tag: &str) -> Vec<u8> {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{IMAGE}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{c}","size":2}},"layers":[],"annotations":{{"t":"{tag}"}}}}"#,
            c = "c".repeat(64)
        )
        .into_bytes()
    }

    fn index_body(children: &[&str]) -> Vec<u8> {
        let entries: Vec<String> = children
            .iter()
            .map(|d| format!(r#"{{"mediaType":"{IMAGE}","digest":"{d}","size":10}}"#))
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    fn referrer_body(subject: &str) -> Vec<u8> {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{IMAGE}","artifactType":"application/x.sig","config":{{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:{c}","size":2}},"layers":[],"subject":{{"mediaType":"{IMAGE}","digest":"{subject}","size":10}}}}"#,
            c = "e".repeat(64)
        )
        .into_bytes()
    }

    // ----- pure -----------------------------------------------------------

    #[test]
    fn record_from_body_carries_size_type_and_no_subject() {
        let body = image_body("a");
        let rec = ManifestRecord::from_body(IMAGE, &body);
        assert_eq!(rec.content_type, IMAGE);
        assert_eq!(rec.size_bytes, body.len() as i64);
        assert_eq!(rec.subject_digest, None);
    }

    #[test]
    fn record_from_body_extracts_subject_digest() {
        let subject = format!("sha256:{}", "a".repeat(64));
        let rec = ManifestRecord::from_body(IMAGE, &referrer_body(&subject));
        assert_eq!(rec.subject_digest.as_deref(), Some(subject.as_str()));
    }

    #[test]
    fn stats_record_counts_inserts_and_failures() {
        let mut s = BackfillStats::default();
        s.record(&Ok(true));
        s.record(&Ok(false));
        s.record(&Err("x".into()));
        assert_eq!(s.rows_inserted, 1);
        assert_eq!(s.candidates_failed, 1);
        assert_eq!(s.candidates_scanned, 0);
    }

    #[test]
    fn verify_body_accepts_matching_digest() {
        let body = image_body("v");
        assert!(verify_body(&compute_sha256(&body), &body).is_ok());
    }

    #[test]
    fn verify_body_rejects_digest_mismatch() {
        let err = verify_body(&format!("sha256:{}", "0".repeat(64)), b"{}").unwrap_err();
        assert!(err.contains("hashes to"), "{err}");
    }

    #[test]
    fn verify_body_skips_hash_check_for_non_sha256_digest() {
        assert!(verify_body("sha512:abc", b"{}").is_ok());
    }

    #[test]
    fn verify_body_rejects_oversized_body() {
        let body = vec![b' '; 4 * 1024 * 1024 + 1];
        let err = verify_body("sha512:abc", &body).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn backfill_content_type_prefers_recorded_value() {
        assert_eq!(
            backfill_content_type(Some(DOCKER_IMAGE), &image_body("r")),
            DOCKER_IMAGE
        );
    }

    #[test]
    fn backfill_content_type_falls_back_to_body_media_type() {
        let body = index_body(&[]);
        assert_eq!(backfill_content_type(None, &body), INDEX);
        assert_eq!(backfill_content_type(Some(""), &body), INDEX);
    }

    #[test]
    fn backfill_content_type_defaults_to_oci_image() {
        let body = br#"{"schemaVersion":2,"config":{"digest":"sha256:x"},"layers":[]}"#;
        assert_eq!(backfill_content_type(None, body), IMAGE);
    }

    #[test]
    fn backfill_content_type_canonicalizes_by_content() {
        // An index recorded with an image media type is stored as an index.
        assert_eq!(backfill_content_type(Some(IMAGE), &index_body(&[])), INDEX);
    }

    #[test]
    fn candidate_sql_scopes_children_to_local_bodies_and_pages() {
        for sql in [CANDIDATE_PAGE_SQL, STILL_LOCAL_CHILD_SQL] {
            assert!(sql.contains("a.storage_key = 'oci-manifests/' || omr.child_digest"));
            assert!(sql.contains("a.is_deleted = false"));
        }
        assert!(CANDIDATE_PAGE_SQL.contains("ot.manifest_digest > $2"));
        assert!(CANDIDATE_PAGE_SQL.contains("LIMIT $3"));
        assert!(STILL_TAGGED_SQL.contains("FOR KEY SHARE"));
        assert!(STILL_LOCAL_CHILD_SQL.contains("FOR SHARE"));
    }

    // ----- DB-backed --------------------------------------------------------

    type Row3 = (String, i64, Option<String>);

    async fn manifest_row(pool: &PgPool, repo_id: Uuid, digest: &str) -> Option<Row3> {
        sqlx::query_as(
            "SELECT content_type, size_bytes, subject_digest FROM oci_manifests \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(digest)
        .fetch_optional(pool)
        .await
        .expect("select oci_manifests row")
    }

    async fn manifest_times(pool: &PgPool, repo_id: Uuid, digest: &str) -> (Ts, Ts) {
        sqlx::query_as(
            "SELECT created_at, last_referenced_at FROM oci_manifests \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(digest)
        .fetch_one(pool)
        .await
        .expect("select oci_manifests times")
    }

    async fn persist_image(pool: &PgPool, repo_id: Uuid, tag: &str, digest: &str, body: &[u8]) {
        persist_tag_and_refs(
            pool,
            repo_id,
            "app",
            tag,
            digest,
            IMAGE,
            &ManifestClass::Image,
            body,
        )
        .await
        .expect("persist");
    }

    async fn delete(pool: &PgPool, repo_id: Uuid, reference: &str, digest: &str, by_digest: bool) {
        let scope = if by_digest {
            OciIndexDeleteScope::ContentAddressed
        } else {
            OciIndexDeleteScope::NamedReference
        };
        delete_oci_manifest_and_artifacts(pool, repo_id, "app", reference, digest, scope)
            .await
            .expect("delete manifest content");
    }

    async fn seed_tag(pool: &PgPool, repo_id: Uuid, tag: &str, digest: &str, ct: &str) {
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, 'app', $2, $3, $4)",
        )
        .bind(repo_id)
        .bind(tag)
        .bind(digest)
        .bind(ct)
        .execute(pool)
        .await
        .expect("seed tag");
    }

    async fn seed_body(fx: &tdh::Fixture, digest: &str, body: &[u8]) {
        crate::storage::filesystem::FilesystemStorage::new(fx.storage_dir.to_str().unwrap())
            .put(
                &manifest_storage_key(digest),
                bytes::Bytes::from(body.to_vec()),
            )
            .await
            .expect("seed manifest body");
    }

    /// What a lifecycle expiry leaves for an image pushed as `app:<tag>`
    /// (`CASCADE_OCI_TAGS_SQL`): the manifest's `artifacts` row in the trash
    /// and its tag gone, with its edge rows untouched.
    async fn expire_like_lifecycle(pool: &PgPool, repo_id: Uuid, tag: &str, digest: &str) {
        let id = crate::api::handlers::oci_v2::upsert_manifest_artifact(
            pool,
            repo_id,
            "app",
            tag,
            digest,
            IMAGE,
            &manifest_storage_key(digest),
            10,
            None,
            None,
        )
        .await
        .expect("seed manifest artifact");
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .expect("trash manifest artifact");
        sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2")
            .bind(repo_id)
            .bind(digest)
            .execute(pool)
            .await
            .expect("prune tag");
    }

    /// What a pre-1.11 replica's delete, or the storage GC's blob-ref prune
    /// after a tag removal, leaves: no tag and no `manifest_blob_refs` rows.
    async fn drop_tag_and_proof(pool: &PgPool, repo_id: Uuid, digest: &str) {
        for sql in [
            "DELETE FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2",
            "DELETE FROM manifest_blob_refs WHERE repository_id = $1 AND manifest_digest = $2",
        ] {
            sqlx::query(sql)
                .bind(repo_id)
                .bind(digest)
                .execute(pool)
                .await
                .expect("drop tag and proof");
        }
    }

    fn fs_registry() -> StorageRegistry {
        StorageRegistry::new(std::collections::HashMap::new(), "filesystem".to_string())
    }

    fn candidate(fx: &tdh::Fixture, digest: &str) -> Candidate {
        Candidate {
            repository_id: fx.repo_id,
            digest: digest.to_string(),
            recorded_type: Some(IMAGE.to_string()),
            first_seen: None,
            last_seen: None,
            location: StorageLocation {
                backend: "filesystem".to_string(),
                path: fx.storage_dir.to_string_lossy().into_owned(),
            },
        }
    }

    /// The dual write: committing a manifest through the shared writer records
    /// its row in the same transaction; a re-push keeps `created_at` and
    /// advances `last_referenced_at`; a delete by digest removes it.
    #[tokio::test]
    async fn persist_tag_and_refs_dual_writes_oci_manifests() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let subject = format!("sha256:{}", "b".repeat(64));
        let body = referrer_body(&subject);
        let digest = compute_sha256(&body);

        persist_image(&fx.pool, fx.repo_id, "sig", &digest, &body).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;

        // Backdate both timestamps so the refresh is observable without a sleep.
        sqlx::query(
            "UPDATE oci_manifests SET created_at = NOW() - INTERVAL '1 day', \
             last_referenced_at = NOW() - INTERVAL '1 day' \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .execute(&fx.pool)
        .await
        .unwrap();
        let (created_before, referenced_before) =
            manifest_times(&fx.pool, fx.repo_id, &digest).await;
        persist_image(&fx.pool, fx.repo_id, "sig2", &digest, &body).await;
        let (created_after, referenced_after) = manifest_times(&fx.pool, fx.repo_id, &digest).await;

        delete(&fx.pool, fx.repo_id, &digest, &digest, true).await;
        let after_delete = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert_eq!(
            row,
            Some((IMAGE.to_string(), body.len() as i64, Some(subject))),
            "a committed manifest must have its oci_manifests row"
        );
        assert_eq!(
            created_after, created_before,
            "re-push must keep created_at"
        );
        assert!(
            referenced_after > referenced_before,
            "re-push must advance last_referenced_at"
        );
        assert_eq!(
            after_delete, None,
            "DELETE by digest must forget the manifest"
        );
    }

    /// What a push leaves behind besides the index rows: the `artifacts` row
    /// at `v2/app/manifests/<reference>`.
    async fn push_image(pool: &PgPool, repo_id: Uuid, reference: &str, digest: &str, body: &[u8]) {
        persist_image(pool, repo_id, reference, digest, body).await;
        crate::api::handlers::oci_v2::upsert_manifest_artifact(
            pool,
            repo_id,
            "app",
            reference,
            digest,
            IMAGE,
            &manifest_storage_key(digest),
            body.len() as i64,
            None,
            None,
        )
        .await
        .expect("upsert manifest artifact");
    }

    #[test]
    fn delete_removes_record_when_the_manifest_is_named_or_left_unaddressable() {
        let d = "sha256:abc";
        assert!(delete_removes_record(true, d, d, true));
        assert!(delete_removes_record(false, d, d, true));
        // #4449: the last tag of a tag-only image goes with its record.
        assert!(delete_removes_record(false, "latest", d, false));
        // A by-digest row still serves it: the record stays.
        assert!(!delete_removes_record(false, "latest", d, true));
    }

    #[test]
    fn live_row_check_excludes_the_deleted_row_and_uses_the_reindex_shape() {
        assert!(LIVE_MANIFEST_ROW_REMAINS_SQL.contains("a.path <> $3"));
        assert!(LIVE_MANIFEST_ROW_REMAINS_SQL.contains("a.is_deleted = false"));
        assert!(LIVE_MANIFEST_ROW_REMAINS_SQL
            .contains(crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!()));
    }

    /// #4449: deleting the LAST tag of an image pushed only by tag leaves the
    /// manifest unpullable by digest (no tag, no edge, no live `artifacts`
    /// row), so its `oci_manifests` row goes too. An image also pushed by
    /// digest keeps a live by-digest row, stays pullable and keeps its record.
    /// A named delete whose reference is the digest (REST delete of a
    /// by-digest artifact) removes the record.
    #[tokio::test]
    async fn last_tag_delete_removes_row_only_when_nothing_addresses_the_manifest() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        // Tag only: the last tag delete forgets the manifest.
        let tag_only = image_body("tag-only");
        let tag_only_digest = compute_sha256(&tag_only);
        push_image(&fx.pool, fx.repo_id, "v1", &tag_only_digest, &tag_only).await;
        delete(&fx.pool, fx.repo_id, "v1", &tag_only_digest, false).await;
        let tag_only_row = manifest_row(&fx.pool, fx.repo_id, &tag_only_digest).await;

        // Two tags: the first tag delete is not the last one.
        let two = image_body("two-tags");
        let two_digest = compute_sha256(&two);
        push_image(&fx.pool, fx.repo_id, "a", &two_digest, &two).await;
        push_image(&fx.pool, fx.repo_id, "b", &two_digest, &two).await;
        delete(&fx.pool, fx.repo_id, "a", &two_digest, false).await;
        let two_after_first = manifest_row(&fx.pool, fx.repo_id, &two_digest).await;
        delete(&fx.pool, fx.repo_id, "b", &two_digest, false).await;
        let two_after_last = manifest_row(&fx.pool, fx.repo_id, &two_digest).await;

        // Tag + digest: the digest row is a tag in `oci_tags` too, so the tag
        // delete is not the last; then the REST-style named delete of the
        // digest removes the record.
        let both = image_body("tag-and-digest");
        let both_digest = compute_sha256(&both);
        push_image(&fx.pool, fx.repo_id, "v1", &both_digest, &both).await;
        push_image(&fx.pool, fx.repo_id, &both_digest, &both_digest, &both).await;
        delete(&fx.pool, fx.repo_id, "v1", &both_digest, false).await;
        let both_after_tag = manifest_row(&fx.pool, fx.repo_id, &both_digest).await;
        delete(&fx.pool, fx.repo_id, &both_digest, &both_digest, false).await;
        let both_after_digest = manifest_row(&fx.pool, fx.repo_id, &both_digest).await;

        // Last tag gone, but a live migrated row (not yet indexed) holds the
        // digest: the record stays for the reindex to pick up.
        let migrated = image_body("migrated");
        let migrated_digest = compute_sha256(&migrated);
        push_image(&fx.pool, fx.repo_id, "v1", &migrated_digest, &migrated).await;
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, 'app/v1/manifest.json', 'app', 1, $2, $3, $4)",
        )
        .bind(fx.repo_id)
        .bind(migrated_digest.trim_start_matches("sha256:"))
        .bind(IMAGE)
        .bind(manifest_storage_key(&migrated_digest))
        .execute(&fx.pool)
        .await
        .expect("seed migrated row");
        delete(&fx.pool, fx.repo_id, "v1", &migrated_digest, false).await;
        let migrated_row = manifest_row(&fx.pool, fx.repo_id, &migrated_digest).await;
        fx.teardown().await;

        assert_eq!(
            tag_only_row, None,
            "#4449: tag-only image, last tag deleted"
        );
        assert!(
            two_after_first.is_some(),
            "a sibling tag keeps the manifest"
        );
        assert_eq!(two_after_last, None, "the last of two tags");
        assert!(
            both_after_tag.is_some(),
            "a tag delete must not forget a manifest still pullable by digest"
        );
        assert_eq!(both_after_digest, None);
        assert!(
            migrated_row.is_some(),
            "a live manifest row for the digest keeps the record"
        );
    }

    /// #4449 with an index: deleting the index's last tag forgets the index.
    /// Deleting the last tag of a child still referenced by ANOTHER tagged
    /// index keeps the child's record (the live parent edge, which also keeps
    /// it pullable), and the other index keeps its own.
    #[tokio::test]
    async fn last_tag_delete_of_index_keeps_shared_child_row() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let child = image_body("shared-child-4449");
        let child_digest = compute_sha256(&child);
        let doomed = index_body(&[&child_digest]);
        let doomed_digest = compute_sha256(&doomed);
        let keeper = format!(
            r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":[{{"mediaType":"{IMAGE}","digest":"{child_digest}","size":10}}],"annotations":{{"k":"keeper"}}}}"#
        )
        .into_bytes();
        let keeper_digest = compute_sha256(&keeper);
        // The child was pushed by its own tag `c1` (index rows + artifacts
        // row), and both indexes reference it.
        push_image(&fx.pool, fx.repo_id, "c1", &child_digest, &child).await;
        for (tag, digest, body) in [
            ("v1", &doomed_digest, &doomed),
            ("v2", &keeper_digest, &keeper),
        ] {
            persist_tag_and_refs(
                &fx.pool,
                fx.repo_id,
                "app",
                tag,
                digest,
                INDEX,
                &ManifestClass::Index,
                body,
            )
            .await
            .expect("persist index");
        }

        delete(&fx.pool, fx.repo_id, "v1", &doomed_digest, false).await;
        // The child's own last tag: nothing but the keeper's edge addresses it.
        delete(&fx.pool, fx.repo_id, "c1", &child_digest, false).await;
        let doomed_row = manifest_row(&fx.pool, fx.repo_id, &doomed_digest).await;
        let keeper_row = manifest_row(&fx.pool, fx.repo_id, &keeper_digest).await;
        let child_row = manifest_row(&fx.pool, fx.repo_id, &child_digest).await;
        fx.teardown().await;

        assert_eq!(doomed_row, None, "the untagged index is gone");
        assert!(keeper_row.is_some());
        assert!(
            child_row.is_some(),
            "the shared child of a live index stays"
        );
    }

    /// Deleting a child manifest by digest while its parent index is still
    /// tagged forgets the child (#1683: the readers answer 404 for it, so its
    /// row goes with it), while the tagged index's edge to it stays, as the
    /// index still names it (#1642).
    #[tokio::test]
    async fn delete_by_digest_forgets_child_of_live_index_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let child = image_body("child-of-live");
        let child_digest = compute_sha256(&child);
        let index = index_body(&[&child_digest]);
        let index_digest = compute_sha256(&index);
        persist_image(&fx.pool, fx.repo_id, &child_digest, &child_digest, &child).await;
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "multi",
            &index_digest,
            INDEX,
            &ManifestClass::Index,
            &index,
        )
        .await
        .expect("persist index");

        delete(&fx.pool, fx.repo_id, &child_digest, &child_digest, true).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &child_digest).await;
        let edges: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_manifest_refs WHERE repository_id = $1 AND child_digest = $2",
        )
        .bind(fx.repo_id)
        .bind(&child_digest)
        .fetch_one(&fx.pool)
        .await
        .expect("count edges");
        fx.teardown().await;
        assert_eq!(row, None, "a child deleted by digest is forgotten");
        assert_eq!(edges, 1, "the tagged index's edge to it stays");
    }

    /// The backfill records pre-existing manifests across several keyset pages:
    /// a tagged index (empty legacy content type, so the type comes from the
    /// body; `created_at` from the earliest tag time) and its locally stored
    /// child. It skips a child that is only referenced (no local body), counts
    /// a tag whose body is missing as a failure, and leaves an
    /// already-recorded manifest alone. A second pass is a no-op.
    #[tokio::test]
    async fn backfill_records_pre_existing_manifests() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let child = image_body("child");
        let child_digest = compute_sha256(&child);
        let remote_only_child = format!("sha256:{}", "d".repeat(64));
        let index = index_body(&[&child_digest, &remote_only_child]);
        let index_digest = compute_sha256(&index);
        let missing_digest = format!("sha256:{}", "f".repeat(64));
        let already = image_body("already");
        let already_digest = compute_sha256(&already);

        for (d, b) in [
            (&child_digest, &child),
            (&index_digest, &index),
            (&already_digest, &already),
        ] {
            seed_body(&fx, d, b).await;
        }
        seed_tag(&fx.pool, fx.repo_id, "latest", &index_digest, "").await;
        seed_tag(&fx.pool, fx.repo_id, "gone", &missing_digest, IMAGE).await;
        seed_tag(&fx.pool, fx.repo_id, "already", &already_digest, IMAGE).await;
        // A second, older tag on the index: the row must be dated to it.
        let tagged_at: Ts = sqlx::query_scalar(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, \
             manifest_content_type, created_at, updated_at) \
             VALUES ($1, 'app', 'old', $2, '', NOW() - INTERVAL '30 days', \
                     NOW() - INTERVAL '30 days') RETURNING created_at",
        )
        .bind(fx.repo_id)
        .bind(&index_digest)
        .fetch_one(&fx.pool)
        .await
        .expect("seed old tag");
        for c in [&child_digest, &remote_only_child] {
            sqlx::query(
                "INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id) \
                 VALUES ($1, $2, $3)",
            )
            .bind(&index_digest)
            .bind(c)
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("seed ref");
        }
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, $2, 'app', $3, $4, $5, $6)",
        )
        .bind(fx.repo_id)
        .bind(format!("v2/app/manifests/{child_digest}"))
        .bind(child.len() as i64)
        .bind(child_digest.trim_start_matches("sha256:"))
        .bind(IMAGE)
        .bind(manifest_storage_key(&child_digest))
        .execute(&fx.pool)
        .await
        .expect("seed child artifact");
        {
            let mut conn = fx.pool.acquire().await.unwrap();
            upsert_in_tx(
                &mut conn,
                fx.repo_id,
                &already_digest,
                &ManifestRecord::from_body(DOCKER_IMAGE, &already),
            )
            .await
            .expect("pre-existing row");
        }

        let registry = fs_registry();
        // Page size 1 so the keyset cursor is exercised across pages.
        let first = run_backfill_scoped(&fx.pool, &registry, Some(fx.repo_id), 1).await;
        let second = run_backfill_scoped(&fx.pool, &registry, Some(fx.repo_id), 1).await;

        let index_row = manifest_row(&fx.pool, fx.repo_id, &index_digest).await;
        let (index_created, _) = manifest_times(&fx.pool, fx.repo_id, &index_digest).await;
        let child_row = manifest_row(&fx.pool, fx.repo_id, &child_digest).await;
        let remote_row = manifest_row(&fx.pool, fx.repo_id, &remote_only_child).await;
        let missing_row = manifest_row(&fx.pool, fx.repo_id, &missing_digest).await;
        let already_row = manifest_row(&fx.pool, fx.repo_id, &already_digest).await;
        fx.teardown().await;

        assert_eq!(
            first,
            BackfillStats {
                candidates_scanned: 3,
                rows_inserted: 2,
                candidates_failed: 1,
            },
            "index + local child inserted, missing body failed, remote-only child \
             and already-recorded manifest not candidates"
        );
        assert_eq!(
            second,
            BackfillStats {
                candidates_scanned: 1,
                rows_inserted: 0,
                candidates_failed: 1,
            },
            "only the unreadable manifest stays a candidate"
        );
        assert_eq!(
            index_row,
            Some((INDEX.to_string(), index.len() as i64, None))
        );
        assert_eq!(
            index_created, tagged_at,
            "created_at is the earliest tag time"
        );
        assert_eq!(
            child_row,
            Some((IMAGE.to_string(), child.len() as i64, None))
        );
        assert_eq!(remote_row, None);
        assert_eq!(missing_row, None);
        assert_eq!(already_row.map(|r| r.0), Some(DOCKER_IMAGE.to_string()));
    }

    /// A row a live push wrote between the candidate scan and the insert wins:
    /// the backfill reports `Ok(false)` and leaves it untouched.
    #[tokio::test]
    async fn process_candidate_never_overwrites_a_live_row() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("raced");
        let digest = compute_sha256(&body);
        seed_body(&fx, &digest, &body).await;
        seed_tag(&fx.pool, fx.repo_id, "raced", &digest, IMAGE).await;
        {
            let mut conn = fx.pool.acquire().await.unwrap();
            upsert_in_tx(
                &mut conn,
                fx.repo_id,
                &digest,
                &ManifestRecord::from_body(DOCKER_IMAGE, &body),
            )
            .await
            .unwrap();
        }
        let outcome = process_candidate(&fx.pool, &fs_registry(), &candidate(&fx, &digest)).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;
        assert_eq!(outcome, Ok(false));
        assert_eq!(row.map(|r| r.0), Some(DOCKER_IMAGE.to_string()));
    }

    /// A manifest deleted after the candidate scan (its tags gone, body still in
    /// storage) is not resurrected by the insert.
    #[tokio::test]
    async fn process_candidate_skips_manifest_deleted_after_scan() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("deleted-mid-pass");
        let digest = compute_sha256(&body);
        seed_body(&fx, &digest, &body).await;
        seed_tag(&fx.pool, fx.repo_id, "t", &digest, IMAGE).await;
        let page = select_page(
            &fx.pool,
            fx.repo_id,
            &candidate(&fx, &digest).location,
            "",
            10,
        )
        .await
        .expect("scan");
        delete(&fx.pool, fx.repo_id, &digest, &digest, true).await;
        let outcome = process_candidate(&fx.pool, &fs_registry(), &page[0]).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;
        assert_eq!(page.len(), 1);
        assert_eq!(outcome, Ok(false));
        assert_eq!(row, None, "a deleted manifest must not be backfilled");
    }

    #[tokio::test]
    async fn backfill_rejects_body_that_does_not_match_digest() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let claimed = format!("sha256:{}", "9".repeat(64));
        seed_body(&fx, &claimed, &image_body("tampered")).await;
        seed_tag(&fx.pool, fx.repo_id, "x", &claimed, IMAGE).await;
        let stats = run_backfill_scoped(&fx.pool, &fs_registry(), Some(fx.repo_id), 10).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &claimed).await;
        fx.teardown().await;
        assert_eq!(stats.candidates_failed, 1);
        assert_eq!(row, None);
    }

    /// Only one replica runs the pass: with the lock held elsewhere,
    /// `run_backfill` returns immediately without scanning.
    #[tokio::test]
    async fn run_backfill_skips_when_another_replica_holds_the_lock() {
        // The backfill lock is shared with the reconcile tests below.
        let _serial = tdh::oci_reindex_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lease = PgAdvisoryLock::new(pool.clone())
            .try_acquire(BACKFILL_LOCK_CLASS, 0)
            .await
            .expect("lock query")
            .expect("lock free in this test");
        let stats = run_backfill(&pool, Arc::new(fs_registry())).await;
        lease.release().await;
        assert_eq!(stats, BackfillStats::default());
    }

    // -----------------------------------------------------------------------
    // #1683 reconcile
    // -----------------------------------------------------------------------

    /// Backdate a row past the reconcile's minimum row age.
    async fn age_row(pool: &PgPool, repo_id: Uuid, digest: &str) {
        sqlx::query(
            "UPDATE oci_manifests SET created_at = NOW() - INTERVAL '1 day', \
             last_referenced_at = NOW() - INTERVAL '1 day' \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(digest)
        .execute(pool)
        .await
        .expect("age row");
    }

    async fn reconcile(fx: &tdh::Fixture) -> ReconcileStats {
        reconcile_unlocked(&fx.pool, &fs_registry(), Some(fx.repo_id), 2).await
    }

    /// #1683: a tag removed outside the manifest-delete handler (the lifecycle
    /// tag prune, the startup orphan-tag reconciliation, a pre-268 replica's
    /// delete) leaves a row for a manifest that 404s by digest. The reconcile
    /// removes it.
    ///
    /// FAILS ON MAIN: there is no reconcile and the row stays.
    #[tokio::test]
    async fn reconcile_removes_the_row_of_a_manifest_whose_tag_was_pruned_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("pruned-1683");
        let digest = compute_sha256(&body);
        persist_image(&fx.pool, fx.repo_id, "v1", &digest, &body).await;
        // What `CASCADE_OCI_TAGS_SQL` does: drop the tag row directly, without
        // the delete unwind, and leave the manifest row in the trash.
        expire_like_lifecycle(&fx.pool, fx.repo_id, "v1", &digest).await;
        age_row(&fx.pool, fx.repo_id, &digest).await;

        let stats = reconcile(&fx).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert_eq!(
            row, None,
            "the unaddressable manifest's row must go: {stats:?}"
        );
        assert_eq!(stats.rows_removed, 1);
    }

    /// #1683: everything that still addresses a manifest keeps its row, and a
    /// young row is left alone even when nothing references it yet.
    #[tokio::test]
    async fn reconcile_keeps_every_addressable_manifest_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        // Tagged.
        let tagged = image_body("tagged-1683");
        let tagged_digest = compute_sha256(&tagged);
        persist_image(&fx.pool, fx.repo_id, "t1", &tagged_digest, &tagged).await;
        // Pushed by tag and by digest, then the tag removed: the live
        // `artifacts` row still serves it by digest.
        let by_digest = image_body("by-digest-1683");
        let by_digest_digest = compute_sha256(&by_digest);
        push_image(
            &fx.pool,
            fx.repo_id,
            &by_digest_digest,
            &by_digest_digest,
            &by_digest,
        )
        .await;
        sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2")
            .bind(fx.repo_id)
            .bind(&by_digest_digest)
            .execute(&fx.pool)
            .await
            .unwrap();
        // The untagged child of a tagged index.
        let child = image_body("child-1683");
        let child_digest = compute_sha256(&child);
        persist_image(&fx.pool, fx.repo_id, "c1", &child_digest, &child).await;
        let index = index_body(&[&child_digest]);
        let index_digest = compute_sha256(&index);
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "idx",
            &index_digest,
            INDEX,
            &ManifestClass::Index,
            &index,
        )
        .await
        .expect("persist index");
        sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1 AND tag = 'c1'")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        for d in [
            &tagged_digest,
            &by_digest_digest,
            &child_digest,
            &index_digest,
        ] {
            age_row(&fx.pool, fx.repo_id, d).await;
        }
        // Young and unreferenced: inside the minimum row age.
        let young = image_body("young-1683");
        let young_digest = compute_sha256(&young);
        persist_image(&fx.pool, fx.repo_id, "y1", &young_digest, &young).await;
        sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1 AND tag = 'y1'")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let stats = reconcile(&fx).await;
        let mut kept = Vec::new();
        for d in [
            &tagged_digest,
            &by_digest_digest,
            &child_digest,
            &index_digest,
            &young_digest,
        ] {
            kept.push(manifest_row(&fx.pool, fx.repo_id, d).await.is_some());
        }
        fx.teardown().await;

        assert_eq!(kept, vec![true; 5], "{stats:?}");
        assert_eq!(stats.rows_removed, 0);
    }

    /// #1683: the child of an index that is itself no longer addressable has
    /// no live edge, so both rows go once both are stale.
    #[tokio::test]
    async fn reconcile_removes_children_of_a_dead_index_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let child = image_body("orphan-child-1683");
        let child_digest = compute_sha256(&child);
        persist_image(&fx.pool, fx.repo_id, "c1", &child_digest, &child).await;
        let index = index_body(&[&child_digest]);
        let index_digest = compute_sha256(&index);
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "idx",
            &index_digest,
            INDEX,
            &ManifestClass::Index,
            &index,
        )
        .await
        .expect("persist index");
        // A lifecycle expiry of both: tags pruned, rows in the trash, the
        // index edge left behind.
        expire_like_lifecycle(&fx.pool, fx.repo_id, "c1", &child_digest).await;
        expire_like_lifecycle(&fx.pool, fx.repo_id, "idx", &index_digest).await;
        age_row(&fx.pool, fx.repo_id, &child_digest).await;
        age_row(&fx.pool, fx.repo_id, &index_digest).await;

        let stats = reconcile(&fx).await;
        let child_row = manifest_row(&fx.pool, fx.repo_id, &child_digest).await;
        let index_row = manifest_row(&fx.pool, fx.repo_id, &index_digest).await;
        fx.teardown().await;

        assert_eq!(child_row, None, "{stats:?}");
        assert_eq!(index_row, None);
    }

    /// #1683: the add half records a manifest the registry knows but has no
    /// row for (a push a pre-268 replica served during a rolling upgrade).
    #[tokio::test]
    async fn reconcile_adds_the_row_of_a_manifest_pushed_without_one_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("pre-268-push-1683");
        let digest = compute_sha256(&body);
        seed_tag(&fx.pool, fx.repo_id, "v1", &digest, IMAGE).await;
        seed_body(&fx, &digest, &body).await;

        let stats = reconcile(&fx).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert!(row.is_some(), "{stats:?}");
        assert_eq!(stats.added.rows_inserted, 1);
    }

    /// #1683 readers precondition (review of #4954): the child of an index of
    /// indexes. The top index is tagged; the middle index is untagged and
    /// kept only by the top index's edge; the leaf image is untagged and kept
    /// only by the middle index's edge. All three are pullable by digest, so
    /// all three rows stay. Neither child has an `artifacts` row or blob refs
    /// of its own here, so nothing but the edges can keep them.
    ///
    /// FAILS ON MAIN: the leaf's parent (the middle index) is neither tagged
    /// nor stored by a live `artifacts` row, so the leaf's edge does not count
    /// and its row is removed while the leaf is still served through the top
    /// index.
    #[tokio::test]
    async fn reconcile_keeps_the_leaf_of_an_index_of_indexes_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let leaf = image_body("leaf-1683");
        let leaf_digest = compute_sha256(&leaf);
        let middle = index_body(&[&leaf_digest]);
        let middle_digest = compute_sha256(&middle);
        let top = index_body(&[&middle_digest]);
        let top_digest = compute_sha256(&top);
        // The leaf and the middle index are recorded by digest pushes whose
        // tag rows a 1.11 replica's orphan-tag reconciliation removed: rows
        // and edges, no tags, no blob refs, no artifacts rows.
        for (digest, body, ct) in [
            (&leaf_digest, &leaf, IMAGE),
            (&middle_digest, &middle, INDEX),
        ] {
            let mut conn = fx.pool.acquire().await.unwrap();
            upsert_in_tx(
                &mut conn,
                fx.repo_id,
                digest,
                &ManifestRecord::from_body(ct, body),
            )
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(&middle_digest)
        .bind(&leaf_digest)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        // The top index: tagged, through the shared writer (records the
        // top -> middle edge and its row).
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "v1",
            &top_digest,
            INDEX,
            &ManifestClass::Index,
            &top,
        )
        .await
        .expect("persist top index");
        for d in [&leaf_digest, &middle_digest, &top_digest] {
            age_row(&fx.pool, fx.repo_id, d).await;
        }

        let stats = reconcile(&fx).await;
        let mut kept = Vec::new();
        for d in [&leaf_digest, &middle_digest, &top_digest] {
            kept.push(manifest_row(&fx.pool, fx.repo_id, d).await.is_some());
        }
        fx.teardown().await;

        assert_eq!(kept, vec![true; 3], "leaf, middle, top: {stats:?}");
        assert_eq!(stats.rows_removed, 0);
    }

    /// #1683 readers precondition (review of #4954): the child of a pre-#2457
    /// migrated index. The index is kept only by its live `artifacts` row
    /// under a generic CAS key (the checksum arm), so no key match finds it;
    /// its untagged child is kept only by the index's edge.
    ///
    /// FAILS ON MAIN: the edge counts only for a tagged parent or one stored at
    /// `oci-manifests/<digest>`, so the child's row is removed while the
    /// migrated index still serves it.
    #[tokio::test]
    async fn reconcile_keeps_the_child_of_a_checksum_only_index_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let child = image_body("migrated-child-1683");
        let child_digest = compute_sha256(&child);
        let index = index_body(&[&child_digest]);
        let index_digest = compute_sha256(&index);
        for (digest, body, ct) in [
            (&child_digest, &child, IMAGE),
            (&index_digest, &index, INDEX),
        ] {
            let mut conn = fx.pool.acquire().await.unwrap();
            upsert_in_tx(
                &mut conn,
                fx.repo_id,
                digest,
                &ManifestRecord::from_body(ct, body),
            )
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(&index_digest)
        .bind(&child_digest)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        // The migrated index's `artifacts` row: a generic CAS key, identified
        // only by its checksum.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, 'app/v1/list.manifest.json', 'app', 'v1', 10, $2, $3, $4)",
        )
        .bind(fx.repo_id)
        .bind(index_digest.strip_prefix("sha256:").unwrap())
        .bind(INDEX)
        .bind(format!(
            "cas/{}",
            index_digest.strip_prefix("sha256:").unwrap()
        ))
        .execute(&fx.pool)
        .await
        .unwrap();
        age_row(&fx.pool, fx.repo_id, &child_digest).await;
        age_row(&fx.pool, fx.repo_id, &index_digest).await;

        let stats = reconcile(&fx).await;
        let child_row = manifest_row(&fx.pool, fx.repo_id, &child_digest).await;
        let index_row = manifest_row(&fx.pool, fx.repo_id, &index_digest).await;
        fx.teardown().await;

        assert!(
            index_row.is_some(),
            "the migrated index keeps its row: {stats:?}"
        );
        assert!(child_row.is_some(), "its child keeps its row: {stats:?}");
        assert_eq!(stats.rows_removed, 0);
    }

    /// #1683 readers precondition: an image whose only tag moved to another
    /// digest is untagged with no `artifacts` row of its own (the tag's row
    /// now stores the new digest), yet a 1.11 reader still serves it by digest
    /// from its `manifest_blob_refs` rows (#1681). The row stays while that
    /// proof does; once the GC prunes the refs, the row goes.
    ///
    /// FAILS ON MAIN: the stale predicate ignores the blob refs and removes
    /// the row of a manifest a 1.11 replica still serves.
    #[tokio::test]
    async fn reconcile_keeps_an_overwritten_image_while_its_blob_refs_last_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let old = image_body("overwritten-old-1683");
        let old_digest = compute_sha256(&old);
        let new = image_body("overwritten-new-1683");
        let new_digest = compute_sha256(&new);
        persist_image(&fx.pool, fx.repo_id, "v1", &old_digest, &old).await;
        persist_image(&fx.pool, fx.repo_id, "v1", &new_digest, &new).await;
        age_row(&fx.pool, fx.repo_id, &old_digest).await;

        let first = reconcile(&fx).await;
        let kept = manifest_row(&fx.pool, fx.repo_id, &old_digest)
            .await
            .is_some();
        sqlx::query(
            "DELETE FROM manifest_blob_refs WHERE repository_id = $1 AND manifest_digest = $2",
        )
        .bind(fx.repo_id)
        .bind(&old_digest)
        .execute(&fx.pool)
        .await
        .unwrap();
        let second = reconcile(&fx).await;
        let after_prune = manifest_row(&fx.pool, fx.repo_id, &old_digest).await;
        fx.teardown().await;

        assert!(kept, "kept while its blob refs prove the push: {first:?}");
        assert_eq!(first.rows_removed, 0);
        assert_eq!(
            after_prune, None,
            "removed once the refs are gone: {second:?}"
        );
    }

    /// #1683: the GC's blob-ref prune retires the rows its refs were the only
    /// proof of, under the reconcile's re-check, and leaves rows that
    /// something else still keeps.
    #[tokio::test]
    async fn retire_rows_if_stale_removes_only_unproven_rows_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let gone = image_body("retire-gone-1683");
        let gone_digest = compute_sha256(&gone);
        let tagged = image_body("retire-tagged-1683");
        let tagged_digest = compute_sha256(&tagged);
        persist_image(&fx.pool, fx.repo_id, "a", &gone_digest, &gone).await;
        persist_image(&fx.pool, fx.repo_id, "b", &tagged_digest, &tagged).await;
        drop_tag_and_proof(&fx.pool, fx.repo_id, &gone_digest).await;
        age_row(&fx.pool, fx.repo_id, &gone_digest).await;
        age_row(&fx.pool, fx.repo_id, &tagged_digest).await;

        let removed = retire_rows_if_stale(
            &fx.pool,
            &[
                (fx.repo_id, gone_digest.clone()),
                (fx.repo_id, tagged_digest.clone()),
            ],
        )
        .await;
        let gone_row = manifest_row(&fx.pool, fx.repo_id, &gone_digest).await;
        let tagged_row = manifest_row(&fx.pool, fx.repo_id, &tagged_digest).await;
        fx.teardown().await;

        assert_eq!(removed, 1);
        assert_eq!(gone_row, None);
        assert!(tagged_row.is_some());
    }

    /// #1683 rolling upgrade: a row a 1.11 replica has just written is never
    /// removed, even before the reference that keeps it is visible: the 1.11
    /// push writes the row in the same transaction as its tag, but a row the
    /// reconcile reads in between (or one whose reference is written by a
    /// later statement) is inside the minimum row age.
    #[tokio::test]
    async fn reconcile_keeps_a_row_a_replica_just_wrote_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("fresh-1683");
        let digest = compute_sha256(&body);
        // The row alone, as the 1.11 dual-write leaves it before the tag is
        // visible to another transaction.
        let mut conn = fx.pool.acquire().await.unwrap();
        upsert_in_tx(
            &mut conn,
            fx.repo_id,
            &digest,
            &ManifestRecord::from_body(IMAGE, &body),
        )
        .await
        .unwrap();
        drop(conn);

        let stats = reconcile(&fx).await;
        let removed = remove_if_still_stale(&fx.pool, fx.repo_id, &digest)
            .await
            .unwrap();
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert!(row.is_some(), "{stats:?}");
        assert!(!removed);
        assert_eq!(stats.stale_found, 0);
    }

    /// #1683: the add half records a manifest a 1.11 reader serves by digest
    /// from its blob refs alone (its tag moved before migration 268, so it
    /// never had a row), and not one whose rows are all in the trash.
    #[tokio::test]
    async fn reconcile_adds_rows_for_manifests_proven_by_blob_refs_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let proven = image_body("proven-1683");
        let proven_digest = compute_sha256(&proven);
        let expired = image_body("expired-1683");
        let expired_digest = compute_sha256(&expired);
        for (tag, digest, body) in [
            ("p", &proven_digest, &proven),
            ("e", &expired_digest, &expired),
        ] {
            persist_image(&fx.pool, fx.repo_id, tag, digest, body).await;
            seed_body(&fx, digest, body).await;
        }
        sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2")
            .bind(fx.repo_id)
            .bind(&proven_digest)
            .execute(&fx.pool)
            .await
            .unwrap();
        expire_like_lifecycle(&fx.pool, fx.repo_id, "e", &expired_digest).await;
        sqlx::query("DELETE FROM oci_manifests WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();

        let stats = reconcile(&fx).await;
        let proven_row = manifest_row(&fx.pool, fx.repo_id, &proven_digest).await;
        let expired_row = manifest_row(&fx.pool, fx.repo_id, &expired_digest).await;
        fx.teardown().await;

        assert!(proven_row.is_some(), "{stats:?}");
        assert_eq!(expired_row, None, "{stats:?}");
        assert_eq!(stats.added.rows_inserted, 1);
    }

    /// #1683: a row found stale by the scan but re-tagged before its removal
    /// (a push of the same digest in between) is kept: the removal re-checks
    /// under the row lock.
    #[tokio::test]
    async fn reconcile_keeps_a_row_retagged_after_the_scan_1683() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("retagged-1683");
        let digest = compute_sha256(&body);
        persist_image(&fx.pool, fx.repo_id, "v1", &digest, &body).await;
        drop_tag_and_proof(&fx.pool, fx.repo_id, &digest).await;
        age_row(&fx.pool, fx.repo_id, &digest).await;
        let stale: Vec<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(&*stale_page_sql()))
            .bind(Uuid::nil())
            .bind("")
            .bind(10_i64)
            .bind(RECONCILE_MIN_ROW_AGE_SECS)
            .bind(Some(fx.repo_id))
            .fetch_all(&fx.pool)
            .await
            .unwrap();
        // The push lands between the scan and the removal.
        seed_tag(&fx.pool, fx.repo_id, "v2", &digest, IMAGE).await;
        let removed = remove_if_still_stale(&fx.pool, fx.repo_id, &digest)
            .await
            .unwrap();
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert_eq!(
            stale,
            vec![(fx.repo_id, digest.clone())],
            "the scan saw it stale"
        );
        assert!(!removed);
        assert!(row.is_some(), "the re-tagged manifest keeps its row");
    }

    /// #1683 review: the checksum arm must compare as `bpchar` so it can use
    /// `idx_artifacts_checksum`; the TEXT comparison cast the column and
    /// planned a scan of `artifacts` per `oci_manifests` row.
    #[test]
    fn stale_predicate_checksum_arm_is_index_friendly_1683() {
        assert!(
            ROW_IS_STALE_SQL.contains("a.checksum_sha256 = SUBSTRING(om.digest FROM 8)::bpchar")
        );
    }

    #[test]
    fn reconcile_interval_parses_1683() {
        assert_eq!(
            parse_reconcile_interval(None),
            RECONCILE_INTERVAL_SECS_DEFAULT
        );
        assert_eq!(parse_reconcile_interval(Some("0")), 0);
        assert_eq!(parse_reconcile_interval(Some(" 3600 ")), 3600);
        assert_eq!(
            parse_reconcile_interval(Some("soon")),
            RECONCILE_INTERVAL_SECS_DEFAULT
        );
    }

    /// #1683: the locked entry point runs the pass when it gets both locks,
    /// and releases them afterwards.
    #[tokio::test]
    async fn run_reconcile_takes_and_releases_both_locks_1683() {
        let _serial = tdh::oci_reindex_serial_lock().await;
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("locked-pass-1683");
        let digest = compute_sha256(&body);
        persist_image(&fx.pool, fx.repo_id, "v1", &digest, &body).await;
        drop_tag_and_proof(&fx.pool, fx.repo_id, &digest).await;
        age_row(&fx.pool, fx.repo_id, &digest).await;

        let stats = run_reconcile_scoped(&fx.pool, &fs_registry(), Some(fx.repo_id)).await;
        let locks = PgAdvisoryLock::new(fx.pool.clone());
        let mut free = true;
        for obj in [0, RECONCILE_LOCK_OBJ] {
            match locks.try_acquire(BACKFILL_LOCK_CLASS, obj).await {
                Ok(Some(lease)) => lease.release().await,
                _ => free = false,
            }
        }
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert_eq!(stats.map(|s| s.rows_removed), Some(1));
        assert_eq!(row, None);
        assert!(free, "both locks are released after the pass");
    }

    /// #1683: another replica holding either lock makes the pass a no-op, and
    /// a pass that got the first lock but not the second gives the first back.
    #[tokio::test]
    async fn run_reconcile_skips_while_another_replica_holds_a_lock_1683() {
        let _serial = tdh::oci_reindex_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let locks = PgAdvisoryLock::new(pool.clone());
        let registry = Arc::new(fs_registry());

        let backfill = locks
            .try_acquire(BACKFILL_LOCK_CLASS, 0)
            .await
            .expect("lock query")
            .expect("lock free in this test");
        let while_backfill_held = run_reconcile(&pool, registry.clone()).await;
        backfill.release().await;

        let reconcile = locks
            .try_acquire(BACKFILL_LOCK_CLASS, RECONCILE_LOCK_OBJ)
            .await
            .expect("lock query")
            .expect("lock free in this test");
        let while_reconcile_held = run_reconcile(&pool, registry.clone()).await;
        let backfill_given_back = locks
            .try_acquire(BACKFILL_LOCK_CLASS, 0)
            .await
            .expect("lock query");
        let given_back = backfill_given_back.is_some();
        if let Some(lease) = backfill_given_back {
            lease.release().await;
        }
        reconcile.release().await;

        assert_eq!(while_backfill_held, None);
        assert_eq!(while_reconcile_held, None);
        assert!(
            given_back,
            "the backfill lock is released when the second is busy"
        );
    }

    /// #1683: with the schedule disabled (`0`), maintenance runs its one
    /// startup pass and returns.
    #[tokio::test]
    async fn maintenance_with_the_schedule_disabled_returns_after_one_pass_1683() {
        let _serial = tdh::oci_reindex_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Hold the lock so the pass is a cheap no-op rather than instance-wide.
        let lease = PgAdvisoryLock::new(pool.clone())
            .try_acquire(BACKFILL_LOCK_CLASS, 0)
            .await
            .expect("lock query")
            .expect("lock free in this test");
        let finished = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            run_maintenance_every(pool.clone(), Arc::new(fs_registry()), 0),
        )
        .await;
        lease.release().await;
        assert!(
            finished.is_ok(),
            "maintenance must return when the schedule is off"
        );
    }
}
