//! Per-image scoping of hosted OCI digests (#5793).
//!
//! In the OCI Distribution Spec `<name>` is `<repository key>/<image>`, and
//! `GET`/`HEAD /v2/<name>/manifests/<digest>` and `/v2/<name>/blobs/<digest>`
//! answer 404 when the digest is not in `<name>`. Every per-digest table of
//! a hosted repository (`oci_manifests`, `oci_blobs`, `manifest_blob_refs`)
//! is repository-wide, so before this a digest resolved under any image name
//! in the repository, including one that was never pushed. Migration 363 adds
//! the per-image links this module owns:
//!
//! * `oci_image_manifests`: a manifest committed under an image. Written by
//!   [`persist_tag_and_refs_in_tx`](crate::api::handlers::oci_v2::persist_tag_and_refs_in_tx)
//!   (push, proxy cache, replication, promotion, migration import, reindex),
//!   so it outlives a tag overwrite and the old digest of an overwritten tag
//!   stays pullable under its image (#1681). A delete by digest under the
//!   image removes it ([`unlink_manifest_in_tx`]), and the row cascades with
//!   the repository's `oci_manifests` row.
//! * `oci_image_blobs`: a blob uploaded or mounted under an image
//!   ([`link_blob`]). A blob a manifest of the image references resolves
//!   without one (the read inserts it lazily), so the replication, promotion
//!   and migration blob writers need none. Cascades with `oci_blobs`.
//! * `oci_image_scope_backfill`: the repositories whose pre-363 content
//!   [`run_backfill`] has attributed. Until a repository has a row, the reads
//!   keep the old repository-wide rule ([`scope_enforced`]), so an upgrade
//!   never answers 404 for content the backfill has not reached yet.
//!
//! The legacy marker: the first backfill of a repository writes one
//! `oci_image_manifests` row with `image = ''` for every manifest it cannot
//! attribute to an image. That is the old digest of a tag overwritten before
//! the upgrade, which no row names any more. It resolves under an image that
//! already holds content in the repository ([`legacy_applies`]), so a
//! pre-upgrade `<image>@<old digest>` pin keeps working, but never under a
//! name that holds nothing. Nothing writes a marker after the first backfill.
//!
//! The backfill runs from the `oci_manifests` maintenance job
//! ([`run_reconcile`](crate::services::oci_manifests::run_reconcile)) at
//! startup and on its schedule. Each pass re-attributes rows written since the
//! previous one, so a push served by a 1.11 replica during a rolling upgrade
//! (which writes no link) gets its link on the next pass.

use std::sync::OnceLock;

use sqlx::PgPool;
use uuid::Uuid;

/// The image name of a legacy marker row ([`legacy_applies`]).
pub(crate) const LEGACY_IMAGE: &str = "";

/// How far before the previous pass a recurring backfill pass re-reads rows,
/// so a transaction that started before that pass and committed after it
/// (its `NOW()` is its start time) is still picked up.
const RESCAN_SLACK: &str = "1 hour";

/// Deepest index nesting the backfill's child attribution follows; matches
/// the read's ancestor walk.
const MAX_CHILD_DEPTH: usize = 8;

/// Rows per page of the backfill's `artifacts` scan.
const ARTIFACT_PAGE_SIZE: i64 = 1000;

/// `AK_OCI_BLOB_SCOPE`: what a blob read under an image that does not hold
/// the blob does. A temporary rollback switch for #5793, to be removed in
/// 1.13.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobScopeMode {
    /// Answer `404 BLOB_UNKNOWN` (the default).
    Enforce,
    /// Serve the blob as before, count `ak_oci_blob_scope_misses_total` and
    /// log a warning, so an operator can see what enforcement would refuse.
    Report,
}

/// Parse `AK_OCI_BLOB_SCOPE`. Unset, empty or anything but `report` means
/// [`BlobScopeMode::Enforce`].
pub(crate) fn parse_blob_scope_mode(raw: Option<&str>) -> BlobScopeMode {
    match raw.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v == "report" => BlobScopeMode::Report,
        _ => BlobScopeMode::Enforce,
    }
}

/// The process's [`BlobScopeMode`], read from the environment once.
pub(crate) fn blob_scope_mode() -> BlobScopeMode {
    static MODE: OnceLock<BlobScopeMode> = OnceLock::new();
    *MODE.get_or_init(|| {
        let mode = parse_blob_scope_mode(std::env::var("AK_OCI_BLOB_SCOPE").ok().as_deref());
        if mode == BlobScopeMode::Report {
            tracing::warn!(
                "AK_OCI_BLOB_SCOPE=report: hosted OCI blob reads are NOT scoped to the image \
                 name; misses are only counted (ak_oci_blob_scope_misses_total). This switch \
                 is temporary and will be removed in 1.13."
            );
        }
        mode
    })
}

/// Whether repository `repo_id` resolves digests per image: its pre-363
/// content has been backfilled. Until then the reads keep the old
/// repository-wide rule.
pub(crate) async fn scope_enforced<'e, E>(executor: E, repo_id: Uuid) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_image_scope_backfill WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .fetch_one(executor)
    .await
}

/// Mark a repository that holds no manifest other than `digest` as
/// backfilled, inside the transaction committing `digest`'s first push: a
/// repository with no pre-363 content has nothing to backfill, and waiting
/// for the next maintenance pass would leave its first pushes resolvable
/// under any name. A no-op for a repository already marked or holding other
/// manifests (the backfill marks those).
pub(crate) async fn mark_if_new_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO oci_image_scope_backfill (repository_id, last_scanned_at) \
         SELECT $1, NOW() \
         WHERE NOT EXISTS (SELECT 1 FROM oci_image_scope_backfill WHERE repository_id = $1) \
           AND NOT EXISTS (SELECT 1 FROM oci_manifests \
                           WHERE repository_id = $1 AND digest <> $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(repo_id)
    .bind(digest)
    .execute(conn)
    .await?;
    Ok(())
}

/// Record that `image` holds manifest `digest`. A no-op when the repository
/// has no `oci_manifests` row for it (the link references that row) or the
/// link exists. Runs inside the caller's transaction on the push path.
pub(crate) async fn link_manifest<'e, E>(
    executor: E,
    repo_id: Uuid,
    image: &str,
    digest: &str,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO oci_image_manifests (repository_id, image, digest) \
         SELECT m.repository_id, $2, m.digest FROM oci_manifests m \
         WHERE m.repository_id = $1 AND m.digest = $3 \
         ON CONFLICT DO NOTHING",
    )
    .bind(repo_id)
    .bind(image)
    .bind(digest)
    .execute(executor)
    .await?;
    Ok(())
}

/// Record that `image` holds blob `digest` (an upload or mount under it). A
/// no-op when the repository has no `oci_blobs` row for it.
pub(crate) async fn link_blob<'e, E>(
    executor: E,
    repo_id: Uuid,
    image: &str,
    digest: &str,
) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO oci_image_blobs (repository_id, image, digest) \
         SELECT b.repository_id, $2, b.digest FROM oci_blobs b \
         WHERE b.repository_id = $1 AND b.digest = $3 \
         ON CONFLICT DO NOTHING",
    )
    .bind(repo_id)
    .bind(image)
    .bind(digest)
    .execute(executor)
    .await?;
    Ok(())
}

/// Drop `image`'s link to manifest `digest` on a delete, inside the delete's
/// transaction (after its `oci_tags` rows are gone).
///
/// * By digest (`by_digest`): the manifest is deleted under the image, so the
///   link goes, and so does the digest's legacy marker, or the marker would
///   keep serving it under the image the delete just named (#4525).
/// * By tag: the link goes only once no tag of the image (a by-digest push
///   records one too) names the digest. A tag overwrite is not a delete and
///   keeps the link (#1681).
pub(crate) async fn unlink_manifest_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    image: &str,
    digest: &str,
    by_digest: bool,
) -> sqlx::Result<()> {
    if by_digest {
        sqlx::query(
            "DELETE FROM oci_image_manifests \
             WHERE repository_id = $1 AND digest = $3 AND image IN ($2, '')",
        )
        .bind(repo_id)
        .bind(image)
        .bind(digest)
        .execute(conn)
        .await?;
    } else {
        sqlx::query(
            "DELETE FROM oci_image_manifests l \
             WHERE l.repository_id = $1 AND l.image = $2 AND l.digest = $3 \
               AND NOT EXISTS (SELECT 1 FROM oci_tags t \
                               WHERE t.repository_id = $1 AND t.name = $2 \
                                 AND t.manifest_digest = $3)",
        )
        .bind(repo_id)
        .bind(image)
        .bind(digest)
        .execute(conn)
        .await?;
    }
    Ok(())
}

/// Drop the links of images that no longer hold their manifest: no tag of
/// the image names it, and the image's manifest rows for those bytes are all
/// in the trash (the #4525 "deleted under this image" state a lifecycle
/// prune, a REST delete or a 1.11 replica's delete leaves). The read already
/// answers 404 for that state; dropping the link keeps the answer once the
/// trashed rows are purged. A tag overwrite leaves no trashed row, so its
/// old digest keeps its link (#1681). `repo_id` `None` sweeps every
/// repository.
pub(crate) async fn unlink_deleted_manifests<'e, E>(
    executor: E,
    repo_id: Option<Uuid>,
) -> sqlx::Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(UNLINK_DELETED_MANIFESTS_SQL)
        .bind(repo_id)
        .execute(executor)
        .await?
        .rows_affected())
}

const UNLINK_DELETED_MANIFESTS_SQL: &str = r#"
    DELETE FROM oci_image_manifests l
    WHERE ($1::uuid IS NULL OR l.repository_id = $1)
      AND l.image <> ''
      AND l.digest LIKE 'sha256:%'
      AND NOT EXISTS (SELECT 1 FROM oci_tags t
                      WHERE t.repository_id = l.repository_id AND t.name = l.image
                        AND t.manifest_digest = l.digest)
      AND EXISTS (SELECT 1 FROM artifacts a
                  WHERE a.repository_id = l.repository_id
                    AND a.checksum_sha256 = SUBSTRING(l.digest FROM 8)::bpchar
                    AND a.is_deleted = true
                    AND starts_with(a.path, 'v2/' || l.image || '/manifests/'))
      AND NOT EXISTS (SELECT 1 FROM artifacts a
                      WHERE a.repository_id = l.repository_id
                        AND a.checksum_sha256 = SUBSTRING(l.digest FROM 8)::bpchar
                        AND a.is_deleted = false
                        AND starts_with(a.path, 'v2/' || l.image || '/manifests/'))
"#;

/// Whether `image` holds a link to manifest `digest`.
pub(crate) async fn manifest_linked(
    db: &PgPool,
    repo_id: Uuid,
    image: &str,
    digest: &str,
) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_image_manifests \
                        WHERE repository_id = $1 AND image = $2 AND digest = $3)",
    )
    .bind(repo_id)
    .bind(image)
    .bind(digest)
    .fetch_one(db)
    .await
}

/// The legacy arm: `digest` carries the backfill's legacy marker and `image`
/// already holds content in the repository (a manifest link or a tag). The
/// caller has already checked that none of the image's manifest rows for the
/// digest is in the trash (#4525).
pub(crate) async fn legacy_applies(
    db: &PgPool,
    repo_id: Uuid,
    image: &str,
    digest: &str,
) -> sqlx::Result<bool> {
    if image == LEGACY_IMAGE {
        return Ok(false);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_image_manifests \
                        WHERE repository_id = $1 AND image = '' AND digest = $3) \
            AND (EXISTS (SELECT 1 FROM oci_image_manifests \
                         WHERE repository_id = $1 AND image = $2) \
                 OR EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = $1 AND name = $2))",
    )
    .bind(repo_id)
    .bind(image)
    .bind(digest)
    .fetch_one(db)
    .await
}

/// What the cheap half of a blob read's scope check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlobLinkState {
    /// The repository has an `oci_blobs` row for the digest.
    pub blob_exists: bool,
    /// The image has an `oci_image_blobs` link to the blob (an upload or
    /// mount under it, or an earlier read that derived it).
    pub linked: bool,
    /// A manifest the image holds directly (a link or a tag) references the
    /// blob.
    pub referenced: bool,
}

/// One query: whether the blob exists in the repository, whether `image` has
/// a blob link to it, and whether a manifest the image holds directly
/// references it. A blob reachable only through an index ancestor or a
/// legacy marker is left to the caller's manifest resolution
/// ([`blob_candidate_manifests`]).
const BLOB_LINK_STATE_SQL: &str = r#"
    SELECT
        EXISTS (SELECT 1 FROM oci_blobs b WHERE b.repository_id = $1 AND b.digest = $3)
            AS blob_exists,
        EXISTS (SELECT 1 FROM oci_image_blobs l
                WHERE l.repository_id = $1 AND l.image = $2 AND l.digest = $3)
            AS linked,
        EXISTS (
            SELECT 1 FROM manifest_blob_refs mbr
            WHERE mbr.blob_digest = $3 AND mbr.repository_id = $1
              AND (
                    EXISTS (SELECT 1 FROM oci_image_manifests ml
                            WHERE ml.repository_id = $1 AND ml.image = $2
                              AND ml.digest = mbr.manifest_digest)
                 OR EXISTS (SELECT 1 FROM oci_tags t
                            WHERE t.repository_id = $1 AND t.name = $2
                              AND t.manifest_digest = mbr.manifest_digest)
              )
        ) AS referenced
"#;

/// [`BLOB_LINK_STATE_SQL`] for one blob read.
pub(crate) async fn blob_link_state(
    db: &PgPool,
    repo_id: Uuid,
    image: &str,
    digest: &str,
) -> sqlx::Result<BlobLinkState> {
    let (blob_exists, linked, referenced): (bool, bool, bool) = sqlx::query_as(BLOB_LINK_STATE_SQL)
        .bind(repo_id)
        .bind(image)
        .bind(digest)
        .fetch_one(db)
        .await?;
    Ok(BlobLinkState {
        blob_exists,
        linked,
        referenced,
    })
}

/// Up to `limit` manifests of the repository that reference blob `digest`,
/// for the caller to resolve under the image one by one (an index child or a
/// legacy-marked manifest).
pub(crate) async fn blob_candidate_manifests(
    db: &PgPool,
    repo_id: Uuid,
    digest: &str,
    limit: i64,
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT DISTINCT manifest_digest FROM manifest_blob_refs \
         WHERE blob_digest = $2 AND repository_id = $1 \
         ORDER BY manifest_digest LIMIT $3",
    )
    .bind(repo_id)
    .bind(digest)
    .bind(limit)
    .fetch_all(db)
    .await
}

/// Count (and log) a hosted blob read under an image that does not hold the
/// blob. `mode` says whether the read was refused or, under
/// `AK_OCI_BLOB_SCOPE=report`, served anyway.
pub(crate) fn record_blob_scope_miss(
    repo_key: &str,
    image: &str,
    digest: &str,
    mode: BlobScopeMode,
) {
    let mode_label = match mode {
        BlobScopeMode::Enforce => "enforce",
        BlobScopeMode::Report => "report",
    };
    metrics::counter!("ak_oci_blob_scope_misses_total", "mode" => mode_label).increment(1);
    match mode {
        BlobScopeMode::Enforce => tracing::debug!(
            repo = %repo_key, image = %image, digest = %digest,
            "blob read under an image that does not hold it: 404 BLOB_UNKNOWN (#5793)"
        ),
        BlobScopeMode::Report => tracing::warn!(
            repo = %repo_key, image = %image, digest = %digest,
            "blob read under an image that does not hold it: served because \
             AK_OCI_BLOB_SCOPE=report (#5793)"
        ),
    }
}

// ---------------------------------------------------------------------------
// Backfill
// ---------------------------------------------------------------------------

/// What one [`run_backfill`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeBackfillStats {
    /// Hosted repositories visited.
    pub repositories: usize,
    /// Repositories whose first backfill completed in this pass (their reads
    /// switched to the per-image rule).
    pub repositories_completed: usize,
    /// Manifest links inserted (tags, manifest rows and index children).
    pub links_inserted: u64,
    /// Legacy markers inserted by first backfills.
    pub legacy_markers: u64,
    /// Repositories whose pass failed (logged, retried next pass).
    pub failed: usize,
}

/// Hosted repositories holding OCI content, optionally just one.
const HOSTED_OCI_REPOSITORIES_SQL: &str = r#"
    SELECT r.id
    FROM repositories r
    WHERE ($1::uuid IS NULL OR r.id = $1)
      AND r.repo_type IN ('local', 'staging')
      AND (
            EXISTS (SELECT 1 FROM oci_manifests m WHERE m.repository_id = r.id)
         OR EXISTS (SELECT 1 FROM oci_blobs b WHERE b.repository_id = r.id)
      )
    ORDER BY r.id
"#;

/// Attribute every hosted repository's manifests to the images that hold
/// them (or only `repository_id`'s). Best-effort and idempotent: a failure is
/// logged, counted and retried on the next pass. The caller holds the
/// `oci_manifests` maintenance lock.
pub async fn run_backfill(db: &PgPool, repository_id: Option<Uuid>) -> ScopeBackfillStats {
    let mut stats = ScopeBackfillStats::default();
    let repos: Vec<Uuid> = match sqlx::query_scalar(HOSTED_OCI_REPOSITORIES_SQL)
        .bind(repository_id)
        .fetch_all(db)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "oci image scope backfill: failed to list repositories");
            stats.failed += 1;
            return stats;
        }
    };
    for repo_id in repos {
        stats.repositories += 1;
        if let Err(e) = backfill_repository(db, repo_id, &mut stats).await {
            stats.failed += 1;
            tracing::warn!(repository_id = %repo_id, error = %e, "oci image scope backfill: repository failed; retried next pass");
        }
    }
    metrics::counter!("ak_oci_image_scope_links_backfilled_total").increment(stats.links_inserted);
    if stats.links_inserted > 0 || stats.repositories_completed > 0 || stats.failed > 0 {
        tracing::info!(
            repositories = stats.repositories,
            completed = stats.repositories_completed,
            links = stats.links_inserted,
            legacy_markers = stats.legacy_markers,
            failed = stats.failed,
            "oci image scope backfill: pass complete"
        );
    }
    stats
}

/// The rows a pass re-reads: everything on a first backfill, otherwise rows
/// written since shortly before the previous pass.
const PASS_STATE_SQL: &str = r#"
    SELECT s.completed_at, s.last_scanned_at, NOW() AS pass_started
    FROM (SELECT 1) one
    LEFT JOIN oci_image_scope_backfill s ON s.repository_id = $1
"#;

/// Links from `oci_tags`: every tag (a by-digest push records one too) links
/// its image to the digest it names.
const LINK_FROM_TAGS_SQL: &str = r#"
    INSERT INTO oci_image_manifests (repository_id, image, digest)
    SELECT t.repository_id, t.name, t.manifest_digest
    FROM oci_tags t
    JOIN oci_manifests m ON m.repository_id = t.repository_id AND m.digest = t.manifest_digest
    WHERE t.repository_id = $1
      AND t.name <> ''
      AND ($2::timestamptz IS NULL OR t.updated_at >= $2)
    ON CONFLICT DO NOTHING
"#;

/// A keyset page of live manifest-shaped `artifacts` rows whose digest the
/// repository records, for attribution through their path.
const LIVE_MANIFEST_ROWS_PAGE_SQL: &str = concat!(
    r#"
    SELECT a.id, a.path::text AS path, 'sha256:' || a.checksum_sha256 AS digest, r.key AS repo_key
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    JOIN oci_manifests m
      ON m.repository_id = a.repository_id AND m.digest = 'sha256:' || a.checksum_sha256
    WHERE a.repository_id = $1
      AND a.is_deleted = false
      AND a.id > $2
      AND ($3::timestamptz IS NULL OR a.updated_at >= $3)
      AND "#,
    crate::services::oci_migration_reindex::reindex_manifest_path_shape_sql!(),
    r#"
    ORDER BY a.id
    LIMIT $4
"#
);

/// Bulk link insert for the attributed `artifacts` rows.
const LINK_BULK_SQL: &str = r#"
    INSERT INTO oci_image_manifests (repository_id, image, digest)
    SELECT $1, img, dig
    FROM UNNEST($2::text[], $3::text[]) AS t(img, dig)
    WHERE EXISTS (SELECT 1 FROM oci_manifests m WHERE m.repository_id = $1 AND m.digest = dig)
    ON CONFLICT DO NOTHING
"#;

/// One level of index children: the children of a manifest an image holds
/// are held by that image too.
const LINK_CHILDREN_SQL: &str = r#"
    INSERT INTO oci_image_manifests (repository_id, image, digest)
    SELECT DISTINCT l.repository_id, l.image, r.child_digest
    FROM oci_image_manifests l
    JOIN oci_manifest_refs r ON r.repository_id = l.repository_id AND r.parent_digest = l.digest
    JOIN oci_manifests m ON m.repository_id = r.repository_id AND m.digest = r.child_digest
    WHERE l.repository_id = $1
      AND l.image <> ''
      AND ($2::timestamptz IS NULL OR l.created_at >= $2)
    ON CONFLICT DO NOTHING
"#;

/// Claim the first backfill of a repository; `None` when another pass (or an
/// earlier one) already completed it.
const CLAIM_FIRST_BACKFILL_SQL: &str = r#"
    INSERT INTO oci_image_scope_backfill (repository_id, completed_at, last_scanned_at)
    VALUES ($1, NOW(), $2)
    ON CONFLICT (repository_id) DO NOTHING
    RETURNING repository_id
"#;

/// The legacy markers of a first backfill: every manifest no image holds.
const LEGACY_MARKERS_SQL: &str = r#"
    INSERT INTO oci_image_manifests (repository_id, image, digest)
    SELECT m.repository_id, '', m.digest
    FROM oci_manifests m
    WHERE m.repository_id = $1
      AND NOT EXISTS (SELECT 1 FROM oci_image_manifests l
                      WHERE l.repository_id = m.repository_id AND l.digest = m.digest)
    ON CONFLICT DO NOTHING
"#;

async fn backfill_repository(
    db: &PgPool,
    repo_id: Uuid,
    stats: &mut ScopeBackfillStats,
) -> sqlx::Result<()> {
    type Ts = chrono::DateTime<chrono::Utc>;
    let (completed, last_scanned, pass_started): (Option<Ts>, Option<Ts>, Ts) =
        sqlx::query_as(PASS_STATE_SQL)
            .bind(repo_id)
            .fetch_one(db)
            .await?;
    // A first backfill reads everything; a later pass what changed since
    // shortly before the previous one.
    let since: Option<Ts> = match (completed, last_scanned) {
        (Some(_), Some(last)) => Some(last - rescan_slack()),
        _ => None,
    };

    // Deletes a 1.11 replica (or any path that trashes rows without the
    // unlink) made since the last pass.
    unlink_deleted_manifests(db, Some(repo_id)).await?;
    stats.links_inserted += sqlx::query(LINK_FROM_TAGS_SQL)
        .bind(repo_id)
        .bind(since)
        .execute(db)
        .await?
        .rows_affected();
    stats.links_inserted += link_from_manifest_rows(db, repo_id, since).await?;
    for _ in 0..MAX_CHILD_DEPTH {
        let added = sqlx::query(LINK_CHILDREN_SQL)
            .bind(repo_id)
            .bind(since)
            .execute(db)
            .await?
            .rows_affected();
        stats.links_inserted += added;
        if added == 0 {
            break;
        }
    }

    if completed.is_some() {
        sqlx::query(
            "UPDATE oci_image_scope_backfill SET last_scanned_at = $2 WHERE repository_id = $1",
        )
        .bind(repo_id)
        .bind(pass_started)
        .execute(db)
        .await?;
        return Ok(());
    }

    // First backfill: the legacy markers and the completion marker commit
    // together, so a repository's reads switch to the per-image rule only
    // once every manifest it holds is attributed or marked.
    let mut tx = db.begin().await?;
    let claimed: Option<Uuid> = sqlx::query_scalar(CLAIM_FIRST_BACKFILL_SQL)
        .bind(repo_id)
        .bind(pass_started)
        .fetch_optional(&mut *tx)
        .await?;
    if claimed.is_none() {
        tx.rollback().await?;
        return Ok(());
    }
    let markers = sqlx::query(LEGACY_MARKERS_SQL)
        .bind(repo_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    stats.legacy_markers += markers;
    stats.repositories_completed += 1;
    Ok(())
}

fn rescan_slack() -> chrono::Duration {
    // RESCAN_SLACK documents the SQL-facing value; keep the two in step.
    debug_assert_eq!(RESCAN_SLACK, "1 hour");
    chrono::Duration::hours(1)
}

/// Attribute live manifest-shaped `artifacts` rows to their image through
/// their path (the canonical `v2/<image>/manifests/<ref>` shape and the
/// migrated source layouts, as the reindex reads them).
async fn link_from_manifest_rows(
    db: &PgPool,
    repo_id: Uuid,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> sqlx::Result<u64> {
    let mut inserted = 0;
    let mut cursor = Uuid::nil();
    loop {
        let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(LIVE_MANIFEST_ROWS_PAGE_SQL)
            .bind(repo_id)
            .bind(cursor)
            .bind(since)
            .bind(ARTIFACT_PAGE_SIZE)
            .fetch_all(db)
            .await?;
        let Some(last) = rows.last() else {
            return Ok(inserted);
        };
        cursor = last.0;
        let (images, digests): (Vec<String>, Vec<String>) = rows
            .iter()
            .filter_map(|(_, path, digest, repo_key)| {
                crate::services::oci_migration_reindex::manifest_row_image(path, repo_key)
                    .filter(|image| !image.is_empty())
                    .map(|image| (image, digest.clone()))
            })
            .unzip();
        if !images.is_empty() {
            inserted += sqlx::query(LINK_BULK_SQL)
                .bind(repo_id)
                .bind(&images)
                .bind(&digests)
                .execute(db)
                .await?
                .rows_affected();
        }
        if (rows.len() as i64) < ARTIFACT_PAGE_SIZE {
            return Ok(inserted);
        }
    }
}

/// Forget the backfill of `repository_ids`, so their reads go back to the
/// repository-wide rule until the next maintenance pass re-runs the first
/// backfill. A restore from an archive that predates migration 363 carries
/// no links, and the per-image rule would otherwise answer 404 for every
/// restored digest that no tag names.
pub(crate) async fn reset_backfill(db: &PgPool, repository_ids: &[Uuid]) -> sqlx::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM oci_image_scope_backfill WHERE repository_id = ANY($1)")
            .bind(repository_ids)
            .execute(db)
            .await?
            .rows_affected(),
    )
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_scope_mode_defaults_to_enforce() {
        assert_eq!(parse_blob_scope_mode(None), BlobScopeMode::Enforce);
        assert_eq!(parse_blob_scope_mode(Some("")), BlobScopeMode::Enforce);
        assert_eq!(
            parse_blob_scope_mode(Some("enforce")),
            BlobScopeMode::Enforce
        );
        assert_eq!(parse_blob_scope_mode(Some("bogus")), BlobScopeMode::Enforce);
        assert_eq!(
            parse_blob_scope_mode(Some(" Report ")),
            BlobScopeMode::Report
        );
    }
}
