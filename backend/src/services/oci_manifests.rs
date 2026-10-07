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
//!
//! The slice is write-only: nothing reads `oci_manifests` yet. Moving manifest
//! GET/HEAD/DELETE, the referrers API and the storage-GC orphan predicate onto
//! it is a later slice of #1683, which must first reconcile the table (rows
//! missed or left behind by pre-268 replicas during a rolling upgrade).

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

/// Forget a deleted manifest (see [`delete_removes_record`]). Runs inside the caller's
/// transaction, after its tag rows and stale index edges are gone.
///
/// A manifest that is still the child of a live index (`oci_manifest_refs`
/// edge kept because the parent is still tagged, #1642) still exists by the
/// registry's rules — it is pullable through the parent — so its row stays.
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
/// the pass to one repository (tests). A repository with no tag has no tagged
/// index either, so it has no candidate in either arm below.
const REPOSITORIES_SQL: &str = r#"
    SELECT r.id, r.storage_backend, r.storage_path
    FROM repositories r
    WHERE ($1::uuid IS NULL OR r.id = $1)
      AND EXISTS (SELECT 1 FROM oci_tags ot WHERE ot.repository_id = r.id)
    ORDER BY r.id
"#;

/// One keyset page (`digest > $2`, `LIMIT $3`) of manifests in repository `$1`
/// the registry already knows about but has no `oci_manifests` row for. Two
/// arms, mirroring how manifests are enumerated today (#1642):
///
/// 1. every digest an `oci_tags` row points at — the tag is this repository's
///    proof that it committed the body;
/// 2. children of an index (`oci_manifest_refs.child_digest`) that have a live
///    `artifacts` row in the SAME repository at `oci-manifests/<digest>`. A
///    bare child edge only proves the parent *references* the digest; on a
///    shared cloud namespace reading `oci-manifests/<digest>` could pick up
///    another repository's body, and a proxy cache normally holds only the
///    architectures actually pulled. The artifacts row is the locality proof,
///    exactly as in `manifest_blob_refs_backfill`'s live set (#3285).
///
/// `recorded_type` is the best media type the database already holds (the
/// tag's, else the artifact's); the body decides when it is empty. Timestamps
/// carry the earliest/latest known commit so a backfilled row is not dated to
/// the upgrade. Both arms filter on `repository_id` so each page reads one
/// repository's rows through its index, not the whole table.
const CANDIDATE_PAGE_SQL: &str = r#"
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
    ) c
    WHERE NOT EXISTS (
            SELECT 1 FROM oci_manifests om
            WHERE om.repository_id = $1 AND om.digest = c.digest
      )
    GROUP BY c.digest
    ORDER BY c.digest
    LIMIT $3
"#;

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

/// Whether the manifest is still known (tagged, or a locally stored child of
/// an index) at insert time, taking row locks that make a concurrent delete
/// wait for this transaction — so a delete either commits first (and this
/// returns false) or runs after the insert (and removes the row itself).
async fn still_known_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<bool, sqlx::Error> {
    for sql in [STILL_TAGGED_SQL, STILL_LOCAL_CHILD_SQL] {
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
    /// tagged keeps the child's row: the kept parent->child edge means it still
    /// exists (pullable through the parent, #1642).
    #[tokio::test]
    async fn delete_by_digest_keeps_child_of_live_index() {
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
        fx.teardown().await;
        assert!(
            row.is_some(),
            "a child of a still-tagged index still exists"
        );
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
}
