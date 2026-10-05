//! First-class OCI manifest existence registry (`oci_manifests`), first slice
//! of artifact-keeper#1683 (#4433).
//!
//! The registry historically had no record of a manifest as such: existence
//! and media type were reconstructed from `oci_tags` (plus the children of a
//! tagged index in `oci_manifest_refs`). Migration 265 adds `oci_manifests`,
//! one row per `(repository_id, digest)`, independent of any tag.
//!
//! This module owns every write to that table:
//!
//! * [`upsert_in_tx`] — called from
//!   [`persist_tag_and_refs_in_tx`](crate::api::handlers::oci_v2::persist_tag_and_refs_in_tx)
//!   in the same transaction as the `oci_tags` upsert, so every path that
//!   commits a manifest (push, proxy cache, migration import) records it, and a
//!   rolled-back push leaves no row behind.
//! * [`delete_in_tx`] — called from the OCI `DELETE .../manifests/<digest>`
//!   unwind, the one path that deletes a manifest as such.
//! * [`run_backfill`] — a one-shot, idempotent, best-effort startup pass that
//!   records manifests committed before migration 265.
//!
//! The slice is write-only: nothing reads `oci_manifests` yet. Moving manifest
//! GET/HEAD/DELETE, the referrers API and the storage-GC orphan predicate onto
//! it is a later slice of #1683.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::api::handlers::oci_digest::compute_sha256;
use crate::api::handlers::oci_v2::{
    classify_manifest, extract_manifest_subject, manifest_storage_key, stored_media_type_for,
};
use crate::services::oci_manifest_refs_backfill::MAX_INDEX_MANIFEST_BYTES;
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

/// Forget a manifest that was explicitly deleted by digest. Runs inside the
/// caller's transaction.
pub(crate) async fn delete_in_tx(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    digest: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM oci_manifests WHERE repository_id = $1 AND digest = $2")
        .bind(repo_id)
        .bind(digest)
        .execute(conn)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Startup backfill
// ---------------------------------------------------------------------------

/// Result of a backfill pass, for tracing and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BackfillStats {
    /// Manifests without an `oci_manifests` row that the pass tried to record.
    pub candidates_scanned: usize,
    /// Rows inserted. Lower than `candidates_scanned - candidates_failed` only
    /// when a live push recorded the same manifest first.
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

/// Manifests the registry already knows about but has no `oci_manifests` row
/// for. Two arms, mirroring how manifests are enumerated today (#1642):
///
/// 1. every `(repository, digest)` an `oci_tags` row points at — the tag is
///    this repository's proof that it committed the body;
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
/// the upgrade. `$1` optionally scopes the pass to one repository (tests).
const CANDIDATE_SQL: &str = r#"
    SELECT c.repository_id,
           c.digest,
           MAX(NULLIF(c.recorded_type, '')) AS recorded_type,
           MIN(c.first_seen) AS first_seen,
           MAX(c.last_seen) AS last_seen,
           r.storage_backend,
           r.storage_path
    FROM (
        SELECT ot.repository_id, ot.manifest_digest AS digest,
               ot.manifest_content_type AS recorded_type,
               ot.created_at AS first_seen, ot.updated_at AS last_seen
        FROM oci_tags ot
        UNION ALL
        SELECT omr.repository_id, omr.child_digest AS digest,
               a.content_type AS recorded_type,
               a.created_at AS first_seen, a.updated_at AS last_seen
        FROM oci_manifest_refs omr
        JOIN artifacts a
          ON a.repository_id = omr.repository_id
         AND a.storage_key = 'oci-manifests/' || omr.child_digest
         AND a.is_deleted = false
    ) c
    JOIN repositories r ON r.id = c.repository_id
    WHERE ($1::uuid IS NULL OR c.repository_id = $1)
      AND NOT EXISTS (
            SELECT 1 FROM oci_manifests om
            WHERE om.repository_id = c.repository_id
              AND om.digest = c.digest
      )
    GROUP BY c.repository_id, c.digest, r.storage_backend, r.storage_path
    ORDER BY c.repository_id, c.digest
"#;

// Pin the `oci-manifests/` literal above to the key the read builds.
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
/// candidate query returns nothing.
pub async fn run_backfill(db: &PgPool, registry: Arc<StorageRegistry>) -> BackfillStats {
    run_backfill_scoped(db, &registry, None).await
}

async fn run_backfill_scoped(
    db: &PgPool,
    registry: &StorageRegistry,
    repository_id: Option<Uuid>,
) -> BackfillStats {
    let candidates = match select_candidates(db, repository_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "oci_manifests backfill: failed to scan candidates; skipping");
            return BackfillStats::default();
        }
    };
    let mut stats = BackfillStats {
        candidates_scanned: candidates.len(),
        ..BackfillStats::default()
    };
    if candidates.is_empty() {
        return stats;
    }
    tracing::info!(
        candidate_count = candidates.len(),
        "oci_manifests backfill: recording pre-existing manifests"
    );
    for candidate in &candidates {
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
    tracing::info!(
        candidates_scanned = stats.candidates_scanned,
        rows_inserted = stats.rows_inserted,
        candidates_failed = stats.candidates_failed,
        "oci_manifests backfill: complete"
    );
    stats
}

async fn select_candidates(
    db: &PgPool,
    repository_id: Option<Uuid>,
) -> sqlx::Result<Vec<Candidate>> {
    let rows = sqlx::query(CANDIDATE_SQL)
        .bind(repository_id)
        .fetch_all(db)
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Candidate {
                repository_id: r.try_get("repository_id")?,
                digest: r.try_get("digest")?,
                recorded_type: r.try_get("recorded_type")?,
                first_seen: r.try_get("first_seen")?,
                last_seen: r.try_get("last_seen")?,
                location: StorageLocation {
                    backend: r.try_get("storage_backend")?,
                    path: r.try_get("storage_path")?,
                },
            })
        })
        .collect()
}

/// Validate a manifest body read back from storage before it is recorded:
/// bounded size, and (for sha256 digests, the only kind the registry
/// computes) the bytes must hash to the digest the row will claim. A body
/// that fails either check is not evidence that the manifest exists.
fn verify_body(digest: &str, body: &[u8]) -> Result<(), String> {
    if body.len() > MAX_INDEX_MANIFEST_BYTES {
        return Err(format!(
            "manifest body exceeds {} bytes (got {})",
            MAX_INDEX_MANIFEST_BYTES,
            body.len()
        ));
    }
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

/// Read one manifest body, verify it, and insert its row. `Ok(true)` when a
/// row was inserted, `Ok(false)` when a concurrent push got there first.
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
    .execute(db)
    .await
    .map_err(|e| format!("insert oci_manifests row: {e}"))?;
    Ok(res.rows_affected() > 0)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::oci_v2::{persist_tag_and_refs, ManifestClass};
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::storage::StorageBackend;

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
        let body = vec![b' '; MAX_INDEX_MANIFEST_BYTES + 1];
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
    fn candidate_sql_scopes_children_to_local_bodies() {
        assert!(CANDIDATE_SQL.contains("FROM oci_tags ot"));
        assert!(CANDIDATE_SQL.contains("a.storage_key = 'oci-manifests/' || omr.child_digest"));
        assert!(CANDIDATE_SQL.contains("a.is_deleted = false"));
        assert!(CANDIDATE_SQL.contains("NOT EXISTS"));
    }

    async fn manifest_row(
        pool: &PgPool,
        repo_id: Uuid,
        digest: &str,
    ) -> Option<(String, i64, Option<String>)> {
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

    fn fs_registry() -> StorageRegistry {
        StorageRegistry::new(std::collections::HashMap::new(), "filesystem".to_string())
    }

    /// The dual write: committing a manifest through the shared writer records
    /// its `oci_manifests` row in the same transaction, a re-push refreshes it,
    /// and an explicit content-addressed delete removes it.
    #[tokio::test]
    async fn persist_tag_and_refs_dual_writes_oci_manifests() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let subject = format!("sha256:{}", "b".repeat(64));
        let body = referrer_body(&subject);
        let digest = compute_sha256(&body);

        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "sig",
            &digest,
            IMAGE,
            &ManifestClass::Image,
            &body,
        )
        .await
        .expect("persist");
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;

        // Second tag for the same digest: still one row, refreshed.
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "sig2",
            &digest,
            IMAGE,
            &ManifestClass::Image,
            &body,
        )
        .await
        .expect("persist again");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_manifests WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .fetch_one(&fx.pool)
        .await
        .unwrap();

        crate::api::handlers::oci_v2::delete_oci_manifest_content(
            &fx.pool,
            fx.repo_id,
            "app",
            &digest,
            &digest,
            crate::api::handlers::oci_v2::OciIndexDeleteScope::ContentAddressed,
        )
        .await
        .expect("delete by digest");
        let after_delete = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;

        assert_eq!(
            row,
            Some((IMAGE.to_string(), body.len() as i64, Some(subject))),
            "a committed manifest must have its oci_manifests row"
        );
        assert_eq!(count, 1);
        assert_eq!(
            after_delete, None,
            "DELETE by digest must forget the manifest"
        );
    }

    /// A tag-name delete leaves the manifest itself in place (it remains
    /// addressable by digest); only a digest delete removes the row.
    #[tokio::test]
    async fn named_reference_delete_keeps_oci_manifests_row() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let body = image_body("named");
        let digest = compute_sha256(&body);
        persist_tag_and_refs(
            &fx.pool,
            fx.repo_id,
            "app",
            "v1",
            &digest,
            IMAGE,
            &ManifestClass::Image,
            &body,
        )
        .await
        .expect("persist");
        crate::api::handlers::oci_v2::delete_oci_manifest_content(
            &fx.pool,
            fx.repo_id,
            "app",
            "v1",
            &digest,
            crate::api::handlers::oci_v2::OciIndexDeleteScope::NamedReference,
        )
        .await
        .expect("delete tag");
        let row = manifest_row(&fx.pool, fx.repo_id, &digest).await;
        fx.teardown().await;
        assert!(row.is_some(), "a tag delete must not forget the manifest");
    }

    /// The backfill records pre-existing manifests: a tagged index, its
    /// locally stored child (artifacts row present), and skips a child that is
    /// only referenced (no local body), a tag whose body is missing (counted as
    /// a failure), and a manifest that already has its row. A second pass is a
    /// no-op.
    #[tokio::test]
    async fn backfill_records_pre_existing_manifests() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage =
            crate::storage::filesystem::FilesystemStorage::new(fx.storage_dir.to_str().unwrap());

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
            storage
                .put(&manifest_storage_key(d), bytes::Bytes::from(b.clone()))
                .await
                .expect("seed manifest body");
        }

        // Pre-migration state: tags + refs + artifacts, no oci_manifests rows.
        // The index tag carries an EMPTY content type (legacy default) so the
        // type must come from the body.
        for (tag, d, ct) in [
            ("latest", &index_digest, ""),
            ("gone", &missing_digest, IMAGE),
            ("already", &already_digest, IMAGE),
        ] {
            sqlx::query(
                "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
                 VALUES ($1, 'app', $2, $3, $4)",
            )
            .bind(fx.repo_id)
            .bind(tag)
            .bind(d)
            .bind(ct)
            .execute(&fx.pool)
            .await
            .expect("seed tag");
        }
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
        let first = run_backfill_scoped(&fx.pool, &registry, Some(fx.repo_id)).await;
        let second = run_backfill_scoped(&fx.pool, &registry, Some(fx.repo_id)).await;

        let index_row = manifest_row(&fx.pool, fx.repo_id, &index_digest).await;
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
            child_row,
            Some((IMAGE.to_string(), child.len() as i64, None))
        );
        assert_eq!(remote_row, None);
        assert_eq!(missing_row, None);
        assert_eq!(
            already_row.map(|r| r.0),
            Some(DOCKER_IMAGE.to_string()),
            "the backfill must never overwrite a row a live push wrote"
        );
    }

    #[tokio::test]
    async fn backfill_rejects_body_that_does_not_match_digest() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage =
            crate::storage::filesystem::FilesystemStorage::new(fx.storage_dir.to_str().unwrap());
        let claimed = format!("sha256:{}", "9".repeat(64));
        storage
            .put(
                &manifest_storage_key(&claimed),
                bytes::Bytes::from(image_body("tampered")),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, 'app', 'x', $2, $3)",
        )
        .bind(fx.repo_id)
        .bind(&claimed)
        .bind(IMAGE)
        .execute(&fx.pool)
        .await
        .unwrap();
        let stats = run_backfill_scoped(&fx.pool, &fs_registry(), Some(fx.repo_id)).await;
        let row = manifest_row(&fx.pool, fx.repo_id, &claimed).await;
        fx.teardown().await;
        assert_eq!(stats.candidates_failed, 1);
        assert_eq!(row, None);
    }
}
