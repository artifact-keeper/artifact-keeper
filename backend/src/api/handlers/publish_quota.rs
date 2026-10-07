//! Storage-quota admission for the format-native publish handlers (#4422).
//!
//! The generic upload API (`ArtifactService`), chunked uploads and `npm
//! publish` enforced the repository quota and, since #2474, the project quota.
//! Every other native publish handler wrote its `artifacts` row (or OCI blob
//! row) directly, so its bytes counted toward both totals but an upload was
//! never refused. These helpers are the one admission path those handlers
//! share, in the same two halves the generic route uses:
//!
//! 1. [`preflight_publish_quota`]: an unlocked best-effort check, run once the
//!    upload size is known and BEFORE the bytes are written to storage, so an
//!    over-quota publish is refused without leaving an object behind.
//! 2. [`begin_admitted_publish`] / [`admit_publish_in_tx`]: the authoritative,
//!    race-free admission ([`RepositoryService::check_quota_locked`]) inside
//!    the transaction that performs the row INSERT. Concurrent publishes into
//!    one repository (or into sibling repositories of a capped project)
//!    serialize on the ledger / project row, so they cannot jointly
//!    over-admit. A denial here is only reachable when a concurrent upload
//!    consumed the headroom after the preflight; the object already written
//!    is left for storage GC, exactly as the npm and chunked paths do.
//!
//! A denial answers the generic route's `507 QUOTA_EXCEEDED`, naming the
//! scope (repository or project) that refused the upload. Unlimited
//! repositories and projects (no quota, or a non-positive sentinel) take no
//! lock and pay one extra primary-key read per publish.
//!
//! The `every_format_publish_runs_quota_admission_4422` gate in `proxy_helpers.rs` reads every
//! handler source and fails when a production `artifacts` insert neither runs
//! through these helpers nor carries a `NO-QUOTA-ADMISSION:` comment saying
//! why the row is not a publish.

use axum::response::{IntoResponse, Response};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::api::handlers::error_helpers::map_db_err;
use crate::services::repository_service::{QuotaScope, RepositoryService};

/// The response a publish refused by a storage quota answers: the generic
/// upload API's `507 QUOTA_EXCEEDED`, naming the scope that refused it.
pub fn quota_denied(scope: QuotaScope) -> Response {
    scope.into_error().into_response()
}

/// `Ok(())` when nothing refused the upload, else the 507 for the scope.
#[allow(clippy::result_large_err)]
fn admit(denied_by: Option<QuotaScope>) -> Result<(), Response> {
    denied_by.map_or(Ok(()), |scope| Err(quota_denied(scope)))
}

/// Where a publish lands, so the preflight can net out the bytes already
/// stored there: an overwrite is charged only its size delta, as the
/// authoritative locked admission charges it.
#[derive(Debug, Clone, Copy)]
pub enum PublishAt<'a> {
    /// The artifact's `(repository_id, path)`.
    Path(&'a str),
    /// The storage key the bytes are written under (the shared put
    /// primitives know the key, not the artifact path).
    StorageKey(&'a str),
}

/// Bytes of the live, hosted rows of `repo_id` at `at`.
async fn live_bytes_at(db: &PgPool, repo_id: Uuid, at: PublishAt<'_>) -> sqlx::Result<i64> {
    let (sql, key) = match at {
        PublishAt::Path(path) => (
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts \
              WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
                AND storage_key NOT LIKE 'proxy-cache/%'",
            path,
        ),
        PublishAt::StorageKey(storage_key) => (
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts \
              WHERE repository_id = $1 AND storage_key = $2 AND is_deleted = false \
                AND storage_key NOT LIKE 'proxy-cache/%'",
            storage_key,
        ),
    };
    sqlx::query_scalar(sql)
        .bind(repo_id)
        .bind(key)
        .fetch_one(db)
        .await
}

/// The scope that refuses an unlocked, best-effort preflight of a
/// `size_bytes` publish into `repo_id` at `at` (repository quota and, if any,
/// its project's aggregate quota), or `None` when it fits. Bytes already
/// stored at `at` are netted out, so an overwrite is charged its delta and one
/// that adds nothing always passes. For callers that report errors as text (a
/// background finalizer); handlers use [`preflight_publish_quota`].
pub async fn preflight_quota_denial(
    db: &PgPool,
    repo_id: Uuid,
    at: PublishAt<'_>,
    size_bytes: i64,
) -> crate::error::Result<Option<QuotaScope>> {
    let service = RepositoryService::new(db.clone());
    // The common case (fits, or no quota) costs no extra query; only a
    // would-be refusal looks up what the publish replaces.
    if service
        .quota_preflight(repo_id, size_bytes)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let replaced = live_bytes_at(db, repo_id, at).await?;
    service
        .quota_preflight(repo_id, size_bytes - replaced)
        .await
}

/// Unlocked best-effort quota preflight for a publish of `size_bytes` into
/// `repo_id` at `at`. Call it once the size is known and before the bytes are
/// written (and before any soft-deleted row at the path is purged).
#[allow(clippy::result_large_err)]
pub async fn preflight_publish_quota(
    db: &PgPool,
    repo_id: Uuid,
    at: PublishAt<'_>,
    size_bytes: i64,
) -> Result<(), Response> {
    let denied_by = preflight_quota_denial(db, repo_id, at, size_bytes)
        .await
        .map_err(IntoResponse::into_response)?;
    admit(denied_by)
}

/// The scope that refuses the authoritative, locked admission of a
/// `size_bytes` write to `path` inside `tx`, or `None` when it fits. The
/// text-error form of [`admit_publish_in_tx`].
pub async fn locked_quota_denial(
    tx: &mut Transaction<'_, Postgres>,
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
    size_bytes: i64,
) -> crate::error::Result<Option<QuotaScope>> {
    let admission = RepositoryService::new(db.clone())
        .check_quota_locked(tx, repo_id, path, size_bytes)
        .await?;
    Ok(admission.denied_by)
}

/// Authoritative admission of a `size_bytes` write to `path` inside `tx`, the
/// transaction the caller performs its `artifacts` INSERT in. Bytes already
/// charged at `(repo_id, path)` are netted out, so an overwrite is charged only
/// its size delta.
#[allow(clippy::result_large_err)]
pub async fn admit_publish_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
    size_bytes: i64,
) -> Result<(), Response> {
    let denied_by = locked_quota_denial(tx, db, repo_id, path, size_bytes)
        .await
        .map_err(IntoResponse::into_response)?;
    admit(denied_by)
}

/// Open the transaction a publish's `artifacts` INSERT must run in, with the
/// authoritative admission for that row already decided. Run the INSERT on
/// `&mut *tx` and commit; dropping the transaction (any `?` before the commit)
/// rolls the admission back with it.
#[allow(clippy::result_large_err)]
pub async fn begin_admitted_publish(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
    size_bytes: i64,
) -> Result<Transaction<'static, Postgres>, Response> {
    let mut tx = db.begin().await.map_err(map_db_err)?;
    admit_publish_in_tx(&mut tx, db, repo_id, path, size_bytes).await?;
    Ok(tx)
}

/// The bytes a push of OCI blob `digest` adds to `repo_id`: zero when the
/// repository already holds that blob (the `ON CONFLICT` re-push charges
/// nothing), else `size_bytes`.
pub(crate) fn oci_blob_charge(already_held: bool, size_bytes: i64) -> i64 {
    if already_held {
        0
    } else {
        size_bytes
    }
}

/// The scope that refuses the authoritative admission of an OCI blob row
/// (`oci_blobs`) inside `tx`, or `None` when it fits. A blob lives in
/// `oci_blobs`, not `artifacts`, so nothing is netted by path; a re-push of a
/// blob the repository already holds is charged nothing.
///
/// The "already held" probe runs AFTER the quota locks are taken (a zero
/// charge still takes them), so two concurrent pushes of one new digest
/// serialize and the second sees the first's committed row instead of being
/// charged the blob a second time.
pub async fn locked_oci_blob_denial(
    tx: &mut Transaction<'_, Postgres>,
    db: &PgPool,
    repo_id: Uuid,
    digest: &str,
    size_bytes: i64,
) -> crate::error::Result<Option<QuotaScope>> {
    // An `oci_blobs` row has no `artifacts` path; this key matches none, so
    // check_quota_locked nets nothing out.
    let path = format!("oci-blob:{digest}");
    locked_quota_denial(tx, db, repo_id, &path, 0).await?;
    let held: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM oci_blobs WHERE repository_id = $1 AND digest = $2")
            .bind(repo_id)
            .bind(digest)
            .fetch_optional(&mut **tx)
            .await?;
    let charge = oci_blob_charge(held.is_some(), size_bytes);
    locked_quota_denial(tx, db, repo_id, &path, charge).await
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    #[test]
    fn denial_is_the_generic_routes_507_naming_the_scope() {
        assert!(admit(None).is_ok());
        for scope in [QuotaScope::Repository, QuotaScope::Project] {
            let resp = admit(Some(scope)).expect_err("a denied scope refuses");
            assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        }
    }

    #[test]
    fn oci_blob_repush_is_charged_nothing() {
        assert_eq!(oci_blob_charge(false, 42), 42);
        assert_eq!(oci_blob_charge(true, 42), 0);
    }

    async fn body_text(resp: Response) -> (StatusCode, String) {
        use http_body_util::BodyExt;
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn insert_row(tx: &mut Transaction<'_, Postgres>, repo_id: Uuid, path: &str, size: i64) {
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'q', '1', $3, $4, 'application/octet-stream', $5)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(size)
        .bind(format!("{:064x}", size))
        .bind(format!("quota-4422/{repo_id}/{path}"))
        .execute(&mut **tx)
        .await
        .expect("insert artifact row");
    }

    /// Repository quota: the preflight and the locked admission agree, a
    /// row admitted and committed counts against the next publish, and an
    /// overwrite of the same path is charged only its delta.
    #[tokio::test]
    async fn repository_quota_refuses_the_publish_that_would_exceed_it_4422() {
        let _serial = tdh::usage_ledger_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query("UPDATE repositories SET quota_bytes = 100 WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();

        preflight_publish_quota(&pool, repo_id, PublishAt::Path("new.bin"), 100)
            .await
            .expect("fits exactly");
        let (status, body) = body_text(
            preflight_publish_quota(&pool, repo_id, PublishAt::Path("new.bin"), 101)
                .await
                .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
        assert!(body.contains("Repository storage quota exceeded"), "{body}");

        let mut tx = begin_admitted_publish(&pool, repo_id, "a.bin", 60)
            .await
            .expect("60 of 100 admitted");
        insert_row(&mut tx, repo_id, "a.bin", 60).await;
        tx.commit().await.unwrap();

        let err = begin_admitted_publish(&pool, repo_id, "b.bin", 50)
            .await
            .expect_err("60 + 50 exceeds 100");
        assert_eq!(err.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert!(
            preflight_publish_quota(&pool, repo_id, PublishAt::Path("b.bin"), 50)
                .await
                .is_err()
        );
        // Overwriting a.bin with 90 bytes is a +30 delta: admitted.
        begin_admitted_publish(&pool, repo_id, "a.bin", 90)
            .await
            .expect("overwrite charged its delta only");

        tdh::cleanup_member_repo(&pool, repo_id, &dir).await;
    }

    /// #4422 review: a publish that adds no bytes is always admitted, by the
    /// preflight (netted by path or by storage key) and by the locked check,
    /// even once the repository is over a quota that was lowered; one that
    /// adds bytes is refused.
    #[tokio::test]
    async fn publishes_that_add_no_bytes_pass_an_exceeded_quota_4422() {
        let _serial = tdh::usage_ledger_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "docker").await;
        let mut tx = begin_admitted_publish(&pool, repo_id, "a.bin", 60)
            .await
            .expect("unlimited");
        insert_row(&mut tx, repo_id, "a.bin", 60).await;
        tx.commit().await.unwrap();
        let digest = format!("sha256:{}", "de".repeat(32));
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, 10, $3)",
        )
        .bind(repo_id)
        .bind(&digest)
        .bind(format!("quota-4422/{repo_id}/blob"))
        .execute(&pool)
        .await
        .unwrap();
        // The quota is lowered below what the repository already holds.
        sqlx::query("UPDATE repositories SET quota_bytes = 50 WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();

        let key = format!("quota-4422/{repo_id}/a.bin");
        for (at, size, admitted) in [
            (PublishAt::Path("a.bin"), 60, true),
            (PublishAt::Path("a.bin"), 40, true),
            (PublishAt::StorageKey(&key), 60, true),
            (PublishAt::Path("a.bin"), 61, false),
            (PublishAt::Path("b.bin"), 1, false),
            (PublishAt::StorageKey("elsewhere"), 1, false),
        ] {
            let result = preflight_publish_quota(&pool, repo_id, at, size).await;
            assert_eq!(result.is_ok(), admitted, "preflight {at:?} {size}");
        }
        for (path, size, admitted) in [
            ("a.bin", 60, true),
            ("a.bin", 40, true),
            ("b.bin", 1, false),
        ] {
            let result = begin_admitted_publish(&pool, repo_id, path, size).await;
            assert_eq!(result.is_ok(), admitted, "locked {path} {size}");
        }
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            locked_oci_blob_denial(&mut tx, &pool, repo_id, &digest, 10)
                .await
                .unwrap(),
            None,
            "a re-push of a held blob is admitted over the cap"
        );
        drop(tx);

        sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
        tdh::cleanup_member_repo(&pool, repo_id, &dir).await;
    }

    /// Project quota: two repositories of one capped project share the cap,
    /// and OCI blob admission charges a re-push nothing.
    #[tokio::test]
    async fn project_quota_is_shared_by_sibling_repositories_4422() {
        let _serial = tdh::usage_ledger_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let project_key = format!("q4422-{}", Uuid::new_v4().simple());
        let project_id: Uuid = sqlx::query_scalar(
            "INSERT INTO projects (key, name, quota_bytes) VALUES ($1, $1, 100) RETURNING id",
        )
        .bind(&project_key)
        .fetch_one(&pool)
        .await
        .expect("project");
        let (a, _, dir_a) = tdh::create_repo(&pool, "local", "generic").await;
        let (b, _, dir_b) = tdh::create_repo(&pool, "local", "docker").await;
        sqlx::query("UPDATE repositories SET project_id = $1 WHERE id = ANY($2)")
            .bind(project_id)
            .bind(vec![a, b])
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = begin_admitted_publish(&pool, a, "x.bin", 80)
            .await
            .expect("80 of 100");
        insert_row(&mut tx, a, "x.bin", 80).await;
        tx.commit().await.unwrap();

        let (status, body) = body_text(
            preflight_publish_quota(&pool, b, PublishAt::Path("y.bin"), 30)
                .await
                .unwrap_err(),
        )
        .await;
        assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
        assert!(body.contains("Project storage quota exceeded"), "{body}");

        let digest = format!("sha256:{}", "ab".repeat(32));
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            locked_oci_blob_denial(&mut tx, &pool, b, &digest, 30)
                .await
                .unwrap(),
            Some(QuotaScope::Project),
            "a new 30-byte blob exceeds the project cap"
        );
        assert_eq!(
            locked_oci_blob_denial(&mut tx, &pool, b, &digest, 20)
                .await
                .unwrap(),
            None,
            "20 bytes fit"
        );
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, 20, $3)",
        )
        .bind(b)
        .bind(&digest)
        .bind(format!("quota-4422/{b}/blob"))
        .execute(&mut *tx)
        .await
        .expect("blob row");
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            locked_oci_blob_denial(&mut tx, &pool, b, &digest, 20)
                .await
                .unwrap(),
            None,
            "a re-push of a held blob adds nothing"
        );
        drop(tx);

        sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
            .bind(b)
            .execute(&pool)
            .await
            .unwrap();
        tdh::cleanup_member_repo(&pool, a, &dir_a).await;
        tdh::cleanup_member_repo(&pool, b, &dir_b).await;
        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
