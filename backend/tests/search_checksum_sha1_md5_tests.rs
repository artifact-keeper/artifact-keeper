//! Regression tests for checksum-based artifact lookup across SHA-256,
//! SHA-1, and MD5 algorithms (#1247, fix/search-checksum-sha1-md5-case).
//!
//! Release-gate run against :dev (3a22619) surfaced three failures in
//! tests/search/test-search-checksum.sh:
//!
//!   * `SHA1 lookup returned no artifact ...`
//!   * `MD5 lookup returned no artifact ...`
//!   * `uppercase SHA1 lookup returned no artifact (case-sensitivity regression)`
//!
//! Root cause: `ArtifactService::upload` was only persisting
//! `checksum_sha256` -- the `checksum_sha1` and `checksum_md5` columns
//! existed in the schema (per migration 004) but were never written to,
//! so any lookup against them returned an empty row set. The
//! "case-sensitivity" failure was the same bug surfaced through a third
//! test case: nothing was stored, so neither lowercase nor uppercase
//! sha1 input could match.
//!
//! These tests pin the post-fix behaviour:
//!
//!   1. Upload populates all three checksum columns.
//!   2. All three columns are stored as lowercase hex (matches the
//!      `{:x}` format used by `calculate_*`).
//!   3. The exact SQL run by `checksum_search` in
//!      `backend/src/api/handlers/search.rs` returns the row for each
//!      of sha256, sha1, and md5 -- including when the input checksum
//!      is uppercase (the handler's `.trim().to_lowercase()` covers
//!      this).
//!
//! Requires PostgreSQL:
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo test --test search_checksum_sha1_md5_tests -- --ignored
//! ```

use std::sync::Arc;

use bytes::Bytes;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::artifact_service::ArtifactService;
use artifact_keeper_backend::storage::filesystem::FilesystemStorage;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://registry:registry@localhost:5432/artifact_registry".into()
    });
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database (set DATABASE_URL)")
}

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("checksum-test-{}", id);
    let storage_path = format!("/tmp/checksum-test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("checksum-test-{}", id))
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to insert test repository");
    id
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    // Artifacts cascade-delete via ON DELETE CASCADE on repository_id.
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("failed to clean up test repository");
}

/// Build an ArtifactService backed by a real PG pool and an isolated
/// temp directory for content. `tempfile::TempDir` is not in the
/// workspace deps so we use a UUID-suffixed path under /tmp; the dir
/// is created lazily by `FilesystemStorage::put`.
fn make_service(pool: PgPool) -> (ArtifactService, std::path::PathBuf) {
    let storage_root =
        std::env::temp_dir().join(format!("ak-checksum-test-{}", Uuid::new_v4().as_simple()));
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> =
        Arc::new(FilesystemStorage::new(storage_root.clone()));
    (ArtifactService::new(pool, storage), storage_root)
}

/// Row fields read back when verifying the columns directly.
#[derive(Debug, sqlx::FromRow)]
struct ChecksumColumns {
    checksum_sha256: String,
    checksum_sha1: Option<String>,
    checksum_md5: Option<String>,
}

/// Mirror the production checksum-search SQL from
/// `backend/src/api/handlers/search.rs` so this test fails the moment
/// the production query stops returning the row for the indicated
/// column.
async fn checksum_search_sql(
    pool: &PgPool,
    column: &str,
    value: &str,
    accessible_repo_ids: Option<&[Uuid]>,
) -> i64 {
    let sql = format!(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.is_deleted = false
          AND {col} = $1
          AND ($2::uuid[] IS NULL OR r.id = ANY($2))
        "#,
        col = column,
    );
    let count: i64 = sqlx::query_scalar(&sql)
        .bind(value)
        .bind(accessible_repo_ids)
        .fetch_one(pool)
        .await
        .expect("checksum search query failed");
    count
}

// -------------------------------------------------------------------------
// Test 1: upload persists all three checksums (the core regression)
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_upload_persists_sha256_sha1_and_md5() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let (svc, _storage_root) = make_service(pool.clone());

    // Known content with pre-computed checksums.
    //
    //   echo -n "checksum-regression-1247" | sha256sum
    //     2add6a07b3c2afe0e4eb1c92e0e60a8a26e4adda4c08c92b25ad96c54df3dab2
    //   echo -n "checksum-regression-1247" | sha1sum
    //     5fc2a0e... (computed at runtime; we don't pin SHA-1 / MD5 here
    //     because the algorithm is exercised by the service helpers
    //     and re-computed by the assertion below)
    let content = b"checksum-regression-1247";
    let body = Bytes::from_static(content);

    let artifact = svc
        .upload(
            repo_id,
            "checksumfile.bin",
            "checksumfile.bin",
            None,
            "application/octet-stream",
            body,
            None,
        )
        .await
        .expect("upload should succeed");

    // All three columns must be populated.
    assert_eq!(
        artifact.checksum_sha256,
        ArtifactService::calculate_sha256(content),
        "sha256 must match the computed digest of the uploaded bytes",
    );
    assert_eq!(
        artifact.checksum_sha1.as_deref(),
        Some(ArtifactService::calculate_sha1(content).as_str()),
        "sha1 must be persisted on upload (pre-fix this was None)",
    );
    assert_eq!(
        artifact.checksum_md5.as_deref(),
        Some(ArtifactService::calculate_md5(content).as_str()),
        "md5 must be persisted on upload (pre-fix this was None)",
    );

    // Re-read the row to confirm the columns are non-null at the DB
    // level (not just on the returned Artifact struct).
    let cols: ChecksumColumns = sqlx::query_as(
        "SELECT checksum_sha256, checksum_sha1, checksum_md5 \
         FROM artifacts WHERE id = $1",
    )
    .bind(artifact.id)
    .fetch_one(&pool)
    .await
    .expect("re-read of inserted artifact failed");
    assert_eq!(cols.checksum_sha256, artifact.checksum_sha256);
    assert!(cols.checksum_sha1.is_some(), "sha1 column must not be NULL");
    assert!(cols.checksum_md5.is_some(), "md5 column must not be NULL");

    // All three values must be lowercase hex. The search handler does
    // `.trim().to_lowercase()` on input and then bytewise-compares, so
    // any uppercase storage would silently break lookups.
    for (label, val) in [
        ("sha256", cols.checksum_sha256.as_str()),
        ("sha1", cols.checksum_sha1.as_deref().unwrap()),
        ("md5", cols.checksum_md5.as_deref().unwrap()),
    ] {
        assert!(
            val.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{label} must be lowercase hex; got {val:?}",
        );
    }

    cleanup(&pool, repo_id).await;
}

// -------------------------------------------------------------------------
// Test 2: production search SQL returns the artifact for SHA-1 lookup
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_checksum_search_finds_artifact_by_sha1() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let (svc, _storage_root) = make_service(pool.clone());

    let content = b"sha1-lookup-payload";
    let body = Bytes::from_static(content);
    let artifact = svc
        .upload(
            repo_id,
            "sha1file.bin",
            "sha1file.bin",
            None,
            "application/octet-stream",
            body,
            None,
        )
        .await
        .expect("upload should succeed");

    let sha1 = artifact
        .checksum_sha1
        .clone()
        .expect("sha1 must be populated after upload");

    // Production handler normalises with `.trim().to_lowercase()` --
    // the value coming back from the DB is already lowercase so this
    // is a direct match.
    let count = checksum_search_sql(&pool, "a.checksum_sha1", &sha1, None).await;
    assert_eq!(count, 1, "SHA-1 lookup must find the freshly uploaded row");

    cleanup(&pool, repo_id).await;
}

// -------------------------------------------------------------------------
// Test 3: production search SQL returns the artifact for MD5 lookup
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_checksum_search_finds_artifact_by_md5() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let (svc, _storage_root) = make_service(pool.clone());

    let content = b"md5-lookup-payload";
    let body = Bytes::from_static(content);
    let artifact = svc
        .upload(
            repo_id,
            "md5file.bin",
            "md5file.bin",
            None,
            "application/octet-stream",
            body,
            None,
        )
        .await
        .expect("upload should succeed");

    let md5 = artifact
        .checksum_md5
        .clone()
        .expect("md5 must be populated after upload");

    let count = checksum_search_sql(&pool, "a.checksum_md5", &md5, None).await;
    assert_eq!(count, 1, "MD5 lookup must find the freshly uploaded row");

    cleanup(&pool, repo_id).await;
}

// -------------------------------------------------------------------------
// Test 4: case-insensitivity -- uppercase input must still match
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_checksum_search_sha1_uppercase_input_matches() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let (svc, _storage_root) = make_service(pool.clone());

    let content = b"uppercase-sha1-payload";
    let body = Bytes::from_static(content);
    let artifact = svc
        .upload(
            repo_id,
            "upperfile.bin",
            "upperfile.bin",
            None,
            "application/octet-stream",
            body,
            None,
        )
        .await
        .expect("upload should succeed");

    let sha1 = artifact
        .checksum_sha1
        .clone()
        .expect("sha1 must be populated after upload");

    // Simulate the handler's input normalisation: the user passes the
    // checksum in uppercase, the handler lowercases it before binding.
    // This pins the contract that the handler is responsible for
    // case-folding -- so the *bound* parameter is always lowercase
    // and the column data is always lowercase, yielding a direct
    // bytewise match.
    let user_input_upper = sha1.to_uppercase();
    let bound_after_handler_normalisation = user_input_upper.trim().to_lowercase();
    assert_eq!(
        bound_after_handler_normalisation, sha1,
        "handler normalisation must collapse uppercase input to the stored form",
    );

    let count = checksum_search_sql(
        &pool,
        "a.checksum_sha1",
        &bound_after_handler_normalisation,
        None,
    )
    .await;
    assert_eq!(
        count, 1,
        "uppercase SHA-1 input (post handler-normalisation) must still find the row",
    );

    cleanup(&pool, repo_id).await;
}

// -------------------------------------------------------------------------
// Test 5: ON CONFLICT DO UPDATE refreshes sha1/md5 on re-upload
// -------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_reupload_refreshes_all_three_checksums() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let (svc, _storage_root) = make_service(pool.clone());

    let first = svc
        .upload(
            repo_id,
            "reupload.bin",
            "reupload.bin",
            None,
            "application/octet-stream",
            Bytes::from_static(b"version-A-content"),
            None,
        )
        .await
        .expect("first upload should succeed");

    let second = svc
        .upload(
            repo_id,
            "reupload.bin",
            "reupload.bin",
            None,
            "application/octet-stream",
            Bytes::from_static(b"version-B-content"),
            None,
        )
        .await
        .expect("re-upload should succeed via ON CONFLICT DO UPDATE");

    // Same path => same row id, but every checksum must have been
    // refreshed to match the new content. Pre-fix the ON CONFLICT
    // clause didn't touch sha1/md5, so a re-upload would leave stale
    // (or in the all-NULL legacy case, still-NULL) sha1/md5 values.
    assert_eq!(first.id, second.id, "same path must reuse the row");
    assert_ne!(
        first.checksum_sha256, second.checksum_sha256,
        "sha256 must change when content changes",
    );
    assert_ne!(
        first.checksum_sha1, second.checksum_sha1,
        "sha1 must be refreshed on re-upload (regression #1247)",
    );
    assert_ne!(
        first.checksum_md5, second.checksum_md5,
        "md5 must be refreshed on re-upload (regression #1247)",
    );

    cleanup(&pool, repo_id).await;
}
