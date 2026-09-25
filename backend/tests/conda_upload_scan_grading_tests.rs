//! Integration target: a conda package pushed through the native
//! `PUT /conda/{repo}/{subdir}/{filename}` route is SCANNED on upload and the
//! repository GRADED — the behavior #4159 fixed and #4158 found had no
//! out-of-process coverage.
//!
//! The pre-#4159 handler wrote the `artifacts` row with raw SQL and returned
//! 201 without ever reaching the auto-scan gate, so a repository with
//! `scan_enabled` + `scan_on_upload` produced no `scan_results` row and its
//! `repo_security_scores` grade stayed null. These tests drive the full
//! production composition (conda router under `repo_visibility_middleware`)
//! with a real `ScannerService` and a made-up package name:
//!
//! * a made-up name has no conda->PyPI alias (#4042), so the dependency scan
//!   completes `partial` with zero findings — deterministic whether or not
//!   the sandbox can reach osv.dev, which is what makes "graded" assertable
//!   at all;
//! * the negative control (`scan_on_upload = false`) must produce NO rows,
//!   so the positive assertion is about the config gate, not about some
//!   unconditional scan.
//!
//! DB-gated: run under `--run-ignored ignored-only` with `DATABASE_URL` and
//! `AK_TESTS_REQUIRE_DB=1`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::AppState;
use artifact_keeper_backend::services::scanner_service::{AdvisoryClient, ScannerService};
use common::conda_support as cs;

/// Insert the repository's scan configuration with `scan_on_upload` set
/// either way.
async fn set_scan_on_upload(pool: &PgPool, repo_id: Uuid, on_upload: bool) {
    sqlx::query(
        "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
             scan_on_proxy, block_on_policy_violation, severity_threshold) \
         VALUES ($1, true, $2, false, false, 'high')",
    )
    .bind(repo_id)
    .bind(on_upload)
    .execute(pool)
    .await
    .expect("seed scan_configs");
}

/// Build the state with a real `ScannerService` wired (dependency scanner
/// only: no trivy adapter, no GitHub token, OSV reachable or not — the
/// made-up package is unidentifiable to every feed, so the outcome does not
/// depend on egress).
fn build_scan_state(
    pool: PgPool,
    storage_path: &str,
    scan_workspace: &str,
) -> artifact_keeper_backend::api::SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(
        artifact_keeper_backend::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        )
        .with_filesystem_bucket_root(storage_path),
    );
    let scanner = ScannerService::new(
        pool.clone(),
        Arc::new(AdvisoryClient::new(None)),
        Arc::new(
            artifact_keeper_backend::services::scan_result_service::ScanResultService::new(
                pool.clone(),
            ),
        ),
        Arc::new(
            artifact_keeper_backend::services::scan_config_service::ScanConfigService::new(
                pool.clone(),
            ),
        ),
        None,
        None,
        false,
        storage.clone(),
        registry.clone(),
        storage_path.to_string(),
        scan_workspace.to_string(),
        None,
        String::new(),
        Arc::new(
            artifact_keeper_backend::services::auth_service::AuthService::new(
                pool.clone(),
                Arc::new(cs::test_config(storage_path)),
            ),
        ),
        None,
        3600,
    );
    let mut app_state = AppState::new(cs::test_config(storage_path), pool, storage, registry);
    app_state.set_scanner_service(Arc::new(scanner));
    Arc::new(app_state)
}

/// Upload one conda v1 package through the production composition.
async fn put_package(app: axum::Router, repo_key: &str, name: &str, auth: &str) -> StatusCode {
    let filename = format!("{}-1.0.0-0.tar.bz2", name);
    let body = cs::conda_v1_package(name, "1.0.0", "0");
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/conda/{}/noarch/{}", repo_key, filename))
        .header("Authorization", auth)
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// Poll for the scan the upload spawned to land a completed row. Returns the
/// row's `(status, scan_completeness)` when one appears inside the budget.
async fn wait_for_scan(
    pool: &PgPool,
    repo_id: Uuid,
    budget: std::time::Duration,
) -> Option<(String, Option<String>)> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT status, scan_completeness FROM scan_results \
             WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(repo_id)
        .fetch_optional(pool)
        .await
        .expect("read scan_results");
        if let Some(row) = row {
            if row.0 == "completed" {
                return Some(row);
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The repository's materialized grade row, once the scan pipeline has
/// recalculated it.
async fn repo_grade(pool: &PgPool, repo_id: Uuid) -> Option<(i32, String)> {
    sqlx::query_as::<_, (i32, String)>(
        "SELECT score, grade FROM repo_security_scores WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_optional(pool)
    .await
    .expect("read repo_security_scores")
}

/// The acceptance test: upload -> scanned -> graded. A made-up package name
/// keeps the assertion deterministic under any feed reachability: the scan
/// must COMPLETE (a `completed` `scan_results` row, `partial` because the
/// package is unidentifiable, never the silent missing row of #4159) and the
/// repository must carry a materialized grade.
#[tokio::test]
#[ignore]
async fn native_put_upload_is_scanned_and_graded() {
    let pool = cs::require_pool().await;
    let username = cs::unique_name("conda-scan-u");
    let user_id = cs::create_user(&pool, &username, "scanpass", false).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-scan", "local", "conda", false).await;
    cs::grant_developer_role(&pool, repo_id, user_id).await;
    set_scan_on_upload(&pool, repo_id, true).await;

    let scan_workspace = std::env::temp_dir().join(format!("conda-scan-ws-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&scan_workspace).expect("scan workspace");
    let state = build_scan_state(
        pool.clone(),
        &storage_path.to_string_lossy(),
        &scan_workspace.to_string_lossy(),
    );
    let app = cs::conda_full_stack(state);

    let status = put_package(
        app,
        &repo_key,
        "integ-unmapped-pkg",
        &cs::basic_auth(&username, "scanpass"),
    )
    .await;
    assert!(
        status.is_success(),
        "conda PUT upload must succeed before scanning is even possible, got {status}"
    );

    let scan = wait_for_scan(&pool, repo_id, std::time::Duration::from_secs(30)).await;
    // The scan writes the grade row as its final step, so once the completed
    // scan row exists the grade read is racy-free within the same budget.
    let mut grade = None;
    if scan.is_some() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while grade.is_none() && std::time::Instant::now() < deadline {
            grade = repo_grade(&pool, repo_id).await;
            if grade.is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, user_id).await;
    cs::cleanup_storage(&storage_path);
    cs::cleanup_storage(&scan_workspace);

    let (scan_status, completeness) = scan.unwrap_or_else(|| {
        panic!(
            "a native conda upload into a scan_on_upload repository must \
             enqueue a scan, but no completed scan_results row ever appeared"
        )
    });
    assert_eq!(scan_status, "completed");
    assert_eq!(
        completeness.as_deref(),
        Some("partial"),
        "a made-up conda name has no alias, so the scan must complete \
         `partial` (the #4042 coverage gap), never silently `complete`"
    );
    let (_score, grade) = grade.unwrap_or_else(|| {
        panic!("the upload's scan must grade the repository, but repo_security_scores stayed empty")
    });
    assert!(
        ["A", "B", "C", "D", "F"].contains(&grade.as_str()),
        "the repository must carry a real grade, got {grade:?}"
    );
}

/// Negative control: the same upload into a repository whose
/// `scan_on_upload` is off must enqueue nothing, so the positive assertion
/// is about the config gate and not about an unconditional scan.
#[tokio::test]
#[ignore]
async fn native_put_upload_enqueues_nothing_when_scan_on_upload_is_disabled() {
    let pool = cs::require_pool().await;
    let username = cs::unique_name("conda-noscan-u");
    let user_id = cs::create_user(&pool, &username, "noscanpass", false).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-noscan", "local", "conda", false).await;
    cs::grant_developer_role(&pool, repo_id, user_id).await;
    set_scan_on_upload(&pool, repo_id, false).await;

    let scan_workspace = std::env::temp_dir().join(format!("conda-noscan-ws-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&scan_workspace).expect("scan workspace");
    let state = build_scan_state(
        pool.clone(),
        &storage_path.to_string_lossy(),
        &scan_workspace.to_string_lossy(),
    );
    let app = cs::conda_full_stack(state);

    let status = put_package(
        app,
        &repo_key,
        "integ-noscan-pkg",
        &cs::basic_auth(&username, "noscanpass"),
    )
    .await;
    assert!(status.is_success(), "conda PUT upload failed: {status}");

    // Two seconds is generous for a spawn that would fire immediately; the
    // positive test proves a scan WOULD land well inside this window.
    let scan = wait_for_scan(&pool, repo_id, std::time::Duration::from_secs(2)).await;
    let grade = repo_grade(&pool, repo_id).await;

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, user_id).await;
    cs::cleanup_storage(&storage_path);
    cs::cleanup_storage(&scan_workspace);

    assert!(
        scan.is_none(),
        "scan_on_upload is disabled, so the upload must not enqueue a scan, got {scan:?}"
    );
    assert!(
        grade.is_none(),
        "with no scan there is nothing to grade, got {grade:?}"
    );
}
