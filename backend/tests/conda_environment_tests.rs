//! Integration target: conda environment ingest and the component ->
//! environment reverse lookup (#4158, covering the #4052/#4054 feature).
//!
//! A stored lockfile is a dependency GRAPH, and the incident question —
//! "which of our environments contain this component, and what pulls it in?"
//! — is answered from the membership index, per platform, with the inclusion
//! chains. These tests drive both production router compositions through the
//! public API (repo-scoped ingest under the optional-auth middleware, the
//! global reverse index under required auth):
//!
//! * ingest stores the graph; re-ingesting the same name replaces it;
//! * the reverse index names the storing environment with the inclusion path;
//! * the index must not answer about repositories the caller cannot read.
//!
//! DB-gated: run under `--run-ignored ignored-only` with `DATABASE_URL` and
//! `AK_TESTS_REQUIRE_DB=1`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::conda_support as cs;

/// A solved conda-lock style document: `pillow` depends on `libwebp`, so
/// "libwebp is vulnerable" is really "you asked for pillow".
const ENV_A: &str = r#"
version: 1
metadata:
  platforms:
    - linux-64
package:
  - name: pillow
    version: 10.0.0
    manager: conda
    platform: linux-64
    dependencies:
      libwebp: ">=1.3.2"
  - name: libwebp
    version: 1.3.2
    manager: conda
    platform: linux-64
    dependencies: {}
"#;

/// POST a lockfile to the repo-scoped ingest endpoint and return the status
/// plus the parsed envelope.
async fn post_lockfile(
    app: axum::Router,
    repo_key: &str,
    name: &str,
    auth: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/repositories/{repo_key}/environments?filename=conda-lock.yml&name={name}"
                ))
                .header("Authorization", auth)
                .header("content-type", "application/octet-stream")
                .body(Body::from(ENV_A))
                .unwrap(),
        )
        .await
        .expect("ingest response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// GET the reverse index for `pkg:conda/libwebp@1.3.2`.
async fn lookup_libwebp(app: axum::Router, auth: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/environments/lookup?purl=pkg%3Aconda%2Flibwebp%401.3.2")
                .header("Authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("lookup response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// End to end through both production compositions: ingest stores the graph,
/// the reverse index names the environment WITH the inclusion chain, and a
/// re-ingest of the same name reports the replacement.
#[tokio::test]
#[ignore]
async fn ingest_then_reverse_lookup_names_the_environment_with_the_inclusion_path() {
    let pool = cs::require_pool().await;
    let username = cs::unique_name("conda-env-u");
    let user_id = cs::create_user(&pool, &username, "envpass", false).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-env", "local", "conda", false).await;
    cs::grant_developer_role(&pool, repo_id, user_id).await;
    let state = cs::build_state(pool.clone(), &storage_path.to_string_lossy());
    let auth = cs::basic_auth(&username, "envpass");

    let (status, created) = post_lockfile(
        cs::environments_repo_stack(state.clone()),
        &repo_key,
        "data-science",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "ingest must store: {created}");
    assert_eq!(created["name"], "data-science");
    assert_eq!(created["replaced"], false);
    assert_eq!(
        created["summary"]["memberships"], 2,
        "both packages join the graph: {created}"
    );

    let (status, replaced) = post_lockfile(
        cs::environments_repo_stack(state.clone()),
        &repo_key,
        "data-science",
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-ingest replaces: {replaced}");
    assert_eq!(replaced["replaced"], true);

    let (status, body) = lookup_libwebp(cs::environments_global_stack(state.clone()), &auth).await;
    assert_eq!(status, StatusCode::OK, "lookup must answer: {body}");
    assert_eq!(body["query"]["purlBase"], "pkg:conda/libwebp@1.3.2");
    let hits = body["hits"].as_array().expect("hits array");
    let hit = hits
        .iter()
        .find(|h| h["environment"]["name"] == "data-science")
        .unwrap_or_else(|| panic!("data-science must be named as affected: {body}"));
    assert_eq!(hit["scope"]["platform"], "linux-64");
    assert_eq!(
        hit["paths"],
        serde_json::json!([["pillow@10.0.0", "libwebp@1.3.2"]]),
        "the inclusion chain is the remediation: libwebp is here because of pillow"
    );

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, user_id).await;
    cs::cleanup_storage(&storage_path);
}

/// The reverse index must not answer about repositories the caller cannot
/// read: a stranger's lookup for the same component must not even learn that
/// the storing environment exists.
#[tokio::test]
#[ignore]
async fn reverse_lookup_hides_environments_in_repositories_the_caller_cannot_read() {
    let pool = cs::require_pool().await;
    let owner_name = cs::unique_name("conda-env-owner");
    let owner_id = cs::create_user(&pool, &owner_name, "ownerpass", false).await;
    let stranger_name = cs::unique_name("conda-env-stranger");
    let stranger_id = cs::create_user(&pool, &stranger_name, "strangerpass", false).await;
    let (repo_id, repo_key, storage_path) =
        cs::create_repo(&pool, "conda-env-secret", "local", "conda", false).await;
    cs::grant_developer_role(&pool, repo_id, owner_id).await;
    let owner_state = cs::build_state(pool.clone(), &storage_path.to_string_lossy());

    let (status, _) = post_lockfile(
        cs::environments_repo_stack(owner_state.clone()),
        &repo_key,
        "secret-env",
        &cs::basic_auth(&owner_name, "ownerpass"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = lookup_libwebp(
        cs::environments_global_stack(owner_state.clone()),
        &cs::basic_auth(&stranger_name, "strangerpass"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "lookup itself is allowed: {body}");
    let hits = body["hits"].as_array().expect("hits array");
    assert!(
        hits.iter()
            .all(|h| h["environment"]["name"] != "secret-env"),
        "a non-member must not learn that the environment exists: {hits:?}"
    );

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_user(&pool, owner_id).await;
    cs::cleanup_user(&pool, stranger_id).await;
    cs::cleanup_storage(&storage_path);
}

/// Anonymous callers are refused by the required-auth composition outright.
#[tokio::test]
#[ignore]
async fn reverse_lookup_requires_authentication() {
    let pool = cs::require_pool().await;
    let (repo_id, _repo_key, storage_path) =
        cs::create_repo(&pool, "conda-env-anon", "local", "conda", true).await;
    let state = cs::build_state(pool.clone(), &storage_path.to_string_lossy());

    let response = cs::environments_global_stack(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/environments/lookup?purl=pkg%3Aconda%2Flibwebp%401.3.2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("lookup response");
    let status = response.status();

    cs::cleanup_repo(&pool, repo_id).await;
    cs::cleanup_storage(&storage_path);

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the reverse index discloses environment contents, so it is never anonymous"
    );
}
