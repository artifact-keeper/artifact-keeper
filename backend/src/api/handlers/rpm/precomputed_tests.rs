//! #4544: the rebuild endpoint and the per-repository `repodata_mode`.

use super::*;
use crate::api::handlers::proxy_scan_archive::test_support::minimal_rpm;
use crate::api::handlers::{repositories, test_db_helpers as tdh};
use axum::http::Request;

fn app(f: &tdh::Fixture) -> Router {
    tdh::router_with_auth_ext(
        Router::new().nest("/rpm", super::router()).nest(
            "/api/v1/repositories",
            repositories::router().merge(super::repo_router()),
        ),
        f.state.clone(),
        tdh::admin_auth(f.user_id, &f.username),
    )
}

async fn request(
    f: &tdh::Fixture,
    method: &str,
    path: &str,
    body: impl Into<Body>,
) -> (StatusCode, Bytes) {
    tdh::send(
        app(f),
        Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap(),
    )
    .await
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_else(|_| {
        panic!("not JSON: {}", String::from_utf8_lossy(bytes));
    })
}

async fn upload(f: &tdh::Fixture, name: &str) {
    let body = minimal_rpm(name, None, "1.0", "1", "noarch", &[]);
    let (status, resp) = request(
        f,
        "PUT",
        &format!("/rpm/{}/packages/{name}-1.0-1.noarch.rpm", f.repo_key),
        body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&resp)
    );
}

async fn documents(f: &tdh::Fixture) -> Vec<Bytes> {
    let mut out = Vec::new();
    for doc in [
        "repomd.xml",
        "primary.xml.gz",
        "filelists.xml.gz",
        "other.xml.gz",
    ] {
        let (status, body) = request(
            f,
            "GET",
            &format!("/rpm/{}/repodata/{doc}", f.repo_key),
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        out.push(body);
    }
    out
}

async fn rebuild(f: &tdh::Fixture, query: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = request(
        f,
        "POST",
        &format!(
            "/api/v1/repositories/{}/rpm/repodata/rebuild{query}",
            f.repo_key
        ),
        Body::empty(),
    )
    .await;
    (status, json(&body))
}

async fn patch_mode(f: &tdh::Fixture, mode: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = request(
        f,
        "PATCH",
        &format!("/api/v1/repositories/{}", f.repo_key),
        format!(r#"{{"repodata_mode":"{mode}"}}"#),
    )
    .await;
    (status, json(&body))
}

/// `rebuild?wait=true` gives read-your-writes: after it returns, the stored
/// revision lists the package just published, and its bytes equal the
/// on-request render of the same state (`repodata_mode: on_request`).
#[tokio::test]
async fn rebuild_wait_serves_the_write_and_matches_on_request_bytes_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "alpha").await;
    let (status, body) = rebuild(&f, "?wait=true").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "built");
    assert_eq!(body["revision"], 1);
    assert_eq!(body["packages"], 1);

    upload(&f, "beta").await;
    let stale = documents(&f).await;
    let (status, body) = rebuild(&f, "?wait=true").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], 2);
    assert_eq!(body["packages"], 2);
    let precomputed = documents(&f).await;
    assert_ne!(precomputed[1], stale[1], "the rebuild includes beta");
    let (status, body) = rebuild(&f, "?wait=true").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], 2, "nothing changed: no second build");
    assert!(
        crate::services::rpm_repodata_builder::stored_revision(&f.pool, f.repo_id, "")
            .await
            .unwrap()
            .is_some()
    );

    let (status, body) = patch_mode(&f, "on_request").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["repodata_mode"], "on_request");
    assert_eq!(
        documents(&f).await,
        precomputed,
        "byte-identical to the render"
    );
    let (status, _) = rebuild(&f, "?wait=true").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "nothing to rebuild on request"
    );

    let (status, body) = patch_mode(&f, "precomputed").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["repodata_mode"], "precomputed");
    let (status, body) = request(
        &f,
        "GET",
        &format!("/api/v1/repositories/{}", f.repo_key),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["repodata_mode"], "precomputed");
    f.teardown().await;
}

/// Without `wait` the build is only requested (202), and the next builder
/// tick picks the root up without the debounce. Bad roots are refused.
#[tokio::test]
async fn rebuild_without_wait_queues_and_validates_the_root_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "alpha").await;
    let (status, body) = rebuild(&f, "").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "queued");
    let dirty: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT dirty_since FROM rpm_repodata_roots WHERE repository_id = $1 AND root = ''",
    )
    .bind(f.repo_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(dirty.is_some());
    let patient = crate::services::rpm_repodata_builder::BuilderSettings {
        quiet: std::time::Duration::from_secs(3600),
        max_delay: std::time::Duration::from_secs(3600),
        ..Default::default()
    };
    assert!(crate::services::rpm_repodata_builder::run_tick(&f.state, &patient).await >= 1);
    assert!(
        crate::services::rpm_repodata_builder::stored_revision(&f.pool, f.repo_id, "")
            .await
            .unwrap()
            .is_some()
    );
    let (status, _) = rebuild(&f, "?root=el9&wait=true").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no roots at depth zero");
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let (status, body) = rebuild(&f, "?wait=true").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an emptied root can be rebuilt: {body}"
    );
    assert_eq!(body["status"], "empty");
    f.teardown().await;
}

/// `repodata_mode` is for local RPM repositories only, and is omitted from
/// other repositories' responses.
#[tokio::test]
async fn repodata_mode_is_rejected_outside_local_rpm_4544() {
    let Some(f) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let (status, body) = patch_mode(&f, "on_request").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, body) = request(
        &f,
        "GET",
        &format!("/api/v1/repositories/{}", f.repo_key),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json(&body).get("repodata_mode").is_none());
    let (status, _) = rebuild(&f, "?wait=true").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, body) = patch_mode(&f, "sometimes").await;
    assert!(status.is_client_error(), "{body}");
    f.teardown().await;
}

#[test]
fn rebuild_endpoint_and_mode_are_documented_4544() {
    use utoipa::OpenApi;
    let doc = serde_json::to_value(super::RpmRepodataApiDoc::openapi()).unwrap();
    assert!(doc["paths"]
        .get("/api/v1/repositories/{key}/rpm/repodata/rebuild")
        .is_some());
    let repos = serde_json::to_value(crate::api::openapi::build_openapi()).unwrap();
    let schemas = &repos["components"]["schemas"];
    assert!(schemas["RepodataMode"].is_object(), "RepodataMode schema");
    assert!(schemas["CreateRepositoryRequest"]["properties"]["repodata_mode"].is_object());
    assert!(schemas["UpdateRepositoryRequest"]["properties"]["repodata_mode"].is_object());
}

/// A rebuild needs the repository `write` permission: a reader of a private
/// repository and a non-member of a public one are refused, a member with
/// write is not (#4544).
#[tokio::test]
async fn rebuild_requires_repository_write_permission_4544() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    upload(&f, "alpha").await;
    let as_user = |user_id, username: String| {
        tdh::router_with_auth_ext(
            Router::new().nest("/api/v1/repositories", super::repo_router()),
            f.state.clone(),
            tdh::make_auth(user_id, &username),
        )
    };
    let post = || {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/repositories/{}/rpm/repodata/rebuild?wait=true",
                f.repo_key
            ))
            .body(Body::empty())
            .unwrap()
    };
    let (reader, reader_name) = tdh::create_user(&f.pool).await;
    tdh::grant_repo_role(&f.pool, f.repo_id, reader, "reader").await;
    let (status, body) = tdh::send(as_user(reader, reader_name.clone()), post()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&body)
    );

    sqlx::query("UPDATE repositories SET is_public = true, visibility = 'public' WHERE id = $1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let (stranger, stranger_name) = tdh::create_user(&f.pool).await;
    let (status, _) = tdh::send(as_user(stranger, stranger_name), post()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "public is not writable");

    // The fixture user is a developer of the repository.
    let (status, body) = tdh::send(as_user(f.user_id, f.username.clone()), post()).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    for user in [reader, stranger] {
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(user)
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    f.teardown().await;
}
