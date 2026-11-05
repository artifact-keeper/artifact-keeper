//! Integration tests for Agent Plugins repositories (#5251).
//!
//! Drives the production composition: `agent_plugins::router()` nested at
//! `/agentplugins` under `repo_visibility_middleware`, and the repository
//! REST routes under `auth_middleware`, so the token-in-path credential, the
//! visibility gate and the REST delete are the real ones.
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo nextest run --run-ignored ignored-only --test agent_plugins_tests
//! ```

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)

mod common;

use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{middleware, Router};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use artifact_keeper_backend::api::handlers::{agent_plugins, repositories};
use artifact_keeper_backend::api::middleware::auth::{
    auth_middleware, repo_visibility_middleware, RepoVisibilityState,
};
use artifact_keeper_backend::api::SharedState;
use artifact_keeper_backend::services::auth_service::AuthService;

use common::conda_support as cs;

fn stack(state: SharedState) -> Router {
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    let vis = RepoVisibilityState {
        auth_service: auth_service.clone(),
        db: state.db.clone(),
        repo_cache: state.repo_cache.clone(),
        repo_miss_cache: state.repo_miss_cache.clone(),
        permission_service: state.permission_service.clone(),
    };
    let formats = Router::new()
        .nest("/agentplugins", agent_plugins::router())
        .layer(middleware::from_fn_with_state(
            vis,
            repo_visibility_middleware,
        ));
    let rest = Router::new()
        .nest("/api/v1/repositories", repositories::router())
        .layer(middleware::from_fn_with_state(
            auth_service,
            auth_middleware,
        ));
    formats.merge(rest).with_state(state)
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in files {
            w.start_file(*name, opts).unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
        .await
        .expect("body")
        .to_vec();
    (status, headers, body)
}

fn get(uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Body::empty()).unwrap()
}

fn json(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or(Value::Null)
}

fn names(doc: &Value) -> Vec<String> {
    doc["plugins"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| p["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

struct Rig {
    app: Router,
    pool: sqlx::PgPool,
    repo_id: uuid::Uuid,
    key: String,
    user_id: uuid::Uuid,
    basic: String,
    read_token: String,
    dir: std::path::PathBuf,
}

async fn rig(public: bool) -> Rig {
    let pool = cs::require_pool().await;
    let (repo_id, key, dir) = cs::create_repo(&pool, "ap", "local", "agentplugins", public).await;
    let username = cs::unique_name("ap-user");
    let user_id = cs::create_user(&pool, &username, "ap-password-1", true).await;
    cs::grant_developer_role(&pool, repo_id, user_id).await;
    let state = cs::build_state(pool.clone(), &dir.to_string_lossy());
    let auth = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (read_token, _) = auth
        .generate_api_token(user_id, "ap-read", vec!["read:artifacts".into()], None)
        .await
        .expect("mint read token");
    Rig {
        app: stack(state),
        pool,
        repo_id,
        key,
        user_id,
        basic: cs::basic_auth(&username, "ap-password-1"),
        read_token,
        dir,
    }
}

impl Rig {
    async fn publish(&self, name: &str, version: &str, body: Vec<u8>) -> (StatusCode, Value) {
        let sha = format!("{:x}", Sha256::digest(&body));
        let req = Request::builder()
            .method("PUT")
            .uri(format!(
                "/agentplugins/{}/{name}/{version}/{name}-{version}.zip",
                self.key
            ))
            .header("authorization", &self.basic)
            .header("x-checksum-sha256", sha)
            .body(Body::from(body))
            .unwrap();
        let (status, _, body) = call(&self.app, req).await;
        (status, json(&body))
    }

    async fn teardown(self) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(self.user_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM packages WHERE repository_id = $1")
            .bind(self.repo_id)
            .execute(&self.pool)
            .await;
        cs::cleanup_repo(&self.pool, self.repo_id).await;
        cs::cleanup_user(&self.pool, self.user_id).await;
        cs::cleanup_storage(&self.dir);
    }
}

fn claude_bundle(name: &str, version: &str) -> Vec<u8> {
    let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    zip(&[
        (".claude-plugin/plugin.json", manifest.as_bytes()),
        ("commands/hello.md", b"# hello"),
    ])
}

/// Publish, index, download, REST delete, re-index through the real router.
#[tokio::test]
#[ignore]
async fn publish_index_download_delete_reindex() {
    let r = rig(true).await;
    let key = r.key.clone();

    let (s1, b1) = r
        .publish("hello", "1.0.0", claude_bundle("hello", "1.0.0"))
        .await;
    let v2 = claude_bundle("hello", "1.1.0");
    let v2_sha = format!("{:x}", Sha256::digest(&v2));
    let (s2, _) = r.publish("hello", "1.1.0", v2.clone()).await;
    let standard = zip(&[
        (
            "std/plugin.json",
            br#"{"$schema":"https://agent-plugins.org/schemas/plugin-1.0.0.json","name":"std"}"#,
        ),
        ("std/mcp.json", b"{}"),
    ]);
    let (s3, b3) = r.publish("std", "0.1.0", standard).await;
    let (dup, _) = r.publish("hello", "1.1.0", v2.clone()).await;

    // Generic REST uploads are never indexed or served under /agentplugins:
    // a traversal zip at a version-shaped path, and a second file under an
    // existing version's coordinates.
    let traversal = zip(&[(".claude-plugin/plugin.json", b"{}"), ("../evil", b"x")]);
    let mut rest_statuses = Vec::new();
    for path in ["hello/2.0.0/hello-2.0.0.zip", "hello/1.1.0/other.zip"] {
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/repositories/{key}/artifacts/{path}"))
            .header("authorization", &r.basic)
            .body(Body::from(traversal.clone()))
            .unwrap();
        rest_statuses.push(call(&r.app, req).await.0);
    }
    let (rest_dl, _, _) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/hello/2.0.0/hello-2.0.0.zip"),
            None,
        ),
    )
    .await;

    let (claude_status, _, claude) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/claude-marketplace.json"),
            None,
        ),
    )
    .await;
    let claude = json(&claude);
    let (dl_status, dl_headers, dl) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/hello/1.1.0/hello-1.1.0.zip"),
            None,
        ),
    )
    .await;
    let (_, _, vscode) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/vscode-marketplace.json"),
            None,
        ),
    )
    .await;

    // Delete 1.1.0 through the REST API: every document drops it at once.
    let del = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/v1/repositories/{key}/artifacts/hello/1.1.0/hello-1.1.0.zip"
        ))
        .header("authorization", &r.basic)
        .body(Body::empty())
        .unwrap();
    let (del_status, _, del_body) = call(&r.app, del).await;
    let (_, _, after) = call(
        &r.app,
        get(&format!("/agentplugins/{key}/hello/index.json"), None),
    )
    .await;
    let after = json(&after);
    let (gone, _, _) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/hello/1.1.0/hello-1.1.0.zip"),
            None,
        ),
    )
    .await;
    r.teardown().await;

    assert_eq!(s1, StatusCode::CREATED, "{b1}");
    assert_eq!(s2, StatusCode::CREATED);
    assert_eq!(s3, StatusCode::CREATED, "{b3}");
    assert_eq!(b3["harnesses"], serde_json::json!(["standard"]));
    assert_eq!(dup, StatusCode::CONFLICT);

    assert!(
        rest_statuses.iter().all(|s| s.is_success()),
        "the generic REST uploads themselves are accepted: {rest_statuses:?}"
    );
    assert_eq!(rest_dl, StatusCode::NOT_FOUND);
    assert_eq!(claude_status, StatusCode::OK);
    assert_eq!(names(&claude), vec!["hello", "std"]);
    let hello = &claude["plugins"][0];
    assert_eq!(hello["version"], "1.1.0");
    assert_eq!(hello["source"]["source"], "archive");
    assert_eq!(hello["source"]["sha256"], v2_sha);
    assert_eq!(names(&json(&vscode)), vec!["std"]);

    assert_eq!(dl_status, StatusCode::OK);
    assert_eq!(dl, v2);
    assert_eq!(dl_headers["content-type"], "application/zip");
    assert_eq!(dl_headers["x-checksum-sha256"], v2_sha.as_str());

    assert!(
        del_status.is_success(),
        "REST delete: {del_status} {}",
        String::from_utf8_lossy(&del_body)
    );
    assert_eq!(after["latest"], "1.0.0");
    assert_eq!(after["versions"].as_array().unwrap().len(), 1);
    assert_eq!(gone, StatusCode::NOT_FOUND);
}

/// A private repository: anonymous reads are refused, the token-in-path
/// route serves the documents and archives, its URLs keep the prefix, and
/// a bogus token is refused.
#[tokio::test]
#[ignore]
async fn private_repository_token_in_path() {
    let r = rig(false).await;
    let key = r.key.clone();
    sqlx::query("UPDATE repositories SET visibility = 'private' WHERE id = $1")
        .bind(r.repo_id)
        .execute(&r.pool)
        .await
        .ok();
    let (published, body) = r
        .publish("hello", "1.0.0", claude_bundle("hello", "1.0.0"))
        .await;

    let (anon, _, _) = call(
        &r.app,
        get(
            &format!("/agentplugins/{key}/claude-marketplace.json"),
            None,
        ),
    )
    .await;
    let token = r.read_token.clone();
    let (ok, headers, doc) = call(
        &r.app,
        get(
            &format!("/agentplugins/t/{token}/{key}/claude-marketplace.json"),
            None,
        ),
    )
    .await;
    let doc = json(&doc);
    let archive = doc["plugins"][0]["source"]["url"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let archive_path = archive
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map(|(_, p)| format!("/{p}"))
        .unwrap_or_default();
    let (dl, _, _) = call(&r.app, get(&archive_path, None)).await;
    let (bogus, _, _) = call(
        &r.app,
        get(
            &format!("/agentplugins/t/not-a-token/{key}/claude-marketplace.json"),
            None,
        ),
    )
    .await;
    r.teardown().await;

    assert_eq!(published, StatusCode::CREATED, "{body}");
    assert_eq!(anon, StatusCode::UNAUTHORIZED);
    assert_eq!(ok, StatusCode::OK);
    assert_eq!(headers["cache-control"], "private, no-store");
    assert!(
        archive_path.starts_with(&format!("/agentplugins/t/{token}/{key}/")),
        "archive URL must keep the token prefix: {archive}"
    );
    assert_eq!(dl, StatusCode::OK);
    assert_eq!(bogus, StatusCode::UNAUTHORIZED);
}
