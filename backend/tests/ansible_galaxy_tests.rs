//! Ansible Galaxy client-contract integration tests (#3283).
//!
//! The Ansible format had no file in `backend/tests/` at all. Its only
//! coverage was `#[cfg(test)]` unit tests inside
//! `backend/src/api/handlers/ansible.rs`, and the conformance scripts in the
//! DTF repo assert on HTTP status codes only. Between them, three
//! client-visible breaks shipped behind green CI:
//!
//! * #3137 — discovery registered at `/api/` only, while `ansible-galaxy`
//!   requests `/api` (its `_urljoin` strips trailing slashes).
//! * #3137 — `Authorization: Token <key>` rejected as a malformed header;
//!   ansible-core's `GalaxyToken.token_type` is `'Token'`, never `'Bearer'`.
//! * #3282 — the publish response omitted the `task` key that
//!   `publish_collection` indexes unconditionally, so the CLI raised
//!   `KeyError: 'task'` *after* a successful upload.
//!
//! Every one of those is invisible to a test that picks its own URL spelling,
//! its own auth scheme, and reads only a status code. So these tests
//! deliberately do the opposite:
//!
//! 1. They drive the **production composition** — the real handler table
//!    nested at `/ansible` behind `repo_visibility_middleware` — because the
//!    reported 401 in #3137 came from the middleware, which the handler's own
//!    tests never reach.
//! 2. They use a **private** repository, so the middleware is load-bearing
//!    rather than waved through.
//! 3. They authenticate with `Authorization: Token <api_key>` exclusively,
//!    the byte-for-byte header ansible-core emits.
//! 4. They **re-derive** poll URLs the way the client does, from the response
//!    body, instead of constructing them independently. A test that builds its
//!    own URL cannot catch a wrong URL.
//! 5. They assert on **response bodies**, not just statuses.
//!
//! These tests require a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test ansible_galaxy_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt —
                                      // buffering response bodies in test
                                      // assertions is not an artifact path (#1608)

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::Router;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::ansible;
use artifact_keeper_backend::api::middleware::auth::{
    repo_visibility_middleware, RepoVisibilityState,
};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

// ===========================================================================
// Fixture
// ===========================================================================

/// Everything a test needs, torn down by [`Ctx::cleanup`].
///
/// Bundled into one struct rather than repeated per test so the publish and
/// install suites share a single setup path — the seven-helper-per-file shape
/// used elsewhere in `backend/tests/` multiplies quickly once a format needs
/// both a read-scoped and a write-scoped credential.
struct Ctx {
    pool: PgPool,
    app: Router,
    repo_key: String,
    repo_id: Uuid,
    user_id: Uuid,
    /// API token carrying `read:artifacts` + `write:artifacts`.
    write_token: String,
    /// API token carrying `read:artifacts` only, for the scope-gate test.
    read_token: String,
    storage_path: PathBuf,
}

impl Ctx {
    async fn setup() -> Ctx {
        let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();

        let suffix = Uuid::new_v4().to_string();
        let short = &suffix[..8];

        let user_id = Uuid::new_v4();
        let username = format!("ansible-it-u-{}", short);
        let pw_hash = bcrypt::hash("test-password", 4).expect("bcrypt hash failed");
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
             VALUES ($1, $2, $3, $4, 'local', true, true)",
        )
        .bind(user_id)
        .bind(&username)
        .bind(format!("{}@test.local", username))
        .bind(&pw_hash)
        .execute(&pool)
        .await
        .expect("failed to create test user");

        // Private on purpose: a public repo lets `repo_visibility_middleware`
        // wave every read through, which is exactly the code path that did
        // *not* fail in #3137. The reported break was on a private repo.
        let repo_id = Uuid::new_v4();
        let repo_key = format!("ansible-it-{}", short);
        let storage_path = std::env::temp_dir().join(format!("ansible-it-{}", suffix));
        std::fs::create_dir_all(&storage_path).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
             VALUES ($1, $2, $3, $4, 'local', 'ansible', false)",
        )
        .bind(repo_id)
        .bind(&repo_key)
        .bind(&repo_key)
        .bind(&*storage_path.to_string_lossy())
        .execute(&pool)
        .await
        .expect("failed to create ansible repository");

        // An explicit fine-grained grant, rather than relying on the user's
        // admin flag: `repo_visibility_middleware` resolves an API-token
        // principal through `check_repository_action`, which does not inherit
        // `users.is_admin` for a token-authenticated request. Without a grant a
        // private repo answers 404 on read (existence hiding) and 403 on write,
        // which is correct behaviour and exactly what the real deployment in
        // #3137 was doing.
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, ARRAY['read','write','delete'])",
        )
        .bind(user_id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("failed to grant repository permission");

        let storage_str = storage_path.to_string_lossy().to_string();
        let config = Config {
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            storage_path: storage_str.clone(),
            jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
            setup_password_hint: None,
            ..Default::default()
        };
        let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(&storage_str),
        );
        let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let state: SharedState = Arc::new(AppState::new(config, pool.clone(), storage, registry));

        let auth_service = Arc::new(AuthService::new(
            state.db.clone(),
            Arc::new(state.config.clone()),
        ));
        let (write_token, _) = auth_service
            .generate_api_token(
                user_id,
                "galaxy-write",
                vec!["read:artifacts".into(), "write:artifacts".into()],
                None,
            )
            .await
            .expect("mint write token");
        let (read_token, _) = auth_service
            .generate_api_token(user_id, "galaxy-read", vec!["read:artifacts".into()], None)
            .await
            .expect("mint read token");

        let vis_state = RepoVisibilityState {
            auth_service,
            db: state.db.clone(),
            repo_cache: state.repo_cache.clone(),
            permission_service: state.permission_service.clone(),
        };
        // Mirrors `api/routes.rs`: the handler table is nested at `/ansible`
        // and the whole thing sits under `repo_visibility_middleware`, so
        // `extract_repo_key` sees the production `/{format}/{repo_key}/...`
        // path shape.
        let app = Router::new()
            .nest("/ansible", ansible::router())
            .with_state(state)
            .layer(middleware::from_fn_with_state(
                vis_state,
                repo_visibility_middleware,
            ));

        Ctx {
            pool,
            app,
            repo_key,
            repo_id,
            user_id,
            write_token,
            read_token,
            storage_path,
        }
    }

    /// `GET uri` with `Authorization: Token <t>` — the only scheme
    /// `ansible-galaxy` ever sends for a Galaxy server.
    async fn get(&self, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder().uri(uri);
        if let Some(t) = token {
            builder = builder.header(axum::http::header::AUTHORIZATION, format!("Token {}", t));
        }
        let req = builder.body(Body::empty()).expect("build request");
        let resp = self.app.clone().oneshot(req).await.expect("request");
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body")
            .to_vec();
        (status, body)
    }

    async fn get_json(&self, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
        let (status, body) = self.get(uri, token).await;
        (status, decode_body(&body))
    }

    /// POST a collection exactly the way `ansible-galaxy publish` does: a
    /// multipart body with a `sha256` text part and a `file` part whose
    /// filename carries `{namespace}-{name}-{version}.tar.gz`.
    async fn publish(
        &self,
        token: &str,
        filename: &str,
        body: &[u8],
    ) -> (StatusCode, serde_json::Value) {
        let boundary = "----------------------------ansible-galaxy";
        let sha256 = hex::encode(Sha256::digest(body));

        let mut out = Vec::new();
        out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"sha256\"\r\n\r\n");
        out.extend_from_slice(sha256.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        out.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                filename
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/ansible/{}/api/v3/artifacts/collections/",
                self.repo_key
            ))
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Token {}", token),
            )
            .header(
                axum::http::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(out))
            .expect("build upload request");

        let resp = self.app.clone().oneshot(req).await.expect("upload");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        (status, decode_body(&bytes))
    }

    async fn cleanup(&self) {
        let _ = sqlx::query(
            "DELETE FROM artifact_metadata WHERE artifact_id IN \
             (SELECT id FROM artifacts WHERE repository_id = $1)",
        )
        .bind(self.repo_id)
        .execute(&self.pool)
        .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(self.repo_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(self.repo_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(self.repo_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(self.user_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(self.user_id)
            .execute(&self.pool)
            .await;
        let _ = std::fs::remove_dir_all(&self.storage_path);
    }
}

/// Decode a response body as JSON, falling back to the body as a plain string.
/// Error responses from these handlers are `text/plain`, and collapsing them to
/// `null` throws away the only diagnostic a failing assertion has.
fn decode_body(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(body).into_owned()))
}

/// Re-implements ansible-core's `_urljoin`: it joins with `/` after stripping
/// trailing slashes from every fragment. Used so the tests below navigate the
/// API by *deriving* URLs the way the client does rather than hardcoding a
/// spelling the handler happens to register (#3137).
fn urljoin(parts: &[&str]) -> String {
    let joined = parts
        .iter()
        .map(|p| p.trim_end_matches('/'))
        .collect::<Vec<_>>()
        .join("/");
    format!("{}/", joined)
}

/// ansible-core `stable-2.17`..`devel` keep only the last non-empty path
/// segment of the publish response's `task` and rebuild the poll URL from
/// `api_server`. Re-implemented here (rather than reusing the server's own
/// `import_task_href`) so a change to the server's URL shape that the client
/// could not follow shows up as a failure.
fn client_task_id(task: &str) -> String {
    task.split('/')
        .rfind(|s| !s.is_empty())
        .expect("task href has at least one segment")
        .to_string()
}

const COLLECTION_BODY: &[u8] = b"\x1f\x8b\x08\x00fake ansible collection tarball payload";

// ===========================================================================
// Discovery — both spellings, with the Token header attached (#3137)
// ===========================================================================

/// ansible-core's `GalaxyAPI._call_galaxy` probes discovery at `<server>/api`,
/// and `_add_auth_token` attaches `Authorization: Token <key>` to that probe
/// whenever a token is configured — *even though* the probe is
/// `auth_required=False`. So the discovery endpoint must accept the `Token`
/// scheme rather than 401 on it. Then the CLI reassigns `api_server` from
/// whichever discovery URL succeeded, so both spellings must work and must
/// agree.
#[tokio::test]
#[ignore]
async fn test_3283_discovery_accepts_both_spellings_with_token_scheme() {
    let ctx = Ctx::setup().await;

    let bare = format!("/ansible/{}/api", ctx.repo_key);
    let slashed = format!("/ansible/{}/api/", ctx.repo_key);

    let (bare_status, bare_json) = ctx.get_json(&bare, Some(&ctx.write_token)).await;
    let (slashed_status, slashed_json) = ctx.get_json(&slashed, Some(&ctx.write_token)).await;

    assert_eq!(
        bare_status,
        StatusCode::OK,
        "ansible-galaxy requests `/api` with no trailing slash (#3137); body: {bare_json}"
    );
    assert_eq!(slashed_status, StatusCode::OK, "body: {slashed_json}");
    assert_eq!(
        bare_json, slashed_json,
        "the CLI reassigns api_server from whichever spelling answered, so \
         the two must be interchangeable"
    );
    assert_eq!(bare_json["current_version"], "v3");

    // The middleware must still refuse an anonymous probe on a private repo.
    let (anon_status, _) = ctx.get(&bare, None).await;
    assert_eq!(
        anon_status,
        StatusCode::UNAUTHORIZED,
        "private repo discovery must require a credential"
    );

    // A syntactically valid but bogus token must not be waved through just
    // because the scheme parsed.
    let (bogus_status, _) = ctx.get(&bare, Some("not-a-real-token")).await;
    assert_eq!(bogus_status, StatusCode::UNAUTHORIZED);

    ctx.cleanup().await;
}

// ===========================================================================
// Install — discovery → versions → version detail → download
// ===========================================================================

/// The whole `ansible-galaxy collection install` path, navigated by following
/// the hrefs the server advertises instead of by constructing URLs.
///
/// `list_collections`, `version_list` and `version_info` had **zero** coverage
/// of any kind before this test — not a unit test, not a conformance case.
#[tokio::test]
#[ignore]
async fn test_3283_install_path_navigates_by_advertised_hrefs() {
    let ctx = Ctx::setup().await;
    let token = ctx.write_token.clone();

    let (status, _) = ctx
        .publish(&token, "community-general-1.2.3.tar.gz", COLLECTION_BODY)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "seed publish must succeed");

    // 1. Discovery, exactly as the client spells it.
    let api_root = format!("/ansible/{}/api", ctx.repo_key);
    let (status, discovery) = ctx.get_json(&api_root, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let v3 = discovery["available_versions"]["v3"]
        .as_str()
        .expect("discovery must advertise available_versions.v3");

    // 2. v3 service index, at the URL discovery pointed to.
    let v3_root = urljoin(&[&api_root, v3]);
    let (status, index) = ctx.get_json(&v3_root, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "v3 root at {v3_root}");
    assert!(
        index["collections"].is_string(),
        "v3 index must advertise a collections URL, got {index}"
    );

    // 3. Collection listing.
    let (status, list) = ctx
        .get_json(
            &format!("/ansible/{}/api/v3/collections/", ctx.repo_key),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["meta"]["count"], 1, "listing body: {list}");
    assert_eq!(list["data"][0]["namespace"], "community");
    assert_eq!(list["data"][0]["name"], "general");
    assert_eq!(list["data"][0]["highest_version"]["version"], "1.2.3");

    // 4. Version list, at the href the listing advertised.
    let coll_href = list["data"][0]["href"].as_str().expect("collection href");
    let versions_url = urljoin(&[coll_href, "versions"]);
    let (status, versions) = ctx.get_json(&versions_url, Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "versions at {versions_url} (derived from the advertised href)"
    );
    assert_eq!(versions["meta"]["count"], 1, "versions body: {versions}");
    assert_eq!(versions["data"][0]["version"], "1.2.3");

    // 5. Version detail, at the href the version list advertised.
    let version_href = versions["data"][0]["href"].as_str().expect("version href");
    let (status, detail) = ctx.get_json(version_href, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "version detail at {version_href}");
    assert_eq!(
        detail["artifact"]["sha256"],
        hex::encode(Sha256::digest(COLLECTION_BODY))
    );
    assert_eq!(
        detail["artifact"]["size"],
        COLLECTION_BODY.len() as i64,
        "detail body: {detail}"
    );

    // 6. Download, at the `download_url` the detail advertised. This is the
    //    step that makes the href chain load-bearing: if any advertised URL is
    //    wrong the client cannot install, and only a round-trip catches it.
    let download_url = detail["download_url"]
        .as_str()
        .expect("version detail must advertise download_url");
    let (status, bytes) = ctx.get(download_url, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "download at {download_url}");
    assert_eq!(
        bytes, COLLECTION_BODY,
        "downloaded bytes must be the published tarball"
    );

    ctx.cleanup().await;
}

// ===========================================================================
// Publish — upload → task → import poll → completion (#3282)
// ===========================================================================

/// `publish_collection` indexes `resp['task']` unconditionally and then hands
/// it to `wait_import_task`, which polls until `state` leaves `waiting` and
/// `finished_at` is populated. A 404 there is not a soft failure: the poll
/// retries 404 forever and `--import-timeout` defaults to 0, so the CLI hangs
/// rather than erroring.
///
/// This walks that contract with the client's own URL derivation, which is the
/// part a status-code-only conformance script cannot do.
#[tokio::test]
#[ignore]
async fn test_3283_publish_task_is_resolvable_by_the_client() {
    let ctx = Ctx::setup().await;
    let token = ctx.write_token.clone();

    let (status, resp) = ctx
        .publish(&token, "community-crypto-2.0.0.tar.gz", COLLECTION_BODY)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "publish body: {resp}");

    let task = resp["task"]
        .as_str()
        .expect("upload response has no `task`; ansible-galaxy raises KeyError: 'task' (#3282)");
    assert!(
        task.starts_with('/'),
        "task must be root-absolute so devel's urljoin(api_server, task) \
         resolves; got {task}"
    );

    // Poll at the URL the client rebuilds: last non-empty segment of `task`,
    // reattached to api_server. Both client generations land here.
    let import_url = format!(
        "/ansible/{}/api/v3/imports/collections/{}/",
        ctx.repo_key,
        client_task_id(task)
    );
    let (status, import) = ctx.get_json(&import_url, Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "import status {import_url} returned {status}; a 404 hangs the client"
    );
    assert_ne!(
        import["state"], "waiting",
        "state=waiting never exits wait_import_task's poll loop"
    );
    assert!(
        import["finished_at"].is_string(),
        "finished_at is the only loop exit; body: {import}"
    );
    assert!(
        import["messages"].is_array(),
        "wait_import_task iterates messages; body: {import}"
    );

    // The server also registers the spelling without the trailing slash.
    let bare = import_url.trim_end_matches('/').to_string();
    let (bare_status, _) = ctx.get(&bare, Some(&token)).await;
    assert_eq!(
        bare_status,
        StatusCode::OK,
        "the no-trailing-slash import spelling is registered and must answer"
    );

    ctx.cleanup().await;
}

/// A failed publish must return an error, never a `task`. If it returned a
/// task the CLI would report a successful import for an upload that never
/// happened.
#[tokio::test]
#[ignore]
async fn test_3283_failed_publish_carries_no_task() {
    let ctx = Ctx::setup().await;

    let (status, resp) = ctx
        .publish(&ctx.write_token, "not-a-collection.zip", COLLECTION_BODY)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        resp.get("task").is_none(),
        "a rejected upload must not advertise an import task; got {resp}"
    );

    ctx.cleanup().await;
}

// ===========================================================================
// Authorization
// ===========================================================================

/// A read-scoped token must be able to install but not publish. The 403 on
/// `write:artifacts` is enforced at `ansible.rs`'s
/// `require_auth_basic_scope(auth, "ansible", "write:artifacts")` and had no
/// test on the ansible route.
#[tokio::test]
#[ignore]
async fn test_3283_publish_requires_write_scope() {
    let ctx = Ctx::setup().await;

    let (status, _) = ctx
        .publish(
            &ctx.read_token,
            "community-general-9.9.9.tar.gz",
            COLLECTION_BODY,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-only token must not be able to publish"
    );

    // ...but the same token must still be able to read, or the scope gate is
    // just rejecting everything.
    let (status, _) = ctx
        .get(
            &format!("/ansible/{}/api/", ctx.repo_key),
            Some(&ctx.read_token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "read scope must still read");

    ctx.cleanup().await;
}

/// Every authenticated route must accept the `Token` scheme, not just
/// discovery. #3137 was reported against discovery, but `_add_auth_token`
/// attaches the same header to every call, so a scheme regression on any other
/// route breaks install just as thoroughly.
#[tokio::test]
#[ignore]
async fn test_3283_token_scheme_works_on_every_authenticated_route() {
    let ctx = Ctx::setup().await;
    let token = ctx.write_token.clone();

    let (status, _) = ctx
        .publish(&token, "community-general-1.0.0.tar.gz", COLLECTION_BODY)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let repo = &ctx.repo_key;
    for uri in [
        format!("/ansible/{}/api", repo),
        format!("/ansible/{}/api/", repo),
        format!("/ansible/{}/api/v3/", repo),
        format!("/ansible/{}/api/v3/collections/", repo),
        format!("/ansible/{}/api/v3/collections/community/general/", repo),
        format!(
            "/ansible/{}/api/v3/collections/community/general/versions/",
            repo
        ),
        format!(
            "/ansible/{}/api/v3/collections/community/general/versions/1.0.0/",
            repo
        ),
        format!("/ansible/{}/download/community-general-1.0.0.tar.gz", repo),
    ] {
        let (with_token, _) = ctx.get(&uri, Some(&token)).await;
        assert_eq!(
            with_token,
            StatusCode::OK,
            "`Authorization: Token <key>` must be accepted on {uri} (#3137)"
        );

        let (anon, _) = ctx.get(&uri, None).await;
        assert_eq!(
            anon,
            StatusCode::UNAUTHORIZED,
            "{uri} must require a credential on a private repo"
        );
    }

    ctx.cleanup().await;
}
