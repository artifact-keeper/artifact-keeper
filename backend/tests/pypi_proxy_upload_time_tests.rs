//! Integration test for the PyPI proxy `upload-time` fix (proxy half of #1545).
//!
//! For a Remote (or virtual-with-remote) repo, a JSON simple-index request must
//! honour the client `Accept` and serve the upstream's PEP 691 JSON — including
//! PEP 700 `upload-time` — with `files[].url` rewritten through the proxy.
//!
//! Regression discriminator: before the fix, `simple_project` proxied the
//! upstream index ignoring `Accept` and relayed the body verbatim, so the
//! download URLs still pointed at the upstream CDN (and against real PyPI, which
//! defaults to HTML, no `upload-time` was present at all). After the fix the
//! URLs route through the proxy and `upload-time` is preserved.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test pypi_proxy_upload_time_tests -- --ignored
//! ```

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Extension;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use artifact_keeper_backend::api::handlers::pypi;
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::proxy_service::ProxyService;
use artifact_keeper_backend::services::storage_service::{FilesystemBackend, StorageService};

const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    }
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    let mut state = AppState::new(test_config(storage_path), pool.clone(), storage, registry);

    let proxy_backend = Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
        storage_path,
    )));
    let storage_service = Arc::new(StorageService::new(proxy_backend));
    state.proxy_service = Some(Arc::new(ProxyService::new(pool, storage_service)));

    Arc::new(state)
}

async fn create_remote_pypi_repo(pool: &PgPool, upstream_url: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("pypi-remote-{}", &id.to_string()[..8]);
    let storage_path = format!("/tmp/pypi-proxy-ut-{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, is_public)
         VALUES ($1, $2, $2, $3, 'remote', 'pypi'::repository_format, $4, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .bind(upstream_url)
    .execute(pool)
    .await
    .expect("insert remote pypi repo");
    (id, key)
}

async fn cleanup(pool: &PgPool, id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
}

/// Upstream PEP 691 JSON for `requests`, with a CDN download URL, a PEP 700
/// `upload-time`, and a PEP 714 `core-metadata` signal to exercise preservation.
fn upstream_pep691_json() -> String {
    serde_json::json!({
        "meta": {"api-version": "1.1"},
        "name": "requests",
        "versions": ["2.32.3"],
        "files": [{
            "filename": "requests-2.32.3-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/f9/9b/requests-2.32.3-py3-none-any.whl",
            "hashes": {"sha256": "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"},
            "requires-python": ">=3.8",
            "size": 64928,
            "upload-time": "2024-05-29T15:37:49.215370Z",
            "core-metadata": {"sha256": "deadbeefcafe"}
        }]
    })
    .to_string()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn remote_pypi_proxy_serves_pep691_json_with_upload_time() {
    let upstream = MockServer::start().await;
    // Respond to any GET with the PEP 691 JSON. The fix requests the JSON form
    // from upstream; pre-fix it relayed whatever it got verbatim (URLs never
    // rewritten) — which is what this test's URL assertions catch.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(upstream_pep691_json().into_bytes(), PEP691_JSON),
        )
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/pypi-proxy-ut-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let (repo_id, repo_key) = create_remote_pypi_repo(&pool, &upstream.uri()).await;
    let state = build_state(pool.clone(), &storage_path);

    let app = pypi::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/simple/requests/", repo_key))
        .header("accept", PEP691_JSON)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body).to_string();

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert_eq!(status, StatusCode::OK, "body: {}", body_str);
    assert!(
        ct.contains(PEP691_JSON),
        "proxy must serve PEP 691 JSON for a JSON Accept, got content-type {ct}"
    );

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let file = &json["files"][0];

    // Download URL routes through the proxy, not the upstream CDN (the
    // pre-fix verbatim passthrough left this pointing at pythonhosted.org).
    assert_eq!(
        file["url"],
        format!(
            "/pypi/{}/simple/requests/requests-2.32.3-py3-none-any.whl",
            repo_key
        ),
        "files[].url must be rewritten through the proxy"
    );
    assert!(
        !body_str.contains("files.pythonhosted.org"),
        "no upstream CDN URLs should leak through the proxy"
    );

    // PEP 700 upload-time preserved, alongside size / hashes / requires-python.
    assert_eq!(file["upload-time"], "2024-05-29T15:37:49.215370Z");
    assert_eq!(file["size"], 64928);
    assert_eq!(
        file["hashes"]["sha256"],
        "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"
    );
    assert_eq!(file["requires-python"], ">=3.8");

    // PEP 658/714 metadata signal is preserved so clients can request the
    // upstream .metadata resource through the proxy.
    assert_eq!(file["core-metadata"]["sha256"], "deadbeefcafe");
}

/// A remote index may advertise PEP 658 metadata even when the corresponding
/// `.whl.metadata` resource is unavailable upstream. The proxy must preserve
/// the advertised attributes without turning pip's metadata request into a
/// hard 404: extract the metadata from the upstream wheel instead.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn remote_pypi_metadata_404_falls_back_to_wheel_metadata() {
    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: String) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    probe.connect("8.8.8.8:80").unwrap();
    let bind_ip = probe.local_addr().unwrap().ip();
    let _ssrf_allowlist = EnvVarGuard::set(
        "AK_SSRF_ALLOW_PRIVATE_CIDRS",
        format!("{bind_ip}/{}", if bind_ip.is_ipv4() { 32 } else { 128 }),
    );
    let listener = std::net::TcpListener::bind((bind_ip, 0)).unwrap();
    let upstream = MockServer::builder().listener(listener).start().await;
    let project = "demo";
    let wheel = "demo-1.0-py3-none-any.whl";
    let wheel_bytes = {
        use std::io::Write;

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("demo-1.0.dist-info/METADATA", options)
            .unwrap();
        zip.write_all(b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
            .unwrap();
        zip.finish().unwrap();
        cursor.into_inner()
    };
    let index = format!(
        "<html><body><a href=\"/packages/{wheel}\" data-dist-info-metadata=\"sha256=deadbeef\">{wheel}</a></body></html>"
    );

    Mock::given(method("GET"))
        .and(path(format!("/simple/{project}/")))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{wheel}.metadata")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/packages/{wheel}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel_bytes))
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/pypi-proxy-metadata-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let (repo_id, repo_key) = create_remote_pypi_repo(&pool, &upstream.uri()).await;
    let state = build_state(pool.clone(), &storage_path);
    let app = pypi::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/simple/{project}/{wheel}.metadata", repo_key))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_text = String::from_utf8_lossy(&body);

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert_eq!(status, StatusCode::OK, "response body: {body_text}");
    assert_eq!(
        body.as_ref(),
        b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
    );
}
