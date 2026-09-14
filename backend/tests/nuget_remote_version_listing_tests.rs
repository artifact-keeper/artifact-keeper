//! Integration tests for NuGet remote repository version listing, autocomplete, and service index.
//!
//! Tests:
//! 1. `test_service_index_advertises_autocomplete_and_v360`: Checks that `/v3/index.json`
//!    advertises `SearchAutocompleteService` and `RegistrationsBaseUrl/3.6.0`.
//! 2. `test_flatcontainer_versions_merges_upstream_when_local_artifact_exists`: Verifies that
//!    when a local artifact version exists in the DB for a remote repo, `/v3/flatcontainer/{id}/index.json`
//!    still queries upstream and returns all upstream versions rather than only returning the local cached version.
//! 3. `test_autocomplete_endpoint_returns_version_list`: Tests `/v3/autocomplete?id={id}` endpoint.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test nuget_remote_version_listing_tests -- --ignored
//! ```

#![allow(clippy::disallowed_methods)]
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

use artifact_keeper_backend::api::handlers::nuget;
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::proxy_service::ProxyService;
use artifact_keeper_backend::services::storage_service::{FilesystemBackend, StorageService};

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
    state.proxy_service = Some(Arc::new(ProxyService::new(
        pool,
        storage_service,
        artifact_keeper_backend::services::proxy_cache_scope::ProxyCacheScope::unscoped(),
    )));

    Arc::new(state)
}

async fn create_remote_nuget_repo(pool: &PgPool, upstream_url: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("nuget-remote-{}", &id.to_string()[..8]);
    let storage_path = format!("/tmp/nuget-proxy-test-{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, is_public)
         VALUES ($1, $2, $2, $3, 'remote', 'nuget'::repository_format, $4, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .bind(upstream_url)
    .execute(pool)
    .await
    .expect("insert remote nuget repo");
    (id, key)
}

async fn create_local_nuget_repo(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("nuget-local-{}", &id.to_string()[..8]);
    let storage_path = format!("/tmp/nuget-local-test-{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public)
         VALUES ($1, $2, $2, $3, 'local', 'nuget'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("insert local nuget repo");
    (id, key)
}

async fn cleanup(pool: &PgPool, id: Uuid) {
    let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_service_index_advertises_autocomplete_and_v360() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-svc-index-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let (repo_id, repo_key) = create_remote_nuget_repo(&pool, "https://api.nuget.org/v3/index.json").await;
    let state = build_state(pool.clone(), &storage_path);

    let app = nuget::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));

    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v3/index.json", repo_key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let resources = json["resources"].as_array().expect("resources array");

    let has_autocomplete = resources.iter().any(|r| {
        r["@type"]
            .as_str()
            .map(|t| t.starts_with("SearchAutocompleteService"))
            .unwrap_or(false)
    });
    let has_v360 = resources.iter().any(|r| {
        r["@type"].as_str() == Some("RegistrationsBaseUrl/3.6.0")
    });

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert!(
        has_autocomplete,
        "service_index must advertise SearchAutocompleteService"
    );
    assert!(
        has_v360,
        "service_index must advertise RegistrationsBaseUrl/3.6.0"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_flatcontainer_versions_merges_upstream_when_local_artifact_exists() {
    let upstream = MockServer::start().await;

    // 1. Mock upstream service index
    let service_index_json = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3-flatcontainer/", upstream.uri()),
                "@type": "PackageBaseAddress/3.0.0"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/v3/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&service_index_json))
        .mount(&upstream)
        .await;

    // 2. Mock upstream flatcontainer versions response
    let upstream_versions_json = serde_json::json!({
        "versions": ["12.0.1", "13.0.1", "13.0.3"]
    });

    Mock::given(method("GET"))
        .and(path("/v3-flatcontainer/newtonsoft.json/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&upstream_versions_json))
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-flatcontainer-test-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    let upstream_index_url = format!("{}/v3/index.json", upstream.uri());
    let (repo_id, repo_key) = create_remote_nuget_repo(&pool, &upstream_index_url).await;

    // Insert a local artifact row in DB representing 1 restored version ("13.0.1")
    let artifact_id = Uuid::new_v4();
    sqlx::query(
           "INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
            VALUES ($1, $2, 'newtonsoft.json', '13.0.1', 'newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg', 1000, 'sha256placeholder', 'application/octet-stream', 'key', false)"
    )
    .bind(artifact_id)
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("insert local artifact");

    let state = build_state(pool.clone(), &storage_path);

    let app = nuget::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));

    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v3/flatcontainer/newtonsoft.json/index.json", repo_key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let versions = json["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<&str>>();

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    // Prior to fix, this would only return ["13.0.1"] because the local DB hit short-circuited upstream fetch.
    assert!(
        versions.contains(&"12.0.1") && versions.contains(&"13.0.3"),
        "flatcontainer version listing must return all upstream versions even when a version is cached locally; got {:?}",
        versions
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_autocomplete_endpoint_returns_version_list() {
    let upstream = MockServer::start().await;

    // 1. Mock upstream service index with SearchAutocompleteService
    let service_index_json = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3-autocomplete", upstream.uri()),
                "@type": "SearchAutocompleteService"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/v3/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&service_index_json))
        .mount(&upstream)
        .await;

    // 2. Mock upstream autocomplete response
    let autocomplete_json = serde_json::json!({
        "totalHits": 3,
        "data": ["12.0.1", "13.0.1", "13.0.3"]
    });

    Mock::given(method("GET"))
        .and(path("/v3-autocomplete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&autocomplete_json))
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-autocomplete-test-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    let upstream_index_url = format!("{}/v3/index.json", upstream.uri());
    let (repo_id, repo_key) = create_remote_nuget_repo(&pool, &upstream_index_url).await;

    let state = build_state(pool.clone(), &storage_path);

    let app = nuget::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));

    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v3/autocomplete?id=Newtonsoft.Json&prerelease=true", repo_key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let data = json["data"].as_array().expect("data array");

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert_eq!(data.len(), 3);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_local_autocomplete_returns_package_ids_and_versions() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-local-autocomplete-test-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let (repo_id, repo_key) = create_local_nuget_repo(&pool).await;
    sqlx::query(
        "INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
         VALUES ($1, $2, 'Example.Package', '1.2.3', 'example.package/1.2.3/example.package.1.2.3.nupkg', 1, 'sha256placeholder', 'application/octet-stream', 'key', false)",
    )
    .bind(Uuid::new_v4())
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("insert local NuGet artifact");
    let app = nuget::router()
        .with_state(build_state(pool.clone(), &storage_path))
        .layer(Extension::<Option<AuthExtension>>(None));

    for (query, expected) in [
        ("q=example", "Example.Package"),
        ("id=Example.Package", "1.2.3"),
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/{repo_key}/v3/autocomplete?{query}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert!(String::from_utf8_lossy(&body).contains(expected));
    }

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_registration_page_is_proxied_and_rewritten() {
    let upstream = MockServer::start().await;
    let service_index_json = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3-registration/", upstream.uri()),
                "@type": "RegistrationsBaseUrl/3.6.0"
            },
            {
                "@id": format!("{}/v3-flatcontainer/", upstream.uri()),
                "@type": "PackageBaseAddress/3.0.0"
            }
        ]
    });
    Mock::given(method("GET"))
        .and(path("/v3/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&service_index_json))
        .mount(&upstream)
        .await;

    let registration_index = serde_json::json!({
        "items": [{
            "@id": format!(
                "{}/v3-registration/serilog/page/0.1.6/1.2.47.json",
                upstream.uri()
            )
        }]
    });
    Mock::given(method("GET"))
        .and(path("/v3-registration/serilog/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&registration_index))
        .mount(&upstream)
        .await;

    let registration_page = serde_json::json!({
        "@id": format!("{}/v3-registration/serilog/page/0.1.6/1.2.47.json", upstream.uri()),
        "items": [{
            "catalogEntry": {
                "@id": format!("{}/v3-registration/serilog/1.2.47.json", upstream.uri()),
                "packageContent": format!("{}/v3-flatcontainer/serilog/1.2.47/serilog.1.2.47.nupkg", upstream.uri())
            }
        }]
    });
    Mock::given(method("GET"))
        .and(path("/v3-registration/serilog/page/0.1.6/1.2.47.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&registration_page))
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-registration-page-test-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let upstream_index_url = format!("{}/v3/index.json", upstream.uri());
    let (repo_id, repo_key) = create_remote_nuget_repo(&pool, &upstream_index_url).await;
    let state = build_state(pool.clone(), &storage_path);
    let app = nuget::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));

    let index_req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v3/registration/serilog/index.json", repo_key))
        .body(Body::empty())
        .unwrap();
    let index_resp = app.clone().oneshot(index_req).await.unwrap();
    assert_eq!(index_resp.status(), StatusCode::OK);
    let index_body = axum::body::to_bytes(index_resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let index_json: serde_json::Value = serde_json::from_slice(&index_body).unwrap();
    let page_url = index_json["items"][0]["@id"]
        .as_str()
        .expect("rewritten registration page URL");
    assert!(!page_url.contains(&upstream.uri()));
    let page_uri = reqwest::Url::parse(page_url)
        .unwrap()
        .path()
        .strip_prefix("/nuget")
        .expect("NuGet route prefix")
        .to_string();

    let page_req = Request::builder()
        .method("GET")
        .uri(page_uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(page_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "rewritten page URL: {page_url}");
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();

    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert!(
        !body.contains(&upstream.uri()),
        "proxied registration page must not expose upstream URLs: {body}"
    );
    assert!(body.contains(&format!("/{}/v3/registration/serilog/", repo_key)));
    assert!(body.contains(&format!("/{}/v3/flatcontainer/serilog/", repo_key)));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_registration_subresource_rejects_unsafe_paths_before_proxying() {
    let upstream = MockServer::start().await;
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/nuget-registration-path-test-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let upstream_index_url = format!("{}/v3/index.json", upstream.uri());
    let (repo_id, repo_key) = create_remote_nuget_repo(&pool, &upstream_index_url).await;
    let state = build_state(pool.clone(), &storage_path);
    let app = nuget::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));

    for subpath in [
        "page/item%3Fx=.json",
        "page/item%23anchor.json",
        "page/%2E%2E/item.json",
        "page/item%5Cpath.json",
        "page/item.txt",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/{repo_key}/v3/registration/serilog/{subpath}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "subpath: {subpath}");
    }

    let package_id_req = Request::builder()
        .method("GET")
        .uri(format!("/{repo_key}/v3/registration/serilog%3Fx/index.json"))
        .body(Body::empty())
        .unwrap();
    let package_id_resp = app.oneshot(package_id_req).await.unwrap();
    assert_eq!(package_id_resp.status(), StatusCode::BAD_REQUEST);

    let requests = upstream.received_requests().await.unwrap();
    cleanup(&pool, repo_id).await;
    let _ = std::fs::remove_dir_all(&storage_path);
    assert!(requests.is_empty(), "unsafe paths must not reach the upstream");
}
