//! Integration test for the stale-if-error response marking and configurable
//! grace window (#4581).
//!
//! A virtual RubyGems repository resolves `api/v1/gems/{name}.json` through a
//! Remote member. After a successful fill the member's upstream starts
//! answering 503:
//!
//!   * inside the grace window the virtual answers 200 with
//!     `Warning: 110` and `X-AK-Stale-Since`, and the member records that it
//!     served stale;
//!   * past the window the failure surfaces instead of a stale body.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo nextest run --run-ignored ignored-only --test proxy_stale_if_error_tests
//! ```

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Extension;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use artifact_keeper_backend::api::handlers::rubygems;
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::proxy_service::ProxyService;
use artifact_keeper_backend::services::storage_service::{FilesystemBackend, StorageService};

const CACHE_TTL_SECS: i64 = 1;
const GRACE_SECS: i64 = 2;

fn build_state(pool: PgPool, storage_path: &str) -> (SharedState, Arc<ProxyService>) {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    };
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    let mut state = AppState::new(config, pool.clone(), storage, registry);
    let proxy_backend = Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
        storage_path,
    )));
    let proxy = Arc::new(ProxyService::new(
        pool,
        Arc::new(StorageService::new(proxy_backend)),
        artifact_keeper_backend::services::proxy_cache_scope::ProxyCacheScope::unscoped(),
    ));
    state.proxy_service = Some(proxy.clone());
    (Arc::new(state), proxy)
}

async fn insert_repo(
    pool: &PgPool,
    prefix: &str,
    repo_type: &str,
    upstream_url: Option<&str>,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("{prefix}-{}", &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, is_public)
         VALUES ($1, $2, $2, $3, $4::repository_type, 'rubygems'::repository_format, $5, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/stale-if-error-{id}"))
    .bind(repo_type)
    .bind(upstream_url)
    .execute(pool)
    .await
    .expect("insert repo");
    (id, key)
}

async fn set_config(pool: &PgPool, repo_id: Uuid, key: &str, value: i64) {
    sqlx::query("INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3)")
        .bind(repo_id)
        .bind(key)
        .bind(value.to_string())
        .execute(pool)
        .await
        .expect("insert repository_config");
}

async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn stale_member_is_marked_within_grace_and_fails_after_it() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(br#"{"name":"rack"}"#.to_vec(), "application/json"),
        )
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;

    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let storage_path = format!("/tmp/stale-if-error-ut-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();
    let (remote_id, _) = insert_repo(&pool, "gems-remote", "remote", Some(&upstream.uri())).await;
    let (virtual_id, virtual_key) = insert_repo(&pool, "gems-virtual", "virtual", None).await;
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) VALUES ($1, $2, 1)",
    )
    .bind(virtual_id)
    .bind(remote_id)
    .execute(&pool)
    .await
    .unwrap();
    set_config(&pool, remote_id, "cache_ttl_secs", CACHE_TTL_SECS).await;
    set_config(&pool, remote_id, "stale_if_error_grace_secs", GRACE_SECS).await;

    let (state, proxy) = build_state(pool.clone(), &storage_path);
    let app = rubygems::router()
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None));
    let get = || {
        let app = app.clone();
        let uri = format!("/{virtual_key}/api/v1/gems/rack.json");
        async move {
            app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };

    let fresh = get().await;
    let fresh_status = fresh.status();
    let fresh_warning = fresh.headers().get("warning").cloned();
    let fresh_since = fresh.headers().get("x-ak-stale-since").cloned();

    tokio::time::sleep(Duration::from_millis(1300)).await;
    let stale = get().await;
    let stale_status = stale.status();
    let stale_warning = stale.headers().get("warning").cloned();
    let stale_since = stale.headers().get("x-ak-stale-since").cloned();
    let stale_body = axum::body::to_bytes(stale.into_body(), 1 << 20)
        .await
        .unwrap();
    let served_at = proxy.last_stale_served_at(remote_id).await;

    tokio::time::sleep(Duration::from_secs((GRACE_SECS + 1) as u64)).await;
    let expired_status = get().await.status();

    cleanup(&pool, &[virtual_id, remote_id]).await;
    let _ = std::fs::remove_dir_all(&storage_path);

    assert_eq!(fresh_status, StatusCode::OK);
    assert!(fresh_warning.is_none() && fresh_since.is_none());

    assert_eq!(
        stale_status,
        StatusCode::OK,
        "inside the grace the cache serves"
    );
    assert_eq!(&stale_body[..], br#"{"name":"rack"}"#);
    assert_eq!(stale_warning.unwrap(), "110 - \"Response is stale\"");
    assert!(stale_since.is_some(), "X-AK-Stale-Since must be present");
    assert!(
        served_at.is_some(),
        "the member must record that it served stale"
    );

    assert_ne!(
        expired_status,
        StatusCode::OK,
        "past the grace the upstream failure must surface"
    );
}
