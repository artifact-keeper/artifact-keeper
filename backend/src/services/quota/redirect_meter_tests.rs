//! The transfer meter counts every presigned redirect a download `GET` can
//! answer at the object's size (#6035), through the production router and
//! against a real database (each test skips without `DATABASE_URL`).
//!
//! With presigned downloads on, the object's bytes leave storage without
//! passing through the backend, so the size has to be added when the URL is
//! issued; otherwise the transfer quota means less with redirects on than
//! off. Each route below answers `3xx` with `X-Artifact-Storage: redirect-*`
//! for an object of a distinct size, and the meter must grow by exactly that
//! size: not 0 (the redirect was missed) and not twice (counted at the call
//! site and again in the builder).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::download_response::X_ARTIFACT_STORAGE;
use crate::api::handlers::test_db_helpers as tdh;
use crate::api::SharedState;
use crate::services::proxy_cache_scope::ProxyCacheScope;
use crate::services::proxy_service::{CacheMetadata, ProxyService};
use crate::storage::StorageLocation;

struct Walk {
    pool: PgPool,
    state: SharedState,
    app: Router,
    cache: Arc<tdh::PresignMemBackend>,
    auth: String,
    user_id: Uuid,
    repos: Vec<(Uuid, String, std::path::PathBuf)>,
}

impl Walk {
    async fn setup() -> Option<Self> {
        let pool = tdh::try_pool().await?;
        let (proxy, cache) =
            tdh::build_scoped_presign_proxy(pool.clone(), ProxyCacheScope::unscoped());
        let (state, _mem) =
            tdh::build_presigning_cloud_state_with_proxy(pool.clone(), "s3", proxy, |c| {
                // Far above anything these tests download: the meter is on
                // and never refuses.
                c.quotas.transfer_quota_bytes = 1 << 40;
            });
        assert!(state.transfer_meter.enabled());
        let app = crate::api::routes::create_router(state.clone());
        let (user_id, auth) = admin_basic(&pool).await;
        Some(Self {
            pool,
            state,
            app,
            cache,
            auth,
            user_id,
            repos: Vec::new(),
        })
    }

    /// A repository whose objects live on the presigning `s3` backend.
    async fn repo(&mut self, repo_type: &str, format: &str) -> (Uuid, String) {
        let (id, key, dir) = tdh::create_repo(&self.pool, repo_type, format).await;
        sqlx::query(
            "UPDATE repositories SET storage_backend = 's3', storage_path = key WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .unwrap();
        self.repos.push((id, key.clone(), dir));
        (id, key)
    }

    /// Write `size` bytes at `storage_key` in repository `key`'s storage.
    async fn put_object(&self, key: &str, storage_key: &str, size: usize) {
        let location = StorageLocation {
            backend: "s3".to_string(),
            path: key.to_string(),
        };
        self.state
            .storage_for_repo(&location)
            .unwrap()
            .put(storage_key, Bytes::from(vec![b'x'; size]))
            .await
            .unwrap();
    }

    /// A hosted artifact row of `size` bytes at `path`, with its object.
    async fn seed_artifact(&self, repo: (Uuid, &str), path: &str, size: usize) {
        let storage_key = format!("t6035/{}", Uuid::new_v4());
        self.put_object(repo.1, &storage_key, size).await;
        let name = path.rsplit('/').next().unwrap();
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, '1.0', $4, $5, 'application/octet-stream', $6)",
        )
        .bind(repo.0)
        .bind(path)
        .bind(name)
        .bind(size as i64)
        .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
        .bind(&storage_key)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    /// An `oci_blobs` row of `size` bytes, with its object; returns the digest.
    async fn seed_blob(&self, repo: (Uuid, &str), size: usize) -> String {
        let digest = format!("sha256:{:064x}", Uuid::new_v4().as_u128());
        let storage_key = format!("t6035/blobs/{}", &digest[7..]);
        self.put_object(repo.1, &storage_key, size).await;
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(repo.0)
        .bind(&digest)
        .bind(size as i64)
        .bind(&storage_key)
        .execute(&self.pool)
        .await
        .unwrap();
        digest
    }

    /// A fresh proxy-cache entry for Remote `repo_key` whose sidecar records
    /// `size` bytes. The stored body is deliberately a different length, so
    /// a redirect that took its size from anywhere but the sidecar fails.
    fn seed_cache(&self, repo_key: &str, cache_path: &str, size: usize) {
        let scope = ProxyCacheScope::unscoped();
        let content = ProxyService::cache_storage_key(&scope, repo_key, cache_path).unwrap();
        let meta = ProxyService::cache_metadata_key(&scope, repo_key, cache_path).unwrap();
        let mut sidecar: CacheMetadata =
            serde_json::from_slice(&tdh::fresh_cache_sidecar_bytes()).unwrap();
        sidecar.size_bytes = size as i64;
        let mut objects = self.cache.objects.lock().unwrap();
        objects.insert(content, Bytes::from(vec![b'c'; size + 13]));
        objects.insert(meta, Bytes::from(serde_json::to_vec(&sidecar).unwrap()));
    }

    async fn send(&self, method: Method, uri: &str, body: Body) -> (StatusCode, Bytes) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, &self.auth)
            .body(body)
            .unwrap();
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let storage = response
            .headers()
            .get(X_ARTIFACT_STORAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        if status.is_redirection() {
            assert!(
                storage.starts_with("redirect-"),
                "{uri}: a presigned redirect names its source, got {storage:?}"
            );
        }
        (status, body)
    }

    /// `GET uri` answers a presigned redirect and the meter grows by `size`.
    async fn assert_counted(&self, label: &str, uri: &str, size: usize) {
        let before = self.state.transfer_meter.used_bytes();
        let (status, body) = self.send(Method::GET, uri, Body::empty()).await;
        assert!(
            status.is_redirection(),
            "{label}: expected a presigned redirect, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(body.is_empty(), "{label}: a redirect carries no bytes");
        assert_eq!(
            self.state.transfer_meter.used_bytes() - before,
            size as u64,
            "{label}: the meter must count the object's size once"
        );
    }

    async fn teardown(self) {
        let ids: Vec<Uuid> = self.repos.iter().map(|r| r.0).collect();
        for sql in [
            "DELETE FROM oci_blobs WHERE repository_id = ANY($1)",
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = ANY($1)",
        ] {
            let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&ids)
                .execute(&self.pool)
                .await;
        }
        for (id, _, dir) in &self.repos {
            tdh::cleanup_member_repo(&self.pool, *id, dir).await;
        }
        tdh::cleanup_user(&self.pool, self.user_id).await;
        // The meter flushes nothing here (no flusher is spawned), so the
        // shared monthly row is untouched.
    }
}

/// An admin with a bcrypt password, as `Basic` credentials.
async fn admin_basic(pool: &PgPool) -> (Uuid, String) {
    use base64::Engine;
    let id = Uuid::new_v4();
    let username = format!("quota6035-{id}");
    let hash = bcrypt::hash("quotapass", 4).unwrap();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, \
         is_active, password_changed_at, privileges_changed_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'local', true, true, NOW() - INTERVAL '60 seconds', \
         NOW() - INTERVAL '60 seconds', NOW() - INTERVAL '60 seconds', \
         NOW() - INTERVAL '60 seconds')",
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{username}@test.local"))
    .bind(&hash)
    .execute(pool)
    .await
    .unwrap();
    let raw = format!("{username}:quotapass");
    (
        id,
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        ),
    )
}

/// Hosted objects: the repository download API, the Maven blob route, an
/// OCI blob on its own `oci_blobs` row, an OCI blob of a virtual's local
/// member and a PyPI virtual's local member.
#[tokio::test]
async fn hosted_presigned_redirects_count_the_object_size_6035() {
    let Some(mut w) = Walk::setup().await else {
        return;
    };

    // Maven jar published through the router: the Maven route and the
    // repository download API both redirect to it.
    let (_, maven) = w.repo("local", "maven").await;
    let jar_path = "com/t6035/lib/1.0/lib-1.0.jar";
    let (status, body) = w
        .send(
            Method::PUT,
            &format!("/maven/{maven}/{jar_path}"),
            Body::from(vec![b'j'; 1_001]),
        )
        .await;
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&body)
    );
    w.assert_counted(
        "maven hosted blob",
        &format!("/maven/{maven}/{jar_path}"),
        1_001,
    )
    .await;
    w.assert_counted(
        "repository download API",
        &format!("/api/v1/repositories/{maven}/download/{jar_path}"),
        1_001,
    )
    .await;

    // OCI: a local repository's own blob, and a virtual's local member blob.
    let local = w.repo("local", "docker").await;
    let own = w.seed_blob((local.0, &local.1), 2_002).await;
    w.assert_counted(
        "OCI blob on its own oci_blobs row",
        &format!("/v2/{}/myimage/blobs/{own}", local.1),
        2_002,
    )
    .await;
    let virt = w.repo("virtual", "docker").await;
    tdh::link_virtual_member(&w.pool, virt.0, local.0, 1).await;
    let member = w.seed_blob((local.0, &local.1), 3_003).await;
    w.assert_counted(
        "OCI blob of a virtual's local member",
        &format!("/v2/{}/myimage/blobs/{member}", virt.1),
        3_003,
    )
    .await;

    // PyPI: a virtual's hosted member (`local_fetch_or_redirect`).
    let pypi_local = w.repo("local", "pypi").await;
    let wheel = "hosted6035-1.0-py3-none-any.whl";
    w.seed_artifact(
        (pypi_local.0, &pypi_local.1),
        &format!("hosted6035/{wheel}"),
        4_004,
    )
    .await;
    let pypi_virt = w.repo("virtual", "pypi").await;
    tdh::link_virtual_member(&w.pool, pypi_virt.0, pypi_local.0, 1).await;
    w.assert_counted(
        "PyPI virtual's hosted member",
        &format!("/pypi/{}/simple/hosted6035/{wheel}", pypi_virt.1),
        4_004,
    )
    .await;

    w.teardown().await;
}

/// Proxy-cached objects: a Remote OCI blob, a Remote PyPI distribution (direct
/// and through a virtual) and a virtual's Remote member (RubyGems), each
/// redirected from a fresh cache entry whose sidecar records the size.
#[tokio::test]
async fn proxy_cached_presigned_redirects_count_the_object_size_6035() {
    let Some(mut w) = Walk::setup().await else {
        return;
    };

    let (_, oci_remote) = w.repo("remote", "docker").await;
    let digest = format!("sha256:{:064x}", Uuid::new_v4().as_u128());
    w.seed_cache(&oci_remote, &format!("v2/myimage/blobs/{digest}"), 5_005);
    w.assert_counted(
        "OCI Remote blob in the proxy cache",
        &format!("/v2/{oci_remote}/myimage/blobs/{digest}"),
        5_005,
    )
    .await;

    let (_, pypi_remote) = w.repo("remote", "pypi").await;
    let wheel = "cached6035-1.0-py3-none-any.whl";
    w.seed_cache(&pypi_remote, &format!("simple/cached6035/{wheel}"), 6_006);
    w.assert_counted(
        "PyPI Remote proxy cache",
        &format!("/pypi/{pypi_remote}/simple/cached6035/{wheel}"),
        6_006,
    )
    .await;

    // The same remote PyPI cache entry, reached through a virtual.
    let pypi_virt = w.repo("virtual", "pypi").await;
    let pypi_member = w.repos.iter().find(|r| r.1 == pypi_remote).unwrap().0;
    tdh::link_virtual_member(&w.pool, pypi_virt.0, pypi_member, 1).await;
    w.assert_counted(
        "PyPI virtual's Remote member cache",
        &format!("/pypi/{}/simple/cached6035/{wheel}", pypi_virt.1),
        6_006,
    )
    .await;

    let gem_remote = w.repo("remote", "rubygems").await;
    let gem_virt = w.repo("virtual", "rubygems").await;
    tdh::link_virtual_member(&w.pool, gem_virt.0, gem_remote.0, 1).await;
    w.seed_cache(&gem_remote.1, "gems/cached6035-1.0.0.gem", 7_007);
    w.assert_counted(
        "virtual's Remote member cache (RubyGems)",
        &format!("/gems/{}/gems/cached6035-1.0.0.gem", gem_virt.1),
        7_007,
    )
    .await;

    w.teardown().await;
}
