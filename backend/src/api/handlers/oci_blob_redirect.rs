//! Presigned-URL offload for OCI blob pulls (#2894).
//!
//! With `PRESIGNED_DOWNLOADS_ENABLED=true` and a storage backend that can sign
//! URLs (S3 with redirect downloads, GCS, Azure, CloudFront), a
//! `GET /v2/<name>/blobs/<digest>` answers `307 Temporary Redirect` to a signed
//! object-store URL instead of streaming the layer through the backend. That
//! removes the double transfer (object store -> backend -> client) that large
//! image layers otherwise pay. The Distribution spec allows a blob GET to be
//! answered with a 307 ("Pulling blobs"), and every mainstream client
//! (docker, containerd, podman/skopeo, crane) follows it. Docker's and Go's
//! HTTP clients do not forward the registry `Authorization` header to the
//! other host, so the signed query string is the only credential S3 sees.
//!
//! Decisions shared by every call site:
//!
//! * **HEAD is never redirected.** A presigned URL is bound to one HTTP method
//!   (#3181/#3209). `handle_head_blob` is a separate function that never calls
//!   into this module, so HEAD keeps answering with the real headers.
//! * **Range requests are redirected too.** Clients resend `Range` on the
//!   follow-up request, and S3, GCS, Azure and CloudFront all honour it on a
//!   presigned GET, so a resumed pull still gets its 206 — from the object
//!   store instead of from us.
//! * **Gates run first.** Callers invoke these helpers only after every
//!   authorization check and the vulnerable-image re-block
//!   (`enforce_blob_scan_reblock`), so a redirect never hands out a blob the
//!   streaming path would have refused.
//! * **Any doubt falls back to streaming.** Every `None` below means "serve the
//!   blob exactly as before".

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Utc};

use crate::api::download_response::try_presigned_redirect;
use crate::api::handlers::proxy_helpers::try_proxy_cache_redirect;
use crate::api::AppState;
use crate::services::proxy_service::{CacheMetadata, ProxyService};

const DOCKER_CONTENT_DIGEST: HeaderName = HeaderName::from_static("docker-content-digest");

/// The presigned-URL lifetime when blob redirects are enabled, `None` when the
/// operator has not turned presigned downloads on.
fn redirect_expiry(state: &AppState) -> Option<Duration> {
    state
        .config
        .presigned_downloads_enabled
        .then(|| Duration::from_secs(state.config.presigned_download_expiry_secs))
}

/// Turn the generic presigned redirect (a 302 from
/// [`crate::api::download_response::DownloadResponse`]) into the OCI-flavoured
/// one: status `307 Temporary Redirect`, as the Distribution spec names it,
/// plus the `Docker-Content-Digest` header the streaming response carries.
/// `Location`, `Cache-Control` and `X-Artifact-Storage` are kept.
pub(crate) fn into_oci_blob_redirect(mut resp: Response, digest: &str) -> Response {
    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    if let Ok(value) = HeaderValue::from_str(digest) {
        resp.headers_mut().insert(DOCKER_CONTENT_DIGEST, value);
    }
    resp
}

/// Redirect a blob that lives in a repository's own storage (an `oci_blobs`
/// row: hosted pushes, migrated layers, a virtual repo's local member).
///
/// `require_present` asks the backend whether the object exists before
/// signing. Callers set it when a missing object has a better answer than the
/// object store's 404 — a remote repo re-fetches from upstream in that case —
/// and leave it off when the 404 would be the answer anyway, saving a round
/// trip per layer. A failed existence probe counts as "absent".
pub(crate) async fn try_stored_blob_redirect(
    state: &AppState,
    storage: &dyn crate::storage::StorageBackend,
    storage_key: &str,
    digest: &str,
    require_present: bool,
) -> Option<Response> {
    let expiry = redirect_expiry(state)?;
    if !storage.supports_redirect() {
        return None;
    }
    if require_present && !storage.exists(storage_key).await.unwrap_or(false) {
        return None;
    }
    let resp = try_presigned_redirect(storage, storage_key, true, expiry).await?;
    Some(into_oci_blob_redirect(resp, digest))
}

/// Whether a fresh proxy-cache entry may be handed out as a redirect.
///
/// * An entry still inside a Package Age Policy hold must not be (#2075); the
///   streaming path surfaces the hold instead.
/// * An entry stored with an upstream `Content-Encoding` must not be either:
///   the object store would serve the coded bytes without the coding header,
///   and the client's digest check would fail (#3149). The streaming path
///   re-declares the coding.
pub(crate) fn cached_blob_redirect_allowed(meta: &CacheMetadata, now: DateTime<Utc>) -> bool {
    let held = meta.quarantine_until.is_some_and(|until| now < until);
    !held && meta.content_encoding.is_none()
}

/// Redirect a remote repository's blob when the proxy cache already holds a
/// fresh, redirectable copy at `cache_path` (the upstream blob path the
/// streaming pull-through caches it under). A cold cache returns `None`, so the
/// first pull streams from upstream and fills the cache, and later pulls
/// redirect.
///
/// Proxy-cache objects live at the storage root without the configured key
/// prefix, so they are signed through the proxy's own backend handle
/// (`cache_storage_backend`), never through the repo's prefixed handle (#1555).
pub(crate) async fn try_proxy_cached_blob_redirect(
    state: &AppState,
    repo_key: &str,
    cache_path: &str,
    digest: &str,
) -> Option<Response> {
    let expiry = redirect_expiry(state)?;
    let proxy = state.proxy_service.as_ref()?;
    let storage = proxy.cache_storage_backend();
    // Check redirect support before the freshness probe: the probe reads the
    // cache sidecar, which is wasted work on a backend that cannot sign.
    if !storage.supports_redirect() || !proxy.is_cache_fresh(repo_key, cache_path).await {
        return None;
    }
    let meta_key =
        ProxyService::cache_metadata_key(proxy.cache_scope(), repo_key, cache_path).ok()?;
    let meta = proxy.load_cache_metadata_pub(&meta_key).await?;
    if !cached_blob_redirect_allowed(&meta, Utc::now()) {
        return None;
    }
    let cache_key =
        ProxyService::cache_storage_key(proxy.cache_scope(), repo_key, cache_path).ok()?;
    let resp = try_proxy_cache_redirect(storage.as_ref(), &cache_key, true, expiry, true).await?;
    Some(into_oci_blob_redirect(resp, digest))
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::header::{CACHE_CONTROL, LOCATION};

    const DIGEST: &str = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn sidecar() -> CacheMetadata {
        serde_json::from_slice(&tdh::fresh_cache_sidecar_bytes()).expect("sidecar")
    }

    fn location(resp: &Response) -> String {
        resp.headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    fn assert_oci_redirect(resp: &Response) {
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(
            location(resp).contains("X-Amz-Signature"),
            "must point at a signed URL: {}",
            location(resp)
        );
        assert_eq!(
            resp.headers()
                .get(DOCKER_CONTENT_DIGEST)
                .and_then(|v| v.to_str().ok()),
            Some(DIGEST)
        );
    }

    #[test]
    fn into_oci_blob_redirect_uses_307_and_keeps_location() {
        let generic = Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, "https://signed.example.com/k?X-Amz-Signature=x")
            .header(CACHE_CONTROL, "private, max-age=300")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = into_oci_blob_redirect(generic, DIGEST);
        assert_oci_redirect(&resp);
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "private, max-age=300"
        );
    }

    #[test]
    fn into_oci_blob_redirect_skips_an_unrepresentable_digest() {
        let generic = Response::builder()
            .status(StatusCode::FOUND)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = into_oci_blob_redirect(generic, "sha256:bad\nvalue");
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(resp.headers().get(DOCKER_CONTENT_DIGEST).is_none());
    }

    #[test]
    fn cached_blob_redirect_allowed_for_plain_unheld_entry() {
        assert!(cached_blob_redirect_allowed(&sidecar(), Utc::now()));
    }

    #[test]
    fn cached_blob_redirect_refused_for_coded_entry() {
        let mut meta = sidecar();
        meta.content_encoding = Some("gzip".to_string());
        assert!(!cached_blob_redirect_allowed(&meta, Utc::now()));
    }

    #[test]
    fn cached_blob_redirect_follows_the_hold_window() {
        let now = Utc::now();
        let mut meta = sidecar();
        meta.quarantine_until = Some(now + chrono::Duration::hours(1));
        assert!(!cached_blob_redirect_allowed(&meta, now), "active hold");
        meta.quarantine_until = Some(now - chrono::Duration::seconds(1));
        assert!(cached_blob_redirect_allowed(&meta, now), "elapsed hold");
    }

    async fn seeded_cloud(
        presign: bool,
    ) -> (crate::api::SharedState, std::sync::Arc<tdh::MemStorage>) {
        let (state, mem) = if presign {
            tdh::build_state_with_presigning_cloud(tdh::lazy_pool(), "s3")
        } else {
            tdh::build_state_with_cloud(tdh::lazy_pool(), "s3")
        };
        crate::storage::StorageBackend::put(
            mem.as_ref(),
            "blobs/k",
            bytes::Bytes::from_static(b"layer"),
        )
        .await
        .expect("seed");
        (state, mem)
    }

    #[tokio::test]
    async fn stored_blob_redirects_when_enabled_and_signable() {
        let (state, mem) = seeded_cloud(true).await;
        for require_present in [false, true] {
            let resp =
                try_stored_blob_redirect(&state, mem.as_ref(), "blobs/k", DIGEST, require_present)
                    .await
                    .expect("presign-capable backend must redirect");
            assert_oci_redirect(&resp);
            assert!(location(&resp).contains("blobs/k"));
        }
    }

    #[tokio::test]
    async fn stored_blob_streams_when_presigned_downloads_disabled() {
        // Backend can sign, but the operator has not opted in.
        let (state, _mem) = tdh::build_state_with_cloud(tdh::lazy_pool(), "s3");
        let signer = tdh::MemStorage {
            presign: true,
            ..Default::default()
        };
        assert!(
            try_stored_blob_redirect(&state, &signer, "blobs/k", DIGEST, false)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn stored_blob_streams_when_backend_cannot_sign() {
        let (state, _mem) = tdh::build_state_with_presigning_cloud(tdh::lazy_pool(), "s3");
        let (_s, plain) = seeded_cloud(false).await;
        assert!(
            try_stored_blob_redirect(&state, plain.as_ref(), "blobs/k", DIGEST, false)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn stored_blob_presence_check_declines_a_missing_object() {
        let (state, mem) = seeded_cloud(true).await;
        assert!(
            try_stored_blob_redirect(&state, mem.as_ref(), "blobs/missing", DIGEST, true)
                .await
                .is_none(),
            "a missing object must fall back so the caller can re-fetch"
        );
        assert!(
            try_stored_blob_redirect(&state, mem.as_ref(), "blobs/missing", DIGEST, false)
                .await
                .is_some(),
            "without the probe the redirect is issued unconditionally"
        );
    }

    const REPO: &str = "docker-remote";
    const PATH: &str = "v2/library/alpine/blobs/sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    fn proxy_state(
        presign_enabled: bool,
    ) -> (
        crate::api::SharedState,
        std::sync::Arc<tdh::PresignMemBackend>,
        String,
        String,
    ) {
        let pool = tdh::lazy_pool();
        let scope = crate::services::proxy_cache_scope::ProxyCacheScope::unscoped();
        let (proxy, backend) = tdh::build_scoped_presign_proxy(pool.clone(), scope.clone());
        let storage_path = std::env::temp_dir()
            .join(format!("oci-redirect-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned();
        let state = if presign_enabled {
            tdh::build_state_with_proxy_presigned(pool, &storage_path, proxy)
        } else {
            tdh::build_state_with_proxy(pool, &storage_path, proxy)
        };
        let content_key = ProxyService::cache_storage_key(&scope, REPO, PATH).unwrap();
        let meta_key = ProxyService::cache_metadata_key(&scope, REPO, PATH).unwrap();
        (state, backend, content_key, meta_key)
    }

    #[tokio::test]
    async fn proxy_cached_blob_redirects_a_fresh_entry() {
        let (state, backend, content_key, meta_key) = proxy_state(true);
        backend.seed_fresh_entry(&content_key, &meta_key);
        let resp = try_proxy_cached_blob_redirect(&state, REPO, PATH, DIGEST)
            .await
            .expect("fresh cache entry must redirect");
        assert_oci_redirect(&resp);
        assert!(
            location(&resp).contains(&content_key),
            "must sign the cache key itself: {}",
            location(&resp)
        );
    }

    #[tokio::test]
    async fn proxy_cached_blob_streams_on_a_cold_cache() {
        let (state, _backend, _c, _m) = proxy_state(true);
        assert!(try_proxy_cached_blob_redirect(&state, REPO, PATH, DIGEST)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn proxy_cached_blob_streams_when_disabled() {
        let (state, backend, content_key, meta_key) = proxy_state(false);
        backend.seed_fresh_entry(&content_key, &meta_key);
        assert!(try_proxy_cached_blob_redirect(&state, REPO, PATH, DIGEST)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn proxy_cached_blob_streams_a_coded_entry() {
        let (state, backend, content_key, meta_key) = proxy_state(true);
        backend.seed_fresh_entry(&content_key, &meta_key);
        let mut meta = sidecar();
        meta.content_encoding = Some("gzip".to_string());
        backend.objects.lock().unwrap().insert(
            meta_key.clone(),
            bytes::Bytes::from(serde_json::to_vec(&meta).unwrap()),
        );
        assert!(try_proxy_cached_blob_redirect(&state, REPO, PATH, DIGEST)
            .await
            .is_none());
    }
}
