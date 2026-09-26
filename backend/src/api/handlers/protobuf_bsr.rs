//! Connect-RPC reverse-proxy for remote/virtual Protobuf (BSR) repositories.
//!
//! The `buf` CLI speaks Connect over HTTP/1.1 with the **binary protobuf**
//! codec (`Content-Type: application/proto`) and posts to
//! `/{fully.qualified.Service}/{Method}` at the registry hostname root — not
//! under `/proto/{repo_key}`. A remote protobuf repo is therefore a
//! pull-through cache of that wire protocol, not a REST layout of
//! `modules/{owner}/{name}/commits/{digest}`.
//!
//! Client `Authorization` is an Artifact Keeper token and MUST NOT be
//! forwarded upstream (that is what made a valid AK token look like an
//! invalid Buf token). Public BSR modules need no upstream credential;
//! optional bearer/basic on the remote repo still apply when configured.

use std::time::Duration;

use axum::body::Body;
use axum::http::header::{HeaderMap, HeaderName, AUTHORIZATION, CONTENT_TYPE, HOST};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

/// Hard ceiling for a single buffered BSR Connect response body (#1608).
/// Successful responses at or below 16 MiB may still be cached; larger bodies
/// are returned without caching up to this limit.
const MAX_BSR_PROXY_BODY: usize = 128 * 1024 * 1024;

fn connect_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({ "code": code, "message": message });
    super::with_retry_after_on_503(
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap(),
    )
}

/// Headers that must never be copied from the incoming `buf` request onto the
/// upstream BSR call.
fn hop_by_hop_request_headers() -> &'static [HeaderName] {
    // Built once: `HeaderName` values are compared case-insensitively.
    use std::sync::OnceLock;
    static NAMES: OnceLock<Vec<HeaderName>> = OnceLock::new();
    NAMES.get_or_init(|| {
        [
            HOST,
            AUTHORIZATION,
            HeaderName::from_static("content-length"),
            HeaderName::from_static("connection"),
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-authenticate"),
            HeaderName::from_static("proxy-authorization"),
            HeaderName::from_static("te"),
            HeaderName::from_static("trailers"),
            HeaderName::from_static("transfer-encoding"),
            HeaderName::from_static("upgrade"),
            // The client authenticated to Artifact Keeper, not to the
            // upstream BSR. Forwarding these would make buf.build reject a
            // perfectly valid AK token.
            HeaderName::from_static("buf-token"),
            HeaderName::from_static("x-api-key"),
            // Never forward the caller's Accept-Encoding. `default_client()`
            // advertises `identity` and does not decompress (#1608 / http_client
            // no_gzip). Overriding that with curl's default `gzip` makes the
            // upstream return a compressed body; we then either forward it
            // without a reliable Content-Encoding on cache hits, or serve a
            // gzip payload as `application/json` — Connect JSON clients break
            // with "Invalid numeric literal" / null-byte warnings.
            HeaderName::from_static("accept-encoding"),
        ]
        .into()
    })
}

fn hop_by_hop_response_headers() -> &'static [HeaderName] {
    use std::sync::OnceLock;
    static NAMES: OnceLock<Vec<HeaderName>> = OnceLock::new();
    NAMES.get_or_init(|| {
        [
            HeaderName::from_static("connection"),
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("transfer-encoding"),
            HeaderName::from_static("content-length"),
        ]
        .into()
    })
}

/// True when `service` is a BSR Connect service name (path segment 1 of
/// `/Service/Method`).
pub(crate) fn is_bsr_service(service: &str) -> bool {
    service.starts_with("buf.registry.") || service.starts_with("buf.alpha.registry.")
}

/// True when the request path is a BSR Connect RPC at the **host root**
/// (`/buf.registry.../Method`), not under `/proto/{repo_key}/...`.
pub(crate) fn is_bsr_root_connect_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    let service = trimmed.split('/').next().unwrap_or("");
    is_bsr_service(service)
}

/// Repository key used when the `buf` CLI talks to this instance as a BSR
/// host (no `/proto/{key}` prefix). Override with `AK_PROTOBUF_DEFAULT_REPO`.
pub(crate) fn default_protobuf_repo_key() -> String {
    default_protobuf_repo_key_from(std::env::var("AK_PROTOBUF_DEFAULT_REPO").ok().as_deref())
}

pub(crate) fn default_protobuf_repo_key_from(raw: Option<&str>) -> String {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("protobuf")
        .to_string()
}

/// `Service/Method` for `/proto/{repo}/Service/Method` or a host-root
/// `/Service/Method` Connect path. `None` when the request is not BSR.
pub(crate) fn bsr_connect_rpc_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_start_matches('/');
    if let Some(rest) = trimmed.strip_prefix("proto/") {
        let mut parts = rest.splitn(2, '/');
        let repo = parts.next().unwrap_or("");
        let bsr = parts.next().unwrap_or("");
        if repo.is_empty() || !bsr.contains('/') {
            return None;
        }
        let service = bsr.split('/').next().unwrap_or("");
        if is_bsr_service(service) {
            return Some(bsr);
        }
        return None;
    }
    if is_bsr_root_connect_path(path) {
        return Some(trimmed);
    }
    None
}

/// Connect RPCs that only read the registry (`GetGraph`, `Download`, …).
/// These are HTTP POSTs by protocol but must not be treated as artifact writes.
pub(crate) fn is_bsr_read_connect_path(path: &str) -> bool {
    bsr_connect_rpc_path(path).is_some_and(|p| !is_bsr_write_method(p))
}

/// Write RPCs must stay on hosted repos (405 on remote).
pub(crate) fn is_bsr_write_method(bsr_path: &str) -> bool {
    let method = bsr_path.rsplit('/').next().unwrap_or(bsr_path);
    matches!(
        method,
        "Upload"
            | "CreateModules"
            | "UpdateModules"
            | "DeleteModules"
            | "CreateOrUpdateLabels"
            | "ArchiveLabels"
            | "UnarchiveLabels"
    )
}

/// Connect binary protobuf codec used by the `buf` CLI.
pub(crate) fn is_binary_protobuf(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("application/proto")
                || ct.starts_with("application/grpc")
                || ct.starts_with("application/connect+proto")
        })
        .unwrap_or(false)
}

/// Join `{upstream}/` + `{Service}/{Method}` without doubling slashes.
#[allow(clippy::result_large_err)]
pub(crate) fn join_bsr_upstream_url(
    upstream_base: &str,
    bsr_path: &str,
) -> Result<String, Response> {
    let base = upstream_base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            "Remote protobuf repository has an empty upstream_url",
        ));
    }
    let path = bsr_path.trim().trim_start_matches('/');
    if path.is_empty() || !path.contains('/') {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "BSR Connect path must be Service/Method",
        ));
    }
    Ok(format!("{base}/{path}"))
}

fn skip_request_header(name: &HeaderName) -> bool {
    hop_by_hop_request_headers().iter().any(|h| h == name)
}

fn skip_response_header(name: &HeaderName) -> bool {
    hop_by_hop_response_headers().iter().any(|h| h == name)
}

fn cache_key(repo_id: Uuid, bsr_path: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(repo_id.as_bytes());
    hasher.update(bsr_path.as_bytes());
    hasher.update(body);
    format!("protobuf-bsr-v2/{:x}", hasher.finalize())
}

/// Reverse-proxy one Connect RPC to `upstream_base`. Does not forward AK
/// credentials. Caches successful responses on `state.storage` when present.
pub(crate) async fn proxy_connect_rpc(
    state: &SharedState,
    repo_id: Uuid,
    upstream_base: &str,
    bsr_path: &str,
    incoming: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let url = join_bsr_upstream_url(upstream_base, bsr_path)?;
    crate::api::validation::validate_outbound_url(&url, "protobuf BSR upstream").map_err(|e| {
        connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            &format!("Refusing protobuf BSR upstream: {e}"),
        )
    })?;

    let key = cache_key(repo_id, bsr_path, &body);
    if let Ok(cached) = state.storage.get(&key).await {
        if cached.len() >= 4 {
            let status = u16::from_be_bytes([cached[0], cached[1]]);
            let ct_len = u16::from_be_bytes([cached[2], cached[3]]) as usize;
            if cached.len() >= 4 + ct_len {
                let ct = String::from_utf8_lossy(&cached[4..4 + ct_len]).into_owned();
                let payload = cached.slice(4 + ct_len..);
                let mut builder = Response::builder().status(status);
                if !ct.is_empty() {
                    builder = builder.header(CONTENT_TYPE, ct);
                }
                return Ok(builder.body(Body::from(payload)).unwrap());
            }
        }
    }

    let client = crate::services::http_client::default_client();
    let mut req = client.post(&url).timeout(Duration::from_secs(120));
    for (name, value) in incoming.iter() {
        if skip_request_header(name) {
            continue;
        }
        req = req.header(name, value);
    }
    // Optional credentials configured on the *remote repo* (not the caller's
    // AK token). Public BSR modules need none.
    if let Ok(Some(upstream_auth)) =
        crate::services::upstream_auth::load_upstream_auth(&state.db, repo_id).await
    {
        req = crate::services::upstream_auth::apply_upstream_auth(req, &upstream_auth);
    }

    let resp = req.body(body.clone()).send().await.map_err(|e| {
        connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            &format!("Upstream BSR request failed: {e}"),
        )
    })?;

    let status = resp.status();
    let mut builder = Response::builder().status(status.as_u16());
    let mut content_type = String::new();
    for (name, value) in resp.headers() {
        if skip_response_header(name) {
            continue;
        }
        if name == CONTENT_TYPE {
            content_type = value.to_str().unwrap_or("").to_string();
        }
        builder = builder.header(name, value);
    }
    // STREAMING: capped chunked read — never `Response::bytes()` (#1608).
    let mut stream = resp.bytes_stream();
    let mut buf = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            connect_error(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                &format!("Upstream BSR body failed: {e}"),
            )
        })?;
        if buf.len().saturating_add(chunk.len()) > MAX_BSR_PROXY_BODY {
            return Err(connect_error(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                &format!("Upstream BSR body exceeded the {MAX_BSR_PROXY_BODY}-byte limit"),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    let payload = buf.freeze();

    if status.is_success() && payload.len() <= 16 * 1024 * 1024 {
        let mut stored = Vec::with_capacity(4 + content_type.len() + payload.len());
        stored.extend_from_slice(&status.as_u16().to_be_bytes());
        let ct_len = u16::try_from(content_type.len()).unwrap_or(0);
        stored.extend_from_slice(&ct_len.to_be_bytes());
        stored.extend_from_slice(content_type.as_bytes());
        stored.extend_from_slice(&payload);
        let _ = state.storage.put(&key, Bytes::from(stored)).await;
    }

    Ok(builder.body(Body::from(payload)).unwrap())
}

/// If this repo (or a virtual member) should be served by upstream Connect
/// proxy, do so. Returns `None` when the caller should handle the request
/// locally (hosted JSON).
pub(crate) async fn maybe_proxy(
    state: &SharedState,
    repo: &RepoInfo,
    bsr_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    auth: Option<&AuthExtension>,
) -> Result<Option<Response>, Response> {
    if is_bsr_write_method(bsr_path) {
        return Ok(None);
    }

    if repo.repo_type == RepositoryType::Remote {
        let Some(upstream) = repo.upstream_url.as_deref() else {
            return Err(connect_error(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "Remote protobuf repository has no upstream_url",
            ));
        };
        return Ok(Some(
            proxy_connect_rpc(state, repo.id, upstream, bsr_path, headers, body).await?,
        ));
    }

    if repo.repo_type == RepositoryType::Virtual {
        // Binary protobuf from `buf` cannot be served by the hosted JSON
        // handlers — skip straight to remote members.
        if is_binary_protobuf(headers) {
            return Ok(Some(
                proxy_virtual_members(state, repo.id, bsr_path, headers, body, auth).await?,
            ));
        }
        // JSON callers still hit local handlers first; they call
        // [`proxy_virtual_members`] on a miss.
        return Ok(None);
    }

    Ok(None)
}

/// Walk virtual members in priority order and reverse-proxy to the first
/// remote BSR that returns a non-404 Connect response.
pub(crate) async fn proxy_virtual_members(
    state: &SharedState,
    virtual_repo_id: Uuid,
    bsr_path: &str,
    headers: &HeaderMap,
    body: Bytes,
    auth: Option<&AuthExtension>,
) -> Result<Response, Response> {
    let members =
        proxy_helpers::authorized_virtual_members(&state.db, auth, virtual_repo_id).await?;
    let mut last_err: Option<Response> = None;
    for member in members {
        if member.repo_type != RepositoryType::Remote {
            continue;
        }
        let Some(upstream) = member.upstream_url.as_deref() else {
            continue;
        };
        match proxy_connect_rpc(state, member.id, upstream, bsr_path, headers, body.clone()).await {
            Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
                last_err = Some(resp);
                continue;
            }
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "No virtual member served this BSR request",
        )
    }))
}

/// Catch-all for BSR methods we do not implement locally (ListModules, …).
/// Remote/virtual repos still work because we reverse-proxy the bytes.
pub(crate) async fn dispatch_unknown_bsr(
    state: SharedState,
    repo_key: String,
    bsr_path: String,
    headers: HeaderMap,
    body: Bytes,
    auth: Option<AuthExtension>,
) -> Result<Response, Response> {
    let repo = super::protobuf::resolve_protobuf_repo(&state.db, &repo_key).await?;
    if is_bsr_write_method(&bsr_path) {
        proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
        return Err(connect_error(
            StatusCode::NOT_FOUND,
            "unimplemented",
            &format!("BSR method '{bsr_path}' is not implemented on hosted protobuf repos"),
        ));
    }
    if let Some(resp) = maybe_proxy(
        &state,
        &repo,
        &bsr_path,
        &headers,
        body.clone(),
        auth.as_ref(),
    )
    .await?
    {
        return Ok(resp);
    }
    if repo.repo_type == RepositoryType::Virtual {
        return proxy_virtual_members(&state, repo.id, &bsr_path, &headers, body, auth.as_ref())
            .await;
    }
    Err(connect_error(
        StatusCode::NOT_FOUND,
        "unimplemented",
        &format!("BSR method '{bsr_path}' is not implemented on hosted protobuf repos"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_is_bsr_service_accepts_module_and_alpha() {
        assert!(is_bsr_service("buf.registry.module.v1.GraphService"));
        assert!(is_bsr_service(
            "buf.registry.module.v1beta1.DownloadService"
        ));
        assert!(is_bsr_service("buf.alpha.registry.v1alpha1.AuthnService"));
        assert!(!is_bsr_service("npm"));
        assert!(!is_bsr_service("proto"));
    }

    #[test]
    fn test_is_bsr_root_connect_path() {
        assert!(is_bsr_root_connect_path(
            "/buf.registry.module.v1.GraphService/GetGraph"
        ));
        assert!(is_bsr_root_connect_path(
            "buf.registry.module.v1.DownloadService/Download"
        ));
        assert!(!is_bsr_root_connect_path(
            "/proto/buf/buf.registry.module.v1.GraphService/GetGraph"
        ));
        assert!(!is_bsr_root_connect_path("/npm/my-repo/foo"));
    }

    #[test]
    fn test_is_bsr_write_method() {
        assert!(is_bsr_write_method(
            "buf.registry.module.v1beta1.UploadService/Upload"
        ));
        assert!(is_bsr_write_method(
            "buf.registry.module.v1.ModuleService/CreateModules"
        ));
        assert!(!is_bsr_write_method(
            "buf.registry.module.v1.GraphService/GetGraph"
        ));
        assert!(!is_bsr_write_method(
            "buf.registry.module.v1.DownloadService/Download"
        ));
    }

    #[test]
    fn test_join_bsr_upstream_url_trims_slashes() {
        let url = join_bsr_upstream_url(
            "https://buf.build/",
            "/buf.registry.module.v1.GraphService/GetGraph",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://buf.build/buf.registry.module.v1.GraphService/GetGraph"
        );
    }

    #[test]
    fn test_join_bsr_upstream_url_rejects_empty() {
        assert!(join_bsr_upstream_url("  ", "a/b").is_err());
        assert!(join_bsr_upstream_url("https://buf.build", "GetGraph").is_err());
    }

    #[test]
    fn test_is_binary_protobuf_content_types() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
        assert!(is_binary_protobuf(&h));
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(!is_binary_protobuf(&h));
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        assert!(is_binary_protobuf(&h));
    }

    #[test]
    fn test_authorization_is_not_forwarded() {
        assert!(skip_request_header(&AUTHORIZATION));
        assert!(skip_request_header(&HOST));
        assert!(!skip_request_header(&CONTENT_TYPE));
        assert!(!skip_request_header(&HeaderName::from_static(
            "connect-protocol-version"
        )));
    }

    #[test]
    fn test_default_protobuf_repo_key_from() {
        assert_eq!(default_protobuf_repo_key_from(None), "protobuf");
        assert_eq!(default_protobuf_repo_key_from(Some("")), "protobuf");
        assert_eq!(default_protobuf_repo_key_from(Some("  ")), "protobuf");
        assert_eq!(default_protobuf_repo_key_from(Some("bsr")), "bsr");
        assert_eq!(default_protobuf_repo_key_from(Some(" bsr ")), "bsr");
    }

    #[test]
    fn test_bsr_connect_rpc_path_proto_prefix_and_root() {
        assert_eq!(
            bsr_connect_rpc_path("/proto/buf/buf.registry.module.v1.GraphService/GetGraph"),
            Some("buf.registry.module.v1.GraphService/GetGraph")
        );
        assert_eq!(
            bsr_connect_rpc_path("/buf.registry.module.v1.GraphService/GetGraph"),
            Some("buf.registry.module.v1.GraphService/GetGraph")
        );
        assert_eq!(bsr_connect_rpc_path("/npm/my-repo/foo"), None);
        assert_eq!(bsr_connect_rpc_path("/proto/buf"), None);
    }

    #[test]
    fn test_is_bsr_read_connect_path() {
        assert!(is_bsr_read_connect_path(
            "/buf.registry.module.v1.GraphService/GetGraph"
        ));
        assert!(is_bsr_read_connect_path(
            "/proto/protobuf/buf.registry.module.v1beta1.DownloadService/Download"
        ));
        assert!(!is_bsr_read_connect_path(
            "/proto/protobuf/buf.registry.module.v1beta1.UploadService/Upload"
        ));
        assert!(!is_bsr_read_connect_path(
            "/buf.registry.module.v1.ModuleService/CreateModules"
        ));
        assert!(!is_bsr_read_connect_path("/npm/my-repo/foo"));
    }

    #[tokio::test]
    async fn maybe_proxy_skips_write_methods() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let tmp = tempfile::TempDir::new().unwrap();
        let state = tdh::build_state(pool, tmp.path().to_str().unwrap());
        let repo = tdh::make_repo_info(
            uuid::Uuid::new_v4(),
            "proto-remote",
            tmp.path(),
            "remote",
            Some("https://buf.build"),
        );
        let headers = HeaderMap::new();
        let out = maybe_proxy(
            &state,
            &repo,
            "buf.registry.module.v1beta1.UploadService/Upload",
            &headers,
            Bytes::from_static(b"{}"),
            None,
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn proxy_connect_rpc_strips_authorization_and_forwards_body() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_bytes, header, header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // tokio mutex: std MutexGuard cannot be held across `.await`.
        static SSRF_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _lock = SSRF_LOCK.lock().await;
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("8.8.8.8:80").unwrap();
        let bind_ip = probe.local_addr().unwrap().ip();
        let previous_ssrf = std::env::var("AK_SSRF_ALLOW_PRIVATE_CIDRS").ok();
        std::env::set_var(
            "AK_SSRF_ALLOW_PRIVATE_CIDRS",
            format!("{bind_ip}/{}", if bind_ip.is_ipv4() { 32 } else { 128 }),
        );
        let previous_no_proxy = std::env::var("NO_PROXY").ok();
        let mut no_proxy = previous_no_proxy.clone().unwrap_or_default();
        let bind_ip_str = bind_ip.to_string();
        if !no_proxy
            .split(',')
            .any(|e| e.trim().eq_ignore_ascii_case(&bind_ip_str))
        {
            if !no_proxy.is_empty() && !no_proxy.ends_with(',') {
                no_proxy.push(',');
            }
            no_proxy.push_str(&bind_ip_str);
            std::env::set_var("NO_PROXY", &no_proxy);
            std::env::set_var("no_proxy", &no_proxy);
        }
        let listener = std::net::TcpListener::bind((bind_ip, 0)).unwrap();
        let upstream = MockServer::builder().listener(listener).start().await;

        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.GraphService/GetGraph"))
            .and(header("content-type", "application/proto"))
            .and(body_bytes(b"\x00graph"))
            .and(header_exists("connect-protocol-version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(b"\x00ok"),
            )
            .mount(&upstream)
            .await;

        let tmp = tempfile::TempDir::new().unwrap();
        let state = tdh::build_state(pool, tmp.path().to_str().unwrap());
        let mut incoming = HeaderMap::new();
        incoming.insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
        incoming.insert(AUTHORIZATION, HeaderValue::from_static("Bearer ak-secret"));
        incoming.insert(
            HeaderName::from_static("connect-protocol-version"),
            HeaderValue::from_static("1"),
        );
        incoming.insert(
            HeaderName::from_static("buf-token"),
            HeaderValue::from_static("should-not-leak"),
        );
        incoming.insert(
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate, br"),
        );

        let resp = proxy_connect_rpc(
            &state,
            uuid::Uuid::new_v4(),
            upstream.uri().as_str(),
            "buf.registry.module.v1.GraphService/GetGraph",
            &incoming,
            Bytes::from_static(b"\x00graph"),
        )
        .await
        .expect("proxy should succeed");
        assert_eq!(resp.status(), StatusCode::OK);

        let received = upstream
            .received_requests()
            .await
            .expect("mock server should record requests");
        assert_eq!(received.len(), 1);
        assert!(
            received[0].headers.get("authorization").is_none(),
            "AK Authorization must not be forwarded to the BSR"
        );
        assert!(
            received[0].headers.get("buf-token").is_none(),
            "buf-token must not be forwarded to the BSR"
        );
        let ae = received[0]
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ae.is_empty() || ae.eq_ignore_ascii_case("identity"),
            "client Accept-Encoding must not force gzip on upstream (got {ae:?})"
        );

        // Restore SSRF env before dropping the mock (other tests share the process).
        match previous_ssrf {
            Some(v) => std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", v),
            None => std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
        }
        match previous_no_proxy {
            Some(v) => std::env::set_var("NO_PROXY", v),
            None => std::env::remove_var("NO_PROXY"),
        }
    }
}
