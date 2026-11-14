//! Connect-RPC reverse-proxy for remote/virtual Protobuf (BSR) repositories.
//!
//! The `buf` CLI speaks Connect over HTTP/1.1 with the **binary protobuf**
//! codec (`Content-Type: application/proto`) and posts to
//! `/{fully.qualified.Service}/{Method}` under `/proto/{repo_key}` — not a
//! REST layout of `modules/{owner}/{name}/commits/{digest}`.
//!
//! Client credentials (Authorization, Cookie, `x-nuget-apikey`, `buf-token`)
//! are Artifact Keeper tokens and MUST NOT be forwarded upstream. Only an
//! allowlist of Connect headers is copied each way. Only read-only
//! `buf.registry.module.v1` RPCs are proxied; the body is not cached. The
//! upstream host is always the repository's configured `upstream_url`, and an
//! upstream error is answered with a Connect error of our own, never the
//! upstream body.

use std::time::Duration;

use axum::body::Body;
use axum::http::header::{HeaderMap, HeaderName};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use uuid::Uuid;

use super::protobuf::connect_error;
use super::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::proxy_service::redact_url_for_diagnostics;

/// Hard ceiling for a single buffered BSR Connect response body (#1608).
/// Every allowlisted RPC answers with module metadata (never module
/// content, which `Download` serves through `proxy_service`), so this is the
/// same 16 MiB metadata bound the npm audit/meta passthrough uses.
const MAX_BSR_PROXY_BODY: usize = 16 * 1024 * 1024;

/// Total time allowed for one upstream BSR call, body included.
const BSR_PROXY_TIMEOUT: Duration = Duration::from_secs(60);

/// Request headers copied onto the upstream BSR call. Everything else —
/// including Cookie, Authorization, and package-manager API keys — is dropped.
fn allowed_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-type"
            | "connect-protocol-version"
            | "connect-timeout-ms"
            | "accept"
            | "user-agent"
    )
}

/// Response headers copied back from a successful upstream call: the
/// content type plus Connect's own `connect-*` and unary `trailer-*`
/// metadata. Everything else (Set-Cookie, WWW-Authenticate, Location,
/// hop-by-hop and length headers) is dropped; the body is rebuilt here.
fn allowed_response_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name == "content-type" || name.starts_with("connect-") || name.starts_with("trailer-")
}

/// The Connect error we answer with when the upstream returns a non-2xx
/// status. The upstream body is never relayed: it is not ours to vouch for
/// and may carry upstream detail. 404 stays 404 so a virtual walk moves on to
/// the next member; 400 stays a client error; anything else is the upstream
/// failing, which is a 502 to our caller.
fn upstream_status_error(status: reqwest::StatusCode) -> Response {
    let (ours, code) = match status.as_u16() {
        404 => (StatusCode::NOT_FOUND, "not_found"),
        400 => (StatusCode::BAD_REQUEST, "invalid_argument"),
        _ => (StatusCode::BAD_GATEWAY, "unavailable"),
    };
    connect_error(
        ours,
        code,
        &format!("Upstream BSR returned HTTP {}", status.as_u16()),
    )
}

/// True when `service` is a Buf registry Connect service (`buf.registry.*`).
pub(crate) fn is_bsr_service(service: &str) -> bool {
    service.starts_with("buf.registry.")
}

/// Split `Service/Method` and reject traversal / extra segments.
pub(crate) fn parse_bsr_rpc(bsr_path: &str) -> Option<(&str, &str)> {
    let path = bsr_path.trim().trim_start_matches('/');
    if path.is_empty()
        || path.contains("..")
        || path.contains('\\')
        || path.contains('\0')
        || path.contains("//")
    {
        return None;
    }
    let mut parts = path.split('/');
    let service = parts.next().unwrap_or("");
    let method = parts.next().unwrap_or("");
    if service.is_empty() || method.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((service, method))
}

/// Read-only `buf.registry.module.v1` RPCs the `buf` CLI actually calls for
/// module metadata. Owner/org/user/plugin services and `Download` are omitted:
/// Download would skip scan-on-proxy, the age gate and quarantine (#4284).
pub(crate) fn is_allowed_bsr_read_rpc(bsr_path: &str) -> bool {
    let Some((service, method)) = parse_bsr_rpc(bsr_path) else {
        return false;
    };
    matches!(
        (service, method),
        (
            "buf.registry.module.v1.ModuleService",
            "GetModule" | "GetModules" | "ListModules"
        ) | (
            "buf.registry.module.v1.CommitService",
            "GetCommit" | "GetCommits" | "ListCommits"
        ) | (
            "buf.registry.module.v1.LabelService",
            "GetLabel" | "GetLabels" | "ListLabels"
        ) | ("buf.registry.module.v1.GraphService", "GetGraph")
            | (
                "buf.registry.module.v1.ResourceService",
                "GetResource" | "GetResources"
            )
    )
}

pub(crate) use super::protobuf_wire::is_binary_protobuf;

/// Join `{upstream}/` + `{Service}/{Method}` without doubling slashes.
/// Rejects `..` and any path that is not exactly `Service/Method`.
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
    let Some((service, method)) = parse_bsr_rpc(bsr_path) else {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "BSR Connect path must be Service/Method",
        ));
    };
    Ok(format!("{base}/{service}/{method}"))
}

/// Reverse-proxy one Connect RPC to `upstream_base`. Does not forward AK
/// credentials and does not cache the response.
pub(crate) async fn proxy_connect_rpc(
    state: &SharedState,
    repo_id: Uuid,
    upstream_base: &str,
    bsr_path: &str,
    incoming: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    if !is_allowed_bsr_read_rpc(bsr_path) {
        return Err(connect_error(
            StatusCode::NOT_FOUND,
            "unimplemented",
            &format!("BSR method '{bsr_path}' is not an allowlisted read RPC"),
        ));
    }
    let url = join_bsr_upstream_url(upstream_base, bsr_path)?;
    crate::api::validation::validate_outbound_url(&url, "protobuf BSR upstream").map_err(|e| {
        tracing::warn!(
            upstream = %redact_url_for_diagnostics(&url),
            error = %e,
            "refusing protobuf BSR upstream"
        );
        connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            "The repository's upstream URL is not allowed",
        )
    })?;

    let client = crate::services::http_client::default_client();
    let mut req = client.post(&url).timeout(BSR_PROXY_TIMEOUT);
    for (name, value) in incoming.iter() {
        if !allowed_request_header(name) {
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

    let resp = crate::services::upstream_tracing::send_upstream(req.body(body))
        .await
        .map_err(|e| {
            tracing::warn!(
                upstream = %redact_url_for_diagnostics(&url),
                error = %e,
                "protobuf BSR upstream request failed"
            );
            connect_error(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "Upstream BSR request failed",
            )
        })?;

    let status = resp.status();
    if !status.is_success() {
        tracing::debug!(
            upstream = %redact_url_for_diagnostics(&url),
            status = %status,
            "protobuf BSR upstream returned non-success"
        );
        return Err(upstream_status_error(status));
    }
    let mut builder = Response::builder().status(status.as_u16());
    for (name, value) in resp.headers() {
        if allowed_response_header(name) {
            builder = builder.header(name, value);
        }
    }
    // STREAMING: capped chunked read — never `Response::bytes()` (#1608).
    let mut stream = resp.bytes_stream();
    let mut buf = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::warn!(
                upstream = %redact_url_for_diagnostics(&url),
                error = %e,
                "protobuf BSR upstream body failed"
            );
            connect_error(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "Upstream BSR response could not be read",
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
    builder.body(Body::from(payload)).map_err(|_| {
        connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            "Upstream BSR response could not be relayed",
        )
    })
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
    if !is_allowed_bsr_read_rpc(bsr_path) {
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
        // handlers — skip straight to remote members (hosted members have no
        // upstream and are walked over, not proxied).
        if is_binary_protobuf(headers) {
            return Ok(Some(
                proxy_virtual_members(state, repo.id, bsr_path, headers, body, auth).await?,
            ));
        }
        return Ok(None);
    }

    Ok(None)
}

/// Walk virtual members in priority order and reverse-proxy to the first
/// remote BSR that returns a non-404 Connect response. Hosted members are
/// skipped here: they have no upstream URL.
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
    let mut saw_hosted = false;
    for member in members {
        if member.repo_type != RepositoryType::Remote {
            saw_hosted = saw_hosted
                || matches!(
                    member.repo_type,
                    RepositoryType::Local | RepositoryType::Staging
                );
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
        let message = if saw_hosted {
            "No remote virtual member served this BSR request (hosted members are not proxied)"
        } else {
            "No virtual member served this BSR request"
        };
        connect_error(StatusCode::NOT_FOUND, "not_found", message)
    }))
}

/// Catch-all for BSR methods we do not implement locally (ListModules, …).
/// Remote/virtual repos still work because we reverse-proxy allowlisted reads.
pub(crate) async fn dispatch_unknown_bsr(
    state: SharedState,
    repo_key: String,
    bsr_path: String,
    headers: HeaderMap,
    body: Bytes,
    auth: Option<AuthExtension>,
) -> Result<Response, Response> {
    let Some((service, _)) = parse_bsr_rpc(&bsr_path) else {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "BSR Connect path must be Service/Method",
        ));
    };
    if !is_bsr_service(service) {
        return Err(connect_error(
            StatusCode::NOT_FOUND,
            "unimplemented",
            &format!("BSR service '{service}' is not a buf.registry.* read service"),
        ));
    }
    let repo = super::protobuf::resolve_protobuf_repo(&state.db, &repo_key).await?;
    if !is_allowed_bsr_read_rpc(&bsr_path) {
        // Writes have their own routes (CreateModules, Upload, ...), which
        // refuse remote and virtual repositories; anything else that lands
        // here is a method this server neither implements nor proxies.
        return Err(connect_error(
            StatusCode::NOT_FOUND,
            "unimplemented",
            &format!("BSR method '{bsr_path}' is not implemented or proxied"),
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

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::header::{AUTHORIZATION, HOST};
    use axum::http::HeaderValue;

    #[test]
    fn test_is_bsr_service_only_buf_registry() {
        assert!(is_bsr_service("buf.registry.module.v1.GraphService"));
        assert!(is_bsr_service(
            "buf.registry.module.v1beta1.DownloadService"
        ));
        assert!(!is_bsr_service("buf.alpha.registry.v1alpha1.AuthnService"));
        assert!(!is_bsr_service("npm"));
        assert!(!is_bsr_service("proto"));
    }

    #[test]
    fn test_parse_bsr_rpc_rejects_traversal_and_extra_segments() {
        assert_eq!(
            parse_bsr_rpc("buf.registry.module.v1.GraphService/GetGraph"),
            Some(("buf.registry.module.v1.GraphService", "GetGraph"))
        );
        assert!(parse_bsr_rpc("buf.registry.module.v1.GraphService/../GetGraph").is_none());
        assert!(parse_bsr_rpc("buf.registry.module.v1.GraphService/GetGraph/extra").is_none());
        assert!(parse_bsr_rpc("GetGraph").is_none());
        assert!(parse_bsr_rpc("").is_none());
    }

    #[test]
    fn test_is_allowed_bsr_read_rpc() {
        assert!(is_allowed_bsr_read_rpc(
            "buf.registry.module.v1.GraphService/GetGraph"
        ));
        assert!(is_allowed_bsr_read_rpc(
            "buf.registry.module.v1.ModuleService/ListModules"
        ));
        assert!(is_allowed_bsr_read_rpc(
            "buf.registry.module.v1.CommitService/GetCommits"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.registry.module.v1.DownloadService/Download"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.registry.module.v1beta1.DownloadService/Download"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.registry.owner.v1.OwnerService/GetOwner"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.registry.module.v1beta1.UploadService/Upload"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.registry.module.v1.ModuleService/CreateModules"
        ));
        assert!(!is_allowed_bsr_read_rpc(
            "buf.alpha.registry.v1alpha1.AuthnService/GetCurrentUser"
        ));
        assert!(!is_allowed_bsr_read_rpc("evil.Service/GetGraph"));
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
    fn test_join_bsr_upstream_url_rejects_empty_and_dotdot() {
        assert!(join_bsr_upstream_url("  ", "a/b").is_err());
        assert!(join_bsr_upstream_url("https://buf.build", "GetGraph").is_err());
        assert!(join_bsr_upstream_url(
            "https://buf.build",
            "buf.registry.module.v1.GraphService/../GetGraph"
        )
        .is_err());
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
    fn test_request_header_allowlist_drops_cookies_and_creds() {
        assert!(allowed_request_header(&CONTENT_TYPE));
        assert!(allowed_request_header(&HeaderName::from_static(
            "connect-protocol-version"
        )));
        assert!(allowed_request_header(&HeaderName::from_static("accept")));
        assert!(allowed_request_header(&HeaderName::from_static(
            "user-agent"
        )));
        assert!(!allowed_request_header(&AUTHORIZATION));
        assert!(!allowed_request_header(&HOST));
        assert!(!allowed_request_header(&HeaderName::from_static("cookie")));
        assert!(!allowed_request_header(&HeaderName::from_static(
            "x-nuget-apikey"
        )));
        assert!(!allowed_request_header(&HeaderName::from_static(
            "buf-token"
        )));
        assert!(!allowed_request_header(&HeaderName::from_static(
            "accept-encoding"
        )));
    }

    #[test]
    fn test_response_header_allowlist() {
        assert!(allowed_response_header(&CONTENT_TYPE));
        assert!(allowed_response_header(&HeaderName::from_static(
            "connect-content-encoding"
        )));
        assert!(allowed_response_header(&HeaderName::from_static(
            "trailer-x-request-id"
        )));
        for dropped in [
            "set-cookie",
            "www-authenticate",
            "location",
            "content-length",
            "transfer-encoding",
            "x-upstream-internal",
        ] {
            assert!(
                !allowed_response_header(&HeaderName::from_static(dropped)),
                "{dropped} must not be relayed"
            );
        }
    }

    #[test]
    fn test_upstream_status_error_maps_without_upstream_body() {
        let cases = [
            (404, StatusCode::NOT_FOUND),
            (400, StatusCode::BAD_REQUEST),
            (401, StatusCode::BAD_GATEWAY),
            (403, StatusCode::BAD_GATEWAY),
            (500, StatusCode::BAD_GATEWAY),
            (503, StatusCode::BAD_GATEWAY),
        ];
        for (upstream, ours) in cases {
            let resp = upstream_status_error(reqwest::StatusCode::from_u16(upstream).unwrap());
            assert_eq!(resp.status(), ours, "upstream {upstream}");
        }
    }

    #[tokio::test]
    async fn maybe_proxy_skips_non_allowlisted_methods() {
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
        let download = maybe_proxy(
            &state,
            &repo,
            "buf.registry.module.v1.DownloadService/Download",
            &headers,
            Bytes::from_static(b"{}"),
            None,
        )
        .await
        .unwrap();
        assert!(
            download.is_none(),
            "Download must not be reverse-proxied; it has to go through proxy_service"
        );
    }

    struct NoProxyGuard {
        previous_upper: Option<String>,
        previous_lower: Option<String>,
    }

    impl Drop for NoProxyGuard {
        fn drop(&mut self) {
            match &self.previous_upper {
                Some(v) => std::env::set_var("NO_PROXY", v),
                None => std::env::remove_var("NO_PROXY"),
            }
            match &self.previous_lower {
                Some(v) => std::env::set_var("no_proxy", v),
                None => std::env::remove_var("no_proxy"),
            }
        }
    }

    /// Keep HTTP(S)_PROXY from swallowing the wiremock listener. Restored on
    /// drop (including panic) so it shares the same restore discipline as
    /// [`tdh::non_loopback_mock_server`].
    fn pin_no_proxy(server: &wiremock::MockServer) -> NoProxyGuard {
        let host = server
            .uri()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(['/', ':'])
            .next()
            .unwrap_or("")
            .to_string();
        let previous_upper = std::env::var("NO_PROXY").ok();
        let previous_lower = std::env::var("no_proxy").ok();
        if !host.is_empty() {
            let mut no_proxy = previous_upper.clone().unwrap_or_default();
            if !no_proxy
                .split(',')
                .any(|entry| entry.trim().eq_ignore_ascii_case(&host))
            {
                if !no_proxy.is_empty() && !no_proxy.ends_with(',') {
                    no_proxy.push(',');
                }
                no_proxy.push_str(&host);
                std::env::set_var("NO_PROXY", &no_proxy);
                std::env::set_var("no_proxy", &no_proxy);
            }
        }
        NoProxyGuard {
            previous_upper,
            previous_lower,
        }
    }

    #[tokio::test]
    async fn proxy_connect_rpc_strips_cookies_creds_and_set_cookie() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{body_bytes, header, header_exists, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (upstream, _ssrf) = tdh::non_loopback_mock_server().await;
        let _no_proxy = pin_no_proxy(&upstream);

        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.GraphService/GetGraph"))
            .and(header("content-type", "application/proto"))
            .and(body_bytes(b"\x00graph"))
            .and(header_exists("connect-protocol-version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .insert_header("set-cookie", "upstream=must-not-leak")
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
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("sid=1"),
        );
        incoming.insert(
            HeaderName::from_static("x-nuget-apikey"),
            HeaderValue::from_static("should-not-leak"),
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
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "upstream Set-Cookie must not be copied onto the AK response"
        );

        let received = upstream
            .received_requests()
            .await
            .expect("mock server should record requests");
        assert_eq!(received.len(), 1);
        assert!(received[0].headers.get("authorization").is_none());
        assert!(received[0].headers.get("cookie").is_none());
        assert!(received[0].headers.get("x-nuget-apikey").is_none());
        assert!(received[0].headers.get("buf-token").is_none());
        let ae = received[0]
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ae.is_empty() || ae.eq_ignore_ascii_case("identity"),
            "client Accept-Encoding must not force gzip on upstream (got {ae:?})"
        );
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // reads one small, bounded error body (#1608)
    async fn proxy_connect_rpc_never_relays_an_upstream_error_body() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (upstream, _ssrf) = tdh::non_loopback_mock_server().await;
        let _no_proxy = pin_no_proxy(&upstream);
        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.ModuleService/ListModules"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("content-type", "application/json")
                    .insert_header("www-authenticate", "Basic realm=upstream-internal")
                    .set_body_string(r#"{"code":"internal","message":"db at 10.0.0.7 down"}"#),
            )
            .mount(&upstream)
            .await;

        let tmp = tempfile::TempDir::new().unwrap();
        let state = tdh::build_state(pool, tmp.path().to_str().unwrap());
        let mut incoming = HeaderMap::new();
        incoming.insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
        let err = proxy_connect_rpc(
            &state,
            uuid::Uuid::new_v4(),
            upstream.uri().as_str(),
            "buf.registry.module.v1.ModuleService/ListModules",
            &incoming,
            Bytes::from_static(b"\x00list"),
        )
        .await
        .expect_err("an upstream 500 is an error to our caller");
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        assert!(err.headers().get("www-authenticate").is_none());
        let body = axum::body::to_bytes(err.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("10.0.0.7") && !text.contains("upstream-internal"),
            "the upstream error body must not be relayed: {text}"
        );
        assert!(
            text.contains("\"unavailable\""),
            "Connect error code: {text}"
        );
    }

    /// Through the real `/proto` router: an allowlisted read with no local
    /// handler reaches the remote repository's upstream without the caller's
    /// cookie or token; a non-allowlisted `buf.registry.*` method and a
    /// non-`buf.registry` service never reach the upstream.
    #[tokio::test]
    async fn router_catch_all_forwards_only_allowlisted_reads() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::Request;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "protobuf").await else {
            return;
        };
        let (upstream, _ssrf) = tdh::non_loopback_mock_server().await;
        let _no_proxy = pin_no_proxy(&upstream);
        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.ModuleService/ListModules"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(b"\x00modules"),
            )
            .mount(&upstream)
            .await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri().as_str())
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("set remote upstream");

        let call = |rpc: &str| {
            Request::builder()
                .method("POST")
                .uri(format!("/{}/{rpc}", fx.repo_key))
                .header("content-type", "application/proto")
                .header("connect-protocol-version", "1")
                .header("cookie", "ak_access_token=caller-session")
                .header("authorization", "Bearer caller-token")
                .body(Body::from(&b"\x00req"[..]))
                .unwrap()
        };
        let app = || tdh::router_anon(super::super::protobuf::router(), fx.state.clone());

        let (ok_status, ok_body) = tdh::send(
            app(),
            call("buf.registry.module.v1.ModuleService/ListModules"),
        )
        .await;
        let (owner_status, _) =
            tdh::send(app(), call("buf.registry.owner.v1.OwnerService/GetOwner")).await;
        let (write_status, _) = tdh::send(
            app(),
            call("buf.registry.module.v1.ModuleService/DeleteModules"),
        )
        .await;
        let (foreign_status, _) = tdh::send(app(), call("grpc.health.v1.Health/Check")).await;
        let received = upstream.received_requests().await.unwrap_or_default();
        fx.teardown().await;

        assert_eq!(ok_status, StatusCode::OK);
        assert_eq!(&ok_body[..], b"\x00modules");
        assert_eq!(owner_status, StatusCode::NOT_FOUND);
        assert_eq!(write_status, StatusCode::NOT_FOUND);
        assert_eq!(foreign_status, StatusCode::NOT_FOUND);
        assert_eq!(
            received.len(),
            1,
            "only the allowlisted read may reach the upstream"
        );
        assert!(received[0].headers.get("cookie").is_none());
        assert!(received[0].headers.get("authorization").is_none());
    }

    #[tokio::test]
    async fn proxy_virtual_members_walks_past_hosted_member() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "protobuf").await else {
            return;
        };

        let (upstream, _ssrf) = tdh::non_loopback_mock_server().await;
        let _no_proxy = pin_no_proxy(&upstream);
        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.GraphService/GetGraph"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(b"\x00ok"),
            )
            .mount(&upstream)
            .await;

        let hosted = tdh::Fixture::setup("local", "protobuf")
            .await
            .expect("hosted member");
        let remote = tdh::Fixture::setup("remote", "protobuf")
            .await
            .expect("remote member");
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(upstream.uri().as_str())
            .bind(remote.repo_id)
            .execute(&fx.pool)
            .await
            .expect("set remote upstream");
        sqlx::query("UPDATE repositories SET is_public = true WHERE id IN ($1, $2, $3)")
            .bind(fx.repo_id)
            .bind(hosted.repo_id)
            .bind(remote.repo_id)
            .execute(&fx.pool)
            .await
            .expect("public members");
        tdh::link_virtual_member(&fx.pool, fx.repo_id, hosted.repo_id, 1).await;
        tdh::link_virtual_member(&fx.pool, fx.repo_id, remote.repo_id, 2).await;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
        headers.insert(
            HeaderName::from_static("connect-protocol-version"),
            HeaderValue::from_static("1"),
        );
        let resp = proxy_virtual_members(
            &fx.state,
            fx.repo_id,
            "buf.registry.module.v1.GraphService/GetGraph",
            &headers,
            Bytes::from_static(b"\x00graph"),
            None,
        )
        .await
        .expect("virtual walk should reach the remote member");
        hosted.teardown().await;
        remote.teardown().await;
        fx.teardown().await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn proxy_virtual_members_excludes_unauthorized_private_members() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("virtual", "protobuf").await else {
            return;
        };

        let (upstream, _ssrf) = tdh::non_loopback_mock_server().await;
        let _no_proxy = pin_no_proxy(&upstream);
        Mock::given(method("POST"))
            .and(path("/buf.registry.module.v1.GraphService/GetGraph"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(b"\x00ok"),
            )
            .mount(&upstream)
            .await;

        let remote = tdh::Fixture::setup("remote", "protobuf")
            .await
            .expect("private remote member");
        sqlx::query("UPDATE repositories SET upstream_url = $1, is_public = false WHERE id = $2")
            .bind(upstream.uri().as_str())
            .bind(remote.repo_id)
            .execute(&fx.pool)
            .await
            .expect("private remote upstream");
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("public virtual parent");
        tdh::link_virtual_member(&fx.pool, fx.repo_id, remote.repo_id, 1).await;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/proto"));
        let err = proxy_virtual_members(
            &fx.state,
            fx.repo_id,
            "buf.registry.module.v1.GraphService/GetGraph",
            &headers,
            Bytes::from_static(b"\x00graph"),
            None,
        )
        .await
        .expect_err("anonymous caller must not walk a private member");
        let received = upstream.received_requests().await.unwrap_or_default();
        remote.teardown().await;
        fx.teardown().await;
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
        assert!(
            received.is_empty(),
            "unauthorized member must not be forwarded upstream"
        );
    }
}
