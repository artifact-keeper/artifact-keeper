//! Request-scoped client-IP context (#3888).
//!
//! [`client_ip_context_middleware`] resolves the request's client IP once —
//! the socket peer from `ConnectInfo`, with `X-Forwarded-For` believed only
//! when the peer falls inside a configured trusted-proxy CIDR (the
//! `RATE_LIMIT_TRUSTED_PROXY_CIDRS` policy, shared with the rate limiter;
//! see [`resolve_client_ip_addr`] and #2023, GHSA-8jm4-4x6c-6787) — and
//! scopes it as a task-local around the downstream request future, so
//! anything `.await`ed while handling the request (handlers, services,
//! audit emitters, permission gates) observes the same address without
//! threading it through every signature. This mirrors the correlation-ID
//! task-local in [`crate::api::middleware::tracing`].
//!
//! Consumers that need the address call [`current_client_ip`]. Outside a
//! request scope (startup, background jobs, detached `tokio::spawn` tasks,
//! tests that do not establish one) it resolves to `None` — callers must
//! treat `None` as "unknown", never as a sentinel address. Authorization
//! decisions keyed on the client IP (permission `allowed_cidrs` conditions,
//! #1849) fail closed on `None`.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};

use super::rate_limit::{resolve_client_ip_addr, CidrRange};

tokio::task_local! {
    /// The resolved client IP of the request currently being handled.
    ///
    /// [`client_ip_context_middleware`] scopes this around the downstream
    /// request future; the scope wraps the future, not the OS task, so it is
    /// correct under HTTP/2 multiplexing. A future detached with
    /// `tokio::spawn` does NOT inherit the value, which fails closed for
    /// IP-conditioned authorization (#1849): code that needs the address in
    /// a detached task must capture it first with [`current_client_ip`].
    static CURRENT_CLIENT_IP: Option<IpAddr>;
}

/// The resolved client IP of the in-flight request, or `None` when called
/// outside a request scope (background jobs, startup, detached tasks) or when
/// the address could not be resolved. Mirrors
/// [`crate::api::middleware::tracing::current_correlation_id`].
pub fn current_client_ip() -> Option<IpAddr> {
    CURRENT_CLIENT_IP.try_with(|ip| *ip).ok().flatten()
}

/// Runs `fut` with [`current_client_ip`] resolving to `ip` — the same
/// scoping the middleware applies to each request. Public so tests (and any
/// future non-HTTP entry point that knows its caller's address, e.g. a gRPC
/// handler) can establish a scope without standing up a router.
pub async fn with_client_ip_scope<F: Future>(ip: Option<IpAddr>, fut: F) -> F::Output {
    CURRENT_CLIENT_IP.scope(ip, fut).await
}

/// Resolve the request's client IP and scope it for the downstream future.
///
/// Layered once, globally, next to `correlation_id_middleware` in
/// `create_router`, so every route (`/api/v1`, `/v2`, native formats) runs
/// inside the scope. The resolution is the trusted-proxy-aware
/// [`resolve_client_ip_addr`]: the TCP peer is authoritative and a spoofed
/// `X-Forwarded-For` from an untrusted peer is ignored.
pub async fn client_ip_context_middleware(
    State(trusted_proxies): State<Arc<Vec<CidrRange>>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let ip = resolve_client_ip_addr(request.headers(), peer, &trusted_proxies);
    with_client_ip_scope(ip, next.run(request)).await
}
#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::HeaderMap, routing::get, Router};
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    fn req(peer: Option<&str>, xff: Option<&str>) -> Request {
        let mut builder = Request::builder().uri("/");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            let addr: SocketAddr = peer.parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        request
    }

    async fn ip_json() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "ip": current_client_ip().map(|ip| ip.to_string()),
        }))
    }

    async fn observed_ip(trusted: &[&str], request: Request) -> Option<String> {
        let trusted: Vec<CidrRange> = trusted
            .iter()
            .map(|c| CidrRange::parse(c).unwrap())
            .collect();
        let app =
            Router::new()
                .route("/", get(ip_json))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(trusted),
                    client_ip_context_middleware,
                ));
        let response = app.oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("ip")
            .unwrap()
            .as_str()
            .map(str::to_string)
    }

    #[tokio::test]
    async fn test_current_client_ip_is_none_outside_a_scope() {
        assert!(current_client_ip().is_none());
    }

    #[tokio::test]
    async fn test_with_client_ip_scope_bounds_the_value() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let seen = with_client_ip_scope(Some(ip), async { current_client_ip() }).await;
        assert_eq!(seen, Some(ip));
        // The value must not leak past the scope.
        assert!(current_client_ip().is_none());
    }

    #[tokio::test]
    async fn test_middleware_scopes_the_tcp_peer() {
        let seen = observed_ip(&[], req(Some("198.51.100.20:443"), None)).await;
        assert_eq!(seen.as_deref(), Some("198.51.100.20"));
    }

    #[tokio::test]
    async fn test_middleware_ignores_xff_from_an_untrusted_peer() {
        // No trusted proxies configured: a spoofed XFF must not steer the
        // resolved address away from the real peer (#2023).
        let seen = observed_ip(&[], req(Some("198.51.100.20:443"), Some("192.0.2.33"))).await;
        assert_eq!(seen.as_deref(), Some("198.51.100.20"));
    }

    #[tokio::test]
    async fn test_middleware_believes_xff_from_a_trusted_proxy() {
        let seen = observed_ip(
            &["198.51.100.0/24"],
            req(Some("198.51.100.20:443"), Some("192.0.2.33")),
        )
        .await;
        assert_eq!(seen.as_deref(), Some("192.0.2.33"));
    }

    #[tokio::test]
    async fn test_middleware_yields_none_when_nothing_resolves() {
        // No ConnectInfo (test topology) and no parseable XFF: unknown, never
        // a sentinel.
        let seen = observed_ip(&[], req(None, None)).await;
        assert_eq!(seen, None);
    }

    #[tokio::test]
    async fn test_middleware_falls_back_to_parseable_xff_without_peer() {
        // Direct-test / pre-ConnectInfo topology, matching resolve_client_ip_addr.
        let seen = observed_ip(&[], req(None, Some("192.0.2.33"))).await;
        assert_eq!(seen.as_deref(), Some("192.0.2.33"));
    }

    #[test]
    fn test_headerless_request_never_panics() {
        // The middleware reads headers and extensions only; a bare request
        // must resolve to None.
        let headers = HeaderMap::new();
        assert!(resolve_client_ip_addr(&headers, None, &[]).is_none());
    }
}
