//! Per-download telemetry context (#2365).
//!
//! [`DownloadContext`] carries the resolved client IP, authenticated user,
//! and user agent for a download request, so every format handler records
//! real attribution into `download_statistics` instead of the historical
//! `'0.0.0.0'` sentinel with no user.
//!
//! Client-IP resolution reuses the rate limiter's trusted-proxy contract
//! ([`resolve_client_ip_addr`], #2023): the socket peer is authoritative and
//! `X-Forwarded-For` is believed only when the peer is inside a configured
//! `RATE_LIMIT_TRUSTED_PROXY_CIDRS` range. When nothing resolves, the IP is
//! recorded as NULL — never a sentinel value.

use std::convert::Infallible;
use std::net::IpAddr;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap},
};
use uuid::Uuid;

use super::auth::AuthExtension;
use super::rate_limit::{resolve_client_ip_addr, CidrRange};
use crate::api::SharedState;

/// Telemetry attribution for a single download request.
///
/// Extracted via [`FromRequestParts`], so handlers add a `ctx:
/// DownloadContext` parameter and pass it to
/// [`crate::services::artifact_service::record_download`]. Extraction is
/// infallible: an anonymous request yields `user_id: None` and an
/// unresolvable client yields `client_ip: None` — recording stays
/// best-effort and never rejects the download.
#[derive(Debug, Clone, Default)]
pub struct DownloadContext {
    /// Resolved client IP (trusted-proxy-aware), `None` when unresolvable.
    pub client_ip: Option<IpAddr>,
    /// Authenticated principal, `None` for anonymous downloads.
    pub user_id: Option<Uuid>,
    /// The request's `User-Agent` header, when present and valid UTF-8.
    pub user_agent: Option<String>,
}

impl DownloadContext {
    /// Build a context from bare request parts. Pure and synchronous so the
    /// resolution rules are unit-testable without an Axum runtime.
    pub(crate) fn from_parts_inner(
        headers: &HeaderMap,
        peer: Option<IpAddr>,
        auth: Option<&AuthExtension>,
        trusted_proxies: &[CidrRange],
    ) -> Self {
        Self {
            client_ip: resolve_client_ip_addr(headers, peer, trusted_proxies),
            user_id: auth.map(|a| a.user_id),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        }
    }
}

#[async_trait]
impl FromRequestParts<SharedState> for DownloadContext {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        // `optional_auth_middleware` inserts `Option<AuthExtension>`; the
        // required-auth middlewares insert a bare `AuthExtension`. Accept
        // either so the context works under both nests.
        let auth = parts
            .extensions
            .get::<Option<AuthExtension>>()
            .and_then(|opt| opt.as_ref())
            .or_else(|| parts.extensions.get::<AuthExtension>());
        Ok(Self::from_parts_inner(
            &parts.headers,
            peer,
            auth,
            &state.config.rate_limit_trusted_proxy_cidrs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::access_scope::AccessScope;

    fn auth_ext(user_id: Uuid) -> AuthExtension {
        AuthExtension {
            user_id,
            username: "downloader".to_string(),
            email: "downloader@test.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    fn trusted_loopback() -> Vec<CidrRange> {
        vec![CidrRange::parse("127.0.0.0/8").unwrap()]
    }

    #[test]
    fn test_context_trusted_proxy_peer_takes_xff_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.insert(header::USER_AGENT, "npm/10.2.0".parse().unwrap());
        let ctx = DownloadContext::from_parts_inner(
            &headers,
            Some("127.0.0.1".parse().unwrap()),
            None,
            &trusted_loopback(),
        );
        assert_eq!(ctx.client_ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(ctx.user_agent.as_deref(), Some("npm/10.2.0"));
    }

    #[test]
    fn test_context_untrusted_peer_ignores_spoofed_xff() {
        // #2023: an untrusted peer cannot steer attribution via XFF.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let ctx = DownloadContext::from_parts_inner(
            &headers,
            Some("198.51.100.20".parse().unwrap()),
            None,
            &trusted_loopback(),
        );
        assert_eq!(ctx.client_ip, Some("198.51.100.20".parse().unwrap()));
    }

    #[test]
    fn test_context_no_peer_falls_back_to_parseable_xff_else_none() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.0.2.33".parse().unwrap());
        let ctx = DownloadContext::from_parts_inner(&headers, None, None, &[]);
        assert_eq!(ctx.client_ip, Some("192.0.2.33".parse().unwrap()));

        let ctx = DownloadContext::from_parts_inner(&HeaderMap::new(), None, None, &[]);
        assert_eq!(
            ctx.client_ip, None,
            "unresolvable must be None, not 0.0.0.0"
        );
    }

    #[test]
    fn test_context_anonymous_user_is_none_and_authed_user_is_captured() {
        let anonymous = DownloadContext::from_parts_inner(&HeaderMap::new(), None, None, &[]);
        assert_eq!(anonymous.user_id, None);

        let uid = Uuid::new_v4();
        let auth = auth_ext(uid);
        let authed = DownloadContext::from_parts_inner(&HeaderMap::new(), None, Some(&auth), &[]);
        assert_eq!(authed.user_id, Some(uid));
    }

    #[test]
    fn test_context_user_agent_none_when_absent() {
        let ctx = DownloadContext::from_parts_inner(&HeaderMap::new(), None, None, &[]);
        assert_eq!(ctx.user_agent, None);
    }
}
