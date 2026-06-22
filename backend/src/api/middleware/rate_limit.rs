//! Rate limiting middleware.
//!
//! Provides per-IP and per-user rate limiting with configurable limits.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{header::HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::auth::AuthExtension;

/// A parsed CIDR range used for IP-based rate-limit exemption (#969).
///
/// Stored as `(network, prefix_len)` so the membership check is a constant-
/// time bitmask compare, no allocations. Supports both IPv4 and IPv6.
#[derive(Debug, Clone, Copy)]
pub struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    /// Parse a CIDR string of the form `"10.0.0.0/8"` or `"fc00::/7"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/' in CIDR: {}", s))?;
        let network: IpAddr = addr_str
            .parse()
            .map_err(|e| format!("invalid IP '{}': {}", addr_str, e))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix length '{}': {}", prefix_str, e))?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {} exceeds maximum {} for {}",
                prefix_len, max_prefix, addr_str
            ));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Whether `ip` falls within this CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net_bits = u32::from(net);
                let ip_bits = u32::from(ip);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX
                        .checked_shl(32 - self.prefix_len as u32)
                        .unwrap_or(0)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits = u128::from(net);
                let ip_bits = u128::from(ip);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX
                        .checked_shl(128 - self.prefix_len as u32)
                        .unwrap_or(0)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            // Mixed family: a v4 CIDR never contains a v6 address (and
            // vice versa). Operators wanting to cover both must list both.
            _ => false,
        }
    }
}

/// Set of users, service-account flags, and trusted CIDR ranges that bypass
/// rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitExemptions {
    pub usernames: HashSet<String>,
    pub exempt_service_accounts: bool,
    /// IPs in any of these ranges bypass the limiter regardless of auth
    /// state. Intended for trusted internal callers (sidecar probes,
    /// service-mesh nodes, in-cluster CI runners). See #969.
    pub trusted_cidrs: Vec<CidrRange>,
}

impl RateLimitExemptions {
    pub fn new(usernames: Vec<String>, exempt_service_accounts: bool) -> Self {
        Self::with_cidrs(usernames, exempt_service_accounts, Vec::new())
    }

    pub fn with_cidrs(
        usernames: Vec<String>,
        exempt_service_accounts: bool,
        trusted_cidrs: Vec<CidrRange>,
    ) -> Self {
        Self {
            usernames: usernames.into_iter().collect(),
            exempt_service_accounts,
            trusted_cidrs,
        }
    }

    pub fn is_exempt(&self, auth: &AuthExtension) -> bool {
        if self.usernames.contains(&auth.username) {
            return true;
        }
        if self.exempt_service_accounts && auth.is_service_account {
            return true;
        }
        false
    }

    /// Whether `ip` falls within any of the trusted CIDR ranges.
    pub fn is_trusted_cidr(&self, ip: IpAddr) -> bool {
        self.trusted_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.usernames.is_empty() && !self.exempt_service_accounts && self.trusted_cidrs.is_empty()
    }
}

/// Combines a rate limiter with exemption rules, passed as shared state to the middleware.
#[derive(Debug, Clone)]
pub struct RateLimitState {
    pub limiter: Arc<RateLimiter>,
    pub exemptions: Arc<RateLimitExemptions>,
    /// Master on/off switch (driven by `Config::rate_limit_enabled`,
    /// env `RATE_LIMIT_ENABLED`). When `false`, the middleware short-
    /// circuits before touching the limiter so no request is ever limited.
    /// Intended for internal-only / VPN-gated deployments. See #1602.
    pub enabled: bool,
}

/// Whether a request should be limited at all, given the master switch.
///
/// Extracted as a pure function so the enable/disable decision is unit-
/// testable without constructing an Axum request. Returns `true` when the
/// limiter should run, `false` when it must be bypassed entirely (#1602).
#[inline]
pub fn rate_limiting_active(enabled: bool) -> bool {
    enabled
}

/// Per-instance, in-memory rate limiter that tracks requests per key (IP or user ID).
///
/// This limiter is **not shared across replicas**. Each application instance
/// maintains its own counters, so effective per-client limits scale linearly
/// with the number of instances. For multi-instance deployments behind a load
/// balancer, use an ingress-level rate limiter (e.g. NGINX `limit_req`,
/// Envoy, or a cloud WAF) to enforce global limits.
///
/// Uses `std::sync::Mutex` rather than `tokio::sync::RwLock` because the
/// critical section is pure in-memory computation with no async work. A
/// synchronous mutex avoids the overhead of yielding to the Tokio scheduler
/// on every request and prevents task-queue contention that was observed
/// under high-concurrency stress tests (issue #692).
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of key -> (request count, window start time)
    requests: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    /// Maximum number of requests allowed per window
    pub(crate) max_requests: u32,
    /// Duration of the rate limiting window
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified limits.
    ///
    /// # Arguments
    /// * `max_requests` - Maximum number of requests allowed per window
    /// * `window_secs` - Duration of the rate limiting window in seconds
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if a request should be rate limited.
    ///
    /// Returns `Ok(remaining)` with the number of remaining requests if allowed,
    /// or `Err(retry_after_secs)` if the rate limit has been exceeded.
    pub async fn check_rate_limit(&self, key: &str) -> Result<u32, u64> {
        let now = Instant::now();
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());

        let entry = requests.entry(key.to_string()).or_insert((0, now));

        // Check if the window has expired
        if now.duration_since(entry.1) >= self.window {
            // Reset the window
            entry.0 = 1;
            entry.1 = now;
            return Ok(self.max_requests.saturating_sub(1));
        }

        // Check if we've exceeded the limit
        if entry.0 >= self.max_requests {
            let retry_after = self.window.as_secs() - now.duration_since(entry.1).as_secs();
            return Err(retry_after.max(1));
        }

        // Increment the counter
        entry.0 += 1;
        Ok(self.max_requests.saturating_sub(entry.0))
    }

    /// Clean up expired entries from the rate limiter.
    /// Call this periodically to prevent memory bloat.
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        requests.retain(|_, (_, window_start)| now.duration_since(*window_start) < self.window);
    }
}

/// Rate limiting middleware.
///
/// Applies rate limiting based on:
/// 1. User ID (if authenticated)
/// 2. IP address (if not authenticated or as fallback)
///
/// Returns 429 Too Many Requests when the limit is exceeded,
/// with a Retry-After header indicating when to retry.
pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    // Master off switch (#1602): bypass the limiter entirely so no request
    // is limited. Used by internal-only / VPN-gated deployments.
    if !rate_limiting_active(state.enabled) {
        return next.run(request).await;
    }

    // Extract auth from extensions (required or optional middleware)
    let auth = request
        .extensions()
        .get::<AuthExtension>()
        .cloned()
        .or_else(|| {
            request
                .extensions()
                .get::<Option<AuthExtension>>()
                .and_then(|opt| opt.clone())
        });

    // User/service-account exemptions
    if let Some(ref auth) = auth {
        if state.exemptions.is_exempt(auth) {
            let mut response = next.run(request).await;
            if let Ok(value) = HeaderValue::from_str("true") {
                response.headers_mut().insert("X-RateLimit-Exempt", value);
            }
            return response;
        }
    }

    // Trusted-CIDR exemption (#969). Applies to authed and unauthed
    // requests alike: a sidecar probe or in-cluster CI runner calling
    // /api/v1/auth/login from a known internal range bypasses the
    // limiter so concurrent test pods don't exhaust the auth bucket.
    if !state.exemptions.trusted_cidrs.is_empty() {
        if let Some(ip) = extract_client_ip_addr(&request) {
            if state.exemptions.is_trusted_cidr(ip) {
                let mut response = next.run(request).await;
                if let Ok(value) = HeaderValue::from_str("trusted-cidr") {
                    response.headers_mut().insert("X-RateLimit-Exempt", value);
                }
                return response;
            }
        }
    }

    // Determine the rate limit key
    // Priority: authenticated user ID > IP address
    let key = if let Some(ref auth) = auth {
        format!("user:{}", auth.user_id)
    } else {
        extract_client_ip(&request)
    };

    // Check rate limit
    match state.limiter.check_rate_limit(&key).await {
        Ok(remaining) => {
            let mut response = next.run(request).await;

            // Add rate limit headers to successful responses
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&state.limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
                headers.insert("X-RateLimit-Remaining", value);
            }

            response
        }
        Err(retry_after) => {
            tracing::debug!(
                key = %key,
                retry_after = retry_after,
                "rate limit exceeded"
            );

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response();

            // Add Retry-After header
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                headers.insert("Retry-After", value);
            }
            if let Ok(value) = HeaderValue::from_str(&state.limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str("0") {
                headers.insert("X-RateLimit-Remaining", value);
            }

            response
        }
    }
}

/// IP-only rate-limit middleware (#1053).
///
/// Variant of [`rate_limit_middleware`] that ALWAYS keys by source IP,
/// regardless of authentication state. Intended for endpoints that mint
/// presigned download URLs (or any other O(1)-cost-per-request endpoint
/// where an authenticated attacker can issue many concurrent requests
/// from a single host without memory pressure on the backend).
///
/// Username/service-account exemptions and trusted-CIDR exemptions
/// (#969) are still honored.
pub async fn rate_limit_by_ip_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    // Master off switch (#1602): bypass the per-IP limiter entirely. This
    // is the limiter most likely to bite internal callers (e.g. sbt /
    // Coursier hammering the presigned-download path).
    if !rate_limiting_active(state.enabled) {
        return next.run(request).await;
    }

    // Username / service-account exemption: legitimate batch downloads
    // by admin / CI bots should not be throttled even when they
    // originate from a single egress IP.
    let auth = request
        .extensions()
        .get::<AuthExtension>()
        .cloned()
        .or_else(|| {
            request
                .extensions()
                .get::<Option<AuthExtension>>()
                .and_then(|opt| opt.clone())
        });
    if let Some(ref auth) = auth {
        if state.exemptions.is_exempt(auth) {
            let mut response = next.run(request).await;
            if let Ok(value) = HeaderValue::from_str("true") {
                response.headers_mut().insert("X-RateLimit-Exempt", value);
            }
            return response;
        }
    }

    // Trusted-CIDR exemption (#969): sidecar probes / in-cluster CI
    // runners / service-mesh nodes that originate from a known
    // internal range bypass the limiter regardless of auth.
    if !state.exemptions.trusted_cidrs.is_empty() {
        if let Some(ip) = extract_client_ip_addr(&request) {
            if state.exemptions.is_trusted_cidr(ip) {
                let mut response = next.run(request).await;
                if let Ok(value) = HeaderValue::from_str("trusted-cidr") {
                    response.headers_mut().insert("X-RateLimit-Exempt", value);
                }
                return response;
            }
        }
    }

    // The whole point of this variant: key by IP, not user_id. An
    // attacker who has N valid auth tokens behind a single egress IP
    // cannot multiply their presign-mint budget by minting tokens.
    let key = extract_client_ip(&request);

    match state.limiter.check_rate_limit(&key).await {
        Ok(remaining) => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&state.limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
                headers.insert("X-RateLimit-Remaining", value);
            }
            response
        }
        Err(retry_after) => {
            tracing::debug!(
                key = %key,
                retry_after = retry_after,
                "presign-mint rate limit exceeded"
            );
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response();
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                headers.insert("Retry-After", value);
            }
            if let Ok(value) = HeaderValue::from_str(&state.limiter.max_requests.to_string()) {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = HeaderValue::from_str("0") {
                headers.insert("X-RateLimit-Remaining", value);
            }
            response
        }
    }
}

/// Extract the client IP address from the request.
///
/// Uses the actual TCP peer address from ConnectInfo as the primary source.
/// When ConnectInfo is unavailable (common in Kubernetes where the backend
/// sits behind an ingress controller), falls back to X-Forwarded-For set
/// by the trusted reverse proxy. As a last resort, all unauthenticated
/// requests share a single bucket.
fn extract_client_ip(request: &Request) -> String {
    if let Some(ip) = extract_client_ip_addr(request) {
        return format!("ip:{}", ip);
    }
    // Fall back to a stringly-typed XFF first-token even when it does NOT
    // parse as an IpAddr - this preserves pre-#969 bucket behavior for
    // hostnames or malformed entries (the rate-limit key was always a
    // String and never required parseability).
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first) = xff_str.split(',').next() {
                return format!("ip:{}", first.trim());
            }
        }
    }
    "ip:unknown".to_string()
}

/// Extract the client IP as a parsed `IpAddr` for CIDR matching (#969).
/// Returns `None` if the address cannot be resolved or does not parse.
fn extract_client_ip_addr(request: &Request) -> Option<IpAddr> {
    // ConnectInfo: the actual TCP peer.
    if let Some(connect_info) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return Some(connect_info.0.ip());
    }

    // X-Forwarded-For from a trusted ingress (Kubernetes deployment).
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first) = xff_str.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_requests_within_limit() {
        let limiter = RateLimiter::new(5, 60);

        for i in 0..5 {
            let result = limiter.check_rate_limit("test_key").await;
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_requests_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        // Use up the limit
        for _ in 0..3 {
            let result = limiter.check_rate_limit("test_key").await;
            assert!(result.is_ok());
        }

        // Next request should be blocked
        let result = limiter.check_rate_limit("test_key").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_retry_after() {
        let limiter = RateLimiter::new(1, 60);

        // Use up the limit
        let _ = limiter.check_rate_limit("test_key").await;

        // Check retry_after value
        let result = limiter.check_rate_limit("test_key").await;
        assert!(matches!(result, Err(retry_after) if retry_after > 0 && retry_after <= 60));
    }

    #[tokio::test]
    async fn test_rate_limiter_tracks_separate_keys() {
        let limiter = RateLimiter::new(2, 60);

        // Use up limit for key1
        for _ in 0..2 {
            let _ = limiter.check_rate_limit("key1").await;
        }

        // key1 should be blocked
        assert!(limiter.check_rate_limit("key1").await.is_err());

        // key2 should still work
        assert!(limiter.check_rate_limit("key2").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_remaining() {
        let limiter = RateLimiter::new(5, 60);

        let result = limiter.check_rate_limit("test_key").await;
        assert_eq!(result, Ok(4)); // 5 - 1 = 4 remaining

        let result = limiter.check_rate_limit("test_key").await;
        assert_eq!(result, Ok(3)); // 5 - 2 = 3 remaining
    }

    // -----------------------------------------------------------------------
    // Additional RateLimiter tests for improved coverage
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limiter_remaining_counts_down_to_zero() {
        let limiter = RateLimiter::new(3, 60);

        assert_eq!(limiter.check_rate_limit("k").await, Ok(2));
        assert_eq!(limiter.check_rate_limit("k").await, Ok(1));
        assert_eq!(limiter.check_rate_limit("k").await, Ok(0));
        // Next should be blocked
        assert!(limiter.check_rate_limit("k").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_window_reset() {
        // Use a very short window (1 second) to test reset
        let limiter = RateLimiter::new(1, 1);

        // Use up the limit
        assert!(limiter.check_rate_limit("reset_key").await.is_ok());
        assert!(limiter.check_rate_limit("reset_key").await.is_err());

        // Wait for the window to expire
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Should be allowed again after window reset
        let result = limiter.check_rate_limit("reset_key").await;
        assert!(result.is_ok());
        // After reset, remaining should be max_requests - 1
        assert_eq!(result.unwrap(), 0); // 1 - 1 = 0
    }

    #[tokio::test]
    async fn test_rate_limiter_cleanup_expired() {
        let limiter = RateLimiter::new(5, 1);

        // Add some entries
        let _ = limiter.check_rate_limit("key1").await;
        let _ = limiter.check_rate_limit("key2").await;

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Add a fresh entry
        let _ = limiter.check_rate_limit("key3").await;

        // Cleanup should remove expired entries (key1, key2) but keep key3
        limiter.cleanup_expired().await;

        let requests = limiter.requests.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !requests.contains_key("key1"),
            "Expired key1 should be removed"
        );
        assert!(
            !requests.contains_key("key2"),
            "Expired key2 should be removed"
        );
        assert!(requests.contains_key("key3"), "Fresh key3 should be kept");
    }

    #[tokio::test]
    async fn test_rate_limiter_retry_after_minimum_is_one() {
        // When the limit is just reached, retry_after should be at least 1
        let limiter = RateLimiter::new(1, 60);

        let _ = limiter.check_rate_limit("key").await;
        let result = limiter.check_rate_limit("key").await;

        match result {
            Err(retry_after) => {
                assert!(
                    retry_after >= 1,
                    "retry_after should be at least 1, got {}",
                    retry_after
                );
                assert!(
                    retry_after <= 60,
                    "retry_after should be <= window, got {}",
                    retry_after
                );
            }
            Ok(_) => panic!("Expected rate limit error"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_single_request_limit() {
        // With max_requests = 1, first request succeeds, second fails
        let limiter = RateLimiter::new(1, 60);
        assert_eq!(limiter.check_rate_limit("k").await, Ok(0)); // 1-1 = 0 remaining
        assert!(limiter.check_rate_limit("k").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_many_independent_keys() {
        let limiter = RateLimiter::new(1, 60);

        for i in 0..100 {
            let key = format!("key_{}", i);
            assert!(limiter.check_rate_limit(&key).await.is_ok());
        }

        // Each key should now be exhausted
        for i in 0..100 {
            let key = format!("key_{}", i);
            assert!(limiter.check_rate_limit(&key).await.is_err());
        }
    }

    // -----------------------------------------------------------------------
    // extract_client_ip
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_client_ip_uses_x_forwarded_for_as_fallback() {
        // Without ConnectInfo, X-Forwarded-For is used as a fallback
        // (trusted when behind a known reverse proxy / ingress controller)
        let request = axum::extract::Request::builder()
            .header("X-Forwarded-For", "192.168.1.1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:192.168.1.1");
    }

    #[test]
    fn test_extract_client_ip_uses_first_xff_ip() {
        // When XFF contains multiple IPs, use the first (client IP set by proxy)
        let request = axum::extract::Request::builder()
            .header(
                "X-Forwarded-For",
                "203.0.113.50, 70.41.3.18, 150.172.238.178",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_ignores_x_real_ip() {
        let request = axum::extract::Request::builder()
            .header("X-Real-IP", "10.20.30.40")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:unknown");
    }

    #[test]
    fn test_extract_client_ip_no_headers_returns_unknown() {
        let request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&request), "ip:unknown");
    }

    #[test]
    fn test_extract_client_ip_uses_connect_info() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let mut request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        assert_eq!(extract_client_ip(&request), "ip:192.168.1.100");
    }

    #[test]
    fn test_extract_client_ip_connect_info_over_headers() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "10.0.0.5:9999".parse().unwrap();
        let mut request = axum::extract::Request::builder()
            .header("X-Forwarded-For", "1.2.3.4")
            .header("X-Real-IP", "5.6.7.8")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        // ConnectInfo takes priority over spoofable headers
        assert_eq!(extract_client_ip(&request), "ip:10.0.0.5");
    }

    // -----------------------------------------------------------------------
    // RateLimitExemptions
    // -----------------------------------------------------------------------

    fn make_auth(username: &str, is_service_account: bool) -> AuthExtension {
        AuthExtension {
            user_id: uuid::Uuid::new_v4(),
            username: username.to_string(),
            email: format!("{}@test.com", username),
            is_admin: false,
            is_api_token: false,
            is_service_account,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_exemptions_by_username() {
        let ex = RateLimitExemptions::new(vec!["ci-bot".into()], false);
        assert!(ex.is_exempt(&make_auth("ci-bot", false)));
        assert!(!ex.is_exempt(&make_auth("alice", false)));
    }

    #[test]
    fn test_exemptions_service_accounts() {
        let ex = RateLimitExemptions::new(Vec::new(), true);
        assert!(ex.is_exempt(&make_auth("deploy-sa", true)));
        assert!(!ex.is_exempt(&make_auth("alice", false)));
    }

    #[test]
    fn test_exemptions_empty() {
        let ex = RateLimitExemptions::new(Vec::new(), false);
        assert!(ex.is_empty());
        assert!(!ex.is_exempt(&make_auth("alice", true)));
    }

    #[test]
    fn test_exemptions_combined() {
        let ex = RateLimitExemptions::new(vec!["ci-bot".into()], true);
        assert!(!ex.is_empty());
        assert!(ex.is_exempt(&make_auth("ci-bot", false)));
        assert!(ex.is_exempt(&make_auth("deploy-sa", true)));
        assert!(!ex.is_exempt(&make_auth("alice", false)));
    }

    // ── CIDR parsing & matching (#969) ───────────────────────────────────────

    #[test]
    fn test_cidr_parse_ipv4() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert_eq!(cidr.prefix_len, 8);
    }

    #[test]
    fn test_cidr_parse_ipv6() {
        let cidr = CidrRange::parse("fc00::/7").unwrap();
        assert_eq!(cidr.prefix_len, 7);
    }

    #[test]
    fn test_cidr_parse_loopback() {
        assert!(CidrRange::parse("127.0.0.1/32").is_ok());
        assert!(CidrRange::parse("::1/128").is_ok());
    }

    #[test]
    fn test_cidr_parse_rejects_missing_slash() {
        assert!(CidrRange::parse("10.0.0.0").is_err());
    }

    #[test]
    fn test_cidr_parse_rejects_bad_ip() {
        assert!(CidrRange::parse("not-an-ip/8").is_err());
    }

    #[test]
    fn test_cidr_parse_rejects_oversize_prefix() {
        // /33 is invalid for IPv4
        assert!(CidrRange::parse("10.0.0.0/33").is_err());
        // /129 is invalid for IPv6
        assert!(CidrRange::parse("::/129").is_err());
    }

    #[test]
    fn test_cidr_parse_zero_prefix_matches_everything() {
        // 0.0.0.0/0 must accept any IPv4.
        let cidr = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains("1.2.3.4".parse().unwrap()));
        assert!(cidr.contains("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn test_cidr_contains_ipv4_in_range() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.0.0.1".parse().unwrap()));
        assert!(cidr.contains("10.255.255.254".parse().unwrap()));
    }

    #[test]
    fn test_cidr_contains_ipv4_out_of_range() {
        let cidr = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(!cidr.contains("11.0.0.1".parse().unwrap()));
        assert!(!cidr.contains("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_contains_ipv6_in_range() {
        let cidr = CidrRange::parse("fc00::/7").unwrap();
        assert!(cidr.contains("fc00::1".parse().unwrap()));
        assert!(cidr.contains("fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_contains_ipv6_out_of_range() {
        let cidr = CidrRange::parse("fc00::/7").unwrap();
        assert!(!cidr.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_mixed_family_does_not_match() {
        // A v4 CIDR never contains a v6 address.
        let v4 = CidrRange::parse("10.0.0.0/8").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
        // And vice versa.
        let v6 = CidrRange::parse("fc00::/7").unwrap();
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_exemptions_is_trusted_cidr() {
        let cidrs = vec![
            CidrRange::parse("10.0.0.0/8").unwrap(),
            CidrRange::parse("fc00::/7").unwrap(),
            CidrRange::parse("127.0.0.1/32").unwrap(),
        ];
        let ex = RateLimitExemptions::with_cidrs(Vec::new(), false, cidrs);

        assert!(ex.is_trusted_cidr("10.0.0.5".parse().unwrap()));
        assert!(ex.is_trusted_cidr("fc00::1".parse().unwrap()));
        assert!(ex.is_trusted_cidr("127.0.0.1".parse().unwrap()));
        assert!(!ex.is_trusted_cidr("8.8.8.8".parse().unwrap()));
        assert!(!ex.is_trusted_cidr("2001:db8::1".parse().unwrap()));
        // 127.0.0.2 is NOT in 127.0.0.1/32 (single host)
        assert!(!ex.is_trusted_cidr("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_exemptions_is_empty_with_only_cidrs() {
        let ex = RateLimitExemptions::with_cidrs(
            Vec::new(),
            false,
            vec![CidrRange::parse("10.0.0.0/8").unwrap()],
        );
        // is_empty must report false when CIDRs are configured, otherwise
        // the middleware will skip the per-IP check.
        assert!(!ex.is_empty());
    }

    #[test]
    fn test_exemptions_is_empty_truly_empty() {
        let ex = RateLimitExemptions::with_cidrs(Vec::new(), false, Vec::new());
        assert!(ex.is_empty());
    }

    // ── #1053: rate_limit_by_ip_middleware integration ──────────────────────
    //
    // The IP-only middleware shares its core (limiter + extract_client_ip
    // + exemption rules) with the existing rate_limit_middleware, both of
    // which are exercised by the unit tests above. The behavior delta this
    // variant introduces is only "key by IP regardless of auth", which is
    // mechanical: it replaces the `if auth { user:id } else { ip }` ternary
    // with `extract_client_ip(...)` unconditionally.
    //
    // We therefore test the building blocks rather than the middleware fn:
    // a concrete check that two different authed user_ids from the same IP
    // share the same key, and that two different IPs do not.

    #[test]
    fn test_presign_keying_collapses_multiple_users_on_same_ip() {
        // The IP-only middleware uses extract_client_ip (which returns
        // "ip:<addr>") regardless of auth. Two requests from different
        // user_ids but the same IP must therefore share the same bucket
        // key, which is the property #1053 was filed to enforce.
        let req1 = axum::extract::Request::builder()
            .header("X-Forwarded-For", "203.0.113.42")
            .body(axum::body::Body::empty())
            .unwrap();
        let req2 = axum::extract::Request::builder()
            .header("X-Forwarded-For", "203.0.113.42")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_client_ip(&req1), extract_client_ip(&req2));
        assert_eq!(extract_client_ip(&req1), "ip:203.0.113.42");
    }

    // --- Master enable/disable switch (#1602) ---

    #[test]
    fn test_rate_limiting_active_reflects_flag() {
        // Pure decision helper: enabled => active, disabled => bypass.
        assert!(rate_limiting_active(true));
        assert!(!rate_limiting_active(false));
    }

    fn state_with(enabled: bool) -> RateLimitState {
        // Capacity-1 limiter: with the limiter active, the 2nd+ request from
        // the same key would 429. With enabled=false the layer must bypass.
        RateLimitState {
            limiter: Arc::new(RateLimiter::new(1, 60)),
            exemptions: Arc::new(RateLimitExemptions::new(Vec::new(), false)),
            enabled,
        }
    }

    /// Drive `n` sequential requests (same X-Forwarded-For) through a one-route
    /// router carrying `app` and return how many returned 429.
    async fn count_429s(app: axum::Router, n: usize) -> usize {
        use tower::ServiceExt;
        let mut limited = 0;
        for _ in 0..n {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header("X-Forwarded-For", "203.0.113.99")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                limited += 1;
            }
        }
        limited
    }

    #[tokio::test]
    async fn test_disabled_user_middleware_never_limits() {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(false),
                rate_limit_middleware,
            ));
        assert_eq!(
            count_429s(app, 5).await,
            0,
            "disabled limiter must not 429 any request"
        );
    }

    #[tokio::test]
    async fn test_enabled_user_middleware_still_limits() {
        // Sanity: enabled=true with the same tiny limiter DOES 429, proving
        // the bypass above is the flag's doing, not an inert layer.
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(true),
                rate_limit_middleware,
            ));
        assert!(
            count_429s(app, 5).await > 0,
            "enabled limiter must 429 once capacity exceeded"
        );
    }

    #[tokio::test]
    async fn test_disabled_by_ip_middleware_never_limits() {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(false),
                rate_limit_by_ip_middleware,
            ));
        assert_eq!(
            count_429s(app, 5).await,
            0,
            "disabled per-IP limiter must not 429 any request"
        );
    }

    #[tokio::test]
    async fn test_enabled_by_ip_middleware_still_limits() {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(true),
                rate_limit_by_ip_middleware,
            ));
        assert!(
            count_429s(app, 5).await > 0,
            "enabled per-IP limiter must 429 once capacity exceeded"
        );
    }

    #[test]
    fn test_presign_keying_separates_buckets_by_ip() {
        let req1 = axum::extract::Request::builder()
            .header("X-Forwarded-For", "203.0.113.42")
            .body(axum::body::Body::empty())
            .unwrap();
        let req2 = axum::extract::Request::builder()
            .header("X-Forwarded-For", "198.51.100.7")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_ne!(extract_client_ip(&req1), extract_client_ip(&req2));
    }

    // ── Layer-ordering regression: auth must populate before the limiter ──────
    //
    // `rate_limit_middleware` keys authenticated callers by `user:<id>` and only
    // falls back to `ip:<addr>` when no `AuthExtension` is present in the request
    // extensions. The `/search` nest pairs this limiter with
    // `optional_auth_middleware`; whether per-user keying actually happens
    // depends entirely on which layer runs FIRST on the request path.
    //
    // Tower runs the OUTERMOST layer (the last `.layer()` call) first. So the
    // limiter must be the INNER layer (applied first / wrapped by auth) for the
    // auth extension to already be set when it reads it. The two tests below
    // pin both halves of that contract so a future re-order can't silently
    // collapse all callers behind a shared egress IP into one bucket again.

    /// Middleware that injects a fixed `AuthExtension` (a stand-in for
    /// `optional_auth_middleware` resolving a token to a user). Used to model
    /// the auth layer in the ordering tests below.
    async fn inject_auth(mut request: Request, next: Next) -> Response {
        // The user id is derived from a request header so each test can simulate
        // a distinct authenticated principal sharing one source IP.
        let uid_seed = request
            .headers()
            .get("x-test-user")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0")
            .to_string();
        // Stable per-seed UUID so repeated requests from the same simulated user
        // hash to the same rate-limit key. Built deterministically from the seed
        // bytes (no extra uuid features needed).
        let mut bytes = [0u8; 16];
        for (i, b) in uid_seed.bytes().enumerate().take(16) {
            bytes[i] = b;
        }
        let user_id = uuid::Uuid::from_bytes(bytes);
        request.extensions_mut().insert(AuthExtension {
            user_id,
            username: format!("user-{uid_seed}"),
            email: format!("user-{uid_seed}@test"),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        });
        next.run(request).await
    }

    /// Drive one request as simulated user `seed` from a fixed source IP and
    /// return its status.
    async fn one_request_as(app: &axum::Router, seed: &str) -> StatusCode {
        use tower::ServiceExt;
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("X-Forwarded-For", "203.0.113.7")
                    .header("x-test-user", seed)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn search_rate_limit_layer_runs_after_auth() {
        // FIXED ORDER: limiter applied first (inner), auth applied last (outer).
        // Auth therefore runs BEFORE the limiter, so the limiter keys by
        // `user:<id>`. Two different authenticated users sharing one source IP
        // must get INDEPENDENT buckets: user A exhausting a capacity-1 bucket
        // must NOT 429 user B.
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            // Inner: the rate limiter.
            .layer(axum::middleware::from_fn_with_state(
                state_with(true),
                rate_limit_middleware,
            ))
            // Outer: auth injection (runs first on the request path).
            .layer(axum::middleware::from_fn(inject_auth));

        // User A: first request OK, second 429 (capacity-1 bucket).
        assert_eq!(one_request_as(&app, "alice").await, StatusCode::OK);
        assert_eq!(
            one_request_as(&app, "alice").await,
            StatusCode::TOO_MANY_REQUESTS,
            "user A's own bucket must exhaust at capacity"
        );
        // User B, SAME source IP, must still be allowed — proof the key is the
        // user id, not the shared IP.
        assert_eq!(
            one_request_as(&app, "bob").await,
            StatusCode::OK,
            "a second authenticated user on the same IP must have an \
             independent bucket; sharing one means the limiter keyed by IP \
             because it ran before auth (the bug this fix addresses)"
        );
    }

    #[tokio::test]
    async fn buggy_order_collapses_users_into_one_ip_bucket() {
        // BUGGY ORDER (the pre-fix arrangement): auth applied first (inner),
        // limiter applied last (outer). The limiter therefore runs BEFORE auth
        // is set, sees no `AuthExtension`, and keys by source IP. Two different
        // users on the same IP then SHARE one bucket — exactly the fleet-wide
        // search outage. This test documents the failure mode so the contract
        // in `search_rate_limit_layer_runs_after_auth` is unambiguous.
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            // Inner: auth injection.
            .layer(axum::middleware::from_fn(inject_auth))
            // Outer: the rate limiter (runs first, before auth -> keys by IP).
            .layer(axum::middleware::from_fn_with_state(
                state_with(true),
                rate_limit_middleware,
            ));

        assert_eq!(one_request_as(&app, "alice").await, StatusCode::OK);
        // User B on the same IP is throttled by user A's traffic: shared bucket.
        assert_eq!(
            one_request_as(&app, "bob").await,
            StatusCode::TOO_MANY_REQUESTS,
            "with the limiter outside auth, all users on one IP share a bucket"
        );
    }

    // Source-level guard: the `/search` nest must apply the limiter as the inner
    // layer and `optional_auth_middleware` as the outer one. A runtime test of
    // the real nest needs full app state + a DB, so pin the ordering in source.
    #[test]
    fn search_nest_applies_auth_outside_rate_limit() {
        const ROUTES_SRC: &str = include_str!("../routes.rs");
        // The user-facing search nest is the one that wires the dedicated search
        // limiter. Anchor on that unique state so this test isn't confused by
        // the separate admin `/search` nest (which has no limiter).
        let rl = ROUTES_SRC
            .find("search_rate_limit_state")
            .expect("search nest must apply the search rate limiter");
        // The first `optional_auth_middleware` after the limiter wiring belongs
        // to the same nest. For per-user keying, auth must be applied AFTER the
        // limiter in source (Tower's last `.layer()` is outermost / runs first),
        // so `optional_auth_middleware` must appear LATER than the limiter here.
        let auth_after = ROUTES_SRC[rl..]
            .find("optional_auth_middleware")
            .expect("search nest must apply optional auth after the limiter");
        assert!(
            auth_after > 0,
            "optional_auth_middleware must be applied after (outside of) the \
             search rate limiter so the auth extension is populated when the \
             limiter keys the request; otherwise search is keyed by IP and \
             collapses all callers into one bucket"
        );
    }
}
