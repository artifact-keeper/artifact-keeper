//! Rate limiting middleware.
//!
//! Provides per-IP and per-user rate limiting with configurable limits.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::auth::AuthExtension;

/// Maximum login request body we will buffer to peek the `username` for
/// per-account rate-limit keying. Login payloads are tiny (`{"username":...,
/// "password":...}`); anything larger is not a legitimate login and is keyed
/// by IP alone (it still passes through to the handler, which rejects it).
const LOGIN_BODY_PEEK_LIMIT: usize = 64 * 1024;

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
    /// CIDR ranges identifying trusted reverse proxies. `X-Forwarded-For` is
    /// consulted for client-IP resolution **only** when the immediate TCP
    /// peer falls within one of these ranges; otherwise the real TCP peer is
    /// used so a spoofed/rotating `XFF` from an untrusted client cannot steer
    /// or multiply its rate-limit budget. Empty (the default) means `XFF` is
    /// never trusted. Driven by `Config::rate_limit_trusted_proxy_cidrs`
    /// (env `RATE_LIMIT_TRUSTED_PROXY_CIDRS`).
    ///
    /// Within a believed chain the client is the **rightmost** token outside
    /// these ranges — appending proxies preserve a client-supplied prefix, so
    /// the leftmost token is attacker-controlled (GHSA-8jm4-4x6c-6787). Every
    /// hop of a multi-proxy chain must be covered by these ranges; any token
    /// not covered is treated as the client.
    pub trusted_proxies: Arc<Vec<CidrRange>>,
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

/// Pull an `AuthExtension` out of request extensions, whether it was inserted
/// directly (required-auth middleware) or as an `Option` (optional-auth
/// middleware). Shared by every rate-limit middleware.
fn auth_from_request(request: &Request) -> Option<AuthExtension> {
    request
        .extensions()
        .get::<AuthExtension>()
        .cloned()
        .or_else(|| {
            request
                .extensions()
                .get::<Option<AuthExtension>>()
                .and_then(|opt| opt.clone())
        })
}

/// Run the username/service-account and trusted-CIDR exemption checks shared by
/// every rate-limit middleware (#969). Returns `Some(tag)` with the
/// `X-RateLimit-Exempt` header value when the request is exempt (the caller then
/// runs `next` and tags the response), or `None` so the caller proceeds to keyed
/// limiting.
fn check_rate_limit_exemptions(
    exemptions: &RateLimitExemptions,
    auth: Option<&AuthExtension>,
    request: &Request,
    trusted_proxies: &[CidrRange],
) -> Option<&'static str> {
    // User/service-account exemption.
    if let Some(auth) = auth {
        if exemptions.is_exempt(auth) {
            return Some("true");
        }
    }
    // Trusted-CIDR exemption (#969): applies to authed and unauthed alike.
    if !exemptions.trusted_cidrs.is_empty() {
        if let Some(ip) = extract_client_ip_addr(request, trusted_proxies) {
            if exemptions.is_trusted_cidr(ip) {
                return Some("trusted-cidr");
            }
        }
    }
    None
}

/// Tag a response as rate-limit-exempt and return it.
fn tag_exempt(mut response: Response, tag: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(tag) {
        response.headers_mut().insert("X-RateLimit-Exempt", value);
    }
    response
}

/// Attach the `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers to an
/// allowed response.
fn tag_allowed(mut response: Response, max_requests: u32, remaining: u32) -> Response {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&max_requests.to_string()) {
        headers.insert("X-RateLimit-Limit", value);
    }
    if let Ok(value) = HeaderValue::from_str(&remaining.to_string()) {
        headers.insert("X-RateLimit-Remaining", value);
    }
    response
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
    let auth = auth_from_request(&request);

    // Username/service-account + trusted-CIDR exemptions (#969).
    if let Some(tag) = check_rate_limit_exemptions(
        &state.exemptions,
        auth.as_ref(),
        &request,
        &state.trusted_proxies,
    ) {
        return tag_exempt(next.run(request).await, tag);
    }

    // Determine the rate limit key
    // Priority: authenticated user ID > IP address
    let key = if let Some(ref auth) = auth {
        format!("user:{}", auth.user_id)
    } else {
        extract_client_ip(&request, &state.trusted_proxies)
    };

    // Check rate limit
    match state.limiter.check_rate_limit(&key).await {
        Ok(remaining) => tag_allowed(
            next.run(request).await,
            state.limiter.max_requests,
            remaining,
        ),
        Err(retry_after) => {
            tracing::debug!(key = %key, retry_after, "rate limit exceeded");
            too_many_requests(retry_after, state.limiter.max_requests)
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

    // Username/service-account + trusted-CIDR exemptions (#969). Legitimate
    // batch downloads by admin / CI bots (or trusted internal ranges) should
    // not be throttled even when they share a single egress IP.
    let auth = auth_from_request(&request);
    if let Some(tag) = check_rate_limit_exemptions(
        &state.exemptions,
        auth.as_ref(),
        &request,
        &state.trusted_proxies,
    ) {
        return tag_exempt(next.run(request).await, tag);
    }

    // The whole point of this variant: key by IP, not user_id. An
    // attacker who has N valid auth tokens behind a single egress IP
    // cannot multiply their presign-mint budget by minting tokens.
    let key = extract_client_ip(&request, &state.trusted_proxies);

    match state.limiter.check_rate_limit(&key).await {
        Ok(remaining) => tag_allowed(
            next.run(request).await,
            state.limiter.max_requests,
            remaining,
        ),
        Err(retry_after) => {
            tracing::debug!(key = %key, retry_after, "presign-mint rate limit exceeded");
            too_many_requests(retry_after, state.limiter.max_requests)
        }
    }
}

/// State for the login-only rate-limit middleware.
///
/// Wraps the standard [`RateLimitState`] (the shared auth limiter, exemptions,
/// and master switch — used here so the login path honors exactly the same
/// username/service-account exemptions, trusted-CIDR exemptions (#969), and
/// master off-switch (#1602) as [`rate_limit_middleware`]) and adds a global
/// backstop limiter. The auth limiter is keyed per-`(username, source-IP)` so a
/// junk flood against one identity/origin cannot exhaust the budget for other
/// accounts; the backstop bounds the total login volume (and the size of the
/// per-key map) so a username-cycling attacker cannot drive unbounded distinct
/// keys.
#[derive(Debug, Clone)]
pub struct LoginRateLimitState {
    /// Per-`(username, ip)` auth limiter + exemptions + master switch.
    pub inner: RateLimitState,
    /// Global shedding backstop, keyed on a single constant bucket. Capacity is
    /// sized far above any legitimate concurrent-login volume.
    pub backstop: Arc<RateLimiter>,
}

/// Build the login rate-limit key from a username and the request's client IP.
///
/// Extracted as a pure function so the keyspace contract (one bucket per
/// `(username, ip)` pair) is unit-testable without constructing middleware.
/// Login is case-sensitive at the auth layer (the `WHERE username = $1` lookup
/// uses no `LOWER`/`ILIKE`), so the username is used verbatim to match the auth
/// identity 1:1.
pub fn login_rate_limit_key(username: &str, client_ip: &str) -> String {
    format!("login:{}|{}", username, client_ip)
}

/// Login-only rate-limit middleware.
///
/// Variant of [`rate_limit_middleware`] for the unauthenticated `POST
/// /auth/login` route. It buffers the (tiny) login JSON, extracts `username`,
/// and keys the auth limiter per-`(username, source-IP)` instead of per-IP, so
/// a junk flood against one identity/origin exhausts only its own bucket and
/// correct logins by other users — or the same user from another IP — are
/// unaffected, while per-account brute-force caps still hold.
///
/// A global backstop limiter (keyed on one constant bucket) sheds once total
/// login volume per window exceeds its high ceiling, bounding the per-key map
/// against a username-cycling attacker.
///
/// Username/service-account exemptions, trusted-CIDR exemptions (#969), and the
/// master off-switch (#1602) are honored identically to [`rate_limit_middleware`].
pub async fn login_rate_limit_middleware(
    State(state): State<LoginRateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let inner = &state.inner;

    // Master off switch (#1602): bypass the limiter entirely.
    if !rate_limiting_active(inner.enabled) {
        return next.run(request).await;
    }

    // Username/service-account + trusted-CIDR exemptions (#969). /login is
    // unauthenticated, but optional-auth middleware could populate an
    // AuthExtension upstream; honor the same exemption contract as
    // rate_limit_middleware for parity.
    let auth = auth_from_request(&request);
    if let Some(tag) = check_rate_limit_exemptions(
        &inner.exemptions,
        auth.as_ref(),
        &request,
        &inner.trusted_proxies,
    ) {
        return tag_exempt(next.run(request).await, tag);
    }

    // Resolve the client IP before consuming the body.
    let client_ip = extract_client_ip(&request, &inner.trusted_proxies);

    // Buffer the (small) login body so we can peek `username`, then re-attach
    // it unchanged for the handler's custom Json extractor.
    let (parts, body) = request.into_parts();
    #[allow(clippy::disallowed_methods)]
    // STREAMING-EXEMPT: buffers the small login body (LOGIN_BODY_PEEK_LIMIT) to peek username, re-attached unchanged; not an artifact path (#1608)
    let bytes = match axum::body::to_bytes(body, LOGIN_BODY_PEEK_LIMIT).await {
        Ok(b) => b,
        Err(_) => {
            // Body too large or unreadable: not a legitimate login. Reconstruct
            // an empty-bodied request keyed by IP and let the handler reject it.
            let request = Request::from_parts(parts, Body::empty());
            return run_login_with_key(&state, &client_ip, request, next).await;
        }
    };

    // Best-effort username extraction; on any parse failure fall back to an
    // IP-only key (the body is still forwarded unchanged for the handler).
    let username = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("username")
                .and_then(|u| u.as_str())
                .map(|s| s.to_string())
        });

    let key = match username {
        Some(name) => login_rate_limit_key(&name, &client_ip),
        None => client_ip.clone(),
    };

    // Reattach the buffered body unchanged (Content-Type/headers in `parts`
    // are preserved) so the login handler's extractor sees the original body.
    let request = Request::from_parts(parts, Body::from(bytes));
    run_login_with_key(&state, &key, request, next).await
}

/// Apply the global backstop, then the per-key login limiter, then run the
/// request. Shared tail of [`login_rate_limit_middleware`] so both the
/// normal and the oversized-body paths key and shed identically.
async fn run_login_with_key(
    state: &LoginRateLimitState,
    key: &str,
    request: Request,
    next: Next,
) -> Response {
    // Global backstop first: sheds (rather than starves) once total login
    // volume per window exceeds its high ceiling.
    if let Err(retry_after) = state.backstop.check_rate_limit("login:global").await {
        return too_many_requests(retry_after, state.backstop.max_requests);
    }

    match state.inner.limiter.check_rate_limit(key).await {
        Ok(remaining) => tag_allowed(
            next.run(request).await,
            state.inner.limiter.max_requests,
            remaining,
        ),
        Err(retry_after) => {
            tracing::debug!(key = %key, retry_after, "login rate limit exceeded");
            too_many_requests(retry_after, state.inner.limiter.max_requests)
        }
    }
}

/// Build a 429 response with `Retry-After` and `X-RateLimit-*` headers.
fn too_many_requests(retry_after: u64, max_requests: u32) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        "Rate limit exceeded. Please try again later.",
    )
        .into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        headers.insert("Retry-After", value);
    }
    if let Ok(value) = HeaderValue::from_str(&max_requests.to_string()) {
        headers.insert("X-RateLimit-Limit", value);
    }
    if let Ok(value) = HeaderValue::from_str("0") {
        headers.insert("X-RateLimit-Remaining", value);
    }
    response
}

/// First `X-Forwarded-For` token, trimmed, as a string (may be a hostname or
/// otherwise non-parseable). `None` when the header is absent or empty. Used
/// only by the no-`ConnectInfo` (test-harness) fallback in
/// [`resolve_client_ip_addr`]; trusted-proxy resolution never takes the
/// leftmost token — see [`rightmost_untrusted_xff_token`]
/// (GHSA-8jm4-4x6c-6787).
fn first_xff_token_in(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Rightmost `X-Forwarded-For` token that is NOT itself a trusted proxy —
/// the right-side-aware client-IP selection for GHSA-8jm4-4x6c-6787.
///
/// Trusted appending proxies (Caddy in the default compose deployment)
/// preserve any client-supplied `XFF` prefix and append the address they
/// actually observed, so the LEFTMOST token is attacker-controlled while the
/// RIGHT side of the chain is appended by hops we trust. Walk the tokens
/// right-to-left from the immediate peer: skip tokens inside a trusted-proxy
/// CIDR (appends by hops in our own chain) and select the first token outside
/// every trusted range — the address the outermost trusted proxy observed for
/// the downstream client.
///
/// An attacker prefix token can never be selected: it always sits LEFT of the
/// trusted proxy's own append, and the walk stops at the first non-trusted
/// token from the right. A non-empty token that fails to parse as an `IpAddr`
/// aborts the walk (`None` → caller falls back to the TCP peer) rather than
/// diving further left into attacker-controlled text; empty tokens carry no
/// information and are skipped. `None` is also returned when every token is
/// trusted (no client IP recoverable from the header).
///
/// ⚠️ Walks **every** `X-Forwarded-For` field line, last line first, not just
/// the first one (#3372). RFC 9110 §5.2 makes repeated field lines equivalent
/// to the comma-joined value *in order*, and proxies differ in which they
/// emit: Caddy merges into one line, but HAProxy (`option forwardfor`), Go
/// `net/http` reverse proxies and some Envoy configurations `Add` a second
/// line. Reading only `headers.get()` there returns the ATTACKER's line —
/// theirs arrives first — and the walk never sees the trusted proxy's own
/// append, leaving GHSA-8jm4-4x6c-6787 unmitigated for those topologies.
///
/// Tokens are stripped of an optional `:port` suffix and `[..]` brackets
/// before parsing: Azure Application Gateway appends `1.2.3.4:5678` and some
/// proxies append `[2001:db8::1]`, and treating either as unparseable aborted
/// the walk and silently collapsed every client onto the shared peer bucket.
/// Strip the decorations real proxies add to an `X-Forwarded-For` token so it
/// parses as a bare `IpAddr`: surrounding whitespace, `[..]` brackets around an
/// IPv6 literal, and a trailing `:port`.
///
/// A bare IPv6 address contains multiple colons and must NOT be truncated at
/// one, so a `:port` is only stripped when the remainder still looks like an
/// address (bracketed form, or a single colon as in `1.2.3.4:5678`).
fn normalize_xff_token(token: &str) -> &str {
    let t = token.trim();
    if let Some(rest) = t.strip_prefix('[') {
        // `[2001:db8::1]` or `[2001:db8::1]:443`
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
        return t;
    }
    if t.matches(':').count() == 1 {
        // `1.2.3.4:5678` — an IPv4 address with a port. A bare IPv6 always
        // has two or more colons, so this cannot truncate one.
        if let Some((host, _port)) = t.rsplit_once(':') {
            return host;
        }
    }
    t
}

fn rightmost_untrusted_xff_token(
    headers: &axum::http::HeaderMap,
    trusted_proxies: &[CidrRange],
) -> Option<IpAddr> {
    // Last field line first, then tokens right-to-left within each line.
    let lines: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if lines.is_empty() {
        return None;
    }
    for token in lines.iter().rev().flat_map(|line| line.split(',').rev()) {
        let token = normalize_xff_token(token);
        if token.is_empty() {
            continue;
        }
        match token.parse::<IpAddr>() {
            // Trusted proxy hop: keep walking left toward the client.
            Ok(ip) if trusted_proxies.iter().any(|cidr| cidr.contains(ip)) => continue,
            // First non-trusted IP from the right: the client as observed by
            // the outermost trusted proxy.
            Ok(ip) => return Some(ip),
            // Unparseable token: the chain is not a well-formed trusted
            // append; bail to the TCP peer instead of trusting text further
            // left.
            Err(_) => return None,
        }
    }
    None
}

/// Extract the client IP address from the request, as the rate-limit key.
///
/// The real TCP peer address from `ConnectInfo` is authoritative. The
/// spoofable `X-Forwarded-For` header is consulted to recover the real client
/// IP **only** when the immediate peer is a configured trusted reverse proxy
/// (`trusted_proxies`); otherwise it is ignored so a rotating/spoofed `XFF`
/// from an untrusted client cannot steer or multiply its budget (#2023).
/// Within a believed chain the client is the rightmost token outside the
/// trusted ranges — never the attacker-controlled leftmost token
/// (GHSA-8jm4-4x6c-6787, see [`resolve_client_ip_addr`]).
///
/// When `ConnectInfo` is unavailable (e.g. a test harness building the Router
/// directly, with no socket peer), a parseable `XFF` token is used as a
/// last-resort fallback so keying still distinguishes callers; otherwise all
/// such requests would share a single `ip:unknown` bucket. Only validated
/// `IpAddr` values ever key a bucket: a raw, unparseable (attacker-
/// controlled) `XFF` token is never used (GHSA-8jm4-4x6c-6787).
fn extract_client_ip(request: &Request, trusted_proxies: &[CidrRange]) -> String {
    if let Some(ip) = extract_client_ip_addr(request, trusted_proxies) {
        return format!("ip:{}", ip);
    }
    // GHSA-8jm4-4x6c-6787: no raw-string XFF fallback. With `ConnectInfo`
    // present this branch is unreachable (`resolve_client_ip_addr` always
    // yields at least the socket peer); without it, an unparseable XFF
    // collapses into the shared `ip:unknown` bucket instead of minting an
    // attacker-named bucket per request.
    "ip:unknown".to_string()
}

/// Extract the client IP as a parsed `IpAddr` for CIDR matching (#969) and
/// rate-limit keying (#2023).
///
/// `ConnectInfo` (the real TCP peer) is authoritative. `X-Forwarded-For` is
/// trusted to override the peer **only** when that peer is a configured
/// trusted reverse proxy; for any other (untrusted) peer the socket IP is
/// returned and `XFF` is ignored. When `ConnectInfo` is absent entirely, fall
/// back to a parseable `XFF` (direct-test / pre-ConnectInfo topology).
/// Returns `None` if the address cannot be resolved or does not parse.
fn extract_client_ip_addr(request: &Request, trusted_proxies: &[CidrRange]) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    resolve_client_ip_addr(request.headers(), peer, trusted_proxies)
}

/// Core client-IP resolution over bare request parts (#2365).
///
/// Same trusted-proxy contract as [`extract_client_ip_addr`], which delegates
/// here: the socket `peer` is authoritative; `X-Forwarded-For` overrides it
/// **only** when the peer falls inside a configured trusted-proxy CIDR
/// (#2023), and then the client is the rightmost token outside the trusted
/// ranges — never the attacker-controlled leftmost token
/// (GHSA-8jm4-4x6c-6787, see [`rightmost_untrusted_xff_token`]). With no peer
/// at all (test harness / pre-`ConnectInfo` topology), a parseable `XFF`
/// first token is a last-resort fallback. Returns `None` when nothing
/// resolves — callers must record "unknown", never a sentinel.
pub(crate) fn resolve_client_ip_addr(
    headers: &axum::http::HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &[CidrRange],
) -> Option<IpAddr> {
    if let Some(peer) = peer {
        // Believe XFF only when the immediate peer is a trusted proxy.
        if trusted_proxies.iter().any(|cidr| cidr.contains(peer)) {
            // GHSA-8jm4-4x6c-6787: select the rightmost non-trusted token,
            // NOT the leftmost. An appending trusted proxy preserves any
            // client-supplied XFF prefix, so the leftmost token is attacker-
            // controlled; the proxy's own append sits on the right. On any
            // parse/trust failure the walk yields None and the real TCP peer
            // remains the key.
            if let Some(ip) = rightmost_untrusted_xff_token(headers, trusted_proxies) {
                return Some(ip);
            }
        }
        // Untrusted peer (or trusted peer with no/unparseable/all-trusted
        // XFF): the real TCP peer is the key.
        return Some(peer);
    }

    // No ConnectInfo (test harness / pre-ConnectInfo topology): fall back to a
    // parseable XFF first token so keying still distinguishes callers.
    if let Some(first) = first_xff_token_in(headers) {
        if let Ok(ip) = first.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {

    // ---- GHSA-8jm4 follow-up: multi-line XFF + token normalization (#3372) ----

    fn xff_lines(lines: &[&str]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for l in lines {
            h.append(
                "x-forwarded-for",
                axum::http::HeaderValue::from_str(l).unwrap(),
            );
        }
        h
    }

    /// REVERT-PROOF for the core defect. A proxy that `Add`s its own field
    /// line (HAProxy `option forwardfor`, Go `net/http`, some Envoy configs)
    /// puts the ATTACKER's line first. Reading only `headers.get()` returns
    /// `9.9.9.9` and the walk never sees the trusted proxy's own append, so
    /// the attacker controls the rate-limit key — the advisory, unmitigated.
    #[test]
    fn xff_walks_every_field_line_not_just_the_first() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        // line 1 = attacker-supplied; line 2 = the trusted proxy's observation
        let headers = xff_lines(&["9.9.9.9", "203.0.113.9, 172.30.0.5"]);
        assert_eq!(
            rightmost_untrusted_xff_token(&headers, &trusted),
            Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            "must select the client observed by the trusted proxy, not the attacker's first line"
        );
    }

    /// The attacker cannot win by making their line the LAST one either: the
    /// walk starts at the right, and their token is not inside a trusted CIDR,
    /// so it is only selected if no trusted hop appended after it. Here the
    /// real proxy's line is last, so its observation wins.
    #[test]
    fn xff_attacker_line_does_not_win_when_proxy_appends_after() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        let headers = xff_lines(&["1.2.3.4, 9.9.9.9", "203.0.113.9, 172.30.0.5"]);
        assert_eq!(
            rightmost_untrusted_xff_token(&headers, &trusted),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

    /// Single merged line (Caddy, the shipped compose stack) is unchanged.
    #[test]
    fn xff_single_merged_line_still_selects_rightmost_untrusted() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        let headers = xff_lines(&["9.9.9.9, 203.0.113.9, 172.30.0.5"]);
        assert_eq!(
            rightmost_untrusted_xff_token(&headers, &trusted),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

    /// Azure Application Gateway appends `ip:port`. Pre-fix that token failed
    /// to parse, aborted the walk, and silently collapsed every client onto
    /// the shared TCP-peer bucket.
    #[test]
    fn xff_strips_port_suffix_from_ipv4_token() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        let headers = xff_lines(&["203.0.113.9:5678, 172.30.0.5"]);
        assert_eq!(
            rightmost_untrusted_xff_token(&headers, &trusted),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

    /// Bracketed IPv6, with and without a port.
    #[test]
    fn xff_strips_brackets_from_ipv6_token() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        for tok in ["[2001:db8::1]", "[2001:db8::1]:443"] {
            let headers = xff_lines(&[&format!("{tok}, 172.30.0.5")]);
            assert_eq!(
                rightmost_untrusted_xff_token(&headers, &trusted),
                Some("2001:db8::1".parse::<IpAddr>().unwrap()),
                "failed for {tok}"
            );
        }
    }

    /// A BARE IPv6 address has multiple colons and must never be truncated at
    /// one — the port-strip must not corrupt it.
    #[test]
    fn xff_bare_ipv6_is_not_truncated_by_port_strip() {
        assert_eq!(normalize_xff_token("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_xff_token(" 2001:db8::1 "), "2001:db8::1");
        // single-colon IPv6 is not representable, so this is unambiguously host:port
        assert_eq!(normalize_xff_token("1.2.3.4:5678"), "1.2.3.4");
        assert_eq!(normalize_xff_token("1.2.3.4"), "1.2.3.4");
    }

    /// Every token trusted → no client IP recoverable → caller uses the peer.
    #[test]
    fn xff_all_trusted_yields_none() {
        let trusted = vec![CidrRange::parse("172.30.0.0/24").unwrap()];
        let headers = xff_lines(&["172.30.0.9", "172.30.0.5"]);
        assert_eq!(rightmost_untrusted_xff_token(&headers, &trusted), None);
    }

    /// Empty trusted list must fail CLOSED (fall back to the TCP peer), never
    /// open onto attacker-controlled header text.
    #[test]
    fn xff_empty_trusted_list_selects_rightmost_and_caller_falls_back() {
        let headers = xff_lines(&["9.9.9.9, 203.0.113.9"]);
        // With nothing trusted, the rightmost token is returned; the CALLER
        // (resolve_client_ip_addr) only consults this when the peer is itself
        // trusted, which an empty list makes impossible.
        assert_eq!(
            rightmost_untrusted_xff_token(&headers, &[]),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

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

    /// No trusted-proxy CIDRs configured (the secure default): XFF is never
    /// believed when a real TCP peer is present.
    fn no_trusted_proxies() -> Vec<CidrRange> {
        Vec::new()
    }

    /// A trusted-proxy set covering the whole loopback range, mirroring the
    /// reverse-proxy deployment (`RATE_LIMIT_TRUSTED_PROXY_CIDRS=127.0.0.0/8`).
    fn loopback_trusted_proxies() -> Vec<CidrRange> {
        vec![CidrRange::parse("127.0.0.0/8").unwrap()]
    }

    /// Build a request with a `ConnectInfo` peer and an optional XFF header.
    fn req_with_peer(peer: &str, xff: Option<&str>) -> Request {
        use std::net::SocketAddr;
        let addr: SocketAddr = peer.parse().unwrap();
        let mut builder = axum::extract::Request::builder();
        if let Some(xff) = xff {
            builder = builder.header("X-Forwarded-For", xff);
        }
        let mut request = builder.body(axum::body::Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        request
    }

    #[test]
    fn test_extract_client_ip_honors_xff_from_trusted_proxy() {
        // Behind a configured reverse proxy (peer in trusted_proxies), the XFF
        // first token resolves the real client IP — legit reverse-proxy mode.
        let request = req_with_peer("127.0.0.1:443", Some("192.168.1.1"));
        assert_eq!(
            extract_client_ip(&request, &loopback_trusted_proxies()),
            "ip:192.168.1.1"
        );
    }

    #[test]
    fn test_extract_client_ip_uses_rightmost_untrusted_xff_from_trusted_proxy() {
        // GHSA-8jm4-4x6c-6787: when XFF contains multiple IPs and the peer is
        // a trusted APPENDING proxy (Caddy in the default compose deployment),
        // the client IP is the rightmost token outside the trusted ranges —
        // the address the proxy itself observed and appended — never the
        // leftmost token, which is a client-supplied (spoofable) prefix.
        let request = req_with_peer(
            "127.0.0.1:443",
            Some("203.0.113.50, 70.41.3.18, 150.172.238.178"),
        );
        assert_eq!(
            extract_client_ip(&request, &loopback_trusted_proxies()),
            "ip:150.172.238.178"
        );
    }

    #[test]
    fn test_ghsa_8jm4_attacker_xff_prefix_does_not_control_resolved_ip() {
        // GHSA-8jm4-4x6c-6787: an unauthenticated caller sends
        // `X-Forwarded-For: 10.9.9.9`; the trusted appending proxy (peer
        // 127.0.0.1) preserves the prefix and appends the real client IP.
        // Resolution must track the proxy-observed address, so the spoofed
        // prefix token never steers keying or IP attribution.
        let proxies = loopback_trusted_proxies();
        let request = req_with_peer("127.0.0.1:443", Some("10.9.9.9, 198.51.100.23"));
        assert_eq!(
            extract_client_ip(&request, &proxies),
            "ip:198.51.100.23",
            "the trusted proxy's own append (rightmost) must win, not the \
             client-supplied prefix (leftmost)"
        );
        // The parts-level core (#2365) follows the same contract.
        let ip = resolve_client_ip_addr(
            &xff_headers("10.9.9.9, 198.51.100.23"),
            Some("127.0.0.1".parse().unwrap()),
            &proxies,
        );
        assert_eq!(ip, Some("198.51.100.23".parse().unwrap()));
    }

    #[test]
    fn test_ghsa_8jm4_rotating_xff_prefix_behind_trusted_proxy_shares_bucket() {
        // GHSA-8jm4-4x6c-6787: rotating the spoofed prefix across requests
        // must NOT mint a fresh rate-limit bucket per request — every variant
        // resolves to the same proxy-appended client IP.
        let proxies = loopback_trusted_proxies();
        let keys: Vec<String> = (1..=5)
            .map(|i| {
                let xff = format!("10.0.0.{i}, 198.51.100.23");
                extract_client_ip(&req_with_peer("127.0.0.1:443", Some(&xff)), &proxies)
            })
            .collect();
        assert!(
            keys.iter().all(|k| k == "ip:198.51.100.23"),
            "all spoofed-prefix variants must collapse to one bucket, got {keys:?}"
        );
    }

    #[test]
    fn test_ghsa_8jm4_cannot_spoof_trusted_cidr_exemption_via_xff_prefix() {
        // GHSA-8jm4-4x6c-6787: a `RATE_LIMIT_TRUSTED_CIDRS` exemption (#969)
        // must not be claimable by prefixing XFF with an exempt address. The
        // resolved IP is the proxy's append (198.51.100.23), which is NOT in
        // the exemption range, so the request is not exempt.
        let proxies = loopback_trusted_proxies();
        let exemptions = RateLimitExemptions::with_cidrs(
            Vec::new(),
            false,
            vec![CidrRange::parse("10.0.0.0/8").unwrap()],
        );
        let request = req_with_peer("127.0.0.1:443", Some("10.0.0.5, 198.51.100.23"));
        let ip = extract_client_ip_addr(&request, &proxies).unwrap();
        assert_eq!(ip, "198.51.100.23".parse::<IpAddr>().unwrap());
        assert!(
            !exemptions.is_trusted_cidr(ip),
            "a spoofed prefix token inside the exemption range must never be \
             the resolved IP"
        );
        // Sanity: a caller whose REAL peer is inside the range still exempts.
        let real = req_with_peer("10.0.0.5:1234", None);
        let real_ip = extract_client_ip_addr(&real, &proxies).unwrap();
        assert!(exemptions.is_trusted_cidr(real_ip));
    }

    #[test]
    fn test_ghsa_8jm4_multi_hop_chain_walks_past_trusted_proxies() {
        // GHSA-8jm4-4x6c-6787: two trusted hops — client -> front proxy
        // (203.0.113.1) -> Caddy (127.0.0.1) -> backend. XFF arrives as
        // "spoofed-prefix, real-client, front-proxy"; the right-to-left walk
        // skips the trusted front-proxy append and lands on the real client,
        // not the attacker prefix.
        let proxies = vec![
            CidrRange::parse("127.0.0.0/8").unwrap(),
            CidrRange::parse("203.0.113.1/32").unwrap(),
        ];
        let request = req_with_peer(
            "127.0.0.1:443",
            Some("10.9.9.9, 198.51.100.23, 203.0.113.1"),
        );
        assert_eq!(extract_client_ip(&request, &proxies), "ip:198.51.100.23");
    }

    #[test]
    fn test_ghsa_8jm4_unparseable_xff_token_falls_back_to_peer() {
        // GHSA-8jm4-4x6c-6787: a non-empty token that does not parse as an
        // IpAddr aborts the right-to-left walk — resolution must NOT continue
        // left into attacker-controlled prefix text, and the raw token must
        // never become a bucket key. The real TCP peer remains the key.
        let request = req_with_peer("127.0.0.1:443", Some("10.0.0.5, bogus-token"));
        assert_eq!(
            extract_client_ip(&request, &loopback_trusted_proxies()),
            "ip:127.0.0.1"
        );
    }

    #[test]
    fn test_extract_client_ip_ignores_xff_from_untrusted_peer() {
        // Default policy (no trusted proxies): XFF from an untrusted peer is
        // ignored; keying tracks the real TCP peer (#2023).
        let request = req_with_peer("198.51.100.9:5555", Some("192.168.1.1"));
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:198.51.100.9"
        );
    }

    #[test]
    fn test_extract_client_ip_rotating_xff_from_untrusted_keys_per_socket() {
        // A single untrusted peer rotating XFF across requests must NOT split
        // into separate buckets — both resolve to the same socket IP, so the
        // attacker cannot multiply their rate-limit budget (#2023).
        let req1 = req_with_peer("198.51.100.9:1111", Some("10.0.0.1"));
        let req2 = req_with_peer("198.51.100.9:2222", Some("10.0.0.2"));
        let proxies = no_trusted_proxies();
        assert_eq!(
            extract_client_ip(&req1, &proxies),
            extract_client_ip(&req2, &proxies)
        );
        assert_eq!(extract_client_ip(&req1, &proxies), "ip:198.51.100.9");
    }

    #[test]
    fn test_extract_client_ip_trusted_peer_empty_xff_falls_back_to_peer() {
        // Trusted proxy but no XFF present: fall back to the proxy's socket IP
        // rather than collapsing to `ip:unknown`.
        let request = req_with_peer("127.0.0.1:443", None);
        assert_eq!(
            extract_client_ip(&request, &loopback_trusted_proxies()),
            "ip:127.0.0.1"
        );
    }

    #[test]
    fn test_extract_client_ip_uses_x_forwarded_for_when_no_connect_info() {
        // Direct-test / pre-ConnectInfo topology: with NO ConnectInfo at all,
        // XFF is the last-resort key so callers are still distinguished.
        let request = axum::extract::Request::builder()
            .header("X-Forwarded-For", "192.168.1.1")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:192.168.1.1"
        );
    }

    #[test]
    fn test_extract_client_ip_ignores_x_real_ip() {
        let request = axum::extract::Request::builder()
            .header("X-Real-IP", "10.20.30.40")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:unknown"
        );
    }

    #[test]
    fn test_extract_client_ip_no_headers_returns_unknown() {
        let request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:unknown"
        );
    }

    #[test]
    fn test_extract_client_ip_uses_connect_info() {
        let request = req_with_peer("192.168.1.100:12345", None);
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:192.168.1.100"
        );
    }

    #[test]
    fn test_extract_client_ip_connect_info_over_headers() {
        // Untrusted peer: ConnectInfo wins over spoofable headers.
        let request = req_with_peer("10.0.0.5:9999", Some("1.2.3.4"));
        assert_eq!(
            extract_client_ip(&request, &no_trusted_proxies()),
            "ip:10.0.0.5"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_client_ip_addr (parts-level core; #2365)
    // -----------------------------------------------------------------------

    fn xff_headers(xff: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", xff.parse().unwrap());
        headers
    }

    #[test]
    fn test_resolve_client_ip_addr_trusted_peer_uses_xff() {
        let ip = resolve_client_ip_addr(
            &xff_headers("203.0.113.7"),
            Some("127.0.0.1".parse().unwrap()),
            &loopback_trusted_proxies(),
        );
        assert_eq!(ip, Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_addr_untrusted_peer_ignores_xff() {
        // Spoofed XFF from an untrusted peer must not steer attribution
        // (#2023): the socket peer wins.
        let ip = resolve_client_ip_addr(
            &xff_headers("203.0.113.7"),
            Some("198.51.100.9".parse().unwrap()),
            &no_trusted_proxies(),
        );
        assert_eq!(ip, Some("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_addr_trusted_peer_unparseable_xff_falls_back_to_peer() {
        let ip = resolve_client_ip_addr(
            &xff_headers("not-an-ip"),
            Some("127.0.0.1".parse().unwrap()),
            &loopback_trusted_proxies(),
        );
        assert_eq!(ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_addr_no_peer_falls_back_to_parseable_xff() {
        let ip = resolve_client_ip_addr(&xff_headers("192.0.2.4"), None, &no_trusted_proxies());
        assert_eq!(ip, Some("192.0.2.4".parse().unwrap()));
    }

    #[test]
    fn test_resolve_client_ip_addr_nothing_resolvable_is_none() {
        // No peer + no (parseable) XFF: None, never a `0.0.0.0` sentinel.
        let empty = axum::http::HeaderMap::new();
        assert_eq!(
            resolve_client_ip_addr(&empty, None, &no_trusted_proxies()),
            None
        );
        assert_eq!(
            resolve_client_ip_addr(&xff_headers("bogus"), None, &no_trusted_proxies()),
            None
        );
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
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
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
        let proxies = no_trusted_proxies();
        assert_eq!(
            extract_client_ip(&req1, &proxies),
            extract_client_ip(&req2, &proxies)
        );
        assert_eq!(extract_client_ip(&req1, &proxies), "ip:203.0.113.42");
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
            trusted_proxies: Arc::new(Vec::new()),
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
        let proxies = no_trusted_proxies();
        assert_ne!(
            extract_client_ip(&req1, &proxies),
            extract_client_ip(&req2, &proxies)
        );
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
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
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

    // ── Login per-(username, IP) limiter (login-ratelimit-global-dos) ─────────

    #[test]
    fn test_login_rate_limit_key_partitions_by_user_and_ip() {
        // The key must combine username and IP: same user different IP, and
        // same IP different user, must all be distinct buckets.
        let a = login_rate_limit_key("alice", "ip:10.0.0.1");
        let b = login_rate_limit_key("bob", "ip:10.0.0.1"); // same IP, diff user
        let c = login_rate_limit_key("alice", "ip:10.0.0.2"); // same user, diff IP
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        // Stable for the same (user, ip).
        assert_eq!(a, login_rate_limit_key("alice", "ip:10.0.0.1"));
    }

    #[test]
    fn test_login_rate_limit_key_is_case_sensitive() {
        // Login is case-sensitive at the auth layer, so the key must be too.
        assert_ne!(
            login_rate_limit_key("Admin", "ip:10.0.0.1"),
            login_rate_limit_key("admin", "ip:10.0.0.1")
        );
    }

    /// Build a login middleware app with the given per-key and backstop caps.
    fn login_app(per_key: u32, backstop: u32) -> axum::Router {
        use axum::routing::post;
        let state = LoginRateLimitState {
            inner: RateLimitState {
                limiter: Arc::new(RateLimiter::new(per_key, 60)),
                exemptions: Arc::new(RateLimitExemptions::new(Vec::new(), false)),
                enabled: true,
                trusted_proxies: Arc::new(Vec::new()),
            },
            backstop: Arc::new(RateLimiter::new(backstop, 60)),
        };
        axum::Router::new()
            .route("/login", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                login_rate_limit_middleware,
            ))
    }

    /// Drive one login request for `username` from source IP `xff`.
    async fn login_once(app: &axum::Router, username: &str, xff: &str) -> StatusCode {
        use tower::ServiceExt;
        let body = format!(r#"{{"username":"{username}","password":"x"}}"#);
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("X-Forwarded-For", xff)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn test_login_flood_on_one_identity_does_not_lock_out_others() {
        // The finding's exact claim: a flood on (user=x, ip=A) 429s, while
        // (user=y, ip=B) and (user=y, ip=A) stay non-429.
        let app = login_app(3, 10_000);

        // Exhaust (x, A): first 3 OK, then 429.
        assert_eq!(login_once(&app, "x", "10.0.0.1").await, StatusCode::OK);
        assert_eq!(login_once(&app, "x", "10.0.0.1").await, StatusCode::OK);
        assert_eq!(login_once(&app, "x", "10.0.0.1").await, StatusCode::OK);
        assert_eq!(
            login_once(&app, "x", "10.0.0.1").await,
            StatusCode::TOO_MANY_REQUESTS,
            "(x, A) must exhaust its own bucket"
        );

        // (y, B) and (y, A) must be unaffected by the (x, A) flood.
        assert_eq!(
            login_once(&app, "y", "10.0.0.2").await,
            StatusCode::OK,
            "different user on a different IP must have an independent bucket"
        );
        assert_eq!(
            login_once(&app, "y", "10.0.0.1").await,
            StatusCode::OK,
            "different user on the SAME IP must have an independent bucket"
        );
        // The same victim user x from another IP is also fine.
        assert_eq!(
            login_once(&app, "x", "10.0.0.9").await,
            StatusCode::OK,
            "the same user from another IP must have an independent bucket"
        );
    }

    #[tokio::test]
    async fn test_login_global_backstop_sheds_with_retry_after() {
        // Backstop capacity 2, huge per-key cap: distinct (user, ip) keys never
        // hit their own bucket but the global backstop trips after 2 attempts.
        let app = login_app(10_000, 2);
        assert_eq!(login_once(&app, "u1", "10.0.0.1").await, StatusCode::OK);
        assert_eq!(login_once(&app, "u2", "10.0.0.2").await, StatusCode::OK);

        use tower::ServiceExt;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("X-Forwarded-For", "10.0.0.3")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"u3","password":"x"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key("Retry-After"),
            "backstop 429 must carry Retry-After"
        );
    }

    #[tokio::test]
    async fn test_login_middleware_preserves_body_for_handler() {
        // A valid login through the middleware must reach the handler with its
        // body intact (the handler here echoes the parsed username back).
        use axum::routing::post;
        use tower::ServiceExt;
        let state = LoginRateLimitState {
            inner: RateLimitState {
                limiter: Arc::new(RateLimiter::new(100, 60)),
                exemptions: Arc::new(RateLimitExemptions::new(Vec::new(), false)),
                enabled: true,
                trusted_proxies: Arc::new(Vec::new()),
            },
            backstop: Arc::new(RateLimiter::new(10_000, 60)),
        };
        let app = axum::Router::new()
            .route(
                "/login",
                post(|body: axum::body::Bytes| async move {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    v.get("username").unwrap().as_str().unwrap().to_string()
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                login_rate_limit_middleware,
            ));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("X-Forwarded-For", "10.0.0.1")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"username":"carol","password":"secret"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            &bytes[..],
            b"carol",
            "handler must receive the original body"
        );
    }

    #[tokio::test]
    async fn test_login_middleware_master_switch_bypasses() {
        // With the master switch off (#1602), the login middleware must never
        // 429 even past the per-key capacity.
        use axum::routing::post;
        let state = LoginRateLimitState {
            inner: RateLimitState {
                limiter: Arc::new(RateLimiter::new(1, 60)),
                exemptions: Arc::new(RateLimitExemptions::new(Vec::new(), false)),
                enabled: false,
                trusted_proxies: Arc::new(Vec::new()),
            },
            backstop: Arc::new(RateLimiter::new(1, 60)),
        };
        let app = axum::Router::new()
            .route("/login", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                login_rate_limit_middleware,
            ));
        for _ in 0..5 {
            assert_eq!(login_once(&app, "x", "10.0.0.1").await, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_login_middleware_username_exemption_bypasses() {
        // A username on the exemption list bypasses the login limiter even
        // when an AuthExtension was populated upstream.
        use axum::routing::post;
        let state = LoginRateLimitState {
            inner: RateLimitState {
                limiter: Arc::new(RateLimiter::new(1, 60)),
                exemptions: Arc::new(RateLimitExemptions::new(vec!["ci-bot".into()], false)),
                enabled: true,
                trusted_proxies: Arc::new(Vec::new()),
            },
            backstop: Arc::new(RateLimiter::new(10_000, 60)),
        };
        let app = axum::Router::new()
            .route("/login", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                login_rate_limit_middleware,
            ))
            // Outer: inject an exempt principal (models optional auth resolving).
            .layer(axum::middleware::from_fn(
                |mut request: Request, next: Next| async move {
                    request.extensions_mut().insert(AuthExtension {
                        user_id: uuid::Uuid::new_v4(),
                        username: "ci-bot".to_string(),
                        email: "ci-bot@test".to_string(),
                        is_admin: false,
                        is_api_token: false,
                        is_service_account: false,
                        scopes: None,
                        allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
                        iat_ms: None,
                    });
                    next.run(request).await
                },
            ));
        for _ in 0..5 {
            assert_eq!(login_once(&app, "ci-bot", "10.0.0.1").await, StatusCode::OK);
        }
    }

    // ── ConnectInfo per-source-IP keying (global-ratelimit-keying) ────────────
    //
    // The general (api, 10000/window) and download (presign, 30/window) limiters
    // key unauthenticated callers by `extract_client_ip`, whose PRIMARY source is
    // the TCP peer in `ConnectInfo<SocketAddr>`. That extension is only populated
    // because the server is served with `into_make_service_with_connect_info`
    // (main.rs). Without a real peer key these limiters collapse to one shared
    // `ip:unknown` bucket and a single client's flood 429s the whole instance.
    //
    // The tests below drive requests carrying a real `ConnectInfo` (not an XFF
    // header) so they exercise the same key path the wired server uses, and pin
    // that a flood from source IP A does NOT 429 a request from source IP B —
    // for BOTH `rate_limit_middleware` (general) and `rate_limit_by_ip_middleware`
    // (download). A regression that drops the ConnectInfo wiring (or re-collapses
    // the bucket) makes B share A's bucket and these tests fail.

    /// Build a request whose `ConnectInfo<SocketAddr>` peer is `peer` (no XFF
    /// header), modelling a direct-to-backend connection from that source IP.
    fn req_from_peer(peer: &str) -> Request {
        let addr: std::net::SocketAddr = peer.parse().unwrap();
        let mut request = Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        request
    }

    /// Drive `n` requests from ConnectInfo peer `peer` through `app` and return
    /// how many returned 429.
    async fn count_429s_from_peer(app: &axum::Router, peer: &str, n: usize) -> usize {
        use tower::ServiceExt;
        let mut limited = 0;
        for _ in 0..n {
            let resp = app.clone().oneshot(req_from_peer(peer)).await.unwrap();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                limited += 1;
            }
        }
        limited
    }

    #[tokio::test]
    async fn general_limiter_flood_from_one_peer_does_not_429_another_peer() {
        // The general limiter (rate_limit_middleware) on an anonymous request
        // keys by the ConnectInfo peer. A flood from peer A must exhaust only
        // A's bucket; peer B must still be served.
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(true), // capacity-1 limiter, enabled, no exemptions
                rate_limit_middleware,
            ));

        // Flood from peer A until it 429s (capacity-1 => 1 OK then 429s).
        assert!(
            count_429s_from_peer(&app, "203.0.113.10:5000", 5).await > 0,
            "peer A's flood must exhaust A's own bucket"
        );
        // Peer B, distinct source IP, must NOT be rate-limited by A's flood —
        // proof the limiter keys per source IP, not one shared bucket.
        let resp_b = {
            use tower::ServiceExt;
            app.clone()
                .oneshot(req_from_peer("198.51.100.20:6000"))
                .await
                .unwrap()
        };
        assert_eq!(
            resp_b.status(),
            StatusCode::OK,
            "a flood from peer A must not 429 a fresh request from peer B; \
             sharing a bucket means ConnectInfo keying is broken (the whole-\
             instance DoS this fix addresses)"
        );
    }

    #[tokio::test]
    async fn download_limiter_flood_from_one_peer_does_not_429_another_peer() {
        // The download/presign limiter (rate_limit_by_ip_middleware) ALWAYS keys
        // by the ConnectInfo peer. Same property: A's flood must not 429 B.
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state_with(true),
                rate_limit_by_ip_middleware,
            ));

        assert!(
            count_429s_from_peer(&app, "203.0.113.30:7000", 5).await > 0,
            "peer A's download flood must exhaust A's own bucket"
        );
        let resp_b = {
            use tower::ServiceExt;
            app.clone()
                .oneshot(req_from_peer("198.51.100.40:8000"))
                .await
                .unwrap()
        };
        assert_eq!(
            resp_b.status(),
            StatusCode::OK,
            "a download flood from peer A must not 429 a download from peer B"
        );
    }
}
