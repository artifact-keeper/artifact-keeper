//! Destination checks for requests the SSRF-guarded clients send through an
//! environment proxy (#5459, #5109).
//!
//! A request routed through a proxy is never resolved here: `reqwest` hands
//! the destination host name to the proxy (an absolute-form request line for
//! `http://`, `CONNECT host:port` for `https://`), so the connect-time SSRF
//! resolver (`ssrf_dns`) only ever sees the proxy's own name. Left to
//! `reqwest`'s automatic environment proxy, a guarded client applied no
//! destination check at all to a host name it proxied.
//!
//! The guarded clients therefore replace that automatic proxy with an
//! [`EnvProxyGuard`]:
//!
//! - **Routing** ([`EnvProxyGuard::reqwest_proxy`]) reads the same variables
//!   through the same matcher `reqwest` uses (`HTTP_PROXY`/`http_proxy`,
//!   `HTTPS_PROXY`/`https_proxy`, `ALL_PROXY`/`all_proxy`, `NO_PROXY`/
//!   `no_proxy`; upper case first, even when empty), so what goes through the
//!   proxy is unchanged.
//! - **Every new connection** to a destination the proxy would carry is
//!   checked first by a connector layer ([`EnvProxyGuard::layer`]): the host
//!   is resolved asynchronously, with [`LOOKUP_TIMEOUT`], and refused when it
//!   does not resolve or any address is outside the trust class's policy.
//!   A refused destination never reaches the proxy.
//! - **Every plain-HTTP upstream request** is checked again on the upstream
//!   send path ([`check_upstream_request`]): a forward-proxied `http://`
//!   connection is pooled per destination and reused, and a reused
//!   connection never passes the connector layer.
//! - **Redirect hops** the proxy would carry are checked by the redirect
//!   policy with the same fail-closed rule.
//!
//! The proxy still resolves the name itself. An answer that changes between
//! AK's lookup and the proxy's is for the proxy's own destination policy to
//! refuse; `AK_UPSTREAM_ENV_PROXY=ignore` keeps the upstream clients off the
//! environment proxy altogether.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::client::proxy::matcher::{Intercept, Matcher};

use crate::api::validation::{self, BlockReason, HostVerdict, OutboundUrlContext};

/// Longest a proxied destination's lookup may take before it is refused.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Environment variable selecting [`UpstreamEnvProxyMode`].
pub const UPSTREAM_ENV_PROXY_VAR: &str = "AK_UPSTREAM_ENV_PROXY";

/// Whether the upstream clients (`http_client::base_client_builder` and
/// everything built on it) use the environment proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamEnvProxyMode {
    /// Use it, checking each destination first (the default).
    Check,
    /// Never use it: connect directly, under the connect-time SSRF resolver.
    Ignore,
}

/// Read [`UPSTREAM_ENV_PROXY_VAR`]: `check` (or unset) or `ignore`, either
/// case. Any other value is reported once and read as `check`, which keeps
/// the destination checks and the deployment's routing.
pub fn upstream_env_proxy_mode() -> UpstreamEnvProxyMode {
    let raw = std::env::var(UPSTREAM_ENV_PROXY_VAR).unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "check" => UpstreamEnvProxyMode::Check,
        "ignore" => UpstreamEnvProxyMode::Ignore,
        _ => {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    value = %raw,
                    "{UPSTREAM_ENV_PROXY_VAR} must be `check` or `ignore`; using `check`"
                );
            });
            UpstreamEnvProxyMode::Check
        }
    }
}

/// Resolve a host name to its addresses. Injectable so tests can pin
/// answers; production uses [`system_lookup`].
pub(crate) type Lookup = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>
        + Send
        + Sync,
>;

/// Most proxied-destination lookups in flight at once. A lookup runs on the
/// blocking pool and keeps its thread until the system resolver gives up,
/// even after [`LOOKUP_TIMEOUT`] drops the future, so the count is bounded.
const MAX_CONCURRENT_LOOKUPS: usize = 32;

/// The system resolver, bounded by [`LOOKUP_TIMEOUT`] (waiting for a lookup
/// slot included) and [`MAX_CONCURRENT_LOOKUPS`]. A timeout is an error,
/// which the check reads as a refusal.
fn system_lookup() -> Lookup {
    static SLOTS: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(MAX_CONCURRENT_LOOKUPS);
    Arc::new(|host: String| {
        Box::pin(async move {
            let lookup = async {
                let _slot = SLOTS.acquire().await.map_err(std::io::Error::other)?;
                let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
                Ok::<_, std::io::Error>(addrs.map(|a| a.ip()).collect())
            };
            tokio::time::timeout(LOOKUP_TIMEOUT, lookup)
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "lookup timed out")
                })?
        })
    })
}

/// The first of `names` that is set, as `hyper-util` reads the proxy
/// variables: an upper-case variable that is set, even to the empty string,
/// hides the lower-case one.
fn first_env(names: [&str; 2]) -> String {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .unwrap_or_default()
}

/// The environment proxy of one guarded client and the destination check it
/// applies (see the module docs).
#[derive(Clone)]
pub(crate) struct EnvProxyGuard {
    matcher: Arc<Matcher>,
    ctx: OutboundUrlContext,
    lookup: Lookup,
    /// Whether a proxy variable is set at all (read from the variables, not
    /// from the matcher, so no `NO_PROXY` entry can turn it off); when not,
    /// the connector layer has nothing to check.
    configured: bool,
    /// Whether a variable that covers `http://` is set.
    plain_http: bool,
}

impl EnvProxyGuard {
    /// The environment proxy as `reqwest` would read it now, for the trust
    /// class `ctx`.
    pub(crate) fn from_env(ctx: OutboundUrlContext) -> Self {
        Self::with_lookup(ctx, system_lookup())
    }

    /// [`Self::from_env`] with `lookup` in place of the system resolver.
    pub(crate) fn with_lookup(ctx: OutboundUrlContext, lookup: Lookup) -> Self {
        // The matcher ignores every variable in a CGI process.
        let cgi = std::env::var_os("REQUEST_METHOD").is_some();
        let set = |names| !cgi && !first_env(names).trim().is_empty();
        let all = set(["ALL_PROXY", "all_proxy"]);
        let plain_http = all || set(["HTTP_PROXY", "http_proxy"]);
        Self {
            matcher: Arc::new(Matcher::from_system()),
            ctx,
            lookup,
            configured: plain_http || set(["HTTPS_PROXY", "https_proxy"]),
            plain_http,
        }
    }

    /// Whether the environment proxy would carry a request for `url`.
    ///
    /// Always asks the matcher, which is cheap: a probe destination could be
    /// named by a `NO_PROXY` suffix (`.invalid`) and would then report no
    /// proxy while real hosts are still proxied.
    pub(crate) fn proxies(&self, url: &reqwest::Url) -> bool {
        url.as_str()
            .parse::<http::Uri>()
            .is_ok_and(|uri| self.matcher.intercept(&uri).is_some())
    }

    /// Whether plain-HTTP destinations may go through the environment proxy
    /// (forward-proxied, so a pooled connection is reused per destination):
    /// a variable covering `http://` is set.
    pub(crate) fn proxies_plain_http(&self) -> bool {
        self.plain_http
    }

    /// The routing half: a `reqwest` proxy that sends a request where the
    /// environment proxy would, credentials included. It does no checking;
    /// [`Self::layer`] and [`check_upstream_request`] do.
    pub(crate) fn reqwest_proxy(&self) -> reqwest::Proxy {
        let matcher = Arc::clone(&self.matcher);
        reqwest::Proxy::custom(move |url| {
            let dst: http::Uri = url.as_str().parse().ok()?;
            matcher.intercept(&dst).map(|i| intercept_proxy_url(&i))
        })
    }

    /// The connector layer that checks each new connection's destination.
    pub(crate) fn layer(&self) -> ProxiedDestinationLayer {
        ProxiedDestinationLayer {
            guard: self.clone(),
        }
    }

    /// Check `host` (a name or IP literal, possibly bracketed) as a
    /// destination about to be handed to the proxy: refused when the policy
    /// refuses the name or any address, or when it does not resolve.
    pub(crate) async fn check(&self, host: &str) -> Result<(), BlockReason> {
        let name = match validation::host_verdict(host, self.ctx) {
            HostVerdict::Blocked(reason) => return Err(reason),
            HostVerdict::Allowed => return Ok(()),
            HostVerdict::Resolve(name) => name,
        };
        match (self.lookup)(name).await {
            Ok(ips) if !ips.is_empty() => match validation::first_blocked_ip(ips, self.ctx) {
                Some(reason) => Err(reason),
                None => Ok(()),
            },
            _ => Err(BlockReason::Unresolved(host.to_string())),
        }
    }

    /// Log and count one refused proxied destination.
    fn record_refusal(&self, destination: &str, reason: &BlockReason) {
        tracing::warn!(
            target: "security",
            destination = %destination,
            reason = reason.metric_label(),
            surface = self.ctx.ssrf_surface(),
            "refusing to send a disallowed destination through the environment proxy"
        );
        crate::services::metrics_service::record_outbound_url_blocked(
            reason.metric_label(),
            "environment proxy destination",
        );
        crate::services::metrics_service::record_ssrf_block(self.ctx.ssrf_surface());
    }

    /// Check `url` as a destination the proxy would carry, recording a
    /// refusal. `Ok` when the proxy would not carry it.
    async fn check_url(&self, url: &reqwest::Url) -> Result<(), BlockReason> {
        if !self.proxies(url) {
            return Ok(());
        }
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        let result = self.check(host).await;
        if let Err(reason) = &result {
            self.record_refusal(&redacted_origin(url), reason);
        }
        result
    }

    /// The trust class this guard checks against.
    pub(crate) fn ctx(&self) -> OutboundUrlContext {
        self.ctx
    }
}

/// `scheme://host:port` of `url`, without userinfo, path or query.
fn redacted_origin(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}

/// The error a refused proxied destination fails with, worded so
/// [`crate::services::ssrf_refusal::is_ssrf_refusal_error`] recognizes it.
fn refusal_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "proxied destination {}",
            crate::services::ssrf_refusal::CONNECT_REFUSAL_PHRASE
        ),
    )
}

/// The destination of a `reqwest` connector request, read from its `Debug`
/// form (`Unnameable(http://host:port/)`): the type is deliberately
/// unnameable and exposes nothing else. `None` when the form changes, which
/// the layer treats as a refusal so a `reqwest` upgrade cannot silently
/// switch the check off (the routing tests then fail).
pub(crate) fn destination_from_connector_request(debug: &str) -> Option<http::Uri> {
    let inner = debug.strip_prefix("Unnameable(")?.strip_suffix(')')?;
    let uri: http::Uri = inner.parse().ok()?;
    uri.host()?;
    Some(uri)
}

/// See [`EnvProxyGuard::layer`].
#[derive(Clone)]
pub(crate) struct ProxiedDestinationLayer {
    guard: EnvProxyGuard,
}

impl<S> tower::Layer<S> for ProxiedDestinationLayer {
    type Service = ProxiedDestinationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxiedDestinationService {
            inner,
            guard: self.guard.clone(),
        }
    }
}

/// See [`EnvProxyGuard::layer`].
#[derive(Clone)]
pub(crate) struct ProxiedDestinationService<S> {
    inner: S,
    guard: EnvProxyGuard,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<S, Req> tower::Service<Req> for ProxiedDestinationService<S>
where
    S: tower::Service<Req, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    Req: std::fmt::Debug + Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        // The readied service handles this call; a fresh clone takes its
        // place (tower's clone-and-swap).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let guard = self.guard.clone();
        let dst = guard
            .configured
            .then(|| destination_from_connector_request(&format!("{req:?}")));
        Box::pin(async move {
            match dst {
                None => {}
                Some(None) => {
                    let reason = BlockReason::Unresolved("<unreadable destination>".into());
                    guard.record_refusal("<unreadable destination>", &reason);
                    return Err(Box::new(refusal_error()) as BoxError);
                }
                Some(Some(dst)) => {
                    let checked = match reqwest::Url::parse(&dst.to_string()) {
                        Ok(url) => guard.check_url(&url).await,
                        Err(_) => {
                            let reason = BlockReason::Unresolved(dst.to_string());
                            guard.record_refusal("<unparseable destination>", &reason);
                            Err(reason)
                        }
                    };
                    if checked.is_err() {
                        return Err(Box::new(refusal_error()) as BoxError);
                    }
                }
            }
            inner.call(req).await
        })
    }
}

/// Test override of the guard [`check_upstream_request`] uses, so a test
/// need not keep the proxy variables set while it sends.
#[cfg(test)]
pub(crate) static TEST_UPSTREAM_GUARD: std::sync::Mutex<Option<EnvProxyGuard>> =
    std::sync::Mutex::new(None);

/// The installed [`TEST_UPSTREAM_GUARD`], if any.
#[cfg(test)]
fn test_upstream_guard() -> Option<EnvProxyGuard> {
    TEST_UPSTREAM_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// No override outside tests.
#[cfg(not(test))]
fn test_upstream_guard() -> Option<EnvProxyGuard> {
    None
}

/// The per-request half for the upstream send path
/// (`upstream_tracing::send_upstream_audited`): a plain-HTTP destination the
/// environment proxy would carry is checked before every request, because a
/// reused forward-proxy connection skips the connector layer. HTTPS needs no
/// per-request check: a reused `CONNECT` tunnel stays at the address the
/// proxy reached when the tunnel, checked by the layer, was opened.
///
/// Only for a request sent by a client that uses the environment proxy (the
/// shared upstream client); a per-repository `direct`/`explicit` client is
/// not routed by it and is skipped by the caller.
pub(crate) async fn check_upstream_request(url: &reqwest::Url) -> reqwest::Result<()> {
    let overridden = test_upstream_guard();
    if url.scheme() != "http"
        || (overridden.is_none() && upstream_env_proxy_mode() == UpstreamEnvProxyMode::Ignore)
    {
        return Ok(());
    }
    let guard = overridden.unwrap_or_else(|| EnvProxyGuard::from_env(OutboundUrlContext::Upstream));
    match guard.check_url(url).await {
        Ok(()) => Ok(()),
        Err(_) => Err(refusal_reqwest_error().await),
    }
}

/// A `reqwest::Error` carrying the connect-time SSRF refusal, for a request
/// refused before it was sent. `reqwest` offers no constructor, so this
/// issues a request to the refused-destination host, which the SSRF resolver
/// refuses before any lookup: nothing leaves the process.
async fn refusal_reqwest_error() -> reqwest::Error {
    static CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
        crate::services::http_client::plain_client_builder()
            .no_proxy()
            .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver_exempting(
                Default::default(),
            ))
            .build()
            .expect("build the SSRF refusal client")
    });
    let url = format!(
        "http://{}/",
        crate::services::ssrf_dns::REFUSED_DESTINATION_PROXY_HOST
    );
    match CLIENT.get(url).send().await {
        Err(err) => err,
        Ok(_) => unreachable!("the SSRF resolver refuses the refused-destination host"),
    }
}

/// The environment proxy `intercept` names, as a URL `reqwest` accepts,
/// credentials included. The matcher keeps an `http(s)` proxy's credentials
/// only as a `Proxy-Authorization` value, so they are decoded back into the
/// URL's userinfo, which `reqwest` turns into the same header.
pub(crate) fn intercept_proxy_url(intercept: &Intercept) -> reqwest::Url {
    let mut url = match reqwest::Url::parse(&intercept.uri().to_string()) {
        Ok(url) => url,
        // Unreachable for a URI the matcher built; a proxy named this way
        // cannot connect, so the request fails rather than going direct.
        Err(_) => reqwest::Url::parse(&format!(
            "http://{}/",
            crate::services::ssrf_dns::REFUSED_DESTINATION_PROXY_HOST
        ))
        .expect("valid URL"),
    };
    let credentials = intercept
        .raw_auth()
        .map(|(user, pass)| (user.to_string(), pass.to_string()))
        .or_else(|| intercept.basic_auth().and_then(decode_basic_auth));
    if let Some((user, pass)) = credentials {
        // Only fails for a URL that cannot carry userinfo, which an
        // `http(s)`/`socks` proxy URL always can.
        let _ = url.set_username(&user);
        let _ = url.set_password((!pass.is_empty()).then_some(pass.as_str()));
    }
    url
}

/// `user` and `password` from a `Basic` `Proxy-Authorization` value.
pub(crate) fn decode_basic_auth(value: &reqwest::header::HeaderValue) -> Option<(String, String)> {
    use base64::Engine as _;
    let encoded = value.to_str().ok()?.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}
