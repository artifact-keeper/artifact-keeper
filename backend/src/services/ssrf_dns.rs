//! SSRF-validating DNS resolver: rejects hostnames that resolve to blocked
//! (loopback / link-local / private / cloud-metadata) IPs at connect time,
//! closing the DNS-rebinding gap that URL-string validation cannot catch.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Which trust class the resolver enforces. Selects whether private /
/// CGNAT / IPv6 unique-local addresses are dropped (the default,
/// attacker-influenceable upstream/proxy targets), permitted (trusted
/// operator-configured internal services, issue #2389), or gated on the
/// per-surface allow toggle (webhook delivery / SSO discovery, issue
/// #2380). The cloud-metadata / loopback / link-local hard-blocks apply
/// to every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverMode {
    /// Fail-closed: block every private/internal address (upstream/proxy).
    Upstream,
    /// Trusted operator-configured internal service: permit private/CGNAT/ULA
    /// but keep metadata/loopback/link-local blocked.
    TrustedInternal,
    /// Webhook delivery target: private/CGNAT/ULA permitted only when
    /// `WEBHOOK_ALLOW_PRIVATE_IPS` (or the shared
    /// `AK_SSRF_ALLOW_PRIVATE_CIDRS` allowlist) opts the address in;
    /// otherwise identical to [`ResolverMode::Upstream`].
    Webhook,
    /// SSO/OIDC discovery-token-JWKS-userinfo fetch against a configured
    /// IdP: private/CGNAT/ULA permitted only when `SSO_ALLOW_PRIVATE_IPS`
    /// (or `AK_SSRF_ALLOW_PRIVATE_CIDRS`) opts the address in; otherwise
    /// identical to [`ResolverMode::Upstream`].
    SsoDiscovery,
}

/// A `reqwest` DNS resolver that resolves via the OS resolver and then drops
/// any address rejected by the SSRF policy for its [`ResolverMode`]. If every
/// resolved address is blocked, resolution fails (the request never connects),
/// defeating DNS-rebinding attacks that pass the URL-string check.
#[derive(Debug, Clone)]
pub struct SsrfGuardResolver {
    mode: ResolverMode,
    /// EXACT (case-insensitive, full-host) allow-set of the operator-configured
    /// egress-proxy host(s), read once at construction from the proxy env
    /// (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, upper and lower case). A host in
    /// this set skips the SSRF filter entirely — the proxy's own (often
    /// private) address must be reachable or every outbound fetch fails closed
    /// with a 502/500 (issue #2570). The set is EMPTY when no proxy env is set,
    /// in which case the resolver is byte-for-byte the pre-existing
    /// fail-closed guard. Matching is exact full-host equality only; it never
    /// relaxes any other target and never does subdomain/suffix/prefix matching.
    exempt_proxy_hosts: HashSet<String>,
}

impl Default for SsrfGuardResolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Upstream,
            exempt_proxy_hosts: HashSet::new(),
        }
    }
}

impl SsrfGuardResolver {
    /// Construct a resolver for `mode`, reading the configured egress-proxy
    /// host(s) from the process environment so the proxy's own address is
    /// exempt from the SSRF DNS filter for THIS resolver (issue #2570). All
    /// production constructors funnel through here; tests build the struct
    /// directly with an explicit `exempt_proxy_hosts` (or `..Default::default()`
    /// for the empty, fail-closed baseline).
    fn with_mode(mode: ResolverMode) -> Self {
        Self {
            mode,
            exempt_proxy_hosts: configured_proxy_hosts(),
        }
    }

    /// True when `host` is an exact (case-insensitive, full-host) match for a
    /// configured egress-proxy host. Delegates to the free [`host_is_exempt`]
    /// so the match rule is unit-testable without any DNS/network I/O.
    fn is_exempt_proxy_host(&self, host: &str) -> bool {
        host_is_exempt(&self.exempt_proxy_hosts, host)
    }
}

/// Parse the bare host token out of a proxy URL value (`HTTP_PROXY` and
/// friends): strip an optional `scheme://`, an optional `user:pass@`
/// userinfo, any path/query, and a trailing `:port`, returning the host
/// lowercased. `http://user:pass@proxy.corp:3128` → `proxy.corp`. Returns
/// `None` for an empty or hostless value.
fn proxy_host_token(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    // Strip scheme (`http://`, `https://`, `socks5://`, …) if present.
    let after_scheme = match v.find("://") {
        Some(i) => &v[i + 3..],
        None => v,
    };
    // Strip userinfo (`user:pass@`) — use the LAST '@' so a password
    // containing '@' does not truncate the host.
    let after_userinfo = match after_scheme.rfind('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    // Drop any path/query/fragment.
    let hostport = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    // Strip the port. Handle a bracketed IPv6 literal (`[::1]:port`) so the
    // ':' inside the address is not mistaken for the port separator.
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest,
        }
    } else {
        match hostport.find(':') {
            Some(i) => &hostport[..i],
            None => hostport,
        }
    };
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Read the set of configured egress-proxy host tokens from the environment,
/// covering all six proxy vars (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` in
/// upper and lower case). Hosts are lowercased for case-insensitive exact
/// matching. Empty when no proxy env is set (resolver stays fail-closed).
pub(crate) fn configured_proxy_hosts() -> HashSet<String> {
    const VARS: [&str; 6] = [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];
    let mut set = HashSet::new();
    for var in VARS {
        if let Ok(val) = std::env::var(var) {
            if let Some(host) = proxy_host_token(&val) {
                set.insert(host);
            }
        }
    }
    set
}

/// EXACT full-host, case-insensitive membership test against the proxy
/// exempt-set. An empty set always returns false (no proxy configured ⇒ the
/// resolver is fully fail-closed). No subdomain/suffix/prefix matching:
/// `proxy.corp.attacker.com` and `10.0.0.5.attacker.com` are NOT exempted
/// by a `proxy.corp` / `10.0.0.5` entry.
///
/// The match is host-keyed and PORT-AGNOSTIC (the port is stripped from the
/// proxy value at parse time). This is safe: the exemption affects only DNS
/// *name resolution*, which is inherently port-independent, and reqwest still
/// dials the proxy's configured port — it grants no reach to a different
/// service/port on that host, so port-agnosticism does not widen the guard.
fn host_is_exempt(exempt: &HashSet<String>, host: &str) -> bool {
    !exempt.is_empty() && exempt.contains(host.to_ascii_lowercase().as_str())
}

/// Convenience: an `Arc<dyn Resolve>` for `ClientBuilder::dns_resolver` that
/// blocks every private/internal address (upstream / remote-proxy — the
/// fail-closed default).
pub fn ssrf_guard_resolver() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver::with_mode(ResolverMode::Upstream))
}

/// `Arc<dyn Resolve>` for trusted operator-configured internal-service
/// clients (e.g. the scanner-adapter): permits private/CGNAT/ULA targets but
/// retains the metadata/loopback/link-local hard-blocks (issue #2389).
pub fn ssrf_guard_resolver_internal() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver::with_mode(ResolverMode::TrustedInternal))
}

/// `Arc<dyn Resolve>` for webhook-delivery clients: private/CGNAT/ULA
/// targets pass only when the operator has opted in via
/// `WEBHOOK_ALLOW_PRIVATE_IPS` or `AK_SSRF_ALLOW_PRIVATE_CIDRS`; the
/// metadata/loopback/link-local hard-blocks always apply (issue #2380).
pub fn ssrf_guard_resolver_webhook() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver::with_mode(ResolverMode::Webhook))
}

/// `Arc<dyn Resolve>` for SSO/OIDC-fetch clients: private/CGNAT/ULA
/// targets pass only when the operator has opted in via
/// `SSO_ALLOW_PRIVATE_IPS` or `AK_SSRF_ALLOW_PRIVATE_CIDRS`; the
/// metadata/loopback/link-local hard-blocks always apply (issue #2380).
pub fn ssrf_guard_resolver_sso() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver::with_mode(ResolverMode::SsoDiscovery))
}

/// True when a resolved IP must be dropped for the given [`ResolverMode`].
fn is_blocked_for(mode: ResolverMode, ip: std::net::IpAddr) -> bool {
    match mode {
        ResolverMode::Upstream => crate::api::validation::is_blocked_resolved_ip(ip),
        ResolverMode::TrustedInternal => {
            crate::api::validation::is_blocked_resolved_ip_internal(ip)
        }
        ResolverMode::Webhook => crate::api::validation::is_blocked_resolved_ip_webhook(ip),
        ResolverMode::SsoDiscovery => crate::api::validation::is_blocked_resolved_ip_sso(ip),
    }
}

/// Pure filter: keep only addresses not rejected by the SSRF policy for
/// `mode`. Extracted from [`SsrfGuardResolver::resolve`] so the
/// security-critical mixed-address case (some resolved addresses blocked,
/// some not) can be unit tested without any DNS/network I/O.
fn filter_allowed(
    mode: ResolverMode,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    addrs
        .into_iter()
        .filter(|sa| !is_blocked_for(mode, sa.ip()))
        .collect()
}

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let mode = self.mode;
        // Exempt the configured egress-proxy host (issue #2570): matched by
        // EXACT full-host equality BEFORE the mode-specific filter. Computed
        // here (sync, outside the future) so no reference into `self` is held.
        let exempt = self.is_exempt_proxy_host(name.as_str());
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Port 0 is a placeholder; reqwest substitutes the real port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            if exempt {
                // Operator-configured egress proxy: return every resolved
                // address UNFILTERED so the proxy's own (often private)
                // address is reachable. This is keyed on the exact proxy
                // host token only and never widens the guard for any other
                // target.
                let addrs: Addrs = Box::new(resolved.collect::<Vec<SocketAddr>>().into_iter());
                return Ok(addrs);
            }
            let allowed: Vec<SocketAddr> = filter_allowed(mode, resolved);
            if allowed.is_empty() {
                // Previously invisible: an outbound fetch that fails closed
                // here surfaces to the caller as an opaque connect error.
                // Log it (security target) so operators can see WHICH host
                // and mode tripped the guard (issue #2570 diagnostics).
                tracing::warn!(
                    target: "security",
                    host = %host,
                    mode = ?mode,
                    "SSRF DNS guard blocked all resolved addresses for host"
                );
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "all resolved addresses blocked by SSRF policy",
                ));
                return Err(err);
            }
            let addrs: Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security-critical case: given a mix of blocked and allowed
    /// addresses (as a rebinding attacker might produce by returning both
    /// a public IP and a loopback/link-local IP for one hostname), the
    /// filter must drop only the blocked ones and keep the allowed one(s)
    /// intact — proving this is per-address filtering, not an
    /// all-or-nothing decision keyed off the first address.
    #[test]
    fn filter_allowed_drops_only_blocked_from_mixed_input() {
        let blocked_loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let blocked_metadata: SocketAddr = "169.254.169.254:0".parse().unwrap();
        let allowed: SocketAddr = "93.184.216.34:0".parse().unwrap();

        let result = filter_allowed(
            ResolverMode::Upstream,
            [blocked_loopback, allowed, blocked_metadata],
        );

        assert_eq!(
            result,
            vec![allowed],
            "expected only the non-blocked address to survive, got {result:?}"
        );
    }

    #[test]
    fn filter_allowed_all_blocked_returns_empty() {
        let blocked_loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let blocked_metadata: SocketAddr = "169.254.169.254:0".parse().unwrap();

        let result = filter_allowed(ResolverMode::Upstream, [blocked_loopback, blocked_metadata]);

        assert!(
            result.is_empty(),
            "expected all-blocked input to yield an empty result, got {result:?}"
        );
    }

    #[test]
    fn filter_allowed_all_allowed_unchanged() {
        let a: SocketAddr = "93.184.216.34:0".parse().unwrap();
        let b: SocketAddr = "8.8.8.8:0".parse().unwrap();

        let result = filter_allowed(ResolverMode::Upstream, [a, b]);

        assert_eq!(
            result,
            vec![a, b],
            "expected all-allowed input to pass through unchanged, got {result:?}"
        );
    }

    /// Internal mode keeps a private RFC1918 address (operator-configured
    /// scanner-adapter) while STILL dropping metadata/loopback — the exact
    /// behavior split that #2389 relies on.
    #[test]
    fn filter_allowed_internal_keeps_private_drops_hard_blocked() {
        let private_addr: SocketAddr = "10.0.0.5:0".parse().unwrap();
        let blocked_metadata: SocketAddr = "169.254.169.254:0".parse().unwrap();
        let blocked_loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result = filter_allowed(
            ResolverMode::TrustedInternal,
            [blocked_metadata, private_addr, blocked_loopback],
        );

        assert_eq!(
            result,
            vec![private_addr],
            "internal mode must keep the private address and drop metadata/loopback, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolver_rejects_localhost() {
        // `localhost` resolves to 127.0.0.1 / ::1, both blocked.
        let name: Name = "localhost".parse().expect("valid dns name");
        let result = SsrfGuardResolver::default().resolve(name).await;
        assert!(
            result.is_err(),
            "localhost must be refused by the SSRF resolver"
        );
    }

    #[tokio::test]
    async fn resolver_allows_non_blocked_ip_literal() {
        // An IP literal resolves synchronously (no real DNS/network I/O,
        // per std's `ToSocketAddrs` fast path) and 1.1.1.1 is a public
        // address, so the allow-path (not just the reject-path) must let it
        // through with at least one address.
        let name: Name = "1.1.1.1".parse().expect("valid dns name");
        let mut addrs = SsrfGuardResolver::default()
            .resolve(name)
            .await
            .expect("a non-blocked IP literal must resolve successfully");
        assert!(
            addrs.next().is_some(),
            "expected at least one allowed address"
        );
    }

    /// The default (upstream) resolver must still refuse a private RFC1918
    /// literal with no env set — proving the internal-mode exemption does not
    /// leak into the fail-closed path.
    #[tokio::test]
    async fn upstream_resolver_rejects_private_ip_literal() {
        std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
        std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS");
        std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let result = SsrfGuardResolver::default().resolve(name).await;
        assert!(
            result.is_err(),
            "upstream resolver must refuse 10.0.0.5 with no allowlist env set"
        );
    }

    /// The internal-service resolver must ACCEPT a private RFC1918 literal
    /// with no env var set (the #2389 fix) …
    #[tokio::test]
    async fn internal_resolver_allows_private_ip_literal() {
        std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
        std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS");
        std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let mut addrs = SsrfGuardResolver {
            mode: ResolverMode::TrustedInternal,
            ..Default::default()
        }
        .resolve(name)
        .await
        .expect("internal-service resolver must allow a private RFC1918 literal");
        assert!(
            addrs.next().is_some(),
            "expected at least one allowed address for the internal resolver"
        );
    }

    /// Serializes the webhook/SSO toggle tests: they mutate process-wide
    /// env vars, so without this lock `cargo test`'s parallel threads could
    /// flip a toggle under another test's nose. (Under `cargo nextest`,
    /// per-test process isolation makes this a no-op safety net.)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `f` with ONLY the given env toggles set (all other private-IP
    /// allow knobs cleared), restoring the prior values afterwards.
    fn with_toggles<R>(set: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
        const VARS: [&str; 5] = [
            "WEBHOOK_ALLOW_PRIVATE_IPS",
            "SSO_ALLOW_PRIVATE_IPS",
            "UPSTREAM_ALLOW_PRIVATE_IPS",
            "AK_SSRF_ALLOW_PRIVATE_CIDRS",
            "UPSTREAM_PRIVATE_IP_ALLOWLIST",
        ];
        let _lock = ENV_LOCK.lock().unwrap();
        let prev: Vec<(&str, Option<String>)> =
            VARS.iter().map(|v| (*v, std::env::var(v).ok())).collect();
        for v in VARS {
            std::env::remove_var(v);
        }
        for (k, val) in set {
            std::env::set_var(k, val);
        }
        let out = f();
        for (k, val) in prev {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    /// Webhook mode with no toggle set must be exactly as strict as the
    /// upstream mode: a private RFC1918 address is dropped (fail-closed
    /// default, issue #2380).
    #[test]
    fn webhook_mode_blocks_private_when_toggle_off() {
        with_toggles(&[], || {
            let private_addr: SocketAddr = "10.0.0.5:0".parse().unwrap();
            let result = filter_allowed(ResolverMode::Webhook, [private_addr]);
            assert!(
                result.is_empty(),
                "webhook mode must drop a private address with no toggle set, got {result:?}"
            );
        });
    }

    /// `WEBHOOK_ALLOW_PRIVATE_IPS=true` must be honored by the webhook
    /// resolver mode (the #2380 fix) WITHOUT relaxing the upstream mode
    /// under the same environment.
    #[test]
    fn webhook_mode_allows_private_when_toggle_on_upstream_still_blocked() {
        with_toggles(&[("WEBHOOK_ALLOW_PRIVATE_IPS", "true")], || {
            let private_addr: SocketAddr = "10.0.0.5:0".parse().unwrap();
            assert_eq!(
                filter_allowed(ResolverMode::Webhook, [private_addr]),
                vec![private_addr],
                "webhook mode must keep a private address when WEBHOOK_ALLOW_PRIVATE_IPS=true"
            );
            assert!(
                filter_allowed(ResolverMode::Upstream, [private_addr]).is_empty(),
                "upstream mode must STILL drop the private address (webhook toggle must not leak)"
            );
            assert!(
                filter_allowed(ResolverMode::SsoDiscovery, [private_addr]).is_empty(),
                "sso mode must STILL drop the private address (webhook toggle must not leak)"
            );
        });
    }

    /// SSO mode with no toggle set must drop a private address.
    #[test]
    fn sso_mode_blocks_private_when_toggle_off() {
        with_toggles(&[], || {
            let private_addr: SocketAddr = "192.168.7.9:0".parse().unwrap();
            let result = filter_allowed(ResolverMode::SsoDiscovery, [private_addr]);
            assert!(
                result.is_empty(),
                "sso mode must drop a private address with no toggle set, got {result:?}"
            );
        });
    }

    /// `SSO_ALLOW_PRIVATE_IPS=true` must be honored by the SSO resolver
    /// mode WITHOUT relaxing the upstream or webhook modes.
    #[test]
    fn sso_mode_allows_private_when_toggle_on_upstream_still_blocked() {
        with_toggles(&[("SSO_ALLOW_PRIVATE_IPS", "true")], || {
            let private_addr: SocketAddr = "192.168.7.9:0".parse().unwrap();
            assert_eq!(
                filter_allowed(ResolverMode::SsoDiscovery, [private_addr]),
                vec![private_addr],
                "sso mode must keep a private address when SSO_ALLOW_PRIVATE_IPS=true"
            );
            assert!(
                filter_allowed(ResolverMode::Upstream, [private_addr]).is_empty(),
                "upstream mode must STILL drop the private address (sso toggle must not leak)"
            );
            assert!(
                filter_allowed(ResolverMode::Webhook, [private_addr]).is_empty(),
                "webhook mode must STILL drop the private address (sso toggle must not leak)"
            );
        });
    }

    /// Cloud-metadata, loopback and link-local stay hard-blocked in the
    /// webhook and SSO modes even with BOTH toggles enabled — the toggles
    /// relax only the RFC1918/CGNAT/ULA "internal mirror" class, never the
    /// SSRF hard-block class.
    #[test]
    fn webhook_and_sso_modes_keep_hard_blocks_with_toggles_on() {
        with_toggles(
            &[
                ("WEBHOOK_ALLOW_PRIVATE_IPS", "true"),
                ("SSO_ALLOW_PRIVATE_IPS", "true"),
            ],
            || {
                let metadata: SocketAddr = "169.254.169.254:0".parse().unwrap();
                let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let link_local: SocketAddr = "169.254.5.5:0".parse().unwrap();
                for mode in [ResolverMode::Webhook, ResolverMode::SsoDiscovery] {
                    let result = filter_allowed(mode, [metadata, loopback, link_local]);
                    assert!(
                        result.is_empty(),
                        "{mode:?} must drop metadata/loopback/link-local even with toggles on, got {result:?}"
                    );
                }
            },
        );
    }

    /// End-to-end: the webhook-mode resolver refuses a private IP literal
    /// with no toggle set (mirrors the upstream default-deny test).
    #[tokio::test]
    async fn webhook_resolver_rejects_private_ip_literal_by_default() {
        std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
        std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
        std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS");
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let result = SsrfGuardResolver {
            mode: ResolverMode::Webhook,
            ..Default::default()
        }
        .resolve(name)
        .await;
        assert!(
            result.is_err(),
            "webhook resolver must refuse 10.0.0.5 with no toggle set"
        );
    }

    /// End-to-end: the SSO-mode resolver refuses a private IP literal with
    /// no toggle set.
    #[tokio::test]
    async fn sso_resolver_rejects_private_ip_literal_by_default() {
        std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
        std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
        std::env::remove_var("SSO_ALLOW_PRIVATE_IPS");
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let result = SsrfGuardResolver {
            mode: ResolverMode::SsoDiscovery,
            ..Default::default()
        }
        .resolve(name)
        .await;
        assert!(
            result.is_err(),
            "sso resolver must refuse 10.0.0.5 with no toggle set"
        );
    }

    /// … but the internal-service resolver must STILL refuse metadata,
    /// loopback and `localhost` (hard-blocks are never relaxed).
    #[tokio::test]
    async fn internal_resolver_still_refuses_hard_blocked() {
        for host in ["169.254.169.254", "127.0.0.1", "localhost"] {
            let name: Name = host.parse().expect("valid dns name");
            let result = SsrfGuardResolver {
                mode: ResolverMode::TrustedInternal,
                ..Default::default()
            }
            .resolve(name)
            .await;
            assert!(
                result.is_err(),
                "internal resolver must still refuse hard-blocked host {host}"
            );
        }
    }

    // ---- Proxy-host exemption (issue #2570) ----------------------------

    /// All six proxy env vars, so `with_proxy_env` can clear the full set
    /// before applying the ones a test cares about.
    const PROXY_VARS: [&str; 6] = [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];

    /// Run `f` with ONLY the given proxy env vars set (all six cleared
    /// first), restoring the prior values afterwards. Shares [`ENV_LOCK`]
    /// with `with_toggles` so proxy-env and private-IP-toggle tests never
    /// race each other's process-wide env under `cargo test`.
    fn with_proxy_env<R>(set: &[(&str, &str)], f: impl FnOnce() -> R) -> R {
        let _lock = ENV_LOCK.lock().unwrap();
        let prev: Vec<(&str, Option<String>)> = PROXY_VARS
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();
        for v in PROXY_VARS {
            std::env::remove_var(v);
        }
        for (k, val) in set {
            std::env::set_var(k, val);
        }
        let out = f();
        for (k, val) in prev {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    fn exempt_set(hosts: &[&str]) -> HashSet<String> {
        hosts.iter().map(|h| h.to_string()).collect()
    }

    #[test]
    fn proxy_host_token_parses_scheme_creds_and_port() {
        assert_eq!(
            proxy_host_token("http://user:pass@proxy.corp:3128").as_deref(),
            Some("proxy.corp")
        );
        assert_eq!(
            proxy_host_token("https://Proxy.Corp:8080").as_deref(),
            Some("proxy.corp"),
            "host must be lowercased"
        );
        assert_eq!(
            proxy_host_token("proxy.corp").as_deref(),
            Some("proxy.corp")
        );
        assert_eq!(
            proxy_host_token("http://10.0.0.5:3128").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(
            proxy_host_token("http://user:p%40ss@10.0.0.5:3128/path?q=1").as_deref(),
            Some("10.0.0.5"),
            "userinfo/path/query must be stripped"
        );
        assert_eq!(
            proxy_host_token("http://[fd00::1]:3128").as_deref(),
            Some("fd00::1"),
            "bracketed IPv6 literal keeps its inner colons"
        );
        assert_eq!(proxy_host_token("").as_deref(), None);
        assert_eq!(proxy_host_token("   ").as_deref(), None);
    }

    #[test]
    fn configured_proxy_hosts_reads_all_six_vars() {
        with_proxy_env(
            &[
                ("HTTP_PROXY", "http://a.example:3128"),
                ("http_proxy", "http://b.example:3128"),
                ("HTTPS_PROXY", "https://c.example:3128"),
                ("https_proxy", "https://d.example:3128"),
                ("ALL_PROXY", "socks5://e.example:1080"),
                ("all_proxy", "socks5://f.example:1080"),
            ],
            || {
                let hosts = configured_proxy_hosts();
                for h in [
                    "a.example",
                    "b.example",
                    "c.example",
                    "d.example",
                    "e.example",
                    "f.example",
                ] {
                    assert!(hosts.contains(h), "expected {h} in {hosts:?}");
                }
            },
        );
    }

    #[test]
    fn configured_proxy_hosts_empty_when_no_env() {
        with_proxy_env(&[], || {
            assert!(
                configured_proxy_hosts().is_empty(),
                "no proxy env ⇒ empty exempt-set (fail-closed)"
            );
        });
    }

    #[test]
    fn host_is_exempt_exact_and_case_insensitive() {
        let set = exempt_set(&["proxy.corp", "10.0.0.5"]);
        assert!(host_is_exempt(&set, "proxy.corp"));
        assert!(host_is_exempt(&set, "PROXY.CORP"), "case-insensitive");
        assert!(host_is_exempt(&set, "Proxy.Corp"));
        assert!(host_is_exempt(&set, "10.0.0.5"), "IP literal exact match");
    }

    #[test]
    fn host_is_exempt_empty_set_always_false() {
        let empty = HashSet::new();
        assert!(!host_is_exempt(&empty, "proxy.corp"));
        assert!(!host_is_exempt(&empty, "10.0.0.5"));
    }

    #[test]
    fn host_is_exempt_rejects_subdomain_suffix_prefix() {
        let set = exempt_set(&["proxy.corp", "10.0.0.5"]);
        // Subdomain / suffix / prefix must NOT match — the whole point of the
        // security invariant (rt-ssrf-peer-replication attacks these).
        assert!(!host_is_exempt(&set, "proxy.corp.attacker.com"));
        assert!(!host_is_exempt(&set, "evil.proxy.corp"));
        assert!(!host_is_exempt(&set, "proxy.corpX"));
        assert!(!host_is_exempt(&set, "Xproxy.corp"));
        assert!(!host_is_exempt(&set, "10.0.0.5.attacker.com"));
        assert!(!host_is_exempt(&set, "10.0.0.50"));
    }

    /// CORE: a resolver whose exempt-set contains the private literal
    /// `10.0.0.5` (as if it were the configured proxy) must RESOLVE it even
    /// in the fail-closed Upstream mode — the proxy address is reachable.
    #[tokio::test]
    async fn exempt_proxy_host_resolves_private_literal_in_upstream_mode() {
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let resolver = SsrfGuardResolver {
            mode: ResolverMode::Upstream,
            exempt_proxy_hosts: exempt_set(&["10.0.0.5"]),
        };
        let mut addrs = resolver
            .resolve(name)
            .await
            .expect("an exempt proxy host must resolve even at a private IP");
        assert!(
            addrs.next().is_some(),
            "expected at least one (unfiltered) address for the exempt proxy host"
        );
    }

    /// Fail-closed regression guard: with an EMPTY exempt-set the same private
    /// literal must still be refused in Upstream mode (byte-for-byte the
    /// pre-#2570 behavior).
    #[tokio::test]
    async fn empty_exempt_set_still_blocks_private_literal() {
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let resolver = SsrfGuardResolver {
            mode: ResolverMode::Upstream,
            ..Default::default()
        };
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "empty exempt-set must stay fail-closed for a private literal"
        );
    }

    /// Direct-target-still-blocked: a proxy at `proxy.corp` is exempt, but a
    /// DIFFERENT private upstream (`10.0.0.5`, e.g. a NO_PROXY direct target)
    /// must STILL be refused even while the proxy is configured.
    #[tokio::test]
    async fn other_private_target_blocked_when_only_proxy_host_exempt() {
        let name: Name = "10.0.0.5".parse().expect("valid dns name");
        let resolver = SsrfGuardResolver {
            mode: ResolverMode::Upstream,
            exempt_proxy_hosts: exempt_set(&["proxy.corp"]),
        };
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "a non-proxy private target must stay blocked when only the proxy host is exempt"
        );
    }
}
