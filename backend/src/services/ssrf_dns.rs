//! SSRF-validating DNS resolver: rejects hostnames that resolve to blocked
//! (loopback / link-local / private / cloud-metadata) IPs at connect time,
//! closing the DNS-rebinding gap that URL-string validation cannot catch.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Which trust class the resolver enforces. Selects whether private /
/// CGNAT / IPv6 unique-local addresses are dropped (the default,
/// attacker-influenceable upstream/proxy targets) or permitted (trusted
/// operator-configured internal services). The cloud-metadata / loopback /
/// link-local hard-blocks apply to both (issue #2389).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverMode {
    /// Fail-closed: block every private/internal address (upstream/proxy).
    Upstream,
    /// Trusted operator-configured internal service: permit private/CGNAT/ULA
    /// but keep metadata/loopback/link-local blocked.
    TrustedInternal,
}

/// A `reqwest` DNS resolver that resolves via the OS resolver and then drops
/// any address rejected by the SSRF policy for its [`ResolverMode`]. If every
/// resolved address is blocked, resolution fails (the request never connects),
/// defeating DNS-rebinding attacks that pass the URL-string check.
#[derive(Debug, Clone)]
pub struct SsrfGuardResolver {
    mode: ResolverMode,
}

impl Default for SsrfGuardResolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Upstream,
        }
    }
}

/// Convenience: an `Arc<dyn Resolve>` for `ClientBuilder::dns_resolver` that
/// blocks every private/internal address (upstream / remote-proxy / webhook /
/// SSO — the fail-closed default).
pub fn ssrf_guard_resolver() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver::default())
}

/// `Arc<dyn Resolve>` for trusted operator-configured internal-service
/// clients (e.g. the scanner-adapter): permits private/CGNAT/ULA targets but
/// retains the metadata/loopback/link-local hard-blocks (issue #2389).
pub fn ssrf_guard_resolver_internal() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::TrustedInternal,
    })
}

/// True when a resolved IP must be dropped for the given [`ResolverMode`].
fn is_blocked_for(mode: ResolverMode, ip: std::net::IpAddr) -> bool {
    match mode {
        ResolverMode::Upstream => crate::api::validation::is_blocked_resolved_ip(ip),
        ResolverMode::TrustedInternal => {
            crate::api::validation::is_blocked_resolved_ip_internal(ip)
        }
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
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Port 0 is a placeholder; reqwest substitutes the real port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = filter_allowed(mode, resolved);
            if allowed.is_empty() {
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
        }
        .resolve(name)
        .await
        .expect("internal-service resolver must allow a private RFC1918 literal");
        assert!(
            addrs.next().is_some(),
            "expected at least one allowed address for the internal resolver"
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
            }
            .resolve(name)
            .await;
            assert!(
                result.is_err(),
                "internal resolver must still refuse hard-blocked host {host}"
            );
        }
    }
}
