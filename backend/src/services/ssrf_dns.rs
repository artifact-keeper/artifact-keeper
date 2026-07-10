//! SSRF-validating DNS resolver: rejects hostnames that resolve to blocked
//! (loopback / link-local / private / cloud-metadata) IPs at connect time,
//! closing the DNS-rebinding gap that URL-string validation cannot catch.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// A `reqwest` DNS resolver that resolves via the OS resolver and then drops
/// any address rejected by [`crate::api::validation::is_blocked_resolved_ip`].
/// If every resolved address is blocked, resolution fails (the request never
/// connects), defeating DNS-rebinding attacks that pass the URL-string check.
#[derive(Debug, Default, Clone)]
pub struct SsrfGuardResolver;

/// Convenience: an `Arc<dyn Resolve>` for `ClientBuilder::dns_resolver`.
pub fn ssrf_guard_resolver() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver)
}

/// Pure filter: keep only addresses not rejected by
/// [`crate::api::validation::is_blocked_resolved_ip`]. Extracted from
/// [`SsrfGuardResolver::resolve`] so the security-critical mixed-address
/// case (some resolved addresses blocked, some not) can be unit tested
/// without any DNS/network I/O.
fn filter_allowed(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs
        .into_iter()
        .filter(|sa| !crate::api::validation::is_blocked_resolved_ip(sa.ip()))
        .collect()
}

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Port 0 is a placeholder; reqwest substitutes the real port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = filter_allowed(resolved);
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

        let result = filter_allowed([blocked_loopback, allowed, blocked_metadata]);

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

        let result = filter_allowed([blocked_loopback, blocked_metadata]);

        assert!(
            result.is_empty(),
            "expected all-blocked input to yield an empty result, got {result:?}"
        );
    }

    #[test]
    fn filter_allowed_all_allowed_unchanged() {
        let a: SocketAddr = "93.184.216.34:0".parse().unwrap();
        let b: SocketAddr = "8.8.8.8:0".parse().unwrap();

        let result = filter_allowed([a, b]);

        assert_eq!(
            result,
            vec![a, b],
            "expected all-allowed input to pass through unchanged, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolver_rejects_localhost() {
        // `localhost` resolves to 127.0.0.1 / ::1, both blocked.
        let name: Name = "localhost".parse().expect("valid dns name");
        let result = SsrfGuardResolver.resolve(name).await;
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
        let mut addrs = SsrfGuardResolver
            .resolve(name)
            .await
            .expect("a non-blocked IP literal must resolve successfully");
        assert!(
            addrs.next().is_some(),
            "expected at least one allowed address"
        );
    }
}
