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

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            // Port 0 is a placeholder; reqwest substitutes the real port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<SocketAddr> = resolved
                .filter(|sa| !crate::api::validation::is_blocked_resolved_ip(sa.ip()))
                .collect();
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
