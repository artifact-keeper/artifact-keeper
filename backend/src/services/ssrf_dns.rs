//! SSRF-validating DNS resolver: rejects hostnames that resolve to blocked
//! (loopback / link-local / private / cloud-metadata) IPs at connect time,
//! closing the DNS-rebinding gap that URL-string validation cannot catch.

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
}

impl Default for SsrfGuardResolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Upstream,
        }
    }
}

/// Convenience: an `Arc<dyn Resolve>` for `ClientBuilder::dns_resolver` that
/// blocks every private/internal address (upstream / remote-proxy — the
/// fail-closed default).
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

/// `Arc<dyn Resolve>` for webhook-delivery clients: private/CGNAT/ULA
/// targets pass only when the operator has opted in via
/// `WEBHOOK_ALLOW_PRIVATE_IPS` or `AK_SSRF_ALLOW_PRIVATE_CIDRS`; the
/// metadata/loopback/link-local hard-blocks always apply (issue #2380).
pub fn ssrf_guard_resolver_webhook() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::Webhook,
    })
}

/// `Arc<dyn Resolve>` for SSO/OIDC-fetch clients: private/CGNAT/ULA
/// targets pass only when the operator has opted in via
/// `SSO_ALLOW_PRIVATE_IPS` or `AK_SSRF_ALLOW_PRIVATE_CIDRS`; the
/// metadata/loopback/link-local hard-blocks always apply (issue #2380).
pub fn ssrf_guard_resolver_sso() -> Arc<dyn Resolve> {
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::SsoDiscovery,
    })
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
