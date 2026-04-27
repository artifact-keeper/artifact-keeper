//! Shared input validation helpers.
//!
//! Centralizes URL and other validation logic used across multiple handlers
//! and services so that SSRF / injection rules are defined in one place.
//!
//! # Defense layers
//!
//! 1. [`validate_outbound_url`] is the entry point for handlers/services that
//!    receive a URL from a client (e.g. webhook URL, remote repo URL,
//!    upstream config.json `dl` field). Reject before the request ever
//!    issues.
//! 2. The redirect policy on the shared HTTP client (see
//!    `crate::services::http_client::base_client_builder`) calls
//!    [`is_blocked_url`] on every redirect hop. This closes the
//!    redirect-follow bypass — without it, an upstream returning
//!    `302 Location: http://[::ffff:127.0.0.1]/` would defeat layer 1.
//! 3. Egress NetworkPolicy at the cluster layer is a defense-in-depth
//!    follow-up tracked separately.
//!
//! # Residual gaps
//!
//! DNS rebinding: a hostname that resolves to a public IP at validation
//! time and a private IP at fetch time is not caught by string-based
//! validation. Mitigation requires a custom DNS resolver or pinning the
//! resolved IP via `reqwest`'s `resolve_to_addrs`. Tracked as a follow-up.

use crate::error::{AppError, Result};

/// IPv6 link-local prefix `fe80::/10`. The mask covers the top 10 bits.
const IPV6_LINK_LOCAL_MASK: u16 = 0xffc0;
const IPV6_LINK_LOCAL_PREFIX: u16 = 0xfe80;

/// IPv6 unique-local prefix `fc00::/7`. The mask covers the top 7 bits.
const IPV6_UNIQUE_LOCAL_MASK: u16 = 0xfe00;
const IPV6_UNIQUE_LOCAL_PREFIX: u16 = 0xfc00;

/// IPv4 carrier-grade NAT prefix `100.64.0.0/10` (RFC 6598). The mask
/// covers the top 10 bits (full first octet 100, plus top 2 bits of the
/// second octet = 0b01).
const CGNAT_SECOND_OCTET_MASK: u8 = 0xc0;
const CGNAT_SECOND_OCTET_PREFIX: u8 = 0x40;

/// Cloud-provider metadata IPs that fall outside RFC1918 / link-local.
/// Each entry is a single-IP block. The full Alibaba CGNAT range is
/// gated behind `BLOCK_CGNAT_OUTBOUND=true` (off by default) since
/// `100.64.0.0/10` is also used by K8s pod CIDRs in some clusters and
/// by CGNAT-served residential ISPs.
const CLOUD_METADATA_IPS: &[[u8; 4]] = &[
    [192, 0, 0, 192],     // Oracle Cloud Infrastructure
    [100, 100, 100, 200], // Alibaba Cloud
];

/// Hostname blocklist. Both the literal entry and `*.<entry>` forms are
/// blocked. Lowercased before comparison. IP literals (e.g.
/// `169.254.169.254`) are deliberately NOT here — the IP check below
/// covers them and includes their bypass forms (IPv4-mapped IPv6, etc).
const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.azure.com",
    "metadata.tencentyun.com",
    "metadata.oraclecloud.com",
    "metadata.platformequinix.com",
    "backend",
    "postgres",
    "redis",
    "opensearch",
    "trivy",
];

/// Reason a URL was blocked. Returned by [`is_blocked_url`] so callers
/// (validators and the redirect policy) can surface a useful error
/// message and emit a labeled metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockReason {
    Hostname(String),
    Ip(std::net::IpAddr),
}

impl BlockReason {
    /// Short metric label, suitable for a Prometheus `reason` dimension.
    pub(crate) fn metric_label(&self) -> &'static str {
        match self {
            BlockReason::Hostname(_) => "hostname",
            BlockReason::Ip(_) => "ip",
        }
    }
}

/// Validate that a URL is safe for the server to contact (anti-SSRF).
///
/// Rejects private/internal IPs, known cloud metadata endpoints, and
/// Docker-internal service hostnames. `label` is used in error messages
/// (e.g. "Webhook URL", "Remote instance URL").
pub fn validate_outbound_url(url_str: &str, label: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url_str)
        .map_err(|_| AppError::Validation(format!("Invalid {}", label)))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(AppError::Validation(format!(
            "{} must use http or https",
            label
        )));
    }

    if parsed.host_str().is_none() {
        return Err(AppError::Validation(format!("{} must have a host", label)));
    }

    if let Some(reason) = is_blocked_url(&parsed) {
        record_block(label, &reason);
        return Err(match reason {
            BlockReason::Hostname(host) => {
                AppError::Validation(format!("{} host '{}' is not allowed", label, host))
            }
            BlockReason::Ip(ip) => AppError::Validation(format!(
                "{} IP '{}' is not allowed (private/internal network)",
                label, ip
            )),
        });
    }

    Ok(())
}

/// Decide whether a parsed URL targets a blocked address. Used by both
/// [`validate_outbound_url`] and the redirect policy on the shared HTTP
/// client. Returning `Some(_)` means the request must not be issued.
pub(crate) fn is_blocked_url(url: &reqwest::Url) -> Option<BlockReason> {
    let host = url.host_str()?;
    let host_lower = host.to_lowercase();
    // Strip a trailing dot so `localhost.` is treated like `localhost`.
    let host_normalized = host_lower.trim_end_matches('.');

    for blocked in BLOCKED_HOSTS {
        if host_normalized == *blocked || host_normalized.ends_with(&format!(".{}", blocked)) {
            return Some(BlockReason::Hostname(host.to_string()));
        }
    }

    // host_str() returns brackets for IPv6 (e.g. "[::1]"), so strip them
    // before parsing as IpAddr.
    let bare_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare_host.parse::<std::net::IpAddr>() {
        if is_blocked_ip(ip) {
            return Some(BlockReason::Ip(ip));
        }
    }

    None
}

/// Return true when an IP must not be contacted from server-side requests.
///
/// Covers:
/// - IPv4 loopback / RFC1918 private / link-local / unspecified / broadcast
/// - Specific cloud metadata IPs that fall outside RFC1918 (Oracle
///   `192.0.0.192`, Alibaba `100.100.100.200`)
/// - Optionally (gated by `BLOCK_CGNAT_OUTBOUND=true`) the entire
///   `100.64.0.0/10` CGNAT range. Off by default because K8s pod CIDRs
///   and CGNAT-served ISPs legitimately occupy this range
/// - IPv6 loopback (`::1`), unspecified (`::`), link-local (`fe80::/10`),
///   unique-local (`fc00::/7`)
/// - IPv4-mapped IPv6 (`::ffff:0:0/96`) and the deprecated
///   IPv4-compatible IPv6 (`::a.b.c.d`) — both reduce to IPv4 rules so
///   `http://[::ffff:169.254.169.254]/` cannot bypass the IPv4 metadata
///   block. IPv6 own-properties (loopback, link-local, etc.) are
///   evaluated *first* so `::1` is correctly classified as IPv6 loopback
///   rather than IPv4 alias `0.0.0.1`.
pub(crate) fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
    {
        return true;
    }
    let octets = v4.octets();
    if CLOUD_METADATA_IPS.contains(&octets) {
        return true;
    }
    if cgnat_block_enabled()
        && octets[0] == 100
        && (octets[1] & CGNAT_SECOND_OCTET_MASK) == CGNAT_SECOND_OCTET_PREFIX
    {
        return true;
    }
    false
}

fn is_blocked_ipv6(v6: std::net::Ipv6Addr) -> bool {
    // Evaluate IPv6 own properties first so `::1` is caught as IPv6
    // loopback before the IPv4-alias fallthrough re-interprets it.
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    let segs = v6.segments();
    if segs[0] & IPV6_LINK_LOCAL_MASK == IPV6_LINK_LOCAL_PREFIX {
        return true;
    }
    if segs[0] & IPV6_UNIQUE_LOCAL_MASK == IPV6_UNIQUE_LOCAL_PREFIX {
        return true;
    }
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
    // forms must obey the IPv4 rules so attackers cannot bypass them
    // by writing the v4 address inside a v6 literal.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }
    if let Some(v4) = v6.to_ipv4() {
        return is_blocked_ipv4(v4);
    }
    false
}

/// Whether to block the entire `100.64.0.0/10` CGNAT range. Off by
/// default. Operators serving artifact-keeper from a CGNAT-served
/// network or a K8s cluster that uses CGNAT for pod CIDRs would
/// otherwise lose the ability to fetch from those addresses. When set
/// to `true`, every CGNAT IP is rejected as if it were RFC1918.
fn cgnat_block_enabled() -> bool {
    std::env::var("BLOCK_CGNAT_OUTBOUND")
        .map(|v| matches!(v.as_str(), "1" | "true" | "True" | "TRUE"))
        .unwrap_or(false)
}

fn record_block(label: &str, reason: &BlockReason) {
    let detail = match reason {
        BlockReason::Hostname(host) => host.clone(),
        BlockReason::Ip(ip) => ip.to_string(),
    };
    tracing::warn!(
        target: "security",
        label = label,
        reason = reason.metric_label(),
        target_address = %detail,
        "outbound URL blocked"
    );
    crate::services::metrics_service::record_outbound_url_blocked(reason.metric_label(), label);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that mutate `BLOCK_CGNAT_OUTBOUND` must serialize to avoid
    /// racing parallel test threads. `cargo test` runs tests in
    /// parallel; without this lock, an env-var-mutating test can flip
    /// state under another test's nose.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: assert that `validate_outbound_url(url, ...)` rejects with
    /// an error whose message contains both `label_part` (proving the
    /// validator path that fired) and the URL's offending address.
    /// Pinning the message guards against silent regressions where a
    /// future change makes the URL fail for a different reason.
    fn assert_blocked(url: &str, label_part: &str) {
        let err =
            validate_outbound_url(url, "Test URL").expect_err(&format!("expected error for {url}"));
        let msg = err.to_string();
        assert!(
            msg.contains(label_part),
            "for {url}, expected error message to contain '{label_part}', got: {msg}"
        );
    }

    fn assert_blocked_ip(url: &str) {
        assert_blocked(url, "private/internal network");
    }

    fn assert_blocked_host(url: &str) {
        assert_blocked(url, "is not allowed");
    }

    // -----------------------------------------------------------------------
    // Valid URLs (negative baseline — these must still pass)
    // -----------------------------------------------------------------------

    #[test]
    fn test_allows_valid_https() {
        assert!(validate_outbound_url("https://example.com/api", "Test URL").is_ok());
    }

    #[test]
    fn test_allows_valid_http() {
        assert!(validate_outbound_url("http://registry.example.com:8080", "Test URL").is_ok());
    }

    #[test]
    fn test_allows_public_ip() {
        assert!(validate_outbound_url("https://93.184.216.34/api", "Test URL").is_ok());
    }

    #[test]
    fn test_allows_public_ipv6() {
        // Cloudflare DNS — verify the validator does not over-block IPv6.
        assert!(
            validate_outbound_url("https://[2606:4700:4700::1111]/dns-query", "Test URL").is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // Scheme restrictions
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_ftp_scheme() {
        assert!(validate_outbound_url("ftp://files.example.com", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_file_scheme() {
        assert!(validate_outbound_url("file:///etc/passwd", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_ssh_scheme() {
        assert!(validate_outbound_url("ssh://git@github.com/repo", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_invalid_url() {
        assert!(validate_outbound_url("not a url", "Test URL").is_err());
    }

    // -----------------------------------------------------------------------
    // Private / internal IPs (assertion strength: pin the error message)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_loopback() {
        assert_blocked_ip("http://127.0.0.1:9090");
    }

    #[test]
    fn test_rejects_10_network() {
        assert_blocked_ip("http://10.0.0.1/api");
    }

    #[test]
    fn test_rejects_172_16_network() {
        assert_blocked_ip("http://172.16.0.1/api");
    }

    #[test]
    fn test_rejects_192_168_network() {
        assert_blocked_ip("http://192.168.1.1/api");
    }

    #[test]
    fn test_rejects_link_local() {
        assert_blocked_ip("http://169.254.169.254/latest/meta-data");
    }

    #[test]
    fn test_rejects_zero_ip() {
        assert_blocked_ip("http://0.0.0.0/api");
    }

    #[test]
    fn test_rejects_ipv6_loopback() {
        assert_blocked_ip("http://[::1]:8080/api");
    }

    #[test]
    fn test_rejects_ipv6_unspecified() {
        assert_blocked_ip("http://[::]:8080/api");
    }

    // -----------------------------------------------------------------------
    // SSRF bypasses via IPv4-mapped / compatible IPv6 addresses.
    // Without explicit handling, `::ffff:169.254.169.254` parses as an
    // IPv6 address whose `is_loopback()` / `is_unspecified()` are false,
    // slipping past the private-IP check.
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_ipv4_mapped_loopback() {
        assert_blocked_ip("http://[::ffff:127.0.0.1]/api");
    }

    #[test]
    fn test_rejects_ipv4_mapped_aws_metadata() {
        assert_blocked_ip("http://[::ffff:169.254.169.254]/latest/meta-data");
    }

    #[test]
    fn test_rejects_ipv4_mapped_private_10() {
        assert_blocked_ip("http://[::ffff:10.0.0.1]/api");
    }

    #[test]
    fn test_rejects_ipv4_compatible_aws_metadata() {
        // Deprecated IPv4-compatible IPv6 form (::a.b.c.d). Must also
        // reduce to the IPv4 ruleset.
        assert_blocked_ip("http://[::169.254.169.254]/latest/meta-data");
    }

    #[test]
    fn test_rejects_ipv6_link_local() {
        assert_blocked_ip("http://[fe80::1]/api");
    }

    #[test]
    fn test_rejects_ipv6_unique_local() {
        assert_blocked_ip("http://[fc00::1]/api");
        assert_blocked_ip("http://[fd12:3456:789a::1]/api");
    }

    // Range-boundary tests so an off-by-one in the mask logic gets caught.

    #[test]
    fn test_ipv6_link_local_top_of_range_blocked() {
        // febf:ffff:: is the last address of fe80::/10.
        assert_blocked_ip("http://[febf:ffff::1]/api");
    }

    #[test]
    fn test_ipv6_just_above_link_local_allowed() {
        // fec0:: is fec0::/10 (deprecated site-local). The PR does not
        // claim coverage; pin current behavior so a future widening is
        // an explicit decision.
        assert!(
            validate_outbound_url("http://[fec0::1]/api", "Test URL").is_ok(),
            "fec0::/10 (deprecated site-local) is currently NOT blocked"
        );
    }

    #[test]
    fn test_ipv6_unique_local_top_of_range_blocked() {
        // fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff is the last address of fc00::/7.
        assert_blocked_ip("http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/api");
    }

    #[test]
    fn test_ipv6_just_above_unique_local_allowed() {
        // fe00:: is just above fc00::/7 and just below fe80::/10.
        assert!(
            validate_outbound_url("http://[fe00::1]/api", "Test URL").is_ok(),
            "fe00::1 sits between unique-local and link-local; must not be over-blocked"
        );
    }

    #[test]
    fn test_rejects_oracle_cloud_metadata_ip() {
        assert_blocked_ip("http://192.0.0.192/opc/v2/instance");
    }

    #[test]
    fn test_oracle_cloud_metadata_neighbor_allowed() {
        assert!(
            validate_outbound_url("http://192.0.0.191/x", "Test URL").is_ok(),
            "192.0.0.191 must not be blocked; only the specific 192.0.0.192 is"
        );
    }

    #[test]
    fn test_rejects_alibaba_metadata_ip() {
        // Alibaba's specific metadata IP is blocked by default even when
        // the broader CGNAT block is disabled.
        assert_blocked_ip("http://100.100.100.200/latest/meta-data");
    }

    #[test]
    fn test_alibaba_metadata_neighbor_allowed_by_default() {
        // 100.100.100.199 is in CGNAT but not the specific Alibaba IP.
        // With BLOCK_CGNAT_OUTBOUND off (default) it must be allowed,
        // otherwise K8s pod CIDRs in CGNAT and homelab/CGNAT ISPs break.
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("BLOCK_CGNAT_OUTBOUND").ok();
        std::env::remove_var("BLOCK_CGNAT_OUTBOUND");
        let result = validate_outbound_url("http://100.100.100.199/x", "Test URL");
        if let Some(v) = prev {
            std::env::set_var("BLOCK_CGNAT_OUTBOUND", v);
        }
        assert!(
            result.is_ok(),
            "100.100.100.199 (CGNAT but not Alibaba) must be allowed by default; got {:?}",
            result
        );
    }

    #[test]
    fn test_cgnat_block_when_opted_in() {
        // With BLOCK_CGNAT_OUTBOUND=true, the entire 100.64.0.0/10 range
        // must be rejected. Range-boundary cases pin off-by-one bugs in
        // the mask.
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("BLOCK_CGNAT_OUTBOUND").ok();
        std::env::set_var("BLOCK_CGNAT_OUTBOUND", "true");
        let low_in = validate_outbound_url("http://100.64.0.1/x", "Test URL");
        let high_in = validate_outbound_url("http://100.127.255.254/x", "Test URL");
        let low_out = validate_outbound_url("http://100.63.255.255/x", "Test URL");
        let high_out = validate_outbound_url("http://100.128.0.1/x", "Test URL");
        match prev {
            Some(v) => std::env::set_var("BLOCK_CGNAT_OUTBOUND", v),
            None => std::env::remove_var("BLOCK_CGNAT_OUTBOUND"),
        }
        assert!(
            low_in.is_err(),
            "100.64.0.1 must be blocked when CGNAT block is on"
        );
        assert!(
            high_in.is_err(),
            "100.127.255.254 must be blocked when CGNAT block is on"
        );
        assert!(
            low_out.is_ok(),
            "100.63.255.255 must remain allowed (just below CGNAT)"
        );
        assert!(
            high_out.is_ok(),
            "100.128.0.1 must remain allowed (just above CGNAT)"
        );
    }

    // -----------------------------------------------------------------------
    // Blocked hostnames
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_localhost() {
        assert_blocked_host("http://localhost:8080/api");
    }

    #[test]
    fn test_rejects_localhost_trailing_dot() {
        // FQDN trailing-dot form must not slip past the suffix match.
        assert_blocked_host("http://localhost./api");
    }

    #[test]
    fn test_rejects_gcp_metadata() {
        assert_blocked_host("http://metadata.google.internal/computeMetadata");
    }

    #[test]
    fn test_rejects_tencent_metadata() {
        assert_blocked_host("http://metadata.tencentyun.com/latest/meta-data");
    }

    #[test]
    fn test_rejects_oracle_metadata_hostname() {
        assert_blocked_host("http://metadata.oraclecloud.com/opc/v2/instance");
    }

    #[test]
    fn test_rejects_docker_backend() {
        assert_blocked_host("http://backend:8080/api");
    }

    #[test]
    fn test_rejects_docker_postgres() {
        assert_blocked_host("http://postgres:5432");
    }

    #[test]
    fn test_rejects_docker_redis() {
        assert_blocked_host("http://redis:6379");
    }

    // -----------------------------------------------------------------------
    // Non-blocked hostnames (K8s service names are allowed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_allows_fqdn() {
        assert!(validate_outbound_url("https://registry.example.com", "Test URL").is_ok());
    }

    #[test]
    fn test_allows_k8s_service_name() {
        assert!(validate_outbound_url("http://nexus:8081/repository/pypi", "Test URL").is_ok());
    }

    #[test]
    fn test_allows_k8s_fqdn_service() {
        assert!(
            validate_outbound_url("http://nexus.tools.svc.cluster.local:8081", "Test URL").is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // Error message label
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_appears_in_error_message() {
        let result = validate_outbound_url("ftp://example.com", "Remote instance URL");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Remote instance URL"));
    }

    // -----------------------------------------------------------------------
    // is_blocked_url contract — used by the redirect policy on
    // base_client_builder.
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_blocked_url_returns_ip_reason_for_metadata() {
        let url = reqwest::Url::parse("http://[::ffff:169.254.169.254]/").unwrap();
        let reason = is_blocked_url(&url).expect("must block IPv4-mapped AWS metadata");
        assert!(matches!(reason, BlockReason::Ip(_)));
        assert_eq!(reason.metric_label(), "ip");
    }

    #[test]
    fn test_is_blocked_url_returns_hostname_reason_for_localhost() {
        let url = reqwest::Url::parse("http://localhost/").unwrap();
        let reason = is_blocked_url(&url).expect("must block localhost");
        assert!(matches!(reason, BlockReason::Hostname(_)));
        assert_eq!(reason.metric_label(), "hostname");
    }

    #[test]
    fn test_is_blocked_url_passes_public_address() {
        let url = reqwest::Url::parse("https://crates.io/api/v1/crates/serde").unwrap();
        assert!(is_blocked_url(&url).is_none());
    }
}
