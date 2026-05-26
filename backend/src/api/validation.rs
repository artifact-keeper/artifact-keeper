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
///
/// Private-IP allowlist (issues #976, #1224): operators on corporate
/// networks with no public internet, or in-cluster test fixtures that
/// need to reach a mock upstream on a pod CIDR, may need to point
/// upstreams at internal mirrors. Two opt-in escape hatches:
///
/// - `UPSTREAM_ALLOW_PRIVATE_IPS=true` — allow all RFC1918 + IPv6
///   unique-local. Cloud metadata IPs (169.254.169.254, 192.0.0.192,
///   100.100.100.200) and loopback / link-local / unspecified remain
///   blocked, since those are SSRF targets, not "internal mirrors".
/// - `AK_SSRF_ALLOW_PRIVATE_CIDRS=10.0.0.0/8,192.168.7.0/24` — more
///   precise: only the listed CIDRs are exempted. Same metadata /
///   loopback hard-blocks apply. Wins over the blanket toggle if both
///   are set (allowlist is strictly more restrictive).
///   `UPSTREAM_PRIVATE_IP_ALLOWLIST` is accepted as a backward-compatible
///   alias; if both are set, `AK_SSRF_ALLOW_PRIVATE_CIDRS` takes
///   precedence.
pub(crate) fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

/// IPs that remain blocked even when the private-IP allowlist is on.
/// These are SSRF / metadata-server targets, not "internal mirrors".
/// Operators who genuinely need to reach loopback or link-local from
/// the server itself can run a local proxy on a non-loopback interface
/// and point upstreams at that.
fn is_hard_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() {
        return true;
    }
    let octets = v4.octets();
    if CLOUD_METADATA_IPS.contains(&octets) {
        return true;
    }
    false
}

fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    // Hard blocks first: metadata IPs and loopback are never unblocked
    // by the private-IP allowlist toggle.
    if is_hard_blocked_ipv4(v4) {
        return true;
    }
    let octets = v4.octets();
    if v4.is_private() {
        return !private_ip_allowed(std::net::IpAddr::V4(v4));
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
        // Unique-local (fc00::/7) is the IPv6 equivalent of RFC1918.
        // Honor the same allowlist as IPv4 private addresses.
        return !private_ip_allowed(std::net::IpAddr::V6(v6));
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

/// Whether the operator has opted the given private IP into the
/// upstream allowlist. Returns false (i.e. block) by default. Order:
///
/// 1. If `AK_SSRF_ALLOW_PRIVATE_CIDRS` (or its backward-compatible
///    alias `UPSTREAM_PRIVATE_IP_ALLOWLIST`) is set, only IPs inside
///    one of those CIDRs are exempted. The blanket toggle is ignored.
///    If both are set, `AK_SSRF_ALLOW_PRIVATE_CIDRS` wins so the
///    canonical name is the operator's source of truth.
/// 2. Otherwise, `UPSTREAM_ALLOW_PRIVATE_IPS=true` exempts all
///    RFC1918 + IPv6 unique-local addresses.
///
/// Metadata IPs and loopback are checked separately and are never
/// reachable through this path (see `is_hard_blocked_ipv4`).
fn private_ip_allowed(ip: std::net::IpAddr) -> bool {
    if let Some(list) = private_cidr_allowlist_value() {
        return cidr_list_contains(&list, ip);
    }
    upstream_allow_private_ips_enabled()
}

/// Read the configured private-CIDR allowlist, preferring the canonical
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` (issue #1224) over the older
/// `UPSTREAM_PRIVATE_IP_ALLOWLIST` (issue #976). Returns `None` when
/// neither is set, or when both are blank, so the caller can fall
/// through to the blanket toggle. Whitespace-only values are treated as
/// unset.
pub fn private_cidr_allowlist_value() -> Option<String> {
    for name in [
        "AK_SSRF_ALLOW_PRIVATE_CIDRS",
        "UPSTREAM_PRIVATE_IP_ALLOWLIST",
    ] {
        if let Ok(v) = std::env::var(name) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// True when `UPSTREAM_ALLOW_PRIVATE_IPS` is set to a truthy value
/// (`1`, `true`, case-insensitive). Exposed at crate level so `main.rs`
/// can use the same parsing for the startup-log message and there is
/// only one place to update if the accepted vocabulary changes.
pub fn upstream_allow_private_ips_enabled() -> bool {
    match std::env::var("UPSTREAM_ALLOW_PRIVATE_IPS") {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    }
}

/// Parse a comma-separated CIDR list and return true if `ip` lies in
/// any entry. Malformed entries are skipped with a warning so a typo
/// in one CIDR does not silently widen the allowlist. Both `10.0.0.0/8`
/// and a bare IP `10.1.2.3` are accepted (the latter as a /32 or /128).
fn cidr_list_contains(list: &str, ip: std::net::IpAddr) -> bool {
    for raw in list.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        match cidr_contains(entry, ip) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(reason) => {
                tracing::warn!(
                    target: "security",
                    cidr = entry,
                    reason = %reason,
                    "AK_SSRF_ALLOW_PRIVATE_CIDRS / UPSTREAM_PRIVATE_IP_ALLOWLIST entry ignored (malformed)"
                );
            }
        }
    }
    false
}

/// Check a single CIDR entry. Accepts `a.b.c.d/N`, `a.b.c.d`, IPv6
/// `xxxx::/N`, or `xxxx::`. Returns `Err` for malformed input so the
/// caller can log it rather than silently dropping the entry.
fn cidr_contains(entry: &str, ip: std::net::IpAddr) -> std::result::Result<bool, &'static str> {
    let (addr_str, prefix_str) = match entry.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (entry, None),
    };
    let net: std::net::IpAddr = addr_str.parse().map_err(|_| "invalid IP")?;
    // Bare-IP entries: match family and full address.
    let Some(prefix_str) = prefix_str else {
        return Ok(net == ip);
    };
    let prefix: u8 = prefix_str.parse().map_err(|_| "invalid prefix")?;
    // Reject the all-matches prefix in the allowlist. Accepting it would
    // silently widen the allowlist to every RFC1918 / ULA address, which
    // defeats the point of a narrower allowlist over the blanket toggle
    // and is almost always operator error (a copy-pasted 0.0.0.0/0 or
    // ::/0 from a different config). Operators who genuinely want every
    // private IP should set `UPSTREAM_ALLOW_PRIVATE_IPS=true` explicitly
    // instead of widening `AK_SSRF_ALLOW_PRIVATE_CIDRS`.
    if prefix == 0 {
        return Err("prefix 0 (all-IPs) is not permitted in the allowlist");
    }
    match (net, ip) {
        (std::net::IpAddr::V4(net4), std::net::IpAddr::V4(ip4)) => {
            if prefix > 32 {
                return Err("ipv4 prefix > 32");
            }
            Ok(ipv4_in_prefix(net4, ip4, prefix))
        }
        (std::net::IpAddr::V6(net6), std::net::IpAddr::V6(ip6)) => {
            if prefix > 128 {
                return Err("ipv6 prefix > 128");
            }
            Ok(ipv6_in_prefix(net6, ip6, prefix))
        }
        _ => Ok(false), // mixed family: never matches
    }
}

fn ipv4_in_prefix(net: std::net::Ipv4Addr, ip: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn ipv6_in_prefix(net: std::net::Ipv6Addr, ip: std::net::Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
    (u128::from(net) & mask) == (u128::from(ip) & mask)
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
        // Takes the allowlist guard so a parallel test that sets
        // AK_SSRF_ALLOW_PRIVATE_CIDRS or UPSTREAM_PRIVATE_IP_ALLOWLIST
        // for an allowlist scenario does not race this baseline.
        let _g = AllowlistGuard::new();
        assert_blocked_ip("http://10.0.0.1/api");
    }

    #[test]
    fn test_rejects_172_16_network() {
        let _g = AllowlistGuard::new();
        assert_blocked_ip("http://172.16.0.1/api");
    }

    #[test]
    fn test_rejects_192_168_network() {
        let _g = AllowlistGuard::new();
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
        // Env-locked so allowlist-mutating tests don't race the baseline.
        let _g = AllowlistGuard::new();
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

    // -----------------------------------------------------------------------
    // Issue #976: opt-in private-IP allowlist for upstream URLs.
    // Tests serialize on ENV_LOCK because they mutate env vars.
    // -----------------------------------------------------------------------

    /// Take the env lock and snapshot any allowlist-related vars so the
    /// test restores them on drop. Pattern matches `test_cgnat_block_when_opted_in`.
    struct AllowlistGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev_allow: Option<String>,
        prev_list: Option<String>,
        prev_ssrf: Option<String>,
    }

    impl AllowlistGuard {
        fn new() -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            let g = Self {
                _lock: lock,
                prev_allow: std::env::var("UPSTREAM_ALLOW_PRIVATE_IPS").ok(),
                prev_list: std::env::var("UPSTREAM_PRIVATE_IP_ALLOWLIST").ok(),
                prev_ssrf: std::env::var("AK_SSRF_ALLOW_PRIVATE_CIDRS").ok(),
            };
            std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS");
            std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST");
            std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS");
            g
        }
    }

    impl Drop for AllowlistGuard {
        fn drop(&mut self) {
            match &self.prev_allow {
                Some(v) => std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", v),
                None => std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS"),
            }
            match &self.prev_list {
                Some(v) => std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", v),
                None => std::env::remove_var("UPSTREAM_PRIVATE_IP_ALLOWLIST"),
            }
            match &self.prev_ssrf {
                Some(v) => std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", v),
                None => std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
            }
        }
    }

    #[test]
    fn test_allow_private_ips_toggle_unblocks_rfc1918() {
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_url("http://10.0.0.5/x", "Upstream URL").is_ok(),
            "10.0.0.5 must be allowed when UPSTREAM_ALLOW_PRIVATE_IPS=true"
        );
        assert!(
            validate_outbound_url("http://192.168.1.10/x", "Upstream URL").is_ok(),
            "192.168.1.10 must be allowed when UPSTREAM_ALLOW_PRIVATE_IPS=true"
        );
        assert!(
            validate_outbound_url("http://172.16.5.5/x", "Upstream URL").is_ok(),
            "172.16.5.5 must be allowed when UPSTREAM_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_allow_private_ips_toggle_still_blocks_loopback() {
        // The point of allowing private IPs is internal mirrors. Loopback
        // is the server itself; opening it would re-introduce SSRF to
        // localhost services (admin endpoints, etc.).
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert_blocked_ip("http://127.0.0.1:9090");
        assert_blocked_ip("http://[::1]:8080/api");
    }

    #[test]
    fn test_allow_private_ips_toggle_still_blocks_metadata() {
        // AWS / Oracle / Alibaba metadata IPs are the canonical SSRF
        // target. They must NEVER be unblocked, even with the toggle.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert_blocked_ip("http://169.254.169.254/latest/meta-data");
        assert_blocked_ip("http://192.0.0.192/opc/v2/instance");
        assert_blocked_ip("http://100.100.100.200/latest/meta-data");
        // IPv4-mapped IPv6 bypass must also stay closed.
        assert_blocked_ip("http://[::ffff:169.254.169.254]/latest/meta-data");
        // GCP IPv6 link-local metadata equivalent (fe80::a9fe:a9fe). The
        // IPv6 link-local branch catches the whole fe80::/10, so this is
        // already blocked, but pin the behaviour so a refactor cannot
        // accidentally route this through the ULA allowlist branch.
        assert_blocked_ip("http://[fe80::a9fe:a9fe]/latest/meta-data");
    }

    #[test]
    fn test_allow_private_ips_still_blocks_link_local() {
        // 169.254.0.0/16 is link-local. Even with private IPs allowed,
        // link-local must stay blocked because it overlaps the AWS
        // metadata IP and is rarely a legitimate mirror target.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert_blocked_ip("http://169.254.5.5/x");
    }

    #[test]
    fn test_allow_private_ips_off_by_default() {
        // Issue #976 reporter's exact case: 10.0.0.0 with no env vars
        // set must still be rejected (default-deny).
        let _g = AllowlistGuard::new();
        assert_blocked_ip("http://10.0.0.0/x");
    }

    #[test]
    fn test_allow_private_ips_unknown_value_treated_as_off() {
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "maybe");
        assert_blocked_ip("http://10.0.0.5/x");
    }

    #[test]
    fn test_allow_private_ipv6_unique_local() {
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_url("http://[fc00::1]/x", "Upstream URL").is_ok(),
            "fc00::1 (ULA) must be allowed when UPSTREAM_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_cidr_allowlist_exact_match() {
        // Single explicit /32 host: only that one address is exempted.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "192.168.7.10/32");
        assert!(validate_outbound_url("http://192.168.7.10/x", "Upstream URL").is_ok());
        assert_blocked_ip("http://192.168.7.11/x");
        assert_blocked_ip("http://10.0.0.1/x");
    }

    #[test]
    fn test_cidr_allowlist_subnet_match() {
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "10.0.0.0/8");
        assert!(validate_outbound_url("http://10.0.0.1/x", "Upstream URL").is_ok());
        assert!(validate_outbound_url("http://10.255.255.254/x", "Upstream URL").is_ok());
        // Outside the allowlist subnet but still RFC1918 — still blocked.
        assert_blocked_ip("http://192.168.1.1/x");
    }

    #[test]
    fn test_cidr_allowlist_takes_precedence_over_blanket_toggle() {
        // If both are set, the allowlist wins because it is strictly
        // narrower. This must hold so an operator who tightens from
        // "all private" to "just these CIDRs" actually sees the change.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "10.50.0.0/16");
        assert!(validate_outbound_url("http://10.50.1.2/x", "Upstream URL").is_ok());
        // 192.168.x is private but NOT in the allowlist. The narrower
        // list must win over the blanket toggle.
        assert_blocked_ip("http://192.168.1.1/x");
    }

    #[test]
    fn test_cidr_allowlist_still_blocks_metadata_ip_in_range() {
        // 169.254.169.254 is link-local. Even if an operator
        // accidentally adds 169.254.0.0/16 to the allowlist, the
        // metadata IP must NOT be reachable (it is hard-blocked, not
        // gated through the allowlist).
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "169.254.0.0/16");
        assert_blocked_ip("http://169.254.169.254/latest/meta-data");
    }

    #[test]
    fn test_cidr_allowlist_malformed_entries_ignored() {
        // A typo in one entry must not silently widen the allowlist nor
        // crash. The good entry still works; the bad one is skipped.
        let _g = AllowlistGuard::new();
        std::env::set_var(
            "UPSTREAM_PRIVATE_IP_ALLOWLIST",
            "not-an-ip, 10.0.0.0/77, 192.168.7.0/24",
        );
        assert!(validate_outbound_url("http://192.168.7.5/x", "Upstream URL").is_ok());
        assert_blocked_ip("http://10.0.0.1/x");
    }

    #[test]
    fn test_cidr_allowlist_empty_string_treated_as_unset() {
        // An empty / whitespace-only allowlist must not be confused for
        // "block everything"; it should fall through to the blanket
        // toggle (or default-deny if that's also off).
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "   ");
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(validate_outbound_url("http://10.0.0.5/x", "Upstream URL").is_ok());
    }

    #[test]
    fn test_cidr_allowlist_ipv6_subnet() {
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "fd00::/8");
        assert!(validate_outbound_url("http://[fd12::1]/x", "Upstream URL").is_ok());
        // fc00::1 is in fc00::/7 but NOT in fd00::/8 (the second hex
        // nibble differs). Must still be blocked.
        assert_blocked_ip("http://[fc00::1]/x");
    }

    #[test]
    fn test_cidr_allowlist_bare_ip_entry() {
        // Bare-IP entries (no /N) act like /32 (IPv4) or /128 (IPv6).
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "10.0.0.1");
        assert!(validate_outbound_url("http://10.0.0.1/x", "Upstream URL").is_ok());
        assert_blocked_ip("http://10.0.0.2/x");
    }

    // -----------------------------------------------------------------------
    // CIDR helper unit tests (cidr_contains, prefix-math edge cases).
    // -----------------------------------------------------------------------

    #[test]
    fn test_cidr_contains_prefix_zero_rejected() {
        // The allowlist must not accept a /0 entry. Accepting it would
        // silently widen the allowlist to every RFC1918 / ULA address.
        // Operators who genuinely want every private IP should use
        // UPSTREAM_ALLOW_PRIVATE_IPS=true explicitly.
        assert!(cidr_contains("0.0.0.0/0", "1.2.3.4".parse().unwrap()).is_err());
        assert!(cidr_contains("::/0", "2606:4700::1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_cidr_allowlist_prefix_zero_does_not_widen_to_rfc1918() {
        // End-to-end: an operator who pastes 0.0.0.0/0 into the allowlist
        // must not accidentally exempt every RFC1918 address. The bad
        // entry is logged + skipped, and the IP remains blocked unless
        // matched by some other (well-formed) entry or by the blanket
        // UPSTREAM_ALLOW_PRIVATE_IPS toggle.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "0.0.0.0/0");
        assert_blocked_ip("http://10.0.0.5/x");
        assert_blocked_ip("http://192.168.1.1/x");
    }

    #[test]
    fn test_cidr_contains_mixed_family_never_matches() {
        // An IPv4 entry must not match an IPv6 query and vice versa,
        // otherwise an operator listing 10.0.0.0/8 would also exempt
        // ::ffff:10.0.0.1 — already covered separately, but pinning
        // the helper contract guards against accidental fix-by-removal.
        assert!(!cidr_contains("10.0.0.0/8", "::1".parse().unwrap()).unwrap());
        assert!(!cidr_contains("fc00::/7", "10.0.0.1".parse().unwrap()).unwrap());
    }

    #[test]
    fn test_cidr_contains_invalid_prefix_returns_error() {
        assert!(cidr_contains("10.0.0.0/40", "10.0.0.1".parse().unwrap()).is_err());
        assert!(cidr_contains("fc00::/200", "fc00::1".parse().unwrap()).is_err());
    }

    // -----------------------------------------------------------------------
    // Issue #1224: AK_SSRF_ALLOW_PRIVATE_CIDRS is the canonical name for
    // the comma-separated private-CIDR allowlist. UPSTREAM_PRIVATE_IP_ALLOWLIST
    // remains accepted as a backward-compatible alias.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssrf_allow_private_cidrs_default_blocks_private() {
        // Default behaviour with neither env var set: every RFC1918
        // address is still blocked. This pins the production posture
        // so a refactor cannot silently flip the default to "allow".
        let _g = AllowlistGuard::new();
        assert_blocked_ip("http://10.244.0.103:45293/upstream");
        assert_blocked_ip("http://192.168.1.1/x");
        assert_blocked_ip("http://172.16.0.1/x");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_unblocks_listed_pod_cidr() {
        // Issue #1224's exact in-cluster mock-upstream scenario: pod
        // CIDR is 10.244.0.0/16 and the test fixture lives on a pod IP
        // inside that range. With AK_SSRF_ALLOW_PRIVATE_CIDRS set to
        // that CIDR, the validator must let the upstream URL through.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.244.0.0/16");
        assert!(
            validate_outbound_url("http://10.244.0.103:45293/upstream", "Upstream URL").is_ok(),
            "10.244.0.103 must be allowed when AK_SSRF_ALLOW_PRIVATE_CIDRS=10.244.0.0/16"
        );
        // Outside the allowlist subnet but still RFC1918 — stays blocked.
        assert_blocked_ip("http://192.168.1.1/x");
        // Outside the listed pod CIDR but still in 10.0.0.0/8 — stays blocked.
        assert_blocked_ip("http://10.0.0.1/x");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_still_blocks_metadata() {
        // Hard-blocked metadata IPs must not become reachable even if
        // an operator lists a containing CIDR. Defense-in-depth: the
        // metadata IP check fires before the allowlist is consulted.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "169.254.0.0/16");
        assert_blocked_ip("http://169.254.169.254/latest/meta-data");
        // Oracle metadata IP, even if 192.0.0.0/24 is allowlisted.
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "192.0.0.0/24");
        assert_blocked_ip("http://192.0.0.192/opc/v2/instance");
        // Alibaba metadata IP, even if the containing CGNAT block is allowlisted.
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "100.100.100.0/24");
        assert_blocked_ip("http://100.100.100.200/latest/meta-data");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_still_blocks_loopback() {
        // Loopback is the AK process itself. Even with the allowlist
        // covering 127.0.0.0/8, this must stay blocked because it would
        // reintroduce SSRF to localhost admin endpoints.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "127.0.0.0/8");
        assert_blocked_ip("http://127.0.0.1:9090");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_malformed_entries_skipped() {
        // A typo in one entry must not silently widen the allowlist nor
        // crash. The good entry still works; the bad one is logged + skipped.
        let _g = AllowlistGuard::new();
        std::env::set_var(
            "AK_SSRF_ALLOW_PRIVATE_CIDRS",
            "not-an-ip, 10.0.0.0/77, 10.244.0.0/16",
        );
        assert!(
            validate_outbound_url("http://10.244.0.5/x", "Upstream URL").is_ok(),
            "10.244.0.5 must be allowed (good entry survives malformed peers)"
        );
        assert_blocked_ip("http://10.0.0.1/x");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_empty_falls_through() {
        // Empty / whitespace-only is treated as unset so it falls
        // through to the blanket toggle rather than collapsing to
        // "block all private".
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "   ");
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_url("http://10.0.0.5/x", "Upstream URL").is_ok(),
            "blanket toggle must take over when AK_SSRF_ALLOW_PRIVATE_CIDRS is blank"
        );
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_ipv6_subnet() {
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "fd00::/8");
        assert!(validate_outbound_url("http://[fd12::1]/x", "Upstream URL").is_ok());
        assert_blocked_ip("http://[fc00::1]/x");
    }

    #[test]
    fn test_ssrf_allow_private_cidrs_takes_precedence_over_alias() {
        // Both AK_SSRF_ALLOW_PRIVATE_CIDRS (new canonical) and
        // UPSTREAM_PRIVATE_IP_ALLOWLIST (legacy alias) are set. The new
        // name MUST win so an operator who migrates to the canonical
        // name without removing the old one gets the new behaviour.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.244.0.0/16");
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "192.168.99.0/24");
        // In the canonical (new) list, NOT in the legacy alias.
        assert!(
            validate_outbound_url("http://10.244.0.7/x", "Upstream URL").is_ok(),
            "10.244.0.7 must be allowed via AK_SSRF_ALLOW_PRIVATE_CIDRS"
        );
        // In the legacy alias only. The new name wins so this stays blocked.
        assert_blocked_ip("http://192.168.99.1/x");
    }

    #[test]
    fn test_legacy_alias_still_honored_when_new_var_unset() {
        // Backward compatibility: operators who already set the old
        // UPSTREAM_PRIVATE_IP_ALLOWLIST must not have to migrate
        // immediately. With only the alias set, it still takes effect.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "10.0.0.0/8");
        assert!(validate_outbound_url("http://10.5.6.7/x", "Upstream URL").is_ok());
        assert_blocked_ip("http://192.168.1.1/x");
    }

    #[test]
    fn test_private_cidr_allowlist_value_helper() {
        // Direct contract test for the helper main.rs uses to format
        // the boot-time warning. The new name takes precedence; empty
        // / whitespace values fall through; both unset -> None.
        let _g = AllowlistGuard::new();
        assert!(private_cidr_allowlist_value().is_none());

        std::env::set_var("UPSTREAM_PRIVATE_IP_ALLOWLIST", "10.0.0.0/8");
        assert_eq!(
            private_cidr_allowlist_value().as_deref(),
            Some("10.0.0.0/8"),
            "legacy alias picked up when new name is unset"
        );

        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.244.0.0/16");
        assert_eq!(
            private_cidr_allowlist_value().as_deref(),
            Some("10.244.0.0/16"),
            "new canonical name wins over legacy alias"
        );

        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "   ");
        assert_eq!(
            private_cidr_allowlist_value().as_deref(),
            Some("10.0.0.0/8"),
            "blank new value falls through to legacy alias"
        );
    }
}
