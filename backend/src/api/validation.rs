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

/// Which validator path is calling. Each path consults a distinct
/// "allow private IPs" env var so a test cluster that needs to relax one
/// surface does not accidentally relax the other. Issue #1435.
///
/// - [`OutboundUrlContext::Upstream`] reads `UPSTREAM_ALLOW_PRIVATE_IPS`.
///   Use for remote-repository upstream URLs and any other "the backend
///   fetches a package on behalf of a client" path.
/// - [`OutboundUrlContext::Webhook`] reads `WEBHOOK_ALLOW_PRIVATE_IPS`.
///   Use for webhook delivery target URLs.
/// - [`OutboundUrlContext::SsoDiscovery`] reads `SSO_ALLOW_PRIVATE_IPS`.
///   Use for OIDC discovery / token / JWKS / userinfo fetches against a
///   *configured, trusted* identity provider. Kept separate (issue #1891)
///   so a deployment with an internal Keycloak at an RFC1918 address can
///   reach its IdP without also relaxing the upstream-proxy or webhook
///   SSRF guards, which take arbitrary client-influenced URLs.
///
/// The named-CIDR allowlist (`AK_SSRF_ALLOW_PRIVATE_CIDRS`) is shared
/// across all contexts because it is a positive allowlist that operators
/// curate explicitly; widening it is an opt-in action, not a per-surface
/// relaxation. For SSO this is the preferred, narrowest knob: scope it to
/// the IdP host/CIDR (e.g. `AK_SSRF_ALLOW_PRIVATE_CIDRS=10.10.0.8/32`)
/// rather than enabling the blanket `SSO_ALLOW_PRIVATE_IPS` toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundUrlContext {
    /// Remote-proxy / upstream fetch path.
    Upstream,
    /// Webhook delivery target path.
    Webhook,
    /// OIDC/SSO discovery, token, JWKS and userinfo fetch path against a
    /// configured identity provider.
    SsoDiscovery,
}

impl OutboundUrlContext {
    /// Name of the env var that, when set to a truthy value, exempts
    /// RFC1918 / IPv6 unique-local addresses for this context.
    fn env_var(self) -> &'static str {
        match self {
            OutboundUrlContext::Upstream => "UPSTREAM_ALLOW_PRIVATE_IPS",
            OutboundUrlContext::Webhook => "WEBHOOK_ALLOW_PRIVATE_IPS",
            OutboundUrlContext::SsoDiscovery => "SSO_ALLOW_PRIVATE_IPS",
        }
    }
}

/// Validate that a URL is safe for the server to contact (anti-SSRF) in
/// the upstream / remote-proxy context. Reads `UPSTREAM_ALLOW_PRIVATE_IPS`
/// for the private-IP relaxation toggle.
///
/// Rejects private/internal IPs, known cloud metadata endpoints, and
/// Docker-internal service hostnames. `label` is used in error messages
/// (e.g. "Remote instance URL", "PyPI upstream file URL").
///
/// For webhook URLs use [`validate_outbound_webhook_url`] which reads
/// the separate `WEBHOOK_ALLOW_PRIVATE_IPS` env var so test clusters
/// can relax one surface without defeating the SSRF guard on the other.
pub fn validate_outbound_url(url_str: &str, label: &str) -> Result<()> {
    validate_outbound_url_with(url_str, label, OutboundUrlContext::Upstream)
}

/// Validate a webhook delivery target URL (anti-SSRF). Reads
/// `WEBHOOK_ALLOW_PRIVATE_IPS` for the private-IP relaxation toggle.
///
/// Functionally identical to [`validate_outbound_url`] except for which
/// env var gates the RFC1918 / IPv6 unique-local relaxation. Split out
/// in issue #1435 so a test cluster that enables webhook tests against a
/// local mock receiver does not also relax the SSRF guard for remote
/// proxy upstream URLs (and vice versa).
pub fn validate_outbound_webhook_url(url_str: &str, label: &str) -> Result<()> {
    validate_outbound_url_with(url_str, label, OutboundUrlContext::Webhook)
}

/// Validate an OIDC/SSO endpoint URL (discovery, token, JWKS, userinfo)
/// for a *configured, trusted* identity provider (anti-SSRF). Reads
/// `SSO_ALLOW_PRIVATE_IPS` for the private-IP relaxation toggle, and also
/// honors the shared `AK_SSRF_ALLOW_PRIVATE_CIDRS` allowlist.
///
/// Split out in issue #1891: the SSRF hardening in #1832 validated these
/// fetches with the `Upstream` context, so an internal-Keycloak / private
/// IdP deployment could only log in by setting `UPSTREAM_ALLOW_PRIVATE_IPS`
/// — which also reopens the remote-proxy upstream surface to arbitrary
/// private IPs. This dedicated context lets the configured IdP at a private
/// address be reachable without that side effect. The metadata / loopback /
/// link-local hard-blocks still apply (see [`is_hard_blocked_ipv4`]).
///
/// When a request is blocked because the target resolved to a private /
/// internal address, the returned error names the config knobs the
/// operator can use, so the failure is actionable instead of opaque.
pub fn validate_outbound_sso_url(url_str: &str, label: &str) -> Result<()> {
    match validate_outbound_url_with(url_str, label, OutboundUrlContext::SsoDiscovery) {
        Ok(()) => Ok(()),
        // Only the private/internal-IP block is operator-fixable via an
        // allowlist knob; surface guidance for it. Hostname blocks (cloud
        // metadata service names) and loopback are deliberate hard-blocks
        // and must not advertise a bypass.
        Err(AppError::Validation(msg)) if msg.contains("private/internal network") => {
            Err(AppError::Validation(format!(
                "{msg}. The identity provider resolves to a private/internal \
                 address. If this IdP is trusted, allow it by setting \
                 AK_SSRF_ALLOW_PRIVATE_CIDRS to the IdP host/CIDR (preferred, \
                 e.g. AK_SSRF_ALLOW_PRIVATE_CIDRS=10.10.0.8/32) or \
                 SSO_ALLOW_PRIVATE_IPS=true to allow all private IPs for SSO. \
                 Cloud metadata, loopback and link-local addresses stay blocked."
            )))
        }
        Err(other) => Err(other),
    }
}

/// Validate an LDAP server URL (`ldap://` or `ldaps://`) against the SSRF
/// allowlist, reusing the same blocked-host / private-IP rules as
/// [`validate_outbound_url`]. Split out because the shared validator
/// rejects any non-http(s) scheme (so the LDAP schemes cannot be passed
/// through it) and because LDAP uses the `Upstream` context so the
/// existing `UPSTREAM_ALLOW_PRIVATE_IPS` / `AK_SSRF_ALLOW_PRIVATE_CIDRS`
/// operator escape hatches relax it uniformly.
///
/// This checks the string / literal-IP form (and, for DNS names, the
/// resolution at validation time, like [`is_blocked_url_in`]). The
/// connect-time resolved-IP re-check is done by the connectivity probe
/// via [`is_blocked_resolved_ip`] so already-stored configs and the
/// DNS-rebind window are also covered.
pub fn validate_outbound_ldap_url(url_str: &str, label: &str) -> Result<()> {
    let remainder = if let Some(rest) = url_str.strip_prefix("ldaps://") {
        rest
    } else if let Some(rest) = url_str.strip_prefix("ldap://") {
        rest
    } else {
        return Err(AppError::Validation(format!(
            "{} must use ldap or ldaps",
            label
        )));
    };

    // Keep only the authority (drop any path/query/fragment and userinfo),
    // then extract the host (bracket-aware for IPv6 literals).
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or(remainder);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = ldap_authority_host(authority);
    if host.is_empty() {
        return Err(AppError::Validation(format!("{} must have a host", label)));
    }

    if let Some(reason) = is_blocked_host_str(host, OutboundUrlContext::Upstream) {
        record_block(label, &reason);
        return Err(block_reason_to_error(label, reason));
    }

    Ok(())
}

/// Extract the host portion (keeping IPv6 brackets) from an LDAP
/// `host[:port]` authority. Bracket-aware so `[::1]:389` yields `[::1]`
/// rather than splitting inside the address.
fn ldap_authority_host(authority: &str) -> &str {
    if authority.starts_with('[') {
        // IPv6 literal: host runs up to and including the closing bracket.
        if let Some(end) = authority.find(']') {
            return &authority[..=end];
        }
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((h, _)) => h,
        None => authority,
    }
}

/// True when a resolved IP must not be contacted from the server in the
/// upstream context (honors `UPSTREAM_ALLOW_PRIVATE_IPS` /
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS`). Used by the LDAP `/test` connectivity
/// probe to re-check the resolved address before opening a socket, which
/// closes the literal-IP and hostname-resolution (DNS) port-scan oracle
/// for already-stored configs.
pub fn is_blocked_resolved_ip(ip: std::net::IpAddr) -> bool {
    is_blocked_ip_in(ip, OutboundUrlContext::Upstream)
}

/// Common implementation shared by the per-context validators. The
/// `ctx` selects which env var the private-IP relaxation toggle reads.
fn validate_outbound_url_with(url_str: &str, label: &str, ctx: OutboundUrlContext) -> Result<()> {
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

    if let Some(reason) = is_blocked_url_in(&parsed, ctx) {
        record_block(label, &reason);
        return Err(block_reason_to_error(label, reason));
    }

    Ok(())
}

/// Map a [`BlockReason`] to the user-facing [`AppError::Validation`] with
/// the standard message wording. Shared by [`validate_outbound_url_with`]
/// and [`validate_outbound_ldap_url`] so the host/IP messages stay
/// identical across surfaces.
fn block_reason_to_error(label: &str, reason: BlockReason) -> AppError {
    match reason {
        BlockReason::Hostname(host) => {
            AppError::Validation(format!("{} host '{}' is not allowed", label, host))
        }
        BlockReason::Ip(ip) => AppError::Validation(format!(
            "{} IP '{}' is not allowed (private/internal network)",
            label, ip
        )),
    }
}

/// Decide whether a parsed URL targets a blocked address. Used by the
/// redirect policy on the shared HTTP client. Uses the `Upstream`
/// context (i.e. honors `UPSTREAM_ALLOW_PRIVATE_IPS`) because the
/// redirect policy fires on every outbound HTTP, including upstream
/// proxy fetches. Webhook delivery code paths re-validate the final URL
/// with [`validate_outbound_webhook_url`] before sending, so a webhook
/// that depends on `WEBHOOK_ALLOW_PRIVATE_IPS` does not need the
/// redirect policy to also relax under the webhook env var.
pub(crate) fn is_blocked_url(url: &reqwest::Url) -> Option<BlockReason> {
    is_blocked_url_in(url, OutboundUrlContext::Upstream)
}

/// Context-aware variant of [`is_blocked_url`]. Returning `Some(_)`
/// means the request must not be issued for the given context.
fn is_blocked_url_in(url: &reqwest::Url, ctx: OutboundUrlContext) -> Option<BlockReason> {
    let host = url.host_str()?;
    is_blocked_host_str(host, ctx)
}

/// Decide whether a host string (a DNS name or an IP literal, possibly
/// bracketed for IPv6 like `[::1]`) targets a blocked address for the
/// given context. Factored out of [`is_blocked_url_in`] so the
/// `BLOCKED_HOSTS` list, literal-IP rules, and hostname-resolution step
/// live in one place and are shared by [`validate_outbound_ldap_url`]
/// (which cannot reuse the http(s)-only [`validate_outbound_url`]).
fn is_blocked_host_str(host: &str, ctx: OutboundUrlContext) -> Option<BlockReason> {
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
        if is_blocked_ip_in(ip, ctx) {
            return Some(BlockReason::Ip(ip));
        }
        // An IP literal carries no DNS resolution step, so once the IP
        // itself is cleared there is nothing more to check.
        return None;
    }

    // The host is a DNS name, not an IP literal. The string-based checks
    // above (BLOCKED_HOSTS) only catch known service names, so an
    // arbitrary internal container/service name would otherwise sail
    // through and the server would issue the request. Resolve the
    // hostname and re-run the private/internal/loopback/link-local checks
    // against EVERY resolved address; reject if any one of them is
    // internal. `(host, 0)` performs a getaddrinfo lookup; the port is
    // irrelevant to the IP classification.
    //
    // Residual gap (see module docs): this resolves at validation time,
    // so a DNS-rebinding attacker who returns a public IP here and a
    // private IP at fetch time is not caught by this check alone. Pinning
    // the resolved address into the request (reqwest `resolve_to_addrs`)
    // is the follow-up that closes the TOCTOU window.
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (host_normalized, 0u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            if is_blocked_ip_in(ip, ctx) {
                return Some(BlockReason::Ip(ip));
            }
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
/// Private-IP allowlist (issues #976, #1224, #1435): operators on
/// corporate networks with no public internet, or in-cluster test
/// fixtures that need to reach a mock upstream on a pod CIDR, may need
/// to point upstreams at internal mirrors. Three opt-in escape hatches:
///
/// - `UPSTREAM_ALLOW_PRIVATE_IPS=true` — allow all RFC1918 + IPv6
///   unique-local for the **upstream / remote-proxy** path.
/// - `WEBHOOK_ALLOW_PRIVATE_IPS=true` — same relaxation but for the
///   **webhook delivery** path. Split from the upstream toggle in
///   issue #1435 so a test cluster that enables one surface does not
///   silently relax the other.
/// - `AK_SSRF_ALLOW_PRIVATE_CIDRS=10.0.0.0/8,192.168.7.0/24` — more
///   precise: only the listed CIDRs are exempted, and this allowlist
///   applies to **both** contexts. Same metadata / loopback hard-blocks
///   apply. Wins over the blanket toggle if both are set (allowlist is
///   strictly more restrictive).
///   `UPSTREAM_PRIVATE_IP_ALLOWLIST` is accepted as a backward-compatible
///   alias; if both are set, `AK_SSRF_ALLOW_PRIVATE_CIDRS` takes
///   precedence.
///
/// Cloud metadata IPs (169.254.169.254, 192.0.0.192, 100.100.100.200)
/// and loopback / link-local / unspecified remain blocked under every
/// relaxation, since those are SSRF targets, not "internal mirrors".
///
/// Context-aware: selects which env var gates the private-IP allowlist.
fn is_blocked_ip_in(ip: std::net::IpAddr, ctx: OutboundUrlContext) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4, ctx),
        std::net::IpAddr::V6(v6) => is_blocked_ipv6(v6, ctx),
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

fn is_blocked_ipv4(v4: std::net::Ipv4Addr, ctx: OutboundUrlContext) -> bool {
    // Hard blocks first: metadata IPs and loopback are never unblocked
    // by the private-IP allowlist toggle.
    if is_hard_blocked_ipv4(v4) {
        return true;
    }
    let octets = v4.octets();
    if v4.is_private() {
        return !private_ip_allowed(std::net::IpAddr::V4(v4), ctx);
    }
    if cgnat_block_enabled()
        && octets[0] == 100
        && (octets[1] & CGNAT_SECOND_OCTET_MASK) == CGNAT_SECOND_OCTET_PREFIX
    {
        return true;
    }
    false
}

fn is_blocked_ipv6(v6: std::net::Ipv6Addr, ctx: OutboundUrlContext) -> bool {
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
        return !private_ip_allowed(std::net::IpAddr::V6(v6), ctx);
    }
    // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
    // forms must obey the IPv4 rules so attackers cannot bypass them
    // by writing the v4 address inside a v6 literal.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_blocked_ipv4(v4, ctx);
    }
    if let Some(v4) = v6.to_ipv4() {
        return is_blocked_ipv4(v4, ctx);
    }
    false
}

/// Whether the operator has opted the given private IP into the
/// allowlist for the given context. Returns false (i.e. block) by
/// default. Order:
///
/// 1. If `AK_SSRF_ALLOW_PRIVATE_CIDRS` (or its backward-compatible
///    alias `UPSTREAM_PRIVATE_IP_ALLOWLIST`) is set, only IPs inside
///    one of those CIDRs are exempted. The blanket toggle is ignored.
///    If both are set, `AK_SSRF_ALLOW_PRIVATE_CIDRS` wins so the
///    canonical name is the operator's source of truth. The allowlist
///    applies to both contexts.
/// 2. Otherwise, the per-context blanket toggle is consulted:
///    `UPSTREAM_ALLOW_PRIVATE_IPS=true` for the upstream/remote-proxy
///    path, `WEBHOOK_ALLOW_PRIVATE_IPS=true` for the webhook path.
///    Issue #1435 split these so relaxing one does not silently relax
///    the other.
///
/// Metadata IPs and loopback are checked separately and are never
/// reachable through this path (see `is_hard_blocked_ipv4`).
fn private_ip_allowed(ip: std::net::IpAddr, ctx: OutboundUrlContext) -> bool {
    if let Some(list) = private_cidr_allowlist_value() {
        return cidr_list_contains(&list, ip);
    }
    allow_private_ips_enabled(ctx)
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
    allow_private_ips_enabled(OutboundUrlContext::Upstream)
}

/// True when `WEBHOOK_ALLOW_PRIVATE_IPS` is set to a truthy value.
/// Mirror of [`upstream_allow_private_ips_enabled`] for the webhook
/// surface (issue #1435).
pub fn webhook_allow_private_ips_enabled() -> bool {
    allow_private_ips_enabled(OutboundUrlContext::Webhook)
}

/// True when `SSO_ALLOW_PRIVATE_IPS` is set to a truthy value. Mirror of
/// [`upstream_allow_private_ips_enabled`] for the OIDC/SSO discovery
/// surface (issue #1891).
pub fn sso_allow_private_ips_enabled() -> bool {
    allow_private_ips_enabled(OutboundUrlContext::SsoDiscovery)
}

/// Context-aware truthy-env parse. Single source of truth for the
/// "allow private IPs" vocabulary so `1` / `true` / `TRUE` are
/// recognised identically by both surfaces.
fn allow_private_ips_enabled(ctx: OutboundUrlContext) -> bool {
    match std::env::var(ctx.env_var()) {
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
    fn test_rejects_hostname_resolving_to_internal() {
        // Regression: a hostname that is NOT in BLOCKED_HOSTS but
        // resolves (getaddrinfo) to an internal/loopback address must be
        // rejected. Before the resolution step was added, an arbitrary
        // internal container/service name sailed past the string checks
        // and the server issued the outbound request (SSRF).
        //
        // `localhost.localdomain` is the test vehicle: it is not a
        // BLOCKED_HOSTS entry (and does not match the `.localhost`
        // suffix), yet glibc resolves it to loopback. The assertion is
        // guarded so the test does not flake on resolver setups that
        // cannot resolve it — but where it does resolve to an internal
        // IP, blocking is mandatory.
        use std::net::ToSocketAddrs;
        let host = "localhost.localdomain";
        let resolves_internal = (host, 0u16)
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .into_iter()
                    .any(|a| is_blocked_ip_in(a.ip(), OutboundUrlContext::Upstream))
            })
            .unwrap_or(false);
        if resolves_internal {
            assert_blocked_ip(&format!("http://{host}/api"));
        }
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
        prev_webhook: Option<String>,
        prev_sso: Option<String>,
        prev_list: Option<String>,
        prev_ssrf: Option<String>,
    }

    impl AllowlistGuard {
        fn new() -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            let g = Self {
                _lock: lock,
                prev_allow: std::env::var("UPSTREAM_ALLOW_PRIVATE_IPS").ok(),
                prev_webhook: std::env::var("WEBHOOK_ALLOW_PRIVATE_IPS").ok(),
                prev_sso: std::env::var("SSO_ALLOW_PRIVATE_IPS").ok(),
                prev_list: std::env::var("UPSTREAM_PRIVATE_IP_ALLOWLIST").ok(),
                prev_ssrf: std::env::var("AK_SSRF_ALLOW_PRIVATE_CIDRS").ok(),
            };
            std::env::remove_var("UPSTREAM_ALLOW_PRIVATE_IPS");
            std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS");
            std::env::remove_var("SSO_ALLOW_PRIVATE_IPS");
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
            match &self.prev_webhook {
                Some(v) => std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", v),
                None => std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS"),
            }
            match &self.prev_sso {
                Some(v) => std::env::set_var("SSO_ALLOW_PRIVATE_IPS", v),
                None => std::env::remove_var("SSO_ALLOW_PRIVATE_IPS"),
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

    // -----------------------------------------------------------------------
    // Issue #1435: env-var split between upstream and webhook private-IP
    // relaxation. Relaxing one surface must not silently relax the other.
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_validator_ignores_upstream_env_var() {
        // The webhook validator must NOT honor UPSTREAM_ALLOW_PRIVATE_IPS.
        // This is the security regression: the test cluster previously set
        // UPSTREAM_ALLOW_PRIVATE_IPS=1 to allow webhook tests, which also
        // defeated the SSRF guard for remote-proxy upstream URLs. After the
        // split, only WEBHOOK_ALLOW_PRIVATE_IPS relaxes the webhook path.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        let result = validate_outbound_webhook_url("http://10.0.0.1/hook", "Webhook URL");
        assert!(
            result.is_err(),
            "webhook validator must reject 10.0.0.1 when only UPSTREAM_ALLOW_PRIVATE_IPS is set"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("private/internal network"),
            "expected IP-block rejection, got: {msg}"
        );
    }

    #[test]
    fn test_upstream_validator_ignores_webhook_env_var() {
        // Inverse of the above: setting WEBHOOK_ALLOW_PRIVATE_IPS must
        // NOT relax the upstream / remote-proxy validator.
        let _g = AllowlistGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        let result = validate_outbound_url("http://10.0.0.1/upstream", "Upstream URL");
        assert!(
            result.is_err(),
            "upstream validator must reject 10.0.0.1 when only WEBHOOK_ALLOW_PRIVATE_IPS is set"
        );
    }

    #[test]
    fn test_webhook_validator_accepts_rfc1918_when_webhook_env_set() {
        // Positive case: the new webhook env var actually relaxes the
        // webhook surface so the test cluster's mock receiver remains
        // reachable after the rename.
        let _g = AllowlistGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_webhook_url("http://10.0.0.1/hook", "Webhook URL").is_ok(),
            "10.0.0.1 must be allowed for webhook URLs when WEBHOOK_ALLOW_PRIVATE_IPS=true"
        );
        assert!(
            validate_outbound_webhook_url("http://192.168.7.5/hook", "Webhook URL").is_ok(),
            "192.168.7.5 must be allowed for webhook URLs when WEBHOOK_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_webhook_validator_still_blocks_loopback_with_webhook_env() {
        // Loopback is the AK process itself. WEBHOOK_ALLOW_PRIVATE_IPS
        // must NEVER unblock 127.0.0.1 or ::1, since that would let a
        // webhook reach admin endpoints colocated on the same host.
        let _g = AllowlistGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_webhook_url("http://127.0.0.1:9090/hook", "Webhook URL").is_err(),
            "127.0.0.1 must stay blocked even with WEBHOOK_ALLOW_PRIVATE_IPS=true"
        );
        assert!(
            validate_outbound_webhook_url("http://[::1]:8080/hook", "Webhook URL").is_err(),
            "::1 must stay blocked even with WEBHOOK_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_webhook_validator_still_blocks_metadata_with_webhook_env() {
        // Cloud metadata IPs are the canonical SSRF target. They must
        // NEVER be reachable through the webhook surface, regardless of
        // env-var relaxation.
        let _g = AllowlistGuard::new();
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(validate_outbound_webhook_url(
            "http://169.254.169.254/latest/meta-data",
            "Webhook URL"
        )
        .is_err());
        assert!(
            validate_outbound_webhook_url("http://192.0.0.192/opc/v2/instance", "Webhook URL")
                .is_err()
        );
        assert!(validate_outbound_webhook_url(
            "http://100.100.100.200/latest/meta-data",
            "Webhook URL"
        )
        .is_err());
    }

    #[test]
    fn test_named_cidr_allowlist_applies_to_both_contexts() {
        // AK_SSRF_ALLOW_PRIVATE_CIDRS is a positive allowlist that
        // operators curate explicitly. It applies to BOTH contexts.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.244.0.0/16");
        assert!(
            validate_outbound_webhook_url("http://10.244.0.5/hook", "Webhook URL").is_ok(),
            "named allowlist must apply to webhook context"
        );
        assert!(
            validate_outbound_url("http://10.244.0.5/upstream", "Upstream URL").is_ok(),
            "named allowlist must apply to upstream context"
        );
        // Outside the allowlist: both contexts still block.
        assert!(validate_outbound_webhook_url("http://10.0.0.1/hook", "Webhook URL").is_err());
        assert!(validate_outbound_url("http://10.0.0.1/upstream", "Upstream URL").is_err());
    }

    #[test]
    fn test_webhook_allow_private_ips_enabled_helper() {
        // Boot-time helper used by main.rs to log the security posture.
        let _g = AllowlistGuard::new();
        assert!(!webhook_allow_private_ips_enabled());
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(webhook_allow_private_ips_enabled());
        // Truthy vocabulary mirrors UPSTREAM_ALLOW_PRIVATE_IPS.
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "1");
        assert!(webhook_allow_private_ips_enabled());
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "maybe");
        assert!(!webhook_allow_private_ips_enabled());
    }

    // -----------------------------------------------------------------------
    // Issue #1891: dedicated SSO/OIDC discovery context. A configured,
    // trusted IdP at a private IP must be reachable WITHOUT relaxing the
    // upstream-proxy or webhook SSRF guards, and without unblocking
    // metadata / loopback / link-local.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sso_blocks_private_idp_by_default() {
        // Reproduces the regression in #1891: a private-IP IdP is blocked
        // out of the box, with the standard private-network message.
        let _g = AllowlistGuard::new();
        let err = validate_outbound_sso_url(
            "https://10.10.0.8/realms/x/.well-known/openid-configuration",
            "OIDC discovery URL",
        )
        .expect_err("private IdP must be blocked by default");
        assert!(err.to_string().contains("private/internal network"));
    }

    #[test]
    fn test_sso_error_names_the_config_knobs() {
        // The failure must be actionable: name the allowlist knobs so the
        // operator is not left with an opaque VALIDATION_ERROR.
        let _g = AllowlistGuard::new();
        let err = validate_outbound_sso_url(
            "https://10.10.0.8/realms/x/.well-known/openid-configuration",
            "OIDC discovery URL",
        )
        .expect_err("private IdP must be blocked by default");
        let msg = err.to_string();
        assert!(
            msg.contains("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
            "error must mention the preferred CIDR knob: {msg}"
        );
        assert!(
            msg.contains("SSO_ALLOW_PRIVATE_IPS"),
            "error must mention the SSO blanket knob: {msg}"
        );
    }

    #[test]
    fn test_sso_blanket_toggle_unblocks_private_idp() {
        // SSO_ALLOW_PRIVATE_IPS=true allows the configured private IdP.
        let _g = AllowlistGuard::new();
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_sso_url(
                "https://10.10.0.8/realms/x/.well-known/openid-configuration",
                "OIDC discovery URL",
            )
            .is_ok(),
            "10.10.0.8 must be allowed for SSO when SSO_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_sso_cidr_allowlist_scopes_to_idp_host() {
        // Preferred narrow knob: only the IdP /32 is exempted; another
        // private IP outside the CIDR is still blocked for SSO.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.10.0.8/32");
        assert!(
            validate_outbound_sso_url("https://10.10.0.8/realms/x", "OIDC discovery URL").is_ok(),
            "configured IdP /32 must be allowed via AK_SSRF_ALLOW_PRIVATE_CIDRS"
        );
        assert!(
            validate_outbound_sso_url("https://10.10.0.9/realms/x", "OIDC discovery URL").is_err(),
            "a private IP outside the allowlisted CIDR must stay blocked for SSO"
        );
    }

    #[test]
    fn test_sso_toggle_does_not_relax_upstream_or_webhook() {
        // The whole point of the separate context: enabling SSO private
        // IPs must NOT reopen the upstream-proxy or webhook SSRF surfaces.
        let _g = AllowlistGuard::new();
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_url("http://10.10.0.8/upstream", "Upstream URL").is_err(),
            "SSO toggle must not relax the upstream context"
        );
        assert!(
            validate_outbound_webhook_url("http://10.10.0.8/hook", "Webhook URL").is_err(),
            "SSO toggle must not relax the webhook context"
        );
    }

    #[test]
    fn test_upstream_and_webhook_toggles_do_not_relax_sso() {
        // Inverse direction: relaxing the other surfaces must not silently
        // open the SSO surface to arbitrary private IdPs.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_sso_url("http://10.10.0.8/realms/x", "OIDC discovery URL").is_err(),
            "upstream/webhook toggles must not relax the SSO context"
        );
    }

    #[test]
    fn test_sso_toggle_still_blocks_metadata_loopback_linklocal() {
        // Hard blocks must hold even with the blanket SSO toggle on.
        let _g = AllowlistGuard::new();
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_sso_url(
                "http://169.254.169.254/latest/meta-data",
                "OIDC discovery URL"
            )
            .is_err(),
            "AWS metadata IP must stay blocked for SSO"
        );
        assert!(
            validate_outbound_sso_url("http://[::ffff:169.254.169.254]/", "OIDC discovery URL")
                .is_err(),
            "IPv4-mapped metadata IP must stay blocked for SSO"
        );
        assert!(
            validate_outbound_sso_url("http://127.0.0.1/realms/x", "OIDC discovery URL").is_err(),
            "loopback must stay blocked for SSO"
        );
        assert!(
            validate_outbound_sso_url("http://[::1]/realms/x", "OIDC discovery URL").is_err(),
            "IPv6 loopback must stay blocked for SSO"
        );
        assert!(
            validate_outbound_sso_url("http://169.254.5.5/realms/x", "OIDC discovery URL").is_err(),
            "link-local must stay blocked for SSO"
        );
    }

    #[test]
    fn test_sso_cidr_allowlist_still_blocks_metadata() {
        // Even if an operator over-broadly allowlists a range that contains
        // a metadata IP, the metadata hard-block fires first.
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "169.254.0.0/16");
        assert!(
            validate_outbound_sso_url(
                "http://169.254.169.254/latest/meta-data",
                "OIDC discovery URL"
            )
            .is_err(),
            "metadata IP must stay blocked for SSO even if its range is allowlisted"
        );
    }

    #[test]
    fn test_sso_allows_public_idp() {
        let _g = AllowlistGuard::new();
        assert!(
            validate_outbound_sso_url(
                "https://keycloak.example.com/realms/x/.well-known/openid-configuration",
                "OIDC discovery URL",
            )
            .is_ok(),
            "public IdP must be allowed without any toggle"
        );
    }

    #[test]
    fn test_sso_allow_private_ips_enabled_helper() {
        let _g = AllowlistGuard::new();
        assert!(!sso_allow_private_ips_enabled());
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "true");
        assert!(sso_allow_private_ips_enabled());
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "1");
        assert!(sso_allow_private_ips_enabled());
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "maybe");
        assert!(!sso_allow_private_ips_enabled());
    }

    // -----------------------------------------------------------------------
    // LDAP outbound URL validation (validate_outbound_ldap_url). Reuses the
    // same blocked-host / private-IP rules as validate_outbound_url but
    // accepts the ldap:// / ldaps:// schemes (which the http(s)-only
    // validator rejects).
    // -----------------------------------------------------------------------

    #[test]
    fn test_ldap_allows_public_ldaps_with_port() {
        assert!(
            validate_outbound_ldap_url("ldaps://ldap.example.com:636", "LDAP server URL").is_ok()
        );
    }

    #[test]
    fn test_ldap_allows_public_ldap_default_port() {
        assert!(validate_outbound_ldap_url("ldap://ldap.example.com", "LDAP server URL").is_ok());
    }

    #[test]
    fn test_ldap_rejects_private_ip() {
        let _g = AllowlistGuard::new();
        let err = validate_outbound_ldap_url("ldap://10.0.0.1", "LDAP server URL")
            .expect_err("private IP must be rejected");
        assert!(err.to_string().contains("private/internal network"));
    }

    #[test]
    fn test_ldap_rejects_ipv6_loopback() {
        let err = validate_outbound_ldap_url("ldap://[::1]:389", "LDAP server URL")
            .expect_err("ipv6 loopback must be rejected");
        assert!(err.to_string().contains("private/internal network"));
    }

    #[test]
    fn test_ldap_rejects_localhost() {
        let err = validate_outbound_ldap_url("ldap://localhost", "LDAP server URL")
            .expect_err("localhost must be rejected");
        assert!(err.to_string().contains("is not allowed"));
    }

    #[test]
    fn test_ldap_rejects_docker_service_host() {
        // BLOCKED_HOSTS entry — the string check catches it with no DNS.
        let err = validate_outbound_ldap_url("ldaps://postgres", "LDAP server URL")
            .expect_err("internal docker host must be rejected");
        assert!(err.to_string().contains("is not allowed"));
    }

    #[test]
    fn test_ldap_rejects_non_ldap_scheme() {
        assert!(validate_outbound_ldap_url("http://ldap.example.com", "LDAP server URL").is_err());
        assert!(validate_outbound_ldap_url("https://ldap.example.com", "LDAP server URL").is_err());
        assert!(validate_outbound_ldap_url("ldap.example.com:389", "LDAP server URL").is_err());
    }

    #[test]
    fn test_ldap_rejects_hostname_resolving_to_internal() {
        // Mirror of test_rejects_hostname_resolving_to_internal: a non-listed
        // hostname that resolves to an internal IP must be rejected by the
        // resolution step. Guarded so it does not flake where the name does
        // not resolve (e.g. ak-rt-db is a Docker-network-only name).
        use std::net::ToSocketAddrs;
        let host = "localhost.localdomain";
        let resolves_internal = (host, 0u16)
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .into_iter()
                    .any(|a| is_blocked_ip_in(a.ip(), OutboundUrlContext::Upstream))
            })
            .unwrap_or(false);
        if resolves_internal {
            let err = validate_outbound_ldap_url(&format!("ldap://{host}"), "LDAP server URL")
                .expect_err("internal-resolving host must be rejected");
            assert!(err.to_string().contains("private/internal network"));
        }
    }

    #[test]
    fn test_ldap_allow_private_ips_toggle_unblocks() {
        // The existing Upstream escape hatch relaxes LDAP too (no new env var).
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(
            validate_outbound_ldap_url("ldap://10.0.0.5:389", "LDAP server URL").is_ok(),
            "private LDAP host must be allowed when UPSTREAM_ALLOW_PRIVATE_IPS=true"
        );
    }

    #[test]
    fn test_ldap_cidr_allowlist_relaxes_private() {
        let _g = AllowlistGuard::new();
        std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", "10.0.0.0/8");
        assert!(validate_outbound_ldap_url("ldap://10.1.2.3", "LDAP server URL").is_ok());
        // Outside the allowlisted CIDR — still blocked.
        assert!(validate_outbound_ldap_url("ldap://192.168.1.1", "LDAP server URL").is_err());
    }

    #[test]
    fn test_ldap_allow_private_ips_still_blocks_metadata_and_loopback() {
        // Even with the blanket toggle, metadata and loopback stay blocked.
        let _g = AllowlistGuard::new();
        std::env::set_var("UPSTREAM_ALLOW_PRIVATE_IPS", "true");
        assert!(validate_outbound_ldap_url("ldap://169.254.169.254", "LDAP server URL").is_err());
        assert!(validate_outbound_ldap_url("ldaps://127.0.0.1:636", "LDAP server URL").is_err());
    }

    #[test]
    fn test_is_blocked_resolved_ip_contract() {
        let _g = AllowlistGuard::new();
        // Loopback / private / metadata are blocked by default.
        assert!(is_blocked_resolved_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_resolved_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_resolved_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_resolved_ip("::1".parse().unwrap()));
        // A public IP passes.
        assert!(!is_blocked_resolved_ip("93.184.216.34".parse().unwrap()));
    }
}
