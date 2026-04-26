//! Shared input validation helpers.
//!
//! Centralizes URL and other validation logic used across multiple handlers
//! and services so that SSRF / injection rules are defined in one place.

use crate::error::{AppError, Result};

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

    let host_str = parsed
        .host_str()
        .ok_or_else(|| AppError::Validation(format!("{} must have a host", label)))?;

    // Block known internal/metadata hostnames
    let blocked_hosts = [
        "localhost",
        "metadata.google.internal",
        "metadata.azure.com",
        "169.254.169.254",
        "backend",
        "postgres",
        "redis",
        "opensearch",
        "trivy",
    ];
    let host_lower = host_str.to_lowercase();
    for blocked in &blocked_hosts {
        if host_lower == *blocked || host_lower.ends_with(&format!(".{}", blocked)) {
            return Err(AppError::Validation(format!(
                "{} host '{}' is not allowed",
                label, host_str
            )));
        }
    }

    // Block private/internal IP ranges.
    // host_str() returns brackets for IPv6 (e.g. "[::1]"), so strip them
    // before parsing as IpAddr.
    let bare_host = host_str
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host_str);
    if let Ok(ip) = bare_host.parse::<std::net::IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(AppError::Validation(format!(
                "{} IP '{}' is not allowed (private/internal network)",
                label, ip
            )));
        }
    }

    Ok(())
}

/// Return true when an IP must not be contacted from server-side requests.
///
/// Covers:
/// - IPv4 loopback / RFC1918 private / link-local / unspecified / broadcast
/// - Cloud-provider metadata IPs that fall outside RFC1918 (Oracle Cloud
///   `192.0.0.192`, Alibaba Cloud `100.100.100.200` in the CGNAT range)
/// - IPv6 loopback (`::1`), unspecified (`::`), link-local (`fe80::/10`),
///   unique-local (`fc00::/7`)
/// - IPv4-mapped IPv6 (`::ffff:0:0/96`) — these would otherwise let an
///   attacker bypass the IPv4 checks by writing
///   `http://[::ffff:169.254.169.254]/` or `http://[::ffff:127.0.0.1]/`.
///   We unwrap the embedded IPv4 and re-evaluate the IPv4 rules.
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped IPv6 so the IPv4 rules apply.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            // The deprecated IPv4-compatible IPv6 form (::a.b.c.d) is also
            // treated as an IPv4 alias for safety.
            if let Some(v4) = v6.to_ipv4() {
                if !v6.is_loopback() && !v6.is_unspecified() {
                    return is_blocked_ipv4(v4);
                }
            }

            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }

            // IPv6 link-local: fe80::/10
            let segs = v6.segments();
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // IPv6 unique-local: fc00::/7
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            false
        }
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
    // Oracle Cloud metadata: 192.0.0.192 (in IETF Protocol Assignments range).
    if octets == [192, 0, 0, 192] {
        return true;
    }
    // Alibaba Cloud metadata: 100.100.100.200 lives in the CGNAT range
    // (100.64.0.0/10, RFC 6598). Block the entire CGNAT range to cover
    // metadata IPs and other carrier-internal addresses.
    if octets[0] == 100 && (octets[1] & 0xc0) == 0x40 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Valid URLs
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
    // Private / internal IPs
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_loopback() {
        assert!(validate_outbound_url("http://127.0.0.1:9090", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_10_network() {
        assert!(validate_outbound_url("http://10.0.0.1/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_172_16_network() {
        assert!(validate_outbound_url("http://172.16.0.1/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_192_168_network() {
        assert!(validate_outbound_url("http://192.168.1.1/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_link_local() {
        assert!(
            validate_outbound_url("http://169.254.169.254/latest/meta-data", "Test URL").is_err()
        );
    }

    #[test]
    fn test_rejects_zero_ip() {
        assert!(validate_outbound_url("http://0.0.0.0/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_ipv6_loopback() {
        assert!(validate_outbound_url("http://[::1]:8080/api", "Test URL").is_err());
    }

    // -----------------------------------------------------------------------
    // SSRF bypasses via IPv4-mapped IPv6 addresses (e.g. via upstream
    // config.json `dl` field for Cargo registries). Without explicit
    // handling, `::ffff:169.254.169.254` parses as an IPv6 address whose
    // `is_loopback()` / `is_unspecified()` are false, slipping past the
    // private-IP check.
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_ipv4_mapped_loopback() {
        assert!(
            validate_outbound_url("http://[::ffff:127.0.0.1]/api", "Test URL").is_err(),
            "::ffff:127.0.0.1 must be rejected (IPv4-mapped loopback)"
        );
    }

    #[test]
    fn test_rejects_ipv4_mapped_aws_metadata() {
        assert!(
            validate_outbound_url(
                "http://[::ffff:169.254.169.254]/latest/meta-data",
                "Cargo upstream download URL"
            )
            .is_err(),
            "::ffff:169.254.169.254 must be rejected (IPv4-mapped AWS metadata)"
        );
    }

    #[test]
    fn test_rejects_ipv4_mapped_private_10() {
        assert!(
            validate_outbound_url("http://[::ffff:10.0.0.1]/api", "Test URL").is_err(),
            "::ffff:10.0.0.1 must be rejected (IPv4-mapped RFC1918)"
        );
    }

    #[test]
    fn test_rejects_ipv6_link_local() {
        assert!(
            validate_outbound_url("http://[fe80::1]/api", "Test URL").is_err(),
            "fe80::/10 link-local must be rejected"
        );
    }

    #[test]
    fn test_rejects_ipv6_unique_local() {
        assert!(
            validate_outbound_url("http://[fc00::1]/api", "Test URL").is_err(),
            "fc00::/7 unique-local (fc00::1) must be rejected"
        );
        assert!(
            validate_outbound_url("http://[fd12:3456:789a::1]/api", "Test URL").is_err(),
            "fc00::/7 unique-local (fd00::/8) must be rejected"
        );
    }

    #[test]
    fn test_rejects_oracle_cloud_metadata_ip() {
        assert!(
            validate_outbound_url("http://192.0.0.192/opc/v2/instance", "Test URL").is_err(),
            "Oracle Cloud metadata IP 192.0.0.192 must be rejected"
        );
    }

    #[test]
    fn test_rejects_alibaba_metadata_ip() {
        assert!(
            validate_outbound_url("http://100.100.100.200/latest/meta-data", "Test URL").is_err(),
            "Alibaba Cloud metadata IP 100.100.100.200 must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // Blocked hostnames
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejects_localhost() {
        assert!(validate_outbound_url("http://localhost:8080/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_gcp_metadata() {
        assert!(validate_outbound_url(
            "http://metadata.google.internal/computeMetadata",
            "Test URL"
        )
        .is_err());
    }

    #[test]
    fn test_rejects_docker_backend() {
        assert!(validate_outbound_url("http://backend:8080/api", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_docker_postgres() {
        assert!(validate_outbound_url("http://postgres:5432", "Test URL").is_err());
    }

    #[test]
    fn test_rejects_docker_redis() {
        assert!(validate_outbound_url("http://redis:6379", "Test URL").is_err());
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
        // K8s deployments use single-label hostnames for intra-namespace services.
        // These must be allowed for remote repos pointing at other services.
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
}
