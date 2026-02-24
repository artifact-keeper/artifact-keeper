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
        "meilisearch",
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
        let is_blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
        if is_blocked {
            return Err(AppError::Validation(format!(
                "{} IP '{}' is not allowed (private/internal network)",
                label, ip
            )));
        }
    }

    Ok(())
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
    // Error message label
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_appears_in_error_message() {
        let result = validate_outbound_url("ftp://example.com", "Remote instance URL");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Remote instance URL"));
    }
}
