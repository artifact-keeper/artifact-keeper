//! Shared HTTP client builder with custom CA certificate support.
//!
//! All code that creates a `reqwest::Client` should call [`default_client`] for
//! a ready-to-use client, or [`base_client_builder`] when extra configuration
//! (timeouts, user-agent, etc.) is needed before building. This ensures that
//! custom CA certificates (configured via `CUSTOM_CA_CERT_PATH`) are loaded
//! consistently across the application.

use reqwest::redirect::Policy;
use reqwest::tls::Certificate;
use reqwest::ClientBuilder;

/// Maximum number of redirects we will follow even if every hop passes
/// the SSRF check. Matches reqwest's historical default and prevents
/// loops or pathological chains from tying up workers.
const MAX_REDIRECTS: usize = 10;

/// Return a [`ClientBuilder`] pre-loaded with custom CA certificates when
/// the `CUSTOM_CA_CERT_PATH` environment variable is set.
///
/// The variable should point to a PEM file containing one or more CA
/// certificates. This is required for HTTPS connections to internal services
/// (Artifactory, Nexus, remote repositories) that use certificates signed by
/// a private CA.
/// Log detected proxy environment variables once at startup so operators can
/// confirm that `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are (or are not)
/// reaching the backend process.
fn log_proxy_env() {
    use std::sync::Once;
    static LOG_ONCE: Once = Once::new();
    LOG_ONCE.call_once(|| {
        let https = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok();
        let http = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok();
        let all = std::env::var("ALL_PROXY")
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let no = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok();
        if https.is_some() || http.is_some() || all.is_some() {
            tracing::info!(
                https_proxy = ?https,
                http_proxy = ?http,
                all_proxy = ?all,
                no_proxy = ?no,
                "HTTP proxy configuration detected"
            );
        } else {
            tracing::debug!("No HTTP proxy environment variables set");
        }
    });
}

pub fn base_client_builder() -> ClientBuilder {
    log_proxy_env();

    let mut builder = reqwest::Client::builder().redirect(ssrf_redirect_policy());

    if let Ok(ca_path) = std::env::var("CUSTOM_CA_CERT_PATH") {
        match std::fs::read(&ca_path) {
            Ok(pem_bytes) => match Certificate::from_pem_bundle(&pem_bytes) {
                Ok(certs) => {
                    let count = certs.len();
                    for cert in certs {
                        builder = builder.add_root_certificate(cert);
                    }
                    tracing::info!(
                        path = %ca_path,
                        count,
                        "Loaded custom CA certificate(s)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %ca_path,
                        error = %e,
                        "Failed to parse CA certificate(s)"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %ca_path,
                    error = %e,
                    "Failed to read custom CA certificate file"
                );
            }
        }
    }

    builder
}

/// Build and return a ready-to-use [`reqwest::Client`] with custom CA
/// certificates and proxy support.
///
/// Panics if the client cannot be built (should not happen in practice).
pub fn default_client() -> reqwest::Client {
    base_client_builder()
        .build()
        .expect("failed to build default HTTP client")
}

/// Redirect policy that re-runs the SSRF allow-list on every hop. An
/// upstream returning `302 Location: http://[::ffff:127.0.0.1]/` would
/// otherwise defeat the entry-point validator. Caps at
/// [`MAX_REDIRECTS`] hops so a redirect loop cannot tie up a worker.
fn ssrf_redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        if let Some(reason) = crate::api::validation::is_blocked_url(attempt.url()) {
            tracing::warn!(
                target: "security",
                redirect_url = %attempt.url(),
                reason = reason.metric_label(),
                "blocking redirect to disallowed address"
            );
            crate::services::metrics_service::record_outbound_url_blocked(
                reason.metric_label(),
                "http-client redirect",
            );
            return attempt.error("redirect target rejected by SSRF policy");
        }
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::{base_client_builder, default_client};
    use std::io::Write;

    #[test]
    fn test_default_client_builds_successfully() {
        let _client = default_client();
    }

    #[test]
    fn test_base_client_builder_builds_successfully() {
        let _client = base_client_builder().build().unwrap();
    }

    #[test]
    fn test_base_client_builder_no_env() {
        // With no env var set, should return a working builder
        std::env::remove_var("CUSTOM_CA_CERT_PATH");
        let client = base_client_builder().build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_client_builder_with_valid_cert() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Valid self-signed CA cert generated with:
        // openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 365 -subj "/CN=Test CA"
        write!(
            tmp,
            "-----BEGIN CERTIFICATE-----\n\
             MIIDBTCCAe2gAwIBAgIULDO9ZudtvjOpTzI11LEMDEsxdb0wDQYJKoZIhvcNAQEL\n\
             BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAzMDUxODQwNDJaFw0yNzAzMDUx\n\
             ODQwNDJaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n\
             DwAwggEKAoIBAQC3M1eha4KpGf93bVk2peeCrhtp0QFeudqA08CwbiSLU/KeWPTu\n\
             1gXRyO504/LlQ8FqJ+kvUDYUsX2bqwigcTFpOSNiX/Ms3NY5T1yHUaH4UdtPCrPC\n\
             1K/ag7gQa59gvp1mzLawWKCvHJo+hsFIFbvu9vu1Dk2fNDs3FeGsmk2pZcuObtkR\n\
             6z4zfVhhlyIN93fiDYZMKeOoZ9yPcnIbRV3NXGBU+AjHgcMex7ixt9KR7OkKIuy9\n\
             0KqDCNTF1V1aJqmgwx+RySjc9r9JJbsW1DVjms+k0MvRv6DOzWYG3AmcOMalaD37\n\
             tfm+pyzfiSwJz+QTWmYGoS/HqFf+88gn74b1AgMBAAGjUzBRMB0GA1UdDgQWBBRE\n\
             yfyJHG9n6xslh6aNFDGPzBunMjAfBgNVHSMEGDAWgBREyfyJHG9n6xslh6aNFDGP\n\
             zBunMjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCg+qWepnd/\n\
             Ej7bE1cpXiSbhJhdoW/WE+AZod2taDta3BBrU6YU6K/KcbHD2wnyIY94P20XzbiI\n\
             YvlPxjY1eRbF1L/xEdHDweHnbLEQbu9M6rGbM9OD/2l1NN9rLBO1Bli+a7oi3C0P\n\
             k0Dfw/Ta0JUGggDG2y8mIqMhmh+yFZ04cWm+H+LNvDN8hfzYfFjUrmNPnwlnfAyv\n\
             iuc0yrPUPsb/RduVhnG5hlSezelJS4yqRQFj5ltfW+7ZWZwZZu4IV+HqZhcuIKQl\n\
             PT07CcV5QhaQZgfZPPaK3d2B877i3/VABan4hqhvUevK5ddhkXI+QrEn5bS+lhIO\n\
             n+W4ozi64uyI\n\
             -----END CERTIFICATE-----"
        )
        .unwrap();
        tmp.flush().unwrap();

        std::env::set_var("CUSTOM_CA_CERT_PATH", tmp.path().to_str().unwrap());
        let client = base_client_builder().build();
        assert!(client.is_ok());
        std::env::remove_var("CUSTOM_CA_CERT_PATH");
    }

    #[test]
    fn test_base_client_builder_missing_file() {
        std::env::set_var("CUSTOM_CA_CERT_PATH", "/nonexistent/cert.pem");
        // Should not panic, just warn and return a working builder
        let client = base_client_builder().build();
        assert!(client.is_ok());
        std::env::remove_var("CUSTOM_CA_CERT_PATH");
    }

    /// Regression test for the SSRF redirect-follow bypass: any redirect
    /// hop pointing at a blocked address must abort the request, not
    /// silently follow. A bare `reqwest::Client` would tolerate such a
    /// redirect; the policy installed by `base_client_builder` must not.
    #[tokio::test]
    async fn test_redirect_to_blocked_ip_is_refused() {
        // Spin up a tiny TCP listener that always returns
        // `302 Location: http://[::ffff:127.0.0.1]/` and tear down
        // after one connection.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Accept one connection, ignore the request, send a 302 to
            // an SSRF-bypass target. The client should refuse to
            // follow.
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\n\
                          Location: http://[::ffff:127.0.0.1]/admin\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        let client = base_client_builder().build().unwrap();
        let url = format!("http://127.0.0.1:{}/start", addr.port());
        // Bypassing `validate_outbound_url` deliberately — this test
        // exercises the redirect policy specifically. A request that
        // starts at 127.0.0.1 and is refused for THAT reason wouldn't
        // tell us anything about redirect protection. To target only
        // the redirect path, point at the listener and assert the
        // failure mentions the redirect.
        let result = client.get(&url).send().await;

        // Drain the server task.
        let _ = server.await;

        let err = result.expect_err("redirect to ::ffff:127.0.0.1 must be refused");
        assert!(
            err.to_string().contains("SSRF") || err.is_redirect(),
            "expected redirect-rejection error, got: {err}"
        );
    }
}
