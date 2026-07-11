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
use std::time::Duration;

/// Maximum number of redirects we will follow even if every hop passes
/// the SSRF check. Matches reqwest's historical default and prevents
/// loops or pathological chains from tying up workers.
const MAX_REDIRECTS: usize = 10;

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

/// Return a [`ClientBuilder`] pre-loaded with custom CA certificates when
/// the `CUSTOM_CA_CERT_PATH` environment variable is set.
///
/// The variable should point to a PEM file containing one or more CA
/// certificates. This is required for HTTPS connections to internal services
/// (Artifactory, Nexus, remote repositories) that use certificates signed by
/// a private CA.
pub fn base_client_builder() -> ClientBuilder {
    log_proxy_env();

    let builder = reqwest::Client::builder()
        .redirect(ssrf_redirect_policy())
        .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver());

    apply_custom_ca_cert(builder)
}

/// Return a [`ClientBuilder`] for **operator-configured, trusted
/// internal-service** endpoints (the scanner-adapter `TRIVY_ADAPTER_URL`,
/// Dependency-Track, OpenSCAP). It mirrors [`base_client_builder`] — same
/// custom-CA handling — but wires the SSRF DNS resolver and redirect policy
/// in the trusted-internal trust class, so a scanner-adapter on a private
/// network (the normal in-cluster topology) is reachable WITHOUT any
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` operator knob. Cloud-metadata, loopback and
/// link-local addresses stay hard-blocked at connect time and across
/// redirects (issue #2389).
///
/// This must ONLY be used for URLs that come from server configuration, never
/// for attacker/user-influenceable targets (remote-repo upstreams, proxy
/// URLs, webhooks, plugins) — those keep using [`base_client_builder`], which
/// stays fail-closed.
pub fn internal_service_client_builder() -> ClientBuilder {
    log_proxy_env();

    let builder = reqwest::Client::builder()
        .redirect(ssrf_internal_redirect_policy())
        .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver_internal());

    apply_custom_ca_cert(builder)
}

/// Return a [`ClientBuilder`] for **webhook delivery** requests. Mirrors
/// [`base_client_builder`] — same custom-CA handling — but wires the SSRF
/// DNS resolver and redirect policy in the webhook trust class, so the
/// connect-time IP check honors the same `WEBHOOK_ALLOW_PRIVATE_IPS` /
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` opt-ins as the validation-time check
/// instead of unconditionally re-blocking private targets under the
/// upstream context (issue #2380). With no toggle set, behavior is
/// identical to [`base_client_builder`] (fail-closed), and cloud-metadata,
/// loopback and link-local addresses stay hard-blocked at connect time and
/// across redirects regardless of any toggle.
pub fn webhook_client_builder() -> ClientBuilder {
    log_proxy_env();

    let builder = reqwest::Client::builder()
        .redirect(ssrf_webhook_redirect_policy())
        .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver_webhook());

    apply_custom_ca_cert(builder)
}

/// Build and return a ready-to-use webhook-delivery client (see
/// [`webhook_client_builder`]).
///
/// Panics if the client cannot be built (should not happen in practice).
pub fn webhook_client() -> reqwest::Client {
    webhook_client_builder()
        .build()
        .expect("failed to build webhook HTTP client")
}

/// Return a [`ClientBuilder`] for **SSO/OIDC identity-provider fetches**
/// (discovery, token, JWKS, userinfo against a configured IdP). Mirrors
/// [`base_client_builder`] — same custom-CA handling — but wires the SSRF
/// DNS resolver and redirect policy in the SSO trust class, so the
/// connect-time IP check honors `SSO_ALLOW_PRIVATE_IPS` /
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` instead of unconditionally re-blocking a
/// private-network IdP under the upstream context (issue #2380). With no
/// toggle set, behavior is identical to [`base_client_builder`]
/// (fail-closed), and cloud-metadata, loopback and link-local addresses
/// stay hard-blocked at connect time and across redirects regardless of
/// any toggle.
pub fn sso_client_builder() -> ClientBuilder {
    log_proxy_env();

    let builder = reqwest::Client::builder()
        .redirect(ssrf_sso_redirect_policy())
        .dns_resolver(crate::services::ssrf_dns::ssrf_guard_resolver_sso());

    apply_custom_ca_cert(builder)
}

/// Build and return a ready-to-use SSO/OIDC-fetch client (see
/// [`sso_client_builder`]).
///
/// Panics if the client cannot be built (should not happen in practice).
pub fn sso_client() -> reqwest::Client {
    sso_client_builder()
        .build()
        .expect("failed to build SSO HTTP client")
}

/// Load operator-provided custom CA certificate(s) (`CUSTOM_CA_CERT_PATH`)
/// into the builder when configured. Shared by every client builder so the
/// private-CA handling is identical and lives in one place.
fn apply_custom_ca_cert(mut builder: ClientBuilder) -> ClientBuilder {
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

/// Return a client builder suitable for large storage data-plane transfers.
///
/// This intentionally avoids [`ClientBuilder::timeout`], which is a total
/// request deadline and can abort healthy multi-GB uploads or downloads.
/// Instead it sets a `connect_timeout` plus a `read_timeout` that bounds
/// inactivity while *reading the response*. Note that `read_timeout` does not
/// bound time spent streaming a large request *body*, so a stalled upstream
/// that stops reading an upload is governed only by `connect_timeout` and
/// connection-level (TCP) behavior, not by this timeout.
pub fn large_object_client_builder(allow_http: bool) -> ClientBuilder {
    base_client_builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .https_only(!allow_http)
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
    ssrf_redirect_policy_with(
        crate::api::validation::is_blocked_url,
        "http-client redirect",
    )
}

/// Redirect policy for the trusted internal-service clients (#2389). Same
/// per-hop SSRF re-check as [`ssrf_redirect_policy`], but uses the
/// trusted-internal block-list so a redirect to a private address is allowed
/// while a redirect that pivots to a cloud-metadata / loopback / link-local
/// target is still refused.
fn ssrf_internal_redirect_policy() -> Policy {
    ssrf_redirect_policy_with(
        crate::api::validation::is_blocked_url_internal,
        "internal-service redirect",
    )
}

/// Redirect policy for webhook-delivery clients (#2380). Same per-hop SSRF
/// re-check as [`ssrf_redirect_policy`], but in the webhook trust class so
/// a redirect hop honors `WEBHOOK_ALLOW_PRIVATE_IPS` /
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` while metadata / loopback / link-local
/// pivots are still refused.
fn ssrf_webhook_redirect_policy() -> Policy {
    ssrf_redirect_policy_with(
        crate::api::validation::is_blocked_url_webhook,
        "webhook redirect",
    )
}

/// Redirect policy for SSO/OIDC-fetch clients (#2380). Same per-hop SSRF
/// re-check as [`ssrf_redirect_policy`], but in the SSO trust class so a
/// redirect hop honors `SSO_ALLOW_PRIVATE_IPS` /
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` while metadata / loopback / link-local
/// pivots are still refused.
fn ssrf_sso_redirect_policy() -> Policy {
    ssrf_redirect_policy_with(crate::api::validation::is_blocked_url_sso, "sso redirect")
}

/// Shared redirect-policy body: re-run `is_blocked` on every hop and refuse
/// the request if it returns a block reason, capping at [`MAX_REDIRECTS`].
/// The `is_blocked` fn selects the trust class (upstream vs trusted-internal).
fn ssrf_redirect_policy_with(
    is_blocked: fn(&reqwest::Url) -> Option<crate::api::validation::BlockReason>,
    context_label: &'static str,
) -> Policy {
    Policy::custom(move |attempt| {
        if let Some(reason) = is_blocked(attempt.url()) {
            tracing::warn!(
                target: "security",
                redirect_url = %attempt.url(),
                reason = reason.metric_label(),
                "blocking redirect to disallowed address"
            );
            crate::services::metrics_service::record_outbound_url_blocked(
                reason.metric_label(),
                context_label,
            );
            return attempt.error("redirect target rejected by SSRF policy");
        }
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        attempt.follow()
    })
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::{
        base_client_builder, default_client, internal_service_client_builder,
        large_object_client_builder, sso_client_builder, webhook_client_builder,
    };
    use std::io::Write;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    /// A hostname resolving to a blocked IP must be refused at DNS time, not
    /// connected to. `localhost` resolves to 127.0.0.1/::1 (blocked).
    ///
    /// This test is deliberately discriminating: a plain "connection
    /// refused" (e.g. nothing listening on the port) also satisfies
    /// `err.is_connect()`, so an assertion on the error alone would pass
    /// even if `.dns_resolver(...)` were removed from `base_client_builder`
    /// entirely (a false negative). To rule that out, we bind a *real*
    /// listener on `127.0.0.1` and target it via `localhost:{port}` — an
    /// unprotected client WOULD successfully connect to this listener, so
    /// asserting the listener never receives a connection is what actually
    /// proves the resolver blocked the request rather than merely finding
    /// nothing to talk to.
    #[tokio::test]
    async fn test_client_refuses_host_resolving_to_blocked_ip() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        // Bound the request with a short timeout: `base_client_builder`
        // itself sets no total request timeout, and this test's listener
        // never writes an HTTP response. If the resolver regressed and the
        // client actually connected, `.send().await` would otherwise hang
        // forever waiting on a response that never arrives, hanging the
        // test (and CI) instead of failing it. With the resolver correctly
        // in place, rejection happens at the DNS stage well within this
        // bound, so the timeout never fires on the passing path.
        let client = base_client_builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("http://localhost:{port}/");
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("host resolving to a blocked IP must be refused");
        // A DNS/connect-layer rejection (not a live HTTP response).
        assert!(
            err.is_connect()
                || err.is_request()
                || err.to_string().to_lowercase().contains("ssrf")
                || err.to_string().to_lowercase().contains("block"),
            "expected resolver rejection, got: {err}"
        );

        // Discriminating check: the listener must never have accepted a
        // connection. If the resolver were not wired in (or removed), the
        // client would successfully connect to 127.0.0.1:{port} via
        // `localhost`, and this would find a pending connection instead of
        // timing out.
        let accept_result =
            tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            accept_result.is_err(),
            "listener must never accept a connection; the SSRF resolver should have \
             blocked the request before any TCP connection was attempted, but a \
             connection was accepted: {accept_result:?}"
        );
    }

    /// The trusted internal-service client (#2389) relaxes the private-IP
    /// gate for operator-configured endpoints, but the loopback / metadata
    /// hard-blocks must NOT be relaxed: a host resolving to 127.0.0.1 must
    /// still be refused before any TCP connection is made. Mirrors the
    /// discriminating listener assertion used for `base_client_builder`.
    #[tokio::test]
    async fn test_internal_client_still_refuses_loopback_host() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let client = internal_service_client_builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("http://localhost:{port}/");
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("internal client must still refuse a loopback host");
        assert!(
            err.is_connect()
                || err.is_request()
                || err.to_string().to_lowercase().contains("ssrf")
                || err.to_string().to_lowercase().contains("block"),
            "expected resolver rejection, got: {err}"
        );

        let accept_result =
            tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            accept_result.is_err(),
            "internal client must never connect to a loopback listener: {accept_result:?}"
        );
    }

    #[test]
    fn test_webhook_and_sso_client_builders_build_successfully() {
        assert!(webhook_client_builder().build().is_ok());
        assert!(sso_client_builder().build().is_ok());
    }

    /// The webhook and SSO clients (#2380) gate the private-IP class on
    /// their per-surface toggles, but the loopback / metadata hard-blocks
    /// must NOT be relaxed even when the toggles are enabled: a host
    /// resolving to 127.0.0.1 must still be refused before any TCP
    /// connection is made. Mirrors the discriminating listener assertion
    /// used for `base_client_builder` / `internal_service_client_builder`.
    #[tokio::test]
    async fn test_webhook_and_sso_clients_still_refuse_loopback_host() {
        use tokio::net::TcpListener;

        // Enabling the toggles makes this test discriminating: it proves
        // the hard-block holds in the MOST permissive configuration, not
        // merely that the default-deny path fired.
        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");
        std::env::set_var("SSO_ALLOW_PRIVATE_IPS", "true");

        for builder in [webhook_client_builder(), sso_client_builder()] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let port = listener.local_addr().expect("local addr").port();

            let client = builder.timeout(Duration::from_secs(2)).build().unwrap();
            let url = format!("http://localhost:{port}/");
            let err = client
                .get(&url)
                .send()
                .await
                .expect_err("webhook/sso client must still refuse a loopback host");
            assert!(
                err.is_connect()
                    || err.is_request()
                    || err.to_string().to_lowercase().contains("ssrf")
                    || err.to_string().to_lowercase().contains("block"),
                "expected resolver rejection, got: {err}"
            );

            let accept_result =
                tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(
                accept_result.is_err(),
                "webhook/sso client must never connect to a loopback listener even with \
                 its private-IP toggle enabled: {accept_result:?}"
            );
        }

        std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS");
        std::env::remove_var("SSO_ALLOW_PRIVATE_IPS");
    }

    /// A webhook-client redirect hop that pivots onto the cloud-metadata
    /// endpoint must be refused even with the webhook private-IP toggle
    /// enabled — the per-hop redirect re-check uses the webhook trust
    /// class, whose hard-blocks are toggle-independent (#2380).
    #[tokio::test]
    async fn test_webhook_client_refuses_redirect_to_metadata() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        std::env::set_var("WEBHOOK_ALLOW_PRIVATE_IPS", "true");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\n\
                          Location: http://169.254.169.254/latest/meta-data\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        // The entry hop targets the loopback listener by IP literal, which
        // never consults the DNS resolver (and the redirect policy fires
        // only on redirect hops) — this test exercises the redirect policy
        // specifically, mirroring `test_redirect_to_blocked_ip_is_refused`.
        let client = webhook_client_builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{}/start", addr.port());
        let result = client.post(&url).send().await;

        let _ = server.await;
        std::env::remove_var("WEBHOOK_ALLOW_PRIVATE_IPS");

        let err = result.expect_err("redirect to the metadata endpoint must be refused");
        assert!(
            err.to_string().contains("SSRF") || err.is_redirect(),
            "expected redirect-rejection error, got: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_large_object_client_builder_does_not_apply_total_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut received = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.expect("read request");
                assert_ne!(n, 0, "client closed before request headers");
                received.extend_from_slice(&buf[..n]);
                if received.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nO")
                .await
                .expect("write first byte");
            tokio::time::sleep(Duration::from_secs(20)).await;
            socket.write_all(b"K").await.expect("write second byte");
        });

        let client = large_object_client_builder(true)
            .build()
            .expect("build large-object client");
        let request = tokio::spawn(async move {
            client
                .post(&url)
                .body("request body")
                .send()
                .await
                .expect("send request")
                .bytes()
                .await
                .expect("read response")
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;

        assert_eq!(request.await.expect("request task").as_ref(), b"OK");
        server.await.expect("server task");
    }
}
