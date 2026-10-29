//! A wiremock upstream that the upstream outbound address policy admits.
//!
//! Every upstream fetch checks an IP-literal destination against the policy
//! before it is sent, and loopback is refused in every configuration, so a
//! mock on `127.0.0.1` cannot stand in for a remote upstream. The mock binds
//! the host's primary non-loopback address instead, and that one address is
//! added to `AK_SSRF_ALLOW_PRIVATE_CIDRS`, the way an operator admits an
//! internal mirror. The write is process-global; nextest runs each test in its
//! own process.

use super::sso_support::{allow_private_sso_ip, non_loopback_bind_ip};

/// Start a mock upstream on the host's non-loopback address, admitted by a
/// single-address allowlist entry.
pub async fn admitted_mock_server() -> wiremock::MockServer {
    let ip = non_loopback_bind_ip().expect("a non-loopback interface for the mock upstream");
    allow_private_sso_ip(ip);
    let listener = std::net::TcpListener::bind((ip, 0)).expect("bind the mock upstream");
    wiremock::MockServer::builder()
        .listener(listener)
        .start()
        .await
}
