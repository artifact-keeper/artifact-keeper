//! Shared SSO end-to-end test support (#1617, epic #1615).
//!
//! Cross-cutting helpers used by the OIDC (and, in the companion PR, SAML)
//! end-to-end harnesses that drive the real `api::handlers::sso` axum routes
//! against a mock identity provider backed by a throwaway Postgres.
//!
//! The load-bearing piece here is [`non_loopback_bind_ip`] +
//! [`allow_private_sso_ip`]: the OIDC handler performs three server-side
//! first-hop fetches (discovery, token, JWKS), each screened by the outbound
//! SSRF guard. Loopback (`127.0.0.0/8`) is a HARD block that no toggle relaxes
//! (`api::validation::is_hard_blocked_ipv4`), so a mock IdP on wiremock's
//! default `127.0.0.1` bind is unreachable. The harness instead binds the mock
//! to the host's primary non-loopback interface (an RFC1918/CGNAT private IP in
//! CI/ARC pods) and opts that single address into the private-IP allowlist via
//! `AK_SSRF_ALLOW_PRIVATE_CIDRS`, which relaxes private IPs only.

use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

/// `AuthConfigService` encrypts the stored OIDC client secret with a key read
/// from `SSO_ENCRYPTION_KEY`/`JWT_SECRET` in the *process* environment (not the
/// `Config`). CI sets `JWT_SECRET`; for local runs we install a stable key so
/// `create_oidc` (encrypt) and `get_oidc_decrypted` (decrypt) agree. Setting it
/// to a fixed value is idempotent across the tests in a serial binary.
pub fn ensure_sso_encryption_key() {
    if std::env::var("SSO_ENCRYPTION_KEY").is_err() && std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "SSO_ENCRYPTION_KEY",
            "test-sso-encryption-key-at-least-32-bytes-long",
        );
    }
}

/// Connect to the throwaway Postgres named by `DATABASE_URL`, or return `None`
/// so the caller can skip cleanly (matching the repo `--ignored` convention).
pub async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
        .ok()
}

/// Minimal `Config` for building `AppState` in the SSO e2e tests.
pub fn test_config() -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: std::env::temp_dir()
            .join(format!("ak-sso-e2e-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

/// Build a `SharedState` over the given pool with a filesystem storage backend.
pub fn build_state(pool: PgPool) -> SharedState {
    let cfg = test_config();
    std::fs::create_dir_all(&cfg.storage_path).expect("create storage dir");
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(&cfg.storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg, pool, storage, registry))
}

/// Wrap the public SSO router in `with_state` (no auth layer — these are
/// pre-auth public endpoints).
pub fn sso_app(state: SharedState) -> axum::Router {
    artifact_keeper_backend::api::handlers::sso::router().with_state(state)
}

/// Discover a non-loopback local IP for binding the mock IdP.
///
/// Opens a UDP socket and `connect()`s it to a public address — no packets are
/// actually sent; the kernel just selects the primary outbound interface, whose
/// `local_addr()` is the address we bind the mock server to. Returns `None` when
/// the only reachable local address is loopback (isolated runner) so the caller
/// can skip the test the same way it skips when `DATABASE_URL` is unset.
pub fn non_loopback_bind_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

/// Opt a single mock-IdP IP into the outbound SSRF private-IP allowlist by
/// setting `AK_SSRF_ALLOW_PRIVATE_CIDRS=<ip>/32` (or `/128` for IPv6).
///
/// This is a process-global env write, which is why the SSO e2e suites run
/// `--test-threads=1`. The allowlist relaxes only private RFC1918/CGNAT/ULA
/// addresses; loopback and cloud-metadata IPs stay hard-blocked. If the primary
/// interface IP happens to be public the guard already permits it and this call
/// is harmless.
pub fn allow_private_sso_ip(ip: IpAddr) {
    let cidr = match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    };
    std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", cidr);
}
