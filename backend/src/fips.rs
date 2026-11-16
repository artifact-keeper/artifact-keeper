//! FIPS 140-3 mode: the opt-in `fips` cargo feature.
//!
//! For deployments that require FIPS 140-3 validated cryptography. The default
//! build is unaffected: it compiles none of the FIPS-only code below and keeps
//! installing the `ring` rustls provider exactly as it always has.
//!
//! A `fips` build (`cargo build --no-default-features --features fips`):
//!
//! * links the AWS-LC FIPS module (`aws-lc-fips-sys`) under every `aws-lc-rs`
//!   user in the dependency graph, and does not link `ring` at all;
//! * installs [`rustls::crypto::default_fips_provider`] as the process-wide
//!   rustls provider before anything opens a TLS connection, and refuses to
//!   start unless the AWS-LC module reports FIPS mode and the installed
//!   provider reports [`rustls::crypto::CryptoProvider::fips`];
//! * routes Postgres (sqlx) and every reqwest client to that provider.
//!
//! What is covered, what is not, and why, is in `docs/fips.md`.

#[cfg(all(feature = "fips", feature = "default-tls"))]
compile_error!(
    "the `fips` feature cannot be combined with `default-tls` (a default \
     feature): build with `--no-default-features --features fips`, otherwise \
     sqlx keeps using `ring` for Postgres TLS"
);

/// True when this binary was built with the `fips` cargo feature.
pub const ENABLED: bool = cfg!(feature = "fips");

/// The name of the rustls provider this build installs, for the startup log.
pub const PROVIDER_NAME: &str = if ENABLED { "aws-lc-rs (FIPS)" } else { "ring" };

/// Install the FIPS rustls provider as the process default and verify it.
///
/// Fails, and the caller must refuse to start, when the AWS-LC FIPS module is
/// not in FIPS mode (its power-on self tests failed, or it was not built as
/// the FIPS module), or when the process-wide provider that ends up installed
/// does not report FIPS. Installing is idempotent: if a FIPS provider is
/// already installed (a second call, or a test) this only re-verifies it.
#[cfg(feature = "fips")]
pub fn install_fips_provider() -> Result<(), String> {
    aws_lc_rs::try_fips_mode()
        .map_err(|e| format!("the AWS-LC cryptographic module is not in FIPS mode: {e}"))?;

    let provider = rustls::crypto::default_fips_provider();
    if !provider.fips() {
        return Err("the rustls aws-lc-rs provider does not report FIPS mode".to_string());
    }
    // `Err` here means a provider was already installed; whichever one it is,
    // the check below decides.
    let _ = provider.install_default();
    verify_installed_provider()
}

/// Check that the process-wide rustls provider exists and reports FIPS.
#[cfg(feature = "fips")]
pub fn verify_installed_provider() -> Result<(), String> {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(provider) if provider.fips() => Ok(()),
        Some(_) => Err("the installed rustls crypto provider is not FIPS-approved".to_string()),
        None => Err("no rustls crypto provider is installed".to_string()),
    }
}

/// Log the cryptographic mode once tracing is up. `install_fips_provider` runs
/// before tracing is initialised, so its success is reported here. The default
/// build logs nothing, exactly as before.
pub fn log_crypto_mode() {
    if ENABLED {
        tracing::info!(
            fips = true,
            tls_provider = PROVIDER_NAME,
            "FIPS 140-3 mode: TLS and approved-algorithm operations use the AWS-LC FIPS module"
        );
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_matches_the_cargo_feature() {
        assert_eq!(ENABLED, cfg!(feature = "fips"));
        assert_eq!(PROVIDER_NAME == "ring", !ENABLED);
    }

    #[test]
    fn log_crypto_mode_does_not_panic_without_a_subscriber() {
        log_crypto_mode();
    }

    #[cfg(feature = "fips")]
    #[test]
    fn aws_lc_module_is_in_fips_mode() {
        aws_lc_rs::try_fips_mode().expect("aws-lc-rs must be the FIPS module in a fips build");
    }

    #[cfg(feature = "fips")]
    #[test]
    fn default_fips_provider_offers_only_fips_algorithms() {
        let provider = rustls::crypto::default_fips_provider();
        assert!(provider.fips());
        assert!(!provider.cipher_suites.is_empty());
        assert!(provider.cipher_suites.iter().all(|s| s.fips()));
        assert!(!provider.kx_groups.is_empty());
        assert!(provider.kx_groups.iter().all(|g| g.fips()));
        assert!(provider.signature_verification_algorithms.fips());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn install_is_idempotent_and_leaves_a_fips_provider_installed() {
        install_fips_provider().expect("first install");
        install_fips_provider().expect("second install re-verifies");
        verify_installed_provider().expect("installed provider is FIPS");
    }

    /// The handshake end to end: a client built from the installed FIPS
    /// provider negotiates TLS 1.3 with a FIPS cipher suite against a server
    /// on the same provider.
    #[cfg(feature = "fips")]
    #[tokio::test]
    async fn rustls_handshake_uses_the_fips_provider() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        install_fips_provider().expect("install");
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("installed")
            .clone();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );

        let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        assert!(client_config.fips());
        assert!(server_config.fips());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(&buf).await.unwrap();
            tls.shutdown().await.ok();
        });

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        tls.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let suite = conn.negotiated_cipher_suite().expect("suite");
        assert!(suite.fips(), "negotiated {suite:?} is not FIPS-approved");
        server.await.unwrap();
    }
}
