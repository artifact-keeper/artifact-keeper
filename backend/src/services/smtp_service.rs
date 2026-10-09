//! SMTP email delivery service.
//!
//! Provides asynchronous email sending via an SMTP relay. When `SMTP_HOST` is
//! not set in the environment the service operates as a silent no-op, matching
//! the optional-service pattern used by OpenSearch and other integrations.

use crate::config::Config;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// How the SMTP connection is secured (`SMTP_TLS_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    /// `tls`: TLS from the first byte (SMTPS, usually port 465).
    Implicit,
    /// `starttls` (default): connect in plaintext and upgrade with STARTTLS;
    /// fail when the server does not advertise it.
    StartTls,
    /// `starttls-opportunistic`: upgrade with STARTTLS when the server
    /// advertises it, otherwise carry on unencrypted. This is what Forgejo's
    /// `smtp+starttls` and JavaMail's `mail.smtp.starttls.enable` (Nexus) do.
    /// A STARTTLS that is offered but fails (an untrusted certificate, say)
    /// is still an error, never a silent downgrade.
    StartTlsOpportunistic,
    /// `none`: plaintext only, STARTTLS is never attempted.
    None,
}

impl SmtpTlsMode {
    /// Map a validated `SMTP_TLS_MODE` value. Unknown values are already
    /// rewritten to "starttls" by `Config::from_env`.
    pub fn from_config(value: &str) -> Self {
        match value {
            "tls" => Self::Implicit,
            "none" => Self::None,
            "starttls-opportunistic" => Self::StartTlsOpportunistic,
            _ => Self::StartTls,
        }
    }

    /// The `SMTP_TLS_MODE` spelling of this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implicit => "tls",
            Self::StartTls => "starttls",
            Self::StartTlsOpportunistic => "starttls-opportunistic",
            Self::None => "none",
        }
    }
}

/// SMTP email delivery service.
///
/// Wraps an optional `AsyncSmtpTransport`. When the transport is `None`
/// (SMTP_HOST not configured), every public method returns `Ok` without
/// attempting network I/O.
#[derive(Clone)]
pub struct SmtpService {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from_address: Mailbox,
}

impl SmtpService {
    /// Build a new `SmtpService` from application config.
    ///
    /// Returns a no-op instance when `config.smtp_host` is `None`.
    pub fn new(config: &Config) -> Result<Self, SmtpError> {
        let from_address: Mailbox = config
            .smtp_from_address
            .parse()
            .map_err(|e| SmtpError::Config(format!("invalid SMTP_FROM_ADDRESS: {e}")))?;

        let transport = match &config.smtp_host {
            Some(host) => {
                let tls_parameters = build_tls_parameters(host, config)?;
                let tls = match SmtpTlsMode::from_config(&config.smtp_tls_mode) {
                    SmtpTlsMode::Implicit => Tls::Wrapper(tls_parameters),
                    SmtpTlsMode::StartTls => Tls::Required(tls_parameters),
                    SmtpTlsMode::StartTlsOpportunistic => Tls::Opportunistic(tls_parameters),
                    SmtpTlsMode::None => Tls::None,
                };

                let builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                    .port(config.smtp_port)
                    .tls(tls);

                let builder = if let (Some(username), Some(password)) =
                    (&config.smtp_username, &config.smtp_password)
                {
                    builder.credentials(Credentials::new(username.clone(), password.clone()))
                } else {
                    builder
                };

                Some(builder.build())
            }
            None => None,
        };

        Ok(Self {
            transport,
            from_address,
        })
    }

    /// Returns `true` when an SMTP transport has been configured.
    pub fn is_configured(&self) -> bool {
        self.transport.is_some()
    }

    /// Send an email with both HTML and plain-text bodies.
    ///
    /// When SMTP is not configured this is a no-op that returns `Ok(())`.
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<(), SmtpError> {
        let transport = match &self.transport {
            Some(t) => t,
            None => {
                tracing::debug!(
                    to = to,
                    subject = subject,
                    "SMTP not configured, skipping email delivery"
                );
                return Ok(());
            }
        };

        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e| SmtpError::Address(format!("invalid recipient address \"{to}\": {e}")))?;

        let message = Message::builder()
            .from(self.from_address.clone())
            .to(to_mailbox)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(body_text.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(body_html.to_string()),
                    ),
            )
            .map_err(|e| SmtpError::Build(format!("failed to build email message: {e}")))?;

        transport
            .send(message)
            .await
            .map_err(|e| SmtpError::Send(format!("SMTP delivery failed: {e}")))?;

        tracing::info!(to = to, subject = subject, "email sent successfully");
        Ok(())
    }

    /// Send a test email to verify SMTP connectivity.
    ///
    /// Returns an error if SMTP is not configured or if sending fails.
    pub async fn send_test_email(&self, to: &str) -> Result<(), SmtpError> {
        if !self.is_configured() {
            return Err(SmtpError::NotConfigured);
        }

        self.send_email(
            to,
            "Artifact Keeper SMTP Test",
            "<h1>SMTP Configuration Verified</h1>\
             <p>This is a test email from Artifact Keeper confirming that your \
             SMTP settings are working correctly.</p>",
            "SMTP Configuration Verified\n\n\
             This is a test email from Artifact Keeper confirming that your \
             SMTP settings are working correctly.",
        )
        .await
    }
}

/// Build the TLS parameters used for implicit TLS and STARTTLS.
///
/// The system trust store is always used. `SMTP_TLS_CA_CERT` (a PEM path or
/// the PEM text), or failing that the shared `CUSTOM_CA_CERT_PATH`, adds
/// certificates on top of it, so a server whose certificate comes from a
/// private CA can be verified. `SMTP_TLS_SKIP_VERIFY=true` turns verification
/// off entirely and is logged as a warning at startup.
fn build_tls_parameters(host: &str, config: &Config) -> Result<TlsParameters, SmtpError> {
    let mut builder = TlsParameters::builder(host.to_owned());

    if let Some(value) = &config.smtp_tls_ca_cert {
        let source = config.smtp_tls_ca_cert_source.unwrap_or("SMTP_TLS_CA_CERT");
        let (pem, origin) = if value.contains("-----BEGIN") {
            (value.as_bytes().to_vec(), format!("{source} (inline PEM)"))
        } else {
            let bytes = std::fs::read(value).map_err(|e| {
                SmtpError::Config(format!("cannot read {source} file {value}: {e}"))
            })?;
            (bytes, format!("{source} ({value})"))
        };
        let certs = parse_pem_bundle(&pem)
            .map_err(|e| SmtpError::Config(format!("invalid certificate in {origin}: {e}")))?;
        let count = certs.len();
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
        tracing::info!(source = %origin, count, "Loaded extra CA certificate(s) for SMTP");
    }

    if config.smtp_tls_skip_verify {
        tracing::warn!(
            host = %host,
            "SMTP_TLS_SKIP_VERIFY=true: the SMTP server's TLS certificate and hostname are \
             NOT verified. Anyone who can intercept the connection can read the SMTP \
             password and every message. Use SMTP_TLS_CA_CERT instead outside of testing."
        );
        builder = builder
            .dangerous_accept_invalid_certs(true)
            .dangerous_accept_invalid_hostnames(true);
    }

    builder
        .build()
        .map_err(|e| SmtpError::Config(format!("SMTP TLS setup failed: {e}")))
}

/// Split a PEM bundle into certificates. The native-tls backend only reads
/// the first certificate of a buffer, so each block is parsed on its own.
fn parse_pem_bundle(pem: &[u8]) -> Result<Vec<Certificate>, String> {
    const END: &str = "-----END CERTIFICATE-----";
    let text = String::from_utf8_lossy(pem);
    let mut certs = Vec::new();
    for block in text.split(END) {
        let block = block.trim();
        let Some(start) = block.find("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let one = format!("{}\n{END}\n", &block[start..]);
        certs.push(Certificate::from_pem(one.as_bytes()).map_err(|e| e.to_string())?);
    }
    if certs.is_empty() {
        return Err("no PEM certificate found".into());
    }
    Ok(certs)
}

/// Errors that can occur during SMTP operations.
#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("SMTP configuration error: {0}")]
    Config(String),

    #[error("invalid email address: {0}")]
    Address(String),

    #[error("failed to build email: {0}")]
    Build(String),

    #[error("SMTP send error: {0}")]
    Send(String),

    #[error("SMTP is not configured (SMTP_HOST is not set)")]
    NotConfigured,
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::env;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // RAII guard that snapshots env vars on construction and restores them on
    // drop. Without this, set_var calls in these tests leaked process-wide:
    // env is global and ENV_MUTEX only serializes writers among smtp tests,
    // so parallel tests reading DATABASE_URL via try_pool() saw the bogus
    // "postgres://test@127.0.0.1:1/test" URL until the next smtp test ran.
    struct EnvVarGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvVarGuard {
        fn capture(keys: &[&'static str]) -> Self {
            let saved = keys.iter().map(|&k| (k, env::var(k).ok())).collect();
            Self { saved }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(s) => env::set_var(k, s),
                    None => env::remove_var(k),
                }
            }
        }
    }

    const SMTP_ENV_KEYS: &[&str] = &[
        "DATABASE_URL",
        "JWT_SECRET",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_FROM_ADDRESS",
        "SMTP_TLS_MODE",
        "SMTP_TLS_CA_CERT",
        "SMTP_TLS_SKIP_VERIFY",
        "CUSTOM_CA_CERT_PATH",
    ];

    /// Build a minimal Config for testing. Sets only the required env vars
    /// and clears SMTP-related vars unless the caller sets them first.
    fn test_config_no_smtp() -> Config {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::remove_var("SMTP_HOST");
        env::remove_var("SMTP_PORT");
        env::remove_var("SMTP_USERNAME");
        env::remove_var("SMTP_PASSWORD");
        env::remove_var("SMTP_FROM_ADDRESS");
        env::remove_var("SMTP_TLS_MODE");
        env::remove_var("SMTP_TLS_CA_CERT");
        env::remove_var("SMTP_TLS_SKIP_VERIFY");
        env::remove_var("CUSTOM_CA_CERT_PATH");
        Config::from_env().expect("test config should parse")
    }

    fn test_config_with_smtp() -> Config {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::set_var("SMTP_HOST", "mail.example.com");
        env::set_var("SMTP_PORT", "465");
        env::set_var("SMTP_USERNAME", "user@example.com");
        env::set_var("SMTP_PASSWORD", "hunter2");
        env::set_var("SMTP_FROM_ADDRESS", "noreply@example.com");
        env::set_var("SMTP_TLS_MODE", "tls");
        env::remove_var("SMTP_TLS_CA_CERT");
        env::remove_var("SMTP_TLS_SKIP_VERIFY");
        env::remove_var("CUSTOM_CA_CERT_PATH");
        Config::from_env().expect("test config should parse")
    }

    #[test]
    fn test_noop_when_not_configured() {
        let config = test_config_no_smtp();
        let service = SmtpService::new(&config).expect("should build no-op service");
        assert!(!service.is_configured());
    }

    #[tokio::test]
    async fn test_configured_when_smtp_host_set() {
        let config = test_config_with_smtp();
        let service = SmtpService::new(&config).expect("should build configured service");
        assert!(service.is_configured());
    }

    #[tokio::test]
    async fn test_send_email_noop_succeeds() {
        let config = test_config_no_smtp();
        let service = SmtpService::new(&config).unwrap();
        let result = service
            .send_email("test@example.com", "Test Subject", "<p>Hello</p>", "Hello")
            .await;
        assert!(result.is_ok(), "no-op send should succeed");
    }

    #[tokio::test]
    async fn test_send_test_email_returns_error_when_not_configured() {
        let config = test_config_no_smtp();
        let service = SmtpService::new(&config).unwrap();
        let result = service.send_test_email("test@example.com").await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SmtpError::NotConfigured),
            "should return NotConfigured error"
        );
    }

    #[test]
    fn test_invalid_from_address_returns_config_error() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::set_var("SMTP_FROM_ADDRESS", "not-an-email");
        env::remove_var("SMTP_HOST");
        let config = Config::from_env().expect("config should parse");

        let result = SmtpService::new(&config);
        assert!(result.is_err(), "invalid from address should error");
    }

    #[test]
    fn test_config_defaults() {
        let config = test_config_no_smtp();
        assert!(config.smtp_host.is_none());
        assert_eq!(config.smtp_port, 587);
        assert!(config.smtp_username.is_none());
        assert!(config.smtp_password.is_none());
        assert_eq!(config.smtp_from_address, "noreply@artifact-keeper.local");
        assert_eq!(config.smtp_tls_mode, "starttls");
    }

    #[test]
    fn test_config_custom_values() {
        let config = test_config_with_smtp();
        assert_eq!(config.smtp_host.as_deref(), Some("mail.example.com"));
        assert_eq!(config.smtp_port, 465);
        assert_eq!(config.smtp_username.as_deref(), Some("user@example.com"));
        assert_eq!(config.smtp_password.as_deref(), Some("hunter2"));
        assert_eq!(config.smtp_from_address, "noreply@example.com");
        assert_eq!(config.smtp_tls_mode, "tls");
    }

    #[test]
    fn test_tls_mode_fallback_on_invalid() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::set_var("SMTP_TLS_MODE", "invalid-mode");
        let config = Config::from_env().expect("config should parse");
        assert_eq!(config.smtp_tls_mode, "starttls");
    }

    #[tokio::test]
    async fn test_dangerous_mode_builds_transport() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::set_var("SMTP_HOST", "localhost");
        env::set_var("SMTP_TLS_MODE", "none");
        let config = Config::from_env().expect("config should parse");

        let service = SmtpService::new(&config).expect("should build with dangerous mode");
        assert!(service.is_configured());
    }

    // Two throwaway self-signed CA certificates (no keys kept), used to check
    // that SMTP_TLS_CA_CERT / CUSTOM_CA_CERT_PATH are parsed and applied.
    const TEST_CA_A: &str = "-----BEGIN CERTIFICATE-----\nMIIBijCCAS+gAwIBAgIUVCPWRFTpkEFlta+XSyCPmrxww2cwCgYIKoZIzj0EAwIw\nGTEXMBUGA1UEAwwOc210cCB0ZXN0IGNhIGEwIBcNMjYxMDA5MDIxMjM4WhgPMjEy\nNjA5MTUwMjEyMzhaMBkxFzAVBgNVBAMMDnNtdHAgdGVzdCBjYSBhMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAEvjCjWA8hyylibNSO1N57nwSLqBEM8ckpSXPXq5sK\nWFHL4nwBbCVyM3P7suBYWxXtKr/+oHhn1WE4Q90tPQqz8qNTMFEwHQYDVR0OBBYE\nFLSn8P2abCkNi5btOXsg33opcVMhMB8GA1UdIwQYMBaAFLSn8P2abCkNi5btOXsg\n33opcVMhMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANBaZnuQ\nmZZM/VKC8YW+6FD707CP/l4ZRu7c6AEj5529AiEAzKBcxPOGaIJYTKWnwt/RkAv0\ng8f8B7MU/xcOpRnM7wI=\n-----END CERTIFICATE-----\n";
    const TEST_CA_B: &str = "-----BEGIN CERTIFICATE-----\nMIIBiDCCAS+gAwIBAgIUB/mk3bg5D90amYUKXtUD94QB8okwCgYIKoZIzj0EAwIw\nGTEXMBUGA1UEAwwOc210cCB0ZXN0IGNhIGIwIBcNMjYxMDA5MDIxMjM4WhgPMjEy\nNjA5MTUwMjEyMzhaMBkxFzAVBgNVBAMMDnNtdHAgdGVzdCBjYSBiMFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAEgUUDmueefW+CsKCHydAkUgnSPcR61yYVRES/q1IC\nBi2Pr32vjyZa7fmyv1uCKc0kAz8P1rR+fwHgxADRXN7y/6NTMFEwHQYDVR0OBBYE\nFKynQs2FvBv5moM2GFhRuDO41R+EMB8GA1UdIwQYMBaAFKynQs2FvBv5moM2GFhR\nuDO41R+EMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgTwlIuuSh\ndIl7GHaZUjsXY5DFwtaOmS2naPR4ey1TjksCIHuH8WA8uB2Kkn1RL6n2Li3sXKZ4\nFauL8Xribi2ZhYkV\n-----END CERTIFICATE-----\n";

    /// Build a Config with SMTP pointed at localhost and the given extra
    /// environment applied on top. Every SMTP variable not listed is cleared.
    fn config_with(vars: &[(&str, &str)]) -> Config {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvVarGuard::capture(SMTP_ENV_KEYS);
        for k in SMTP_ENV_KEYS {
            env::remove_var(k);
        }
        env::set_var("DATABASE_URL", "postgres://test@127.0.0.1:1/test");
        env::set_var(
            "JWT_SECRET",
            "smtp-suite-passphrase-with-varied-glyphs-2468",
        );
        env::set_var("SMTP_HOST", "localhost");
        for (k, v) in vars {
            env::set_var(k, v);
        }
        Config::from_env().expect("test config should parse")
    }

    fn write_temp_pem(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(contents.as_bytes()).expect("write pem");
        f
    }

    #[test]
    fn test_parse_pem_bundle_reads_every_certificate() {
        let bundle = format!("{TEST_CA_A}{TEST_CA_B}");
        let certs = parse_pem_bundle(bundle.as_bytes()).expect("bundle parses");
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_parse_pem_bundle_rejects_non_pem() {
        assert!(parse_pem_bundle(b"not a certificate").is_err());
        assert!(parse_pem_bundle(b"").is_err());
    }

    #[tokio::test]
    async fn test_ca_cert_inline_pem_is_accepted() {
        let config = config_with(&[("SMTP_TLS_CA_CERT", TEST_CA_A)]);
        assert_eq!(config.smtp_tls_ca_cert_source, Some("SMTP_TLS_CA_CERT"));
        let service = SmtpService::new(&config).expect("inline CA builds");
        assert!(service.is_configured());
    }

    #[tokio::test]
    async fn test_ca_cert_path_is_accepted() {
        let file = write_temp_pem(&format!("{TEST_CA_A}{TEST_CA_B}"));
        let path = file.path().to_str().unwrap();
        let config = config_with(&[("SMTP_TLS_CA_CERT", path)]);
        let service = SmtpService::new(&config).expect("CA file builds");
        assert!(service.is_configured());
    }

    #[test]
    fn test_custom_ca_cert_path_is_the_fallback() {
        let config = config_with(&[("CUSTOM_CA_CERT_PATH", "/etc/pki/custom.pem")]);
        assert_eq!(
            config.smtp_tls_ca_cert.as_deref(),
            Some("/etc/pki/custom.pem")
        );
        assert_eq!(config.smtp_tls_ca_cert_source, Some("CUSTOM_CA_CERT_PATH"));
    }

    #[test]
    fn test_smtp_tls_ca_cert_overrides_custom_ca_cert_path() {
        let config = config_with(&[
            ("CUSTOM_CA_CERT_PATH", "/etc/pki/custom.pem"),
            ("SMTP_TLS_CA_CERT", "/etc/pki/smtp.pem"),
        ]);
        assert_eq!(
            config.smtp_tls_ca_cert.as_deref(),
            Some("/etc/pki/smtp.pem")
        );
        assert_eq!(config.smtp_tls_ca_cert_source, Some("SMTP_TLS_CA_CERT"));
    }

    #[test]
    fn test_ca_cert_missing_file_is_a_config_error() {
        let config = config_with(&[("SMTP_TLS_CA_CERT", "/nonexistent/aksmtp-ca.pem")]);
        let err = SmtpService::new(&config)
            .err()
            .expect("missing file errors");
        assert!(matches!(err, SmtpError::Config(_)), "{err}");
        assert!(err.to_string().contains("SMTP_TLS_CA_CERT"), "{err}");
    }

    #[test]
    fn test_ca_cert_garbage_is_a_config_error() {
        let file = write_temp_pem("hello, not a cert");
        let path = file.path().to_str().unwrap();
        let config = config_with(&[("CUSTOM_CA_CERT_PATH", path)]);
        let err = SmtpService::new(&config).err().expect("garbage errors");
        assert!(err.to_string().contains("CUSTOM_CA_CERT_PATH"), "{err}");
    }

    #[tokio::test]
    async fn test_skip_verify_parses_and_builds() {
        for (raw, want) in [
            ("true", true),
            ("1", true),
            ("TRUE", true),
            ("false", false),
            ("yes", false),
        ] {
            let config = config_with(&[("SMTP_TLS_SKIP_VERIFY", raw)]);
            assert_eq!(
                config.smtp_tls_skip_verify, want,
                "SMTP_TLS_SKIP_VERIFY={raw}"
            );
            assert!(SmtpService::new(&config).unwrap().is_configured());
        }
        assert!(!config_with(&[]).smtp_tls_skip_verify, "default is false");
    }

    #[test]
    fn test_tls_mode_values_round_trip() {
        for mode in [
            SmtpTlsMode::Implicit,
            SmtpTlsMode::StartTls,
            SmtpTlsMode::StartTlsOpportunistic,
            SmtpTlsMode::None,
        ] {
            assert_eq!(SmtpTlsMode::from_config(mode.as_str()), mode);
        }
        assert_eq!(SmtpTlsMode::from_config("garbage"), SmtpTlsMode::StartTls);
    }

    #[tokio::test]
    async fn test_opportunistic_mode_is_accepted_by_config() {
        for raw in ["starttls-opportunistic", "STARTTLS-Opportunistic"] {
            let config = config_with(&[("SMTP_TLS_MODE", raw)]);
            assert_eq!(config.smtp_tls_mode, "starttls-opportunistic", "{raw}");
            assert_eq!(
                SmtpTlsMode::from_config(&config.smtp_tls_mode),
                SmtpTlsMode::StartTlsOpportunistic
            );
            assert!(SmtpService::new(&config).unwrap().is_configured());
        }
    }

    #[test]
    fn test_strict_starttls_stays_the_default() {
        let config = config_with(&[]);
        assert_eq!(
            SmtpTlsMode::from_config(&config.smtp_tls_mode),
            SmtpTlsMode::StartTls
        );
    }
}
