//! SMTP email delivery service.
//!
//! Provides asynchronous email sending via an SMTP relay. When `SMTP_HOST` is
//! not set in the environment the service operates as a silent no-op, matching
//! the optional-service pattern used by Meilisearch and other integrations.

use crate::config::Config;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

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
                let builder =
                    match config.smtp_tls_mode.as_str() {
                        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                            .map_err(|e| SmtpError::Config(format!("SMTP relay TLS error: {e}")))?,
                        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
                        // "starttls" is the default
                        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).map_err(
                            |e| SmtpError::Config(format!("SMTP STARTTLS relay error: {e}")),
                        )?,
                    };

                let builder = builder.port(config.smtp_port);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::env;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Build a minimal Config for testing. Sets only the required env vars
    /// and clears SMTP-related vars unless the caller sets them first.
    fn test_config_no_smtp() -> Config {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("DATABASE_URL", "postgres://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret-at-least-32-chars-long!");
        env::remove_var("SMTP_HOST");
        env::remove_var("SMTP_PORT");
        env::remove_var("SMTP_USERNAME");
        env::remove_var("SMTP_PASSWORD");
        env::remove_var("SMTP_FROM_ADDRESS");
        env::remove_var("SMTP_TLS_MODE");
        Config::from_env().expect("test config should parse")
    }

    fn test_config_with_smtp() -> Config {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("DATABASE_URL", "postgres://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret-at-least-32-chars-long!");
        env::set_var("SMTP_HOST", "mail.example.com");
        env::set_var("SMTP_PORT", "465");
        env::set_var("SMTP_USERNAME", "user@example.com");
        env::set_var("SMTP_PASSWORD", "hunter2");
        env::set_var("SMTP_FROM_ADDRESS", "noreply@example.com");
        env::set_var("SMTP_TLS_MODE", "tls");
        let config = Config::from_env().expect("test config should parse");
        // Clean up
        env::remove_var("SMTP_HOST");
        env::remove_var("SMTP_PORT");
        env::remove_var("SMTP_USERNAME");
        env::remove_var("SMTP_PASSWORD");
        env::remove_var("SMTP_FROM_ADDRESS");
        env::remove_var("SMTP_TLS_MODE");
        config
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
        env::set_var("DATABASE_URL", "postgres://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret-at-least-32-chars-long!");
        env::set_var("SMTP_FROM_ADDRESS", "not-an-email");
        env::remove_var("SMTP_HOST");
        let config = Config::from_env().expect("config should parse");
        env::remove_var("SMTP_FROM_ADDRESS");

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
        env::set_var("DATABASE_URL", "postgres://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret-at-least-32-chars-long!");
        env::set_var("SMTP_TLS_MODE", "invalid-mode");
        let config = Config::from_env().expect("config should parse");
        env::remove_var("SMTP_TLS_MODE");
        assert_eq!(config.smtp_tls_mode, "starttls");
    }

    #[tokio::test]
    async fn test_dangerous_mode_builds_transport() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("DATABASE_URL", "postgres://test@localhost/test");
        env::set_var("JWT_SECRET", "test-secret-at-least-32-chars-long!");
        env::set_var("SMTP_HOST", "localhost");
        env::set_var("SMTP_TLS_MODE", "none");
        let config = Config::from_env().expect("config should parse");
        env::remove_var("SMTP_HOST");
        env::remove_var("SMTP_TLS_MODE");

        let service = SmtpService::new(&config).expect("should build with dangerous mode");
        assert!(service.is_configured());
    }
}
