//! SMTP email delivery service.
//!
//! Provides asynchronous email sending via an SMTP relay. When `SMTP_HOST` is
//! not set in the environment the service operates as a silent no-op, matching
//! the optional-service pattern used by OpenSearch and other integrations.

use crate::config::Config;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{AsyncSmtpConnection, Certificate, Tls, TlsParameters};
use lettre::transport::smtp::commands::Ehlo;
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

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
    /// Where and how the transport connects, kept for error hints and the
    /// test endpoint's EHLO probe. `None` exactly when `transport` is.
    target: Option<SmtpTarget>,
    /// Upper bound on one delivery ([`SEND_TIMEOUT`] outside tests).
    send_timeout: Duration,
}

/// Connection settings behind the transport (no credentials).
#[derive(Clone)]
struct SmtpTarget {
    host: String,
    port: u16,
    mode: SmtpTlsMode,
    tls: TlsParameters,
    has_credentials: bool,
}

/// Upper bound on one delivery. lettre's tokio transport applies its own
/// timeout to the TCP connect only, so a server that accepts the connection
/// and never speaks (a plaintext client on an implicit-TLS port, for
/// example) would otherwise hold the send open indefinitely.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the diagnostic EHLO probe may take in total.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

impl SmtpService {
    /// Build a new `SmtpService` from application config.
    ///
    /// Returns a no-op instance when `config.smtp_host` is `None`.
    pub fn new(config: &Config) -> Result<Self, SmtpError> {
        let from_address: Mailbox = config
            .smtp_from_address
            .parse()
            .map_err(|e| SmtpError::Config(format!("invalid SMTP_FROM_ADDRESS: {e}")))?;

        let mut target = None;
        let transport = match &config.smtp_host {
            Some(host) => {
                let tls_parameters = build_tls_parameters(host, config)?;
                let mode = SmtpTlsMode::from_config(&config.smtp_tls_mode);
                target = Some(SmtpTarget {
                    host: host.clone(),
                    port: config.smtp_port,
                    mode,
                    tls: tls_parameters.clone(),
                    has_credentials: config.smtp_username.is_some()
                        && config.smtp_password.is_some(),
                });
                let tls = match mode {
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
            target,
            send_timeout: SEND_TIMEOUT,
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

        match tokio::time::timeout(self.send_timeout, transport.send(message)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(SmtpError::Delivery(self.delivery_failure(&e))),
            Err(_) => return Err(SmtpError::Delivery(self.timeout_failure())),
        }

        tracing::info!(to = to, subject = subject, "email sent successfully");
        Ok(())
    }

    /// The settings a hint depends on, when SMTP is configured.
    pub fn hint_context(&self) -> Option<HintContext> {
        self.target.as_ref().map(|t| HintContext {
            mode: t.mode,
            port: t.port,
            has_credentials: t.has_credentials,
        })
    }

    fn delivery_failure(&self, err: &lettre::transport::smtp::Error) -> DeliveryFailure {
        let detail = err.to_string();
        let code = err.status().and_then(|c| c.to_string().parse::<u16>().ok());
        let kind = FailureKind::classify(code, err.is_tls(), &detail);
        let hint = self
            .hint_context()
            .and_then(|ctx| hint_for(kind, ctx, &detail, None));
        DeliveryFailure {
            detail,
            kind,
            hint,
            advertised: None,
        }
    }

    fn timeout_failure(&self) -> DeliveryFailure {
        let detail = format!(
            "no SMTP reply within {}s (the server accepted the connection but did not \
             complete the conversation)",
            self.send_timeout.as_secs()
        );
        let kind = FailureKind::Connection;
        let hint = self
            .hint_context()
            .and_then(|ctx| hint_for(kind, ctx, &detail, None));
        DeliveryFailure {
            detail,
            kind,
            hint,
            advertised: None,
        }
    }

    /// Connect separately and record what the server advertises in EHLO,
    /// before and (when offered) after STARTTLS. No credentials are sent and
    /// no mail is submitted. Used by the test endpoint after a failure:
    /// lettre keeps only the AUTH mechanisms it implements, so its own error
    /// cannot say that a server offered, say, only NTLM and GSSAPI.
    pub async fn probe(&self) -> SmtpProbe {
        let Some(target) = &self.target else {
            return SmtpProbe::default();
        };
        match tokio::time::timeout(PROBE_TIMEOUT, probe_target(target)).await {
            Ok(probe) => probe,
            Err(_) => SmtpProbe {
                error: Some(format!("no answer within {}s", PROBE_TIMEOUT.as_secs())),
                ..SmtpProbe::default()
            },
        }
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

async fn probe_target(target: &SmtpTarget) -> SmtpProbe {
    let mut probe = SmtpProbe::default();
    let client_id = ClientId::default();
    let implicit = target.mode == SmtpTlsMode::Implicit;
    let mut conn = match AsyncSmtpConnection::connect_tokio1(
        (target.host.as_str(), target.port),
        Some(PROBE_TIMEOUT),
        &client_id,
        implicit.then(|| target.tls.clone()),
        None,
    )
    .await
    {
        Ok(conn) => conn,
        Err(e) => {
            probe.error = Some(format!("connect: {e}"));
            return probe;
        }
    };

    let caps = match ehlo(&mut conn, &client_id).await {
        Ok(caps) => caps,
        Err(e) => {
            probe.error = Some(format!("EHLO: {e}"));
            conn.abort().await;
            return probe;
        }
    };
    if implicit {
        probe.encrypted = Some(caps);
    } else {
        let offers_starttls = caps.starttls;
        probe.plaintext = Some(caps);
        if offers_starttls {
            match conn.starttls(target.tls.clone(), &client_id).await {
                Ok(()) => match ehlo(&mut conn, &client_id).await {
                    Ok(caps) => probe.encrypted = Some(caps),
                    Err(e) => probe.error = Some(format!("EHLO after STARTTLS: {e}")),
                },
                Err(e) => probe.error = Some(format!("STARTTLS: {e}")),
            }
        }
    }
    conn.abort().await;
    probe
}

async fn ehlo(
    conn: &mut AsyncSmtpConnection,
    client_id: &ClientId,
) -> Result<EhloCapabilities, lettre::transport::smtp::Error> {
    let response = conn.command(Ehlo::new(client_id.clone())).await?;
    Ok(EhloCapabilities::from_lines(response.message()))
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
    Delivery(DeliveryFailure),

    #[error("SMTP is not configured (SMTP_HOST is not set)")]
    NotConfigured,
}

// ---------------------------------------------------------------------------
// Delivery diagnostics (#4591)
// ---------------------------------------------------------------------------

/// A failed delivery: lettre's error text, its class, a one-line hint, and
/// (from the test endpoint only) what the server advertised.
#[derive(Debug, Clone)]
pub struct DeliveryFailure {
    pub detail: String,
    pub kind: FailureKind,
    pub hint: Option<String>,
    pub advertised: Option<String>,
}

impl DeliveryFailure {
    /// Re-derive the hint with a probe result and attach its summary.
    pub fn with_probe(mut self, ctx: HintContext, probe: &SmtpProbe) -> Self {
        if let Some(hint) = hint_for(self.kind, ctx, &self.detail, Some(probe)) {
            self.hint = Some(hint);
        }
        let summary = probe.summary();
        if !summary.is_empty() {
            self.advertised = Some(summary);
        }
        self
    }
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMTP delivery failed: {}", self.detail)?;
        if let Some(advertised) = &self.advertised {
            write!(f, "; server advertised {advertised}")?;
        }
        if let Some(hint) = &self.hint {
            write!(f, "; hint: {hint}")?;
        }
        Ok(())
    }
}

/// The class of an SMTP delivery failure, for choosing a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Credentials are configured but the server advertised no AUTH
    /// mechanism Artifact Keeper can use.
    NoMechanism,
    /// STARTTLS is required and the server did not advertise it.
    NoStartTls,
    /// 535: the server rejected the credentials.
    AuthRejected,
    /// 530: the server wants authentication (or STARTTLS) first.
    AuthRequired,
    /// TLS handshake or certificate verification failed.
    Tls,
    /// Connect failure, timeout, or a dropped connection.
    Connection,
    /// Anything else, a refused sender or recipient for example.
    Other,
}

impl FailureKind {
    /// Classify from what lettre's error exposes publicly: the SMTP reply
    /// code, whether it is a TLS error, and its text.
    pub fn classify(code: Option<u16>, is_tls: bool, text: &str) -> Self {
        if text.contains("No compatible authentication mechanism") {
            return Self::NoMechanism;
        }
        if text.contains("STARTTLS is not supported") {
            return Self::NoStartTls;
        }
        match code {
            Some(535) => return Self::AuthRejected,
            Some(530) => return Self::AuthRequired,
            _ => {}
        }
        // lettre reports most TLS failures, certificate verification
        // included, as "Connection error: ... SSL routines ...", so the
        // text decides as well as the error kind.
        let lower = text.to_ascii_lowercase();
        if is_tls
            || ["ssl routines", "certificate", "handshake"]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            return Self::Tls;
        }
        if [
            "network error",
            "connection error",
            "timed out",
            "connection refused",
            "no smtp reply",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
        {
            return Self::Connection;
        }
        Self::Other
    }
}

/// The parts of the SMTP configuration a hint depends on.
#[derive(Debug, Clone, Copy)]
pub struct HintContext {
    pub mode: SmtpTlsMode,
    pub port: u16,
    pub has_credentials: bool,
}

/// AUTH mechanisms Artifact Keeper uses (lettre's defaults).
pub const SUPPORTED_AUTH_MECHANISMS: &[&str] = &["PLAIN", "LOGIN"];

/// What the server advertised in one EHLO reply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EhloCapabilities {
    pub starttls: bool,
    /// AUTH mechanisms as advertised, upper-cased, NTLM and GSSAPI included.
    pub auth: Vec<String>,
}

impl EhloCapabilities {
    /// Parse the lines of an EHLO reply; the first line is the greeting.
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Self {
        let mut caps = Self::default();
        for line in lines.into_iter().skip(1) {
            let upper = line.trim().to_ascii_uppercase();
            if upper == "STARTTLS" {
                caps.starttls = true;
            } else if let Some(rest) = upper
                .strip_prefix("AUTH ")
                .or_else(|| upper.strip_prefix("AUTH="))
            {
                for mech in rest.split_whitespace() {
                    if !caps.auth.iter().any(|m| m == mech) {
                        caps.auth.push(mech.to_string());
                    }
                }
            }
        }
        caps
    }

    /// Whether any advertised mechanism is one Artifact Keeper can use.
    pub fn has_supported_auth(&self) -> bool {
        self.auth
            .iter()
            .any(|m| SUPPORTED_AUTH_MECHANISMS.contains(&m.as_str()))
    }

    fn auth_list(&self) -> String {
        if self.auth.is_empty() {
            "no AUTH".to_string()
        } else {
            format!("AUTH {}", self.auth.join(" "))
        }
    }
}

/// What a separate EHLO probe saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmtpProbe {
    /// EHLO on the unencrypted connection (absent for implicit TLS).
    pub plaintext: Option<EhloCapabilities>,
    /// EHLO over implicit TLS or after a successful STARTTLS.
    pub encrypted: Option<EhloCapabilities>,
    /// Why the probe stopped early, if it did.
    pub error: Option<String>,
}

impl SmtpProbe {
    /// e.g. `before TLS: STARTTLS, AUTH NTLM GSSAPI; after STARTTLS: AUTH LOGIN PLAIN`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = &self.plaintext {
            let starttls = if p.starttls {
                "STARTTLS"
            } else {
                "no STARTTLS"
            };
            parts.push(format!("before TLS: {starttls}, {}", p.auth_list()));
        }
        if let Some(e) = &self.encrypted {
            let label = if self.plaintext.is_some() {
                "after STARTTLS"
            } else {
                "over TLS"
            };
            parts.push(format!("{label}: {}", e.auth_list()));
        }
        if let Some(err) = &self.error {
            parts.push(format!("probe stopped at {err}"));
        }
        parts.join("; ")
    }
}

const REJECTED_HINT: &str = "the server rejected the username or password (535). On \
     Exchange this usually means SMTP AUTH is disabled for this mailbox or on the receive \
     connector, or that the username has to be DOMAIN\\user or the UPN (user@domain)";

const CERT_HINT: &str = "the server's TLS certificate is not trusted. Set \
     SMTP_TLS_CA_CERT (or CUSTOM_CA_CERT_PATH) to the issuing CA in PEM form, or \
     SMTP_TLS_SKIP_VERIFY=true for testing only";

/// A one-line hint for a failure. `probe`, when present, sharpens it.
pub fn hint_for(
    kind: FailureKind,
    ctx: HintContext,
    detail: &str,
    probe: Option<&SmtpProbe>,
) -> Option<String> {
    let plain = probe.and_then(|p| p.plaintext.as_ref());
    let enc = probe.and_then(|p| p.encrypted.as_ref());
    let port = ctx.port;
    match kind {
        FailureKind::NoMechanism => {
            let upgraded = matches!(ctx.mode, SmtpTlsMode::Implicit | SmtpTlsMode::StartTls);
            if let (Some(p), Some(e), false) = (plain, enc, upgraded) {
                if !p.has_supported_auth() && e.has_supported_auth() {
                    return Some(format!(
                        "the server offers only {} before TLS and {} after STARTTLS; set \
                         SMTP_TLS_MODE=starttls",
                        p.auth_list(),
                        e.auth_list()
                    ));
                }
            }
            if probe.is_none() && ctx.mode == SmtpTlsMode::None {
                return Some(
                    "the server offered no AUTH mechanism Artifact Keeper supports (PLAIN, \
                     LOGIN) on the unencrypted connection. Exchange offers only NTLM and \
                     GSSAPI before TLS by default: use SMTP_TLS_MODE=starttls, or unset \
                     SMTP_USERNAME and SMTP_PASSWORD if the connector relays for this host \
                     without authentication"
                        .to_string(),
                );
            }
            let seen = if upgraded { enc } else { enc.or(plain) };
            let offered = seen
                .map(|c| format!(" (it offered {})", c.auth_list()))
                .unwrap_or_default();
            Some(format!(
                "the server offered no AUTH mechanism Artifact Keeper supports (PLAIN, \
                 LOGIN){offered}. NTLM and GSSAPI are not supported: enable basic \
                 authentication on the server or receive connector, or unset SMTP_USERNAME \
                 and SMTP_PASSWORD if it relays for this host without authentication"
            ))
        }
        FailureKind::NoStartTls => Some(format!(
            "the server did not advertise STARTTLS on port {port}. Use SMTP_TLS_MODE=tls if \
             this is an implicit-TLS port (usually 465), enable TLS on the server (on \
             Exchange, on the receive connector), or use SMTP_TLS_MODE=starttls-opportunistic \
             to send unencrypted when STARTTLS is not offered"
        )),
        FailureKind::AuthRejected => Some(REJECTED_HINT.to_string()),
        FailureKind::AuthRequired => {
            let wants_starttls = detail.to_ascii_uppercase().contains("STARTTLS")
                || (ctx.mode == SmtpTlsMode::None && plain.is_some_and(|p| p.starttls));
            if wants_starttls && ctx.mode == SmtpTlsMode::None {
                Some(
                    "the server requires STARTTLS before it accepts mail: set \
                     SMTP_TLS_MODE=starttls"
                        .to_string(),
                )
            } else if !ctx.has_credentials {
                Some(
                    "the server requires authentication: set SMTP_USERNAME and SMTP_PASSWORD, \
                     or allow this host to relay without authentication on the server"
                        .to_string(),
                )
            } else {
                Some("the server requires authentication before it accepts mail".to_string())
            }
        }
        FailureKind::Tls => {
            let lower = detail.to_ascii_lowercase();
            if lower.contains("certificate") || lower.contains("verify") {
                Some(CERT_HINT.to_string())
            } else if ctx.mode == SmtpTlsMode::Implicit {
                Some(format!(
                    "the TLS handshake failed. SMTP_TLS_MODE=tls expects TLS from the first \
                     byte (usually port 465); if port {port} starts unencrypted (587, 25), use \
                     SMTP_TLS_MODE=starttls"
                ))
            } else {
                Some(format!("the TLS handshake failed. {CERT_HINT}"))
            }
        }
        FailureKind::Connection => {
            if port == 465 && ctx.mode != SmtpTlsMode::Implicit {
                Some(
                    "port 465 normally expects TLS from the first byte: set SMTP_TLS_MODE=tls"
                        .to_string(),
                )
            } else {
                Some(format!(
                    "no SMTP conversation on port {port}. Check SMTP_HOST, SMTP_PORT and \
                     firewalls, and that SMTP_TLS_MODE matches the port (tls for 465, \
                     starttls for 587 and 25)"
                ))
            }
        }
        FailureKind::Other => None,
    }
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

    // -- delivery diagnostics (#4591) --

    fn ctx(mode: SmtpTlsMode, port: u16, has_credentials: bool) -> HintContext {
        HintContext {
            mode,
            port,
            has_credentials,
        }
    }

    fn caps(starttls: bool, auth: &[&str]) -> EhloCapabilities {
        EhloCapabilities {
            starttls,
            auth: auth.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_classify_the_three_reported_errors() {
        // Exactly the lettre texts from discussion #4244.
        assert_eq!(
            FailureKind::classify(
                Some(535),
                false,
                "permanent error (535): 5.7.3 Authentication unsuccessful"
            ),
            FailureKind::AuthRejected
        );
        assert_eq!(
            FailureKind::classify(
                None,
                false,
                "internal client error: STARTTLS is not supported on this server"
            ),
            FailureKind::NoStartTls
        );
        assert_eq!(
            FailureKind::classify(
                None,
                false,
                "internal client error: No compatible authentication mechanism was found"
            ),
            FailureKind::NoMechanism
        );
    }

    #[test]
    fn test_classify_other_failures() {
        assert_eq!(
            FailureKind::classify(
                Some(530),
                false,
                "permanent error (530): 5.7.1 Client was not authenticated"
            ),
            FailureKind::AuthRequired
        );
        assert_eq!(
            FailureKind::classify(None, true, "tls error: certificate verify failed"),
            FailureKind::Tls
        );
        // What lettre 0.11 + native-tls actually report (seen in the matrix):
        // kind Connection, not Tls.
        assert_eq!(
            FailureKind::classify(
                None,
                false,
                "Connection error: Connection error: error:0A000086:SSL routines:\
                 tls_post_process_server_certificate:certificate verify failed:\
                 ssl/statem/statem_clnt.c:2124: (unable to get local issuer certificate)"
            ),
            FailureKind::Tls
        );
        assert_eq!(
            FailureKind::classify(
                None,
                false,
                "Connection error: Connection error: error:0A00010B:SSL routines:\
                 tls_validate_record_header:wrong version number"
            ),
            FailureKind::Tls
        );
        assert_eq!(
            FailureKind::classify(None, false, "no SMTP reply within 60s"),
            FailureKind::Connection
        );
        assert_eq!(
            FailureKind::classify(None, false, "network error: timed out"),
            FailureKind::Connection
        );
        assert_eq!(
            FailureKind::classify(
                Some(550),
                false,
                "permanent error (550): mailbox unavailable"
            ),
            FailureKind::Other
        );
    }

    #[test]
    fn test_ehlo_parsing_keeps_mechanisms_lettre_drops() {
        let lines = [
            "mail.example.com Hello",
            "SIZE 37748736",
            "STARTTLS",
            "AUTH NTLM GSSAPI",
            "AUTH=LOGIN",
            "8BITMIME",
        ];
        let parsed = EhloCapabilities::from_lines(lines);
        assert!(parsed.starttls);
        assert_eq!(parsed.auth, vec!["NTLM", "GSSAPI", "LOGIN"]);
        assert!(parsed.has_supported_auth());
        assert!(!caps(true, &["NTLM", "GSSAPI"]).has_supported_auth());
        // The greeting line is never read as a capability.
        assert!(!EhloCapabilities::from_lines(["STARTTLS"]).starttls);
    }

    #[test]
    fn test_probe_summary() {
        let probe = SmtpProbe {
            plaintext: Some(caps(true, &["NTLM", "GSSAPI"])),
            encrypted: Some(caps(false, &["GSSAPI", "NTLM", "LOGIN", "PLAIN"])),
            error: None,
        };
        assert_eq!(
            probe.summary(),
            "before TLS: STARTTLS, AUTH NTLM GSSAPI; after STARTTLS: AUTH GSSAPI NTLM LOGIN PLAIN"
        );
        let implicit = SmtpProbe {
            plaintext: None,
            encrypted: Some(caps(false, &[])),
            error: None,
        };
        assert_eq!(implicit.summary(), "over TLS: no AUTH");
    }

    #[test]
    fn test_hint_no_mechanism_points_to_starttls_when_basic_auth_follows_tls() {
        let probe = SmtpProbe {
            plaintext: Some(caps(true, &["NTLM", "GSSAPI"])),
            encrypted: Some(caps(false, &["LOGIN", "PLAIN"])),
            error: None,
        };
        let hint = hint_for(
            FailureKind::NoMechanism,
            ctx(SmtpTlsMode::None, 587, true),
            "",
            Some(&probe),
        )
        .unwrap();
        assert!(hint.contains("only AUTH NTLM GSSAPI before TLS"), "{hint}");
        assert!(hint.contains("SMTP_TLS_MODE=starttls"), "{hint}");
        // Without a probe the hint still names the Exchange default.
        let hint = hint_for(
            FailureKind::NoMechanism,
            ctx(SmtpTlsMode::None, 587, true),
            "",
            None,
        )
        .unwrap();
        assert!(hint.contains("NTLM and GSSAPI"), "{hint}");
        assert!(hint.contains("SMTP_TLS_MODE=starttls"), "{hint}");
    }

    #[test]
    fn test_hint_no_mechanism_when_nothing_usable_is_offered() {
        let probe = SmtpProbe {
            plaintext: Some(caps(false, &["NTLM", "GSSAPI"])),
            encrypted: None,
            error: None,
        };
        let hint = hint_for(
            FailureKind::NoMechanism,
            ctx(SmtpTlsMode::StartTlsOpportunistic, 25, true),
            "",
            Some(&probe),
        )
        .unwrap();
        assert!(hint.contains("it offered AUTH NTLM GSSAPI"), "{hint}");
        assert!(hint.contains("unset SMTP_USERNAME"), "{hint}");
    }

    #[test]
    fn test_hint_no_starttls_names_port_and_alternatives() {
        let hint = hint_for(
            FailureKind::NoStartTls,
            ctx(SmtpTlsMode::StartTls, 25, true),
            "",
            None,
        )
        .unwrap();
        assert!(hint.contains("port 25"), "{hint}");
        assert!(hint.contains("SMTP_TLS_MODE=tls"), "{hint}");
        assert!(hint.contains("starttls-opportunistic"), "{hint}");
    }

    #[test]
    fn test_hint_535_mentions_exchange_username_forms() {
        let hint = hint_for(
            FailureKind::AuthRejected,
            ctx(SmtpTlsMode::StartTls, 587, true),
            "",
            None,
        )
        .unwrap();
        assert!(hint.contains("DOMAIN\\user"), "{hint}");
        assert!(hint.contains("SMTP AUTH is disabled"), "{hint}");
    }

    #[test]
    fn test_hint_530_and_tls_variants() {
        let starttls_first = hint_for(
            FailureKind::AuthRequired,
            ctx(SmtpTlsMode::None, 587, false),
            "permanent error (530): 5.7.0 Must issue a STARTTLS command first",
            None,
        )
        .unwrap();
        assert!(
            starttls_first.contains("SMTP_TLS_MODE=starttls"),
            "{starttls_first}"
        );
        let anon = hint_for(
            FailureKind::AuthRequired,
            ctx(SmtpTlsMode::StartTls, 587, false),
            "permanent error (530): 5.7.1 Client was not authenticated",
            None,
        )
        .unwrap();
        assert!(anon.contains("set SMTP_USERNAME"), "{anon}");
        let cert = hint_for(
            FailureKind::Tls,
            ctx(SmtpTlsMode::StartTls, 587, true),
            "tls error: error:0A000086:SSL routines::certificate verify failed",
            None,
        )
        .unwrap();
        assert!(cert.contains("SMTP_TLS_CA_CERT"), "{cert}");
        let handshake = hint_for(
            FailureKind::Tls,
            ctx(SmtpTlsMode::Implicit, 587, true),
            "tls error: wrong version number",
            None,
        )
        .unwrap();
        assert!(handshake.contains("SMTP_TLS_MODE=starttls"), "{handshake}");
        let port465 = hint_for(
            FailureKind::Connection,
            ctx(SmtpTlsMode::StartTls, 465, true),
            "network error: timed out",
            None,
        )
        .unwrap();
        assert!(port465.contains("SMTP_TLS_MODE=tls"), "{port465}");
    }

    #[test]
    fn test_delivery_failure_display() {
        let failure = DeliveryFailure {
            detail: "internal client error: No compatible authentication mechanism was found"
                .into(),
            kind: FailureKind::NoMechanism,
            hint: Some("use starttls".into()),
            advertised: Some("before TLS: STARTTLS, AUTH NTLM".into()),
        };
        assert_eq!(
            SmtpError::Delivery(failure).to_string(),
            "SMTP send error: SMTP delivery failed: internal client error: No compatible \
             authentication mechanism was found; server advertised before TLS: STARTTLS, \
             AUTH NTLM; hint: use starttls"
        );
    }

    /// A one-connection-at-a-time fake of an Exchange connector with TLS
    /// off: no STARTTLS, AUTH NTLM GSSAPI only. Returns its port.
    async fn fake_ntlm_only_server() -> u16 {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut lines = BufReader::new(r).lines();
                    let _ = w
                        .write_all(b"220 fake Microsoft ESMTP MAIL Service ready\r\n")
                        .await;
                    while let Ok(Some(line)) = lines.next_line().await {
                        let verb = line
                            .split_whitespace()
                            .next()
                            .unwrap_or("")
                            .to_ascii_uppercase();
                        let reply: &[u8] = match verb.as_str() {
                            "EHLO" => b"250-fake Hello\r\n250-SIZE 1000000\r\n250-AUTH NTLM GSSAPI\r\n250 8BITMIME\r\n",
                            "QUIT" => b"221 2.0.0 Bye\r\n",
                            _ => b"502 5.3.3 Command not implemented\r\n",
                        };
                        if w.write_all(reply).await.is_err() || verb == "QUIT" {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_send_against_ntlm_only_server_explains_itself() {
        let port = fake_ntlm_only_server().await;
        let port_s = port.to_string();
        let config = config_with(&[
            ("SMTP_HOST", "127.0.0.1"),
            ("SMTP_PORT", port_s.as_str()),
            ("SMTP_TLS_MODE", "none"),
            ("SMTP_USERNAME", "DOMAIN\\svc-ak"),
            ("SMTP_PASSWORD", "not-a-real-password"),
        ]);
        let service = SmtpService::new(&config).unwrap();
        let err = service
            .send_test_email("someone@example.com")
            .await
            .expect_err("no usable mechanism");
        let SmtpError::Delivery(failure) = err else {
            panic!("expected a delivery failure, got {err}");
        };
        assert_eq!(failure.kind, FailureKind::NoMechanism);
        assert!(failure
            .detail
            .contains("No compatible authentication mechanism"));

        let probe = service.probe().await;
        assert_eq!(probe.plaintext, Some(caps(false, &["NTLM", "GSSAPI"])));
        assert_eq!(probe.encrypted, None);

        let failure = failure.with_probe(service.hint_context().unwrap(), &probe);
        let text = failure.to_string();
        assert!(
            text.contains("before TLS: no STARTTLS, AUTH NTLM GSSAPI"),
            "{text}"
        );
        assert!(text.contains("NTLM and GSSAPI are not supported"), "{text}");
        assert!(!text.contains("not-a-real-password"), "{text}");
    }

    #[tokio::test]
    async fn test_strict_starttls_against_server_without_it() {
        let port = fake_ntlm_only_server().await;
        let port_s = port.to_string();
        let config = config_with(&[
            ("SMTP_HOST", "127.0.0.1"),
            ("SMTP_PORT", port_s.as_str()),
            ("SMTP_TLS_MODE", "starttls"),
        ]);
        let service = SmtpService::new(&config).unwrap();
        let err = service
            .send_test_email("someone@example.com")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("STARTTLS is not supported on this server"),
            "{text}"
        );
        assert!(text.contains(&format!("port {port}")), "{text}");
    }

    #[tokio::test]
    async fn test_silent_server_times_out_instead_of_hanging() {
        // Accepts and never speaks, like an implicit-TLS port waiting for a
        // ClientHello while a plaintext client waits for the 220 greeting.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let port_s = port.to_string();
        let config = config_with(&[
            ("SMTP_HOST", "127.0.0.1"),
            ("SMTP_PORT", port_s.as_str()),
            ("SMTP_TLS_MODE", "starttls"),
        ]);
        let mut service = SmtpService::new(&config).unwrap();
        service.send_timeout = Duration::from_millis(300);
        let err = service
            .send_test_email("someone@example.com")
            .await
            .unwrap_err();
        let SmtpError::Delivery(failure) = err else {
            panic!("expected a delivery failure, got {err}");
        };
        assert_eq!(failure.kind, FailureKind::Connection);
        assert!(failure.detail.contains("no SMTP reply within"), "{failure}");
        assert!(
            failure
                .to_string()
                .contains("SMTP_TLS_MODE matches the port"),
            "{failure}"
        );
    }
}
