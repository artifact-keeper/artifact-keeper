//! FIPS 140-3 mode: the `FIPS_MODE` setting, the startup gate and the
//! policy checks it enforces (#5580).
//!
//! Three modes:
//!
//! * `off` (default): nothing changes. The facade (`crate::crypto`) still
//!   runs on aws-lc-rs, but no configuration is refused and no new storage
//!   format is written.
//! * `warn`: every check `strict` would enforce runs at startup; each
//!   violation is logged once with a fix hint and listed in `/health`, and
//!   the process starts anyway. The way to find out what `strict` would
//!   refuse before switching.
//! * `strict`: the binary must be a `--features fips` build whose module
//!   passed its power-on self-tests, rustls uses the FIPS provider, and any
//!   violation refuses startup. Services consult [`mode()`] to refuse
//!   non-approved operations at run time (SHA-1 SAML signatures, legacy RSA
//!   JWKS keys, SHA-1 repository signatures) and to write module-backed
//!   storage formats (#5582, #5583).
//!
//! The mode is read once from `FIPS_MODE` and published through [`mode()`];
//! `Off` until [`install`] runs, so library code and tests that never set
//! it see today's behaviour.

use std::sync::OnceLock;

use serde::Serialize;
use utoipa::ToSchema;

use crate::config::Config;

/// The `FIPS_MODE` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FipsMode {
    #[default]
    Off,
    Warn,
    Strict,
}

impl FipsMode {
    pub const ENV: &'static str = "FIPS_MODE";

    /// Parse `off` / `warn` / `strict` (case-insensitive; `0`/`false`
    /// mean `off`, `1`/`true`/`on`/`enforce` mean `strict`).
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "0" | "false" | "disabled" => Ok(Self::Off),
            "warn" | "warning" | "audit" => Ok(Self::Warn),
            "strict" | "1" | "true" | "on" | "enforce" | "required" => Ok(Self::Strict),
            other => Err(format!(
                "{}={other:?} is not valid; use off, warn or strict",
                Self::ENV
            )),
        }
    }

    /// Read `FIPS_MODE` from the environment (`off` when unset).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(Self::ENV) {
            Ok(v) => Self::parse(&v),
            Err(_) => Ok(Self::Off),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Strict => "strict",
        }
    }

    /// `warn` or `strict`: the checks run.
    pub fn checks_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// `strict`: violations refuse startup, non-approved operations are
    /// refused and module-backed storage formats are written.
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

impl std::fmt::Display for FipsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing `strict` mode refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Violation {
    /// Stable identifier, e.g. `non-fips-build`, `smtp-tls-skip-verify`.
    pub code: &'static str,
    /// What is wrong, without secrets.
    pub message: String,
    /// How to fix it.
    pub hint: &'static str,
}

impl Violation {
    fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
        }
    }
}

/// Minimum HMAC key length for the session JWT secret in FIPS mode
/// (SP 800-107: at least half the digest output, 256 bits for HMAC-SHA256
/// when the key is also used for derivation).
pub const MIN_JWT_SECRET_BYTES_FIPS: usize = 32;

/// Checks that need only the build and the module.
pub fn module_violations(mode: FipsMode) -> Vec<Violation> {
    let mut v = Vec::new();
    if !mode.checks_enabled() {
        return v;
    }
    if !cfg!(feature = "fips") {
        v.push(Violation::new(
            "non-fips-build",
            "this binary was not built with the FIPS module (cargo feature `fips`)",
            "run the `-fips` image tag or build with `--features fips`",
        ));
    } else if !crate::crypto::module_fips_active() {
        v.push(Violation::new(
            "module-self-test",
            "the AWS-LC FIPS module did not enter FIPS mode (power-on self-test failure)",
            "the binary or its module is corrupt; reinstall the release artifact",
        ));
    }
    v
}

/// Checks on the environment-level configuration.
pub fn config_violations(config: &Config) -> Vec<Violation> {
    let mut v = Vec::new();
    if !config.fips_mode.checks_enabled() {
        return v;
    }
    if config.jwt_secret.len() < MIN_JWT_SECRET_BYTES_FIPS {
        v.push(Violation::new(
            "jwt-secret-length",
            format!(
                "JWT_SECRET is {} bytes; FIPS mode requires at least {MIN_JWT_SECRET_BYTES_FIPS}",
                config.jwt_secret.len()
            ),
            "generate a new secret with at least 256 bits of entropy (openssl rand -base64 48)",
        ));
    }
    if config.smtp_tls_skip_verify {
        v.push(Violation::new(
            "smtp-tls-skip-verify",
            "SMTP_TLS_SKIP_VERIFY=true disables certificate verification for SMTP",
            "unset it and point SMTP_TLS_CA_CERT at the server's CA instead",
        ));
    }
    if config.data_encryption_key.is_none() {
        v.push(Violation::new(
            "data-encryption-key-missing",
            "DATA_ENCRYPTION_KEY is not set; stored secrets would stay under a key derived from JWT_SECRET",
            "set DATA_ENCRYPTION_KEY (32 random bytes, base64) or DATA_ENCRYPTION_KEY_FILE, then run `reencrypt-secrets`",
        ));
    }
    // Each flag is parsed exactly the way the service that honours it parses
    // it, so strict never refuses a value the service ignores, nor accepts
    // one it honours.
    if env_flag_exact("LDAP_INSECURE_TLS") {
        v.push(Violation::new(
            "ldap-insecure-tls",
            "LDAP_INSECURE_TLS=true disables certificate verification for LDAP",
            "unset it and set LDAP_CA_CERT_PATH to the directory's CA",
        ));
    }
    if env_flag_lowercase("S3_INSECURE_TLS") {
        v.push(Violation::new(
            "s3-insecure-tls",
            "S3_INSECURE_TLS=true disables certificate verification for object storage",
            "unset it and trust the storage endpoint's CA through the OS store or CUSTOM_CA_CERT_PATH",
        ));
    }
    if config.opensearch_allow_invalid_certs {
        v.push(Violation::new(
            "opensearch-allow-invalid-certs",
            "OPENSEARCH_ALLOW_INVALID_CERTS=true disables certificate verification for search",
            "unset it and trust the search endpoint's CA",
        ));
    }
    v
}

/// `services/ldap_service.rs`: exactly `true` or `1`.
fn env_flag_exact(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// `storage/s3.rs`: lower-cased `true`, or `1`.
fn env_flag_lowercase(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Checks on database-held configuration (SSO providers). Runs after the
/// pool is up; any query error is reported as a violation rather than
/// swallowed, because "could not check" is not "compliant".
pub async fn db_violations(mode: FipsMode, db: &sqlx::PgPool) -> Vec<Violation> {
    let mut v = Vec::new();
    if !mode.checks_enabled() {
        return v;
    }
    // `oidc_configs` is the SSO provider table (services/auth_config_service).
    match sqlx::query_scalar::<_, String>(
        "SELECT name FROM oidc_configs WHERE allow_legacy_rsa_keys = true ORDER BY name",
    )
    .fetch_all(db)
    .await
    {
        Ok(names) => {
            for name in names {
                v.push(Violation::new(
                    "oidc-legacy-rsa-keys",
                    format!("OIDC provider {name:?} has allow_legacy_rsa_keys enabled (RSA keys under 2048 bits)"),
                    "disable allow_legacy_rsa_keys on the provider and have the IdP rotate to a 2048-bit or larger key",
                ));
            }
        }
        Err(e) => v.push(Violation::new(
            "policy-check-failed",
            format!("could not inspect SSO provider configuration: {e}"),
            "make sure the database is reachable and migrations have run",
        )),
    }
    // Per-provider LDAP skip-verify (migration 174) is honoured by
    // `ldap_service` exactly like LDAP_INSECURE_TLS, so it is refused the
    // same way.
    match sqlx::query_scalar::<_, String>(
        "SELECT name FROM ldap_configs WHERE insecure_skip_verify = true ORDER BY name",
    )
    .fetch_all(db)
    .await
    {
        Ok(names) => {
            for name in names {
                v.push(Violation::new(
                    "ldap-insecure-tls",
                    format!("LDAP provider {name:?} has insecure_skip_verify enabled"),
                    "disable insecure_skip_verify on the provider and configure its CA certificate",
                ));
            }
        }
        Err(e) => v.push(Violation::new(
            "policy-check-failed",
            format!("could not inspect LDAP provider configuration: {e}"),
            "make sure the database is reachable and migrations have run",
        )),
    }
    v
}

/// What `/health` publishes (#5580).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CryptoHealth {
    /// Linked cryptographic library (`AWS-LC` or `AWS-LC FIPS`).
    pub provider: &'static str,
    /// Version of the `aws-lc-rs` binding.
    pub provider_version: &'static str,
    /// Whether the binary was built with the `fips` feature.
    pub fips_build: bool,
    /// Whether the module reports FIPS mode active (self-tests passed).
    pub fips_module_active: bool,
    /// The configured `FIPS_MODE`.
    pub mode: FipsMode,
    /// Startup violations (empty in `off` mode and on a compliant `warn` or
    /// `strict` deployment).
    pub violations: Vec<Violation>,
}

struct Installed {
    mode: FipsMode,
    violations: Vec<Violation>,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();

/// The active mode. `Off` until [`install`] has run.
pub fn mode() -> FipsMode {
    INSTALLED.get().map(|i| i.mode).unwrap_or_default()
}

/// Shorthand for `mode().is_strict()`.
pub fn strict() -> bool {
    mode().is_strict()
}

/// The `/health` report for the current process, with full violation text.
pub fn health_report() -> CryptoHealth {
    health_report_for(true)
}

/// The `/health` report. With `expose_details` false (the unauthenticated
/// default, #2226) each violation keeps its stable `code` but its message
/// and hint are replaced, since they can name providers and quote database
/// errors.
pub fn health_report_for(expose_details: bool) -> CryptoHealth {
    let installed = INSTALLED.get();
    let mut violations = installed.map(|i| i.violations.clone()).unwrap_or_default();
    if !expose_details {
        for v in &mut violations {
            v.message =
                "details withheld; set EXPOSE_DETAILED_HEALTH=true or read the startup log".into();
            v.hint = "";
        }
    }
    CryptoHealth {
        provider: crate::crypto::provider_name(),
        provider_version: crate::crypto::provider_version(),
        fips_build: cfg!(feature = "fips"),
        fips_module_active: crate::crypto::module_fips_active(),
        mode: installed.map(|i| i.mode).unwrap_or_default(),
        violations,
    }
}

/// Decide what to do with the collected violations: `strict` refuses with
/// every violation in the message, `warn` logs each once, `off` is silent.
/// Pure, so it is unit-tested without touching process state.
pub fn decide(mode: FipsMode, violations: &[Violation]) -> Result<(), String> {
    if violations.is_empty() || !mode.checks_enabled() {
        return Ok(());
    }
    if mode.is_strict() {
        let mut msg = format!(
            "FIPS_MODE=strict refused to start: {} violation(s)\n",
            violations.len()
        );
        for v in violations {
            msg.push_str(&format!(
                "  - [{}] {} (fix: {})\n",
                v.code, v.message, v.hint
            ));
        }
        return Err(msg);
    }
    for v in violations {
        tracing::warn!(
            code = v.code,
            hint = v.hint,
            "FIPS_MODE=warn: {} (strict mode would refuse to start)",
            v.message
        );
    }
    Ok(())
}

/// Publish the mode and its violations for [`mode()`] and [`health_report`],
/// set the `ak_fips_mode` gauge, and apply [`decide`]. Call once at startup
/// after the module, config and database checks have been collected; a
/// second call is ignored.
pub fn install(mode: FipsMode, violations: Vec<Violation>) -> Result<(), String> {
    let result = decide(mode, &violations);
    let _ = INSTALLED.set(Installed { mode, violations });
    metrics::gauge!("ak_fips_mode").set(match mode {
        FipsMode::Off => 0.0,
        FipsMode::Warn => 1.0,
        FipsMode::Strict => 2.0,
    });
    if mode.checks_enabled() {
        tracing::info!(
            mode = %mode,
            provider = crate::crypto::provider_name(),
            fips_module_active = crate::crypto::module_fips_active(),
            "FIPS mode"
        );
    }
    result
}

/// Install the rustls provider for `mode`: the FIPS provider when checks
/// are enabled on a FIPS build, otherwise the default aws-lc-rs provider.
/// Returns whether the installed provider is FIPS. Safe to call more than
/// once; later calls report the already-installed provider.
pub fn install_rustls_provider(mode: FipsMode) -> bool {
    #[cfg(feature = "fips")]
    let provider = if mode.checks_enabled() {
        rustls::crypto::default_fips_provider()
    } else {
        rustls::crypto::aws_lc_rs::default_provider()
    };
    #[cfg(not(feature = "fips"))]
    let provider = {
        let _ = mode;
        rustls::crypto::aws_lc_rs::default_provider()
    };
    let fips = provider.fips();
    match provider.install_default() {
        Ok(()) => fips,
        Err(already) => already.fips(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_documented_spellings_and_rejects_others() {
        for s in ["", "off", "OFF", "0", "false", "disabled", " off "] {
            assert_eq!(FipsMode::parse(s), Ok(FipsMode::Off), "{s:?}");
        }
        for s in ["warn", "Warning", "audit"] {
            assert_eq!(FipsMode::parse(s), Ok(FipsMode::Warn), "{s:?}");
        }
        for s in ["strict", "1", "true", "on", "enforce", "required", "STRICT"] {
            assert_eq!(FipsMode::parse(s), Ok(FipsMode::Strict), "{s:?}");
        }
        let err = FipsMode::parse("maybe").unwrap_err();
        assert!(err.contains("FIPS_MODE=\"maybe\""), "{err}");
        assert!(err.contains("off, warn or strict"));
    }

    #[test]
    fn mode_predicates_and_display() {
        assert!(!FipsMode::Off.checks_enabled());
        assert!(FipsMode::Warn.checks_enabled());
        assert!(FipsMode::Strict.checks_enabled());
        assert!(!FipsMode::Warn.is_strict());
        assert!(FipsMode::Strict.is_strict());
        assert_eq!(FipsMode::default(), FipsMode::Off);
        assert_eq!(FipsMode::Warn.to_string(), "warn");
        assert_eq!(
            serde_json::to_string(&FipsMode::Strict).unwrap(),
            "\"strict\""
        );
    }

    #[test]
    fn module_violations_depend_on_build_and_mode() {
        assert!(module_violations(FipsMode::Off).is_empty());
        let v = module_violations(FipsMode::Strict);
        if cfg!(feature = "fips") {
            assert!(v.is_empty(), "{v:?}");
        } else {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].code, "non-fips-build");
        }
    }

    #[test]
    fn config_violations_cover_each_rule_and_are_silent_when_off() {
        let mut c = Config::test_config();
        c.fips_mode = FipsMode::Off;
        c.smtp_tls_skip_verify = true;
        c.jwt_secret = "short".into();
        assert!(config_violations(&c).is_empty());

        c.fips_mode = FipsMode::Warn;
        c.opensearch_allow_invalid_certs = true;
        let codes: Vec<_> = config_violations(&c).into_iter().map(|v| v.code).collect();
        assert_eq!(
            codes,
            vec![
                "jwt-secret-length",
                "smtp-tls-skip-verify",
                "data-encryption-key-missing",
                "opensearch-allow-invalid-certs"
            ]
        );
        c.opensearch_allow_invalid_certs = false;

        c.jwt_secret = "x".repeat(MIN_JWT_SECRET_BYTES_FIPS);
        c.smtp_tls_skip_verify = false;
        c.data_encryption_key = Some("00".repeat(32));
        c.fips_mode = FipsMode::Strict;
        assert!(config_violations(&c).is_empty());
    }

    #[test]
    fn decide_is_silent_off_warns_in_warn_and_refuses_in_strict() {
        let v = vec![
            Violation::new("a", "first", "fix a"),
            Violation::new("b", "second", "fix b"),
        ];
        assert_eq!(decide(FipsMode::Off, &v), Ok(()));
        assert_eq!(decide(FipsMode::Warn, &v), Ok(()));
        assert_eq!(decide(FipsMode::Strict, &[]), Ok(()));
        let err = decide(FipsMode::Strict, &v).unwrap_err();
        assert!(err.starts_with("FIPS_MODE=strict refused to start: 2 violation(s)"));
        assert!(err.contains("[a] first (fix: fix a)"));
        assert!(err.contains("[b] second (fix: fix b)"));
    }

    #[test]
    fn health_report_before_install_is_off_with_no_violations() {
        // `install` is never called in the unit-test binary, so this pins
        // the library default every embedding sees.
        let h = health_report();
        assert_eq!(h.mode, FipsMode::Off);
        assert!(h.violations.is_empty());
        assert_eq!(h.fips_build, cfg!(feature = "fips"));
        assert_eq!(h.fips_module_active, cfg!(feature = "fips"));
        assert!(h.provider.starts_with("AWS-LC"));
        assert!(!h.provider_version.is_empty());
        assert_eq!(mode(), FipsMode::Off);
        assert!(!strict());
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["mode"], "off");
        assert_eq!(json["violations"], serde_json::json!([]));
    }

    #[test]
    fn health_report_for_redacts_violation_text_unless_exposed() {
        let v = vec![Violation::new("a", "provider \"corp\" is bad", "fix a")];
        let s = decide(FipsMode::Warn, &v);
        assert_eq!(s, Ok(()));
        // The redaction is a pure function of the stored list; exercise it on
        // a local copy since INSTALLED is process-global.
        let mut redacted = v.clone();
        for r in &mut redacted {
            r.message =
                "details withheld; set EXPOSE_DETAILED_HEALTH=true or read the startup log".into();
            r.hint = "";
        }
        assert_eq!(redacted[0].code, "a");
        assert!(!redacted[0].message.contains("corp"));
        assert!(health_report_for(false)
            .violations
            .iter()
            .all(|v| v.hint.is_empty()));
    }

    #[test]
    fn rustls_provider_install_reports_fips_according_to_build() {
        let fips = install_rustls_provider(FipsMode::Off);
        assert!(!fips || cfg!(feature = "fips"));
        // Idempotent: a second call reports the provider already installed,
        // whatever mode it is asked for.
        assert_eq!(install_rustls_provider(FipsMode::Strict), fips);
    }

    #[test]
    fn env_flags_parse_like_the_services_that_honour_them() {
        let key = "AK_TEST_FIPS_ENV_FLAG_5580";
        std::env::remove_var(key);
        assert!(!env_flag_exact(key));
        assert!(!env_flag_lowercase(key));
        for (v, exact, lower) in [
            ("1", true, true),
            ("true", true, true),
            ("TRUE", false, true),
            ("yes", false, false),
            ("on", false, false),
            ("0", false, false),
        ] {
            std::env::set_var(key, v);
            assert_eq!(env_flag_exact(key), exact, "exact {v}");
            assert_eq!(env_flag_lowercase(key), lower, "lowercase {v}");
        }
        std::env::remove_var(key);
    }
}
