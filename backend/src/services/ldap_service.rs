//! LDAP authentication service.
//!
//! Provides authentication against LDAP/Active Directory servers.
//! Uses a simple bind-based authentication approach.

use std::sync::Arc;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// LDAP configuration parsed from environment
#[derive(Clone)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., ldap://ldap.example.com:389)
    pub url: String,
    /// Base DN for user searches (e.g., dc=example,dc=com)
    pub base_dn: String,
    /// User search filter pattern.
    ///
    /// Supports both `{0}` and `{username}` placeholders.
    pub user_filter: String,
    /// Bind DN for service account (optional, for search-then-bind)
    pub bind_dn: Option<String>,
    /// Bind password for service account
    pub bind_password: Option<String>,
    /// Attribute containing the username
    pub username_attr: String,
    /// Attribute containing the email
    pub email_attr: String,
    /// Attribute containing the display name
    pub display_name_attr: String,
    /// Attribute containing group memberships
    pub groups_attr: String,
    /// Base DN for group searches / scoping (e.g., ou=groups,dc=example,dc=com).
    /// When set, group synchronization is enabled (issue #2468).
    pub group_base_dn: Option<String>,
    /// Group search filter pattern. `{0}`/`{dn}` expand to the user's DN,
    /// `{1}`/`{username}` to the username.
    pub group_filter: Option<String>,
    /// Attribute that names a group (default `cn`).
    pub group_name_attr: String,
    /// Group DN for admin role mapping
    pub admin_group_dn: Option<String>,
    /// Use STARTTLS
    pub use_starttls: bool,
    /// Path to a PEM file with custom CA certificates for LDAPS/STARTTLS
    pub ca_cert_path: Option<String>,
    /// Inline PEM CA certificate(s) trusted for this provider's LDAPS/STARTTLS
    /// handshake (per-provider config, issue #2782). Takes precedence over
    /// `ca_cert_path` when set.
    pub ca_cert_pem: Option<String>,
    /// Skip TLS certificate verification (development only)
    pub no_tls_verify: bool,
}

redacted_debug!(LdapConfig {
    show url,
    show base_dn,
    show user_filter,
    show bind_dn,
    redact_option bind_password,
    show username_attr,
    show email_attr,
    show display_name_attr,
    show groups_attr,
    show group_base_dn,
    show group_filter,
    show group_name_attr,
    show admin_group_dn,
    show use_starttls,
    show ca_cert_path,
    show no_tls_verify,
});

impl LdapConfig {
    /// Read TLS-related settings from environment variables.
    ///
    /// `LDAP_CA_CERT_PATH` takes priority, falling back to the shared
    /// `CUSTOM_CA_CERT_PATH`. `LDAP_INSECURE_TLS=true` skips verification.
    fn tls_from_env() -> (Option<String>, bool) {
        let ca_cert_path = std::env::var("LDAP_CA_CERT_PATH")
            .ok()
            .or_else(|| std::env::var("CUSTOM_CA_CERT_PATH").ok());
        let no_tls_verify = std::env::var("LDAP_INSECURE_TLS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        (ca_cert_path, no_tls_verify)
    }

    /// Attribute that names a group, from `LDAP_GROUP_ATTRIBUTE` (default `cn`).
    fn group_name_attr_from_env() -> String {
        std::env::var("LDAP_GROUP_ATTRIBUTE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "cn".to_string())
    }

    /// Create LDAP config from application config
    pub fn from_config(config: &Config) -> Option<Self> {
        let url = config.ldap_url.clone()?;
        let base_dn = config.ldap_base_dn.clone()?;
        let (ca_cert_path, no_tls_verify) = Self::tls_from_env();

        Some(Self {
            url,
            base_dn,
            user_filter: std::env::var("LDAP_USER_FILTER")
                .unwrap_or_else(|_| "(uid={username})".to_string()),
            bind_dn: std::env::var("LDAP_BIND_DN").ok(),
            bind_password: std::env::var("LDAP_BIND_PASSWORD").ok(),
            username_attr: std::env::var("LDAP_USERNAME_ATTR")
                .unwrap_or_else(|_| "uid".to_string()),
            email_attr: std::env::var("LDAP_EMAIL_ATTR").unwrap_or_else(|_| "mail".to_string()),
            display_name_attr: std::env::var("LDAP_DISPLAY_NAME_ATTR")
                .unwrap_or_else(|_| "cn".to_string()),
            groups_attr: std::env::var("LDAP_GROUPS_ATTR")
                .unwrap_or_else(|_| "memberOf".to_string()),
            group_base_dn: std::env::var("LDAP_GROUP_BASE_DN")
                .ok()
                .filter(|v| !v.is_empty()),
            group_filter: std::env::var("LDAP_GROUP_FILTER")
                .ok()
                .filter(|v| !v.is_empty()),
            group_name_attr: Self::group_name_attr_from_env(),
            admin_group_dn: std::env::var("LDAP_ADMIN_GROUP_DN").ok(),
            use_starttls: std::env::var("LDAP_USE_STARTTLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            ca_cert_path,
            ca_cert_pem: None,
            no_tls_verify,
        })
    }
}

/// LDAP user information extracted from directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUserInfo {
    /// Distinguished name of the user
    pub dn: String,
    /// Username (directory value for the configured username attribute)
    pub username: String,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships (DNs)
    pub groups: Vec<String>,
}

/// LDAP authentication service
///
/// Uses ldap3 for real LDAP/LDAPS bind and search operations.
pub struct LdapService {
    db: PgPool,
    config: LdapConfig,
    #[allow(dead_code)]
    http_client: Client,
}

impl LdapService {
    const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// Classify an LDAP connection error as an internal server error.
    fn connection_error(e: impl std::fmt::Display) -> AppError {
        tracing::error!(error = %e, "LDAP connection failed");
        AppError::Internal(format!("LDAP connection failed: {e}"))
    }

    /// Classify an LDAP bind rejection as an authentication error.
    ///
    /// The original error is logged but never exposed to the caller,
    /// preventing credential or server details from leaking.
    fn bind_error(e: impl std::fmt::Display) -> AppError {
        tracing::error!(error = %e, "LDAP bind failed");
        AppError::Authentication("Invalid credentials".into())
    }

    /// Classify an LDAP search failure as an internal server error.
    fn search_error(e: impl std::fmt::Display) -> AppError {
        tracing::error!(error = %e, "LDAP search failed");
        AppError::Internal(format!("LDAP search failed: {e}"))
    }

    /// Create a new LDAP service
    pub fn new(db: PgPool, app_config: Arc<Config>) -> Result<Self> {
        let config = LdapConfig::from_config(&app_config)
            .ok_or_else(|| AppError::Config("LDAP configuration not set".into()))?;
        if config.no_tls_verify {
            tracing::warn!("LDAP TLS verification is disabled (LDAP_INSECURE_TLS=true). Do not use in production.");
        }
        Ok(Self {
            db,
            config,
            http_client: crate::services::http_client::default_client(),
        })
    }

    /// Create LDAP service from database-stored config
    #[allow(clippy::too_many_arguments)]
    pub fn from_db_config(
        db: PgPool,
        name: &str,
        server_url: &str,
        bind_dn: Option<&str>,
        bind_password: Option<&str>,
        user_base_dn: &str,
        user_filter: &str,
        group_base_dn: Option<&str>,
        group_filter: Option<&str>,
        username_attr: &str,
        email_attr: &str,
        display_name_attr: &str,
        groups_attr: &str,
        admin_group_dn: Option<&str>,
        use_starttls: bool,
        insecure_skip_verify: bool,
        ca_cert_pem: Option<&str>,
    ) -> Self {
        // Environment variables remain a deployment-wide fallback: the
        // effective skip-verify is the per-provider toggle OR the env flag,
        // and an inline per-provider CA (#2782) takes precedence over the
        // env-configured CA file path.
        let (env_ca_cert_path, env_no_tls_verify) = LdapConfig::tls_from_env();
        let no_tls_verify = insecure_skip_verify || env_no_tls_verify;
        let ca_cert_pem = ca_cert_pem.filter(|v| !v.is_empty()).map(String::from);
        let ca_cert_path = if ca_cert_pem.is_some() {
            None
        } else {
            env_ca_cert_path
        };
        if no_tls_verify {
            tracing::warn!(
                provider = %name,
                "LDAP TLS certificate verification is DISABLED for this provider \
                 (insecure skip-verify). Connections are vulnerable to \
                 man-in-the-middle attacks; do not use in production."
            );
        }
        let config = LdapConfig {
            url: server_url.to_string(),
            base_dn: user_base_dn.to_string(),
            user_filter: user_filter.to_string(),
            bind_dn: bind_dn.map(String::from),
            bind_password: bind_password.map(String::from),
            username_attr: username_attr.to_string(),
            email_attr: email_attr.to_string(),
            display_name_attr: display_name_attr.to_string(),
            groups_attr: groups_attr.to_string(),
            group_base_dn: group_base_dn.filter(|v| !v.is_empty()).map(String::from),
            group_filter: group_filter.filter(|v| !v.is_empty()).map(String::from),
            group_name_attr: LdapConfig::group_name_attr_from_env(),
            admin_group_dn: admin_group_dn.map(String::from),
            use_starttls,
            ca_cert_path,
            ca_cert_pem,
            no_tls_verify,
        };
        Self {
            db,
            config,
            http_client: crate::services::http_client::default_client(),
        }
    }

    /// Create LDAP service from explicit config
    pub fn with_config(db: PgPool, config: LdapConfig) -> Self {
        if config.no_tls_verify {
            tracing::warn!("LDAP TLS verification is disabled (LDAP_INSECURE_TLS=true). Do not use in production.");
        }
        Self {
            db,
            config,
            http_client: crate::services::http_client::default_client(),
        }
    }

    /// Authenticate a user against LDAP/Active Directory.
    ///
    /// Behaviour:
    /// 1. Validate that a username and password were provided.
    /// 2. If a service account is configured, perform proper search-then-bind:
    ///    - bind as the service account
    ///    - resolve the user's actual LDAP entry
    ///    - bind again as the resolved user DN with the submitted password
    /// 3. If no service account is configured, fall back to direct bind using
    ///    the submitted username as-is.
    ///
    /// Why this is necessary:
    /// Many LDAP deployments, especially Active Directory, do not accept a
    /// fabricated bind identity derived from `{username_attr}={username},{base_dn}`.
    /// They expect either the user's real distinguished name (DN), or another
    /// accepted login form such as UPN. The previous implementation constructed
    /// a DN-like string and attempted to bind with that value, which can fail
    /// even when:
    /// - the service account can bind,
    /// - the user can be found in LDAP, and
    /// - the submitted password is valid.
    ///
    /// This implementation fixes that by using proper search-then-bind when a
    /// service account is available.
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<LdapUserInfo> {
        if username.is_empty() || password.is_empty() {
            return Err(AppError::Authentication(
                "Username and password required".into(),
            ));
        }

        let user_info = tokio::time::timeout(Self::AUTH_TIMEOUT, async {
            if self.config.bind_dn.is_some() && self.config.bind_password.is_some() {
                let user_info = self.search_user_entry(username).await?;
                self.validate_ldap_credentials(&user_info.dn, password)
                    .await?;
                Ok(user_info)
            } else {
                tracing::debug!(username = %username, "Using direct-bind fallback (no service account configured)");
                self.validate_ldap_credentials(username, password).await?;
                self.get_user_info(username, username).await
            }
        })
        .await
        .map_err(|_| {
            tracing::error!(username = %username, timeout = ?Self::AUTH_TIMEOUT, "LDAP authentication timed out");
            AppError::Internal("LDAP authentication timed out".into())
        })??;

        tracing::info!(
            username = %username,
            dn = %user_info.dn,
            "LDAP authentication successful"
        );

        Ok(user_info)
    }

    /// Get or create a user from LDAP information
    pub async fn get_or_create_user(&self, ldap_user: &LdapUserInfo) -> Result<User> {
        // Check if user already exists by external_id (DN)
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = 'ldap'
            "#,
            ldap_user.dn
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(mut user) = existing_user {
            // Update user info from LDAP
            let is_admin = self.is_admin_from_groups(&ldap_user.groups);

            sqlx::query!(
                r#"
                UPDATE users
                SET email = $1, display_name = $2, is_admin = $3,
                    last_login_at = NOW(), updated_at = NOW()
                WHERE id = $4
                  AND (
                    email IS DISTINCT FROM $1
                    OR display_name IS DISTINCT FROM $2
                    OR is_admin IS DISTINCT FROM $3
                    OR last_login_at IS NULL
                    OR last_login_at < NOW() - INTERVAL '5 minutes'
                  )
                "#,
                ldap_user.email,
                ldap_user.display_name,
                is_admin,
                user.id
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            user.email = ldap_user.email.clone();
            user.display_name = ldap_user.display_name.clone();
            user.is_admin = is_admin;

            return Ok(user);
        }

        // Create new user from LDAP
        let user_id = Uuid::new_v4();
        let is_admin = self.is_admin_from_groups(&ldap_user.groups);

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active, is_service_account)
            VALUES ($1, $2, $3, $4, 'ldap', $5, $6, true, false)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            "#,
            user_id,
            ldap_user.username,
            ldap_user.email,
            ldap_user.display_name,
            ldap_user.dn,
            is_admin
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tracing::info!(
            user_id = %user.id,
            username = %user.username,
            "Created new user from LDAP"
        );

        Ok(user)
    }

    /// Check if user is admin based on group memberships
    fn is_admin_from_groups(&self, groups: &[String]) -> bool {
        if let Some(admin_group) = &self.config.admin_group_dn {
            groups
                .iter()
                .any(|g| g.to_lowercase() == admin_group.to_lowercase())
        } else {
            false
        }
    }

    /// Extract group memberships for role mapping
    pub fn extract_groups(&self, ldap_user: &LdapUserInfo) -> Vec<String> {
        ldap_user.groups.clone()
    }

    /// Map LDAP groups to application roles
    pub fn map_groups_to_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = vec!["user".to_string()];

        if self.is_admin_from_groups(groups) {
            roles.push("admin".to_string());
        }

        // Additional role mappings can be configured via environment
        // LDAP_GROUP_ROLE_MAP=cn=developers,ou=groups,dc=example,dc=com:developer
        if let Ok(mappings) = std::env::var("LDAP_GROUP_ROLE_MAP") {
            for mapping in mappings.split(';') {
                if let Some((group_dn, role)) = mapping.split_once(':') {
                    if groups
                        .iter()
                        .any(|g| g.to_lowercase() == group_dn.to_lowercase())
                    {
                        roles.push(role.to_string());
                    }
                }
            }
        }

        roles.sort();
        roles.dedup();
        roles
    }

    /// Build user DN from username.
    ///
    /// Note:
    /// This helper is retained only for legacy/custom direct-bind scenarios.
    /// It should not be used as the primary authentication path when a service
    /// account is configured, because many LDAP/AD environments require the
    /// user's real DN (resolved via search) rather than a constructed value.
    #[allow(dead_code)]
    fn build_user_dn(&self, username: &str) -> String {
        let pattern = std::env::var("LDAP_USER_DN_PATTERN").unwrap_or_else(|_| {
            format!("{}={{}},{}", self.config.username_attr, self.config.base_dn)
        });

        pattern.replace("{}", username)
    }

    /// Parse PEM certificates from a byte buffer.
    ///
    /// `native_tls::Certificate::from_pem` only handles a single cert, so this
    /// splits the bundle on PEM boundaries and returns each cert individually.
    fn parse_pem_certificates(
        pem_bytes: &[u8],
        source: &str,
    ) -> Result<Vec<native_tls::Certificate>> {
        let pem_str = String::from_utf8_lossy(pem_bytes);
        let mut certs = Vec::new();
        for block in pem_str.split("-----END CERTIFICATE-----") {
            let trimmed = block.trim();
            if trimmed.is_empty() || !trimmed.contains("-----BEGIN CERTIFICATE-----") {
                continue;
            }
            let pem = format!("{trimmed}\n-----END CERTIFICATE-----\n");
            let cert = native_tls::Certificate::from_pem(pem.as_bytes()).map_err(|e| {
                AppError::Config(format!("Failed to parse CA cert from {source}: {e}"))
            })?;
            certs.push(cert);
        }
        if certs.is_empty() {
            return Err(AppError::Config(format!(
                "No valid PEM certificates found in {source}"
            )));
        }
        Ok(certs)
    }

    /// Build LDAP connection settings with TLS configuration.
    ///
    /// Custom CA certificates come from either an inline per-provider PEM
    /// (`ca_cert_pem`, #2782) or the `LDAP_CA_CERT_PATH` (or shared
    /// `CUSTOM_CA_CERT_PATH`) environment fallback; the inline value takes
    /// precedence. `no_tls_verify` (per-provider skip-verify OR
    /// `LDAP_INSECURE_TLS=true`) skips certificate verification for
    /// development environments.
    fn build_conn_settings(&self) -> Result<ldap3::LdapConnSettings> {
        use std::time::Duration;

        let mut settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(10))
            .set_starttls(self.config.use_starttls)
            .set_no_tls_verify(self.config.no_tls_verify);

        // Inline per-provider PEM wins over the env-configured CA file path.
        let ca_source: Option<(Vec<u8>, String)> = if let Some(pem) = &self.config.ca_cert_pem {
            Some((
                pem.as_bytes().to_vec(),
                "inline provider configuration".to_string(),
            ))
        } else if let Some(ca_path) = &self.config.ca_cert_path {
            let pem_bytes = std::fs::read(ca_path).map_err(|e| {
                AppError::Config(format!("Failed to read LDAP CA cert at {ca_path}: {e}"))
            })?;
            Some((pem_bytes, ca_path.clone()))
        } else {
            None
        };

        if let Some((pem_bytes, source)) = ca_source {
            let certs = Self::parse_pem_certificates(&pem_bytes, &source)?;
            let mut builder = native_tls::TlsConnector::builder();
            for cert in &certs {
                builder.add_root_certificate(cert.clone());
            }
            if self.config.no_tls_verify {
                builder.danger_accept_invalid_certs(true);
            }
            let connector = builder
                .build()
                .map_err(|e| AppError::Config(format!("Failed to build TLS connector: {e}")))?;
            settings = settings.set_connector(connector);
            tracing::info!(
                source = %source,
                count = certs.len(),
                "Loaded custom CA certificate(s) for LDAP"
            );
        }

        Ok(settings)
    }

    /// Connect to the LDAP server and bind with the given credentials.
    ///
    /// Builds connection settings (including TLS), opens the connection,
    /// drives it on a background task, and performs a simple bind. Returns
    /// the authenticated `ldap3::Ldap` handle on success.
    async fn connect_and_bind(&self, bind_dn: &str, bind_password: &str) -> Result<ldap3::Ldap> {
        use ldap3::LdapConnAsync;

        tracing::debug!(url = %self.config.url, bind_dn = %bind_dn, "Connecting to LDAP server");

        let settings = self.build_conn_settings()?;

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(Self::connection_error)?;

        ldap3::drive!(conn);

        ldap.simple_bind(bind_dn, bind_password)
            .await
            .map_err(Self::bind_error)?
            .success()
            .map_err(Self::bind_error)?;

        tracing::debug!("LDAP bind successful");

        Ok(ldap)
    }

    /// Build the LDAP search filter for a given username.
    ///
    /// Replaces both `{0}` and `{username}` placeholders in the configured
    /// user filter pattern.
    fn build_search_filter(&self, username: &str) -> String {
        let safe = Self::sanitize_ldap_input(username);
        self.config
            .user_filter
            .replace("{0}", &safe)
            .replace("{username}", &safe)
    }

    /// Return the list of LDAP attributes to request during a user search.
    fn user_search_attrs(&self) -> Vec<&str> {
        vec![
            self.config.username_attr.as_str(),
            self.config.email_attr.as_str(),
            self.config.display_name_attr.as_str(),
            self.config.groups_attr.as_str(),
        ]
    }

    /// Extract user information from an already-constructed `SearchEntry`.
    ///
    /// Pure synchronous helper that maps LDAP attributes to an `LdapUserInfo`.
    fn extract_user_from_entry(&self, entry: ldap3::SearchEntry, username: &str) -> LdapUserInfo {
        let email = entry
            .attrs
            .get(&self.config.email_attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| format!("{}@unknown", username));

        let display_name = entry
            .attrs
            .get(&self.config.display_name_attr)
            .and_then(|v| v.first())
            .cloned();

        // Prefer the exact attribute key (preserves server-returned order for
        // existing deployments). Active Directory returns large multi-valued
        // attributes under a ranged key instead (e.g. `memberOf;range=0-1499`,
        // range retrieval), which the exact lookup misses — fall back to
        // collecting those values so users in many groups still get their
        // memberships (issue #2468).
        let groups = entry
            .attrs
            .get(&self.config.groups_attr)
            .cloned()
            .unwrap_or_else(|| Self::ranged_attr_values(&entry.attrs, &self.config.groups_attr));

        let resolved_username = entry
            .attrs
            .get(&self.config.username_attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| username.to_string());

        LdapUserInfo {
            dn: entry.dn,
            username: resolved_username,
            email,
            display_name,
            groups,
        }
    }

    /// Search for the user's actual LDAP entry using the configured service account.
    ///
    /// This helper is used by the search-then-bind authentication path.
    ///
    /// Important behaviour:
    /// - binds with the configured service account
    /// - searches using the configured user filter
    /// - supports both `{0}` and `{username}` placeholders
    /// - returns the real DN and attributes from LDAP
    ///
    /// Why the placeholder support matters:
    /// The UI/configuration path may produce filters using `{0}`, while older or
    /// environment-based configurations may use `{username}`. Supporting both
    /// forms keeps the runtime behaviour aligned with the configured provider
    /// and avoids silent mismatches during user lookup.
    async fn search_user_entry(&self, username: &str) -> Result<LdapUserInfo> {
        use ldap3::{Scope, SearchEntry};

        tracing::debug!(username = %username, "Searching for user in LDAP");

        let (bind_dn, bind_pw) = match (&self.config.bind_dn, &self.config.bind_password) {
            (Some(dn), Some(pw)) => (dn, pw),
            _ => {
                return Err(AppError::Internal(
                    "LDAP service account not configured for search-then-bind".into(),
                ))
            }
        };

        let mut ldap = self.connect_and_bind(bind_dn, bind_pw).await?;

        let search_filter = self.build_search_filter(username);
        let attrs = self.user_search_attrs();

        let (results, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &search_filter, attrs)
            .await
            .map_err(Self::search_error)?
            .success()
            .map_err(Self::search_error)?;

        ldap.unbind().await.ok();

        let entry = results
            .into_iter()
            .next()
            .ok_or_else(|| AppError::Authentication("User not found in LDAP".into()))?;

        let entry = SearchEntry::construct(entry);

        tracing::debug!(username = %username, dn = %entry.dn, "LDAP user found");

        Ok(self.extract_user_from_entry(entry, username))
    }

    /// Validate LDAP credentials via real LDAP simple bind.
    async fn validate_ldap_credentials(&self, user_dn: &str, password: &str) -> Result<()> {
        let mut ldap = self.connect_and_bind(user_dn, password).await?;

        ldap.unbind().await.ok();
        Ok(())
    }

    /// Get user information from LDAP via real search.
    ///
    /// Delegates to [`search_user_entry`] when bind credentials are available,
    /// falling back to basic synthesized info when the search fails or no
    /// credentials are configured.
    async fn get_user_info(&self, username: &str, user_dn: &str) -> Result<LdapUserInfo> {
        // If we have bind credentials, reuse the shared search logic.
        // Fall through to the basic-info fallback on any error, since the
        // caller expects best-effort results.
        if self.config.bind_dn.is_some() && self.config.bind_password.is_some() {
            match self.search_user_entry(username).await {
                Ok(info) => return Ok(info),
                Err(e) => {
                    tracing::warn!(
                        username = %username,
                        error = %e,
                        "LDAP user search failed, falling back to basic info"
                    );
                }
            }
        }

        // Fallback: construct basic info from the bind identity.
        Ok(LdapUserInfo {
            dn: user_dn.to_string(),
            username: username.to_string(),
            email: format!("{}@unknown", username),
            display_name: None,
            groups: Vec::new(),
        })
    }

    /// Sanitize input to prevent LDAP injection
    fn sanitize_ldap_input(input: &str) -> String {
        input
            .replace('\\', "\\5c")
            .replace('*', "\\2a")
            .replace('(', "\\28")
            .replace(')', "\\29")
            .replace('\0', "\\00")
    }

    /// Collect values of a multi-valued attribute returned under Active
    /// Directory range-retrieval keys (e.g. `memberOf;range=0-1499`).
    ///
    /// Keys are matched case-insensitively. Values are sorted for
    /// deterministic output because `attrs` is an unordered map.
    fn ranged_attr_values(
        attrs: &std::collections::HashMap<String, Vec<String>>,
        name: &str,
    ) -> Vec<String> {
        let lname = name.to_ascii_lowercase();
        let mut out: Vec<String> = attrs
            .iter()
            .filter(|(k, _)| {
                let kl = k.to_ascii_lowercase();
                kl == lname || (kl.starts_with(&lname) && kl[lname.len()..].starts_with(";range="))
            })
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether group synchronization is configured for this provider
    /// (issue #2468): a group base DN and/or a group filter is present.
    pub fn group_sync_configured(&self) -> bool {
        self.config.group_base_dn.is_some() || self.config.group_filter.is_some()
    }

    /// Resolve the names of the groups a user belongs to (issue #2468).
    ///
    /// Two complementary sources are merged:
    ///
    /// 1. The `memberOf` values from the user's own entry (`member_of`) —
    ///    the Active Directory default, also available on OpenLDAP with the
    ///    memberOf overlay. Values are group DNs; when `group_base_dn` is
    ///    configured only DNs under that base are kept, and each DN's first
    ///    RDN value (the group's `cn`) becomes the group name.
    /// 2. A group-entry search under `group_base_dn` using the configured
    ///    `group_filter` (or a default covering RFC 4519 `groupOfNames` /
    ///    `groupOfUniqueNames`, `posixGroup` and AD `member`). This covers
    ///    directories without user-side `memberOf`, and lets operators
    ///    resolve nested AD groups by using the matching-rule-in-chain
    ///    filter `(member:1.2.840.113556.1.4.1941:={0})`.
    ///
    /// Group-search failures are logged and skipped rather than propagated so
    /// login never breaks on a partially configured directory: whatever came
    /// from `memberOf` is still returned.
    pub async fn resolve_group_names(
        &self,
        user_dn: &str,
        username: &str,
        member_of: &[String],
    ) -> Vec<String> {
        let mut names = std::collections::BTreeSet::new();

        for group_dn in member_of {
            if let Some(base) = &self.config.group_base_dn {
                if !Self::dn_under_base(group_dn, base) {
                    continue;
                }
            }
            if let Some(name) = Self::dn_first_rdn_value(group_dn) {
                names.insert(name);
            }
        }

        if self.config.bind_dn.is_some() && self.config.bind_password.is_some() {
            match self.search_group_names(user_dn, username).await {
                Ok(found) => names.extend(found),
                Err(e) => {
                    tracing::warn!(
                        user_dn = %user_dn,
                        error = %e,
                        "LDAP group search failed; continuing with memberOf-derived groups"
                    );
                }
            }
        }

        names.into_iter().collect()
    }

    /// Search group entries the user is a member of and return their names.
    ///
    /// Only the group name attribute is requested — never `member` — so
    /// Active Directory range retrieval on large groups cannot truncate the
    /// result. Entries missing the name attribute fall back to the first RDN
    /// value of their DN.
    async fn search_group_names(&self, user_dn: &str, username: &str) -> Result<Vec<String>> {
        use ldap3::{Scope, SearchEntry};

        let (bind_dn, bind_pw) = match (&self.config.bind_dn, &self.config.bind_password) {
            (Some(dn), Some(pw)) => (dn, pw),
            _ => return Ok(Vec::new()),
        };

        let search_base = self
            .config
            .group_base_dn
            .as_deref()
            .unwrap_or(&self.config.base_dn);
        let filter = self.build_group_filter(user_dn, username);

        let mut ldap = self.connect_and_bind(bind_dn, bind_pw).await?;
        let (results, _) = ldap
            .search(
                search_base,
                Scope::Subtree,
                &filter,
                vec![self.config.group_name_attr.as_str()],
            )
            .await
            .map_err(Self::search_error)?
            .success()
            .map_err(Self::search_error)?;
        ldap.unbind().await.ok();

        let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
        Ok(Self::group_names_from_entries(
            &entries,
            &self.config.group_name_attr,
        ))
    }

    /// Map group search entries to group names using the group name
    /// attribute (case-insensitive), falling back to the first RDN value of
    /// the entry DN when the attribute is absent.
    fn group_names_from_entries(entries: &[ldap3::SearchEntry], name_attr: &str) -> Vec<String> {
        let name_attr = name_attr.to_ascii_lowercase();
        entries
            .iter()
            .filter_map(|entry| {
                entry
                    .attrs
                    .iter()
                    .find(|(k, _)| k.to_ascii_lowercase() == name_attr)
                    .and_then(|(_, v)| v.first().cloned())
                    .or_else(|| Self::dn_first_rdn_value(&entry.dn))
            })
            .collect()
    }

    /// Build the LDAP filter that finds the groups a user belongs to.
    ///
    /// The configured `group_filter` supports `{0}`/`{dn}` (the user's DN)
    /// and `{1}`/`{username}` placeholders, all filter-escaped. A configured
    /// filter without any user placeholder (e.g. `(objectClass=group)`) is
    /// treated as a group-object class filter and AND-ed with the default
    /// membership disjunction — matching every group in the base against the
    /// user would otherwise grant all groups to everyone. Without a
    /// configured filter the default membership disjunction is used alone.
    fn build_group_filter(&self, user_dn: &str, username: &str) -> String {
        let dn = Self::sanitize_ldap_input(user_dn);
        let uname = Self::sanitize_ldap_input(username);
        let membership = format!("(|(member={dn})(uniqueMember={dn})(memberUid={uname}))");

        match &self.config.group_filter {
            Some(f)
                if f.contains("{0}")
                    || f.contains("{dn}")
                    || f.contains("{1}")
                    || f.contains("{username}") =>
            {
                f.replace("{0}", &dn)
                    .replace("{dn}", &dn)
                    .replace("{1}", &uname)
                    .replace("{username}", &uname)
            }
            Some(f) => format!("(&{f}{membership})"),
            None => membership,
        }
    }

    /// Extract the value of the first RDN of a DN
    /// (`CN=devops_,OU=Global,DC=corp,DC=local` → `devops_`).
    ///
    /// Handles backslash-escaped characters (e.g. `CN=a\, b,OU=x`) by
    /// unescaping them into the returned value.
    fn dn_first_rdn_value(dn: &str) -> Option<String> {
        let mut first_rdn = String::new();
        let mut chars = dn.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        first_rdn.push(escaped);
                    }
                }
                ',' => break,
                _ => first_rdn.push(c),
            }
        }
        let (_, value) = first_rdn.split_once('=')?;
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    /// Whether `dn` sits under `base` (case-insensitive, tolerant of
    /// whitespace around RDN separators). An empty base matches everything.
    fn dn_under_base(dn: &str, base: &str) -> bool {
        fn normalize(s: &str) -> String {
            s.split(',')
                .map(|part| part.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(",")
        }
        let dn = normalize(dn);
        let base = normalize(base);
        if base.is_empty() {
            return true;
        }
        dn == base || dn.ends_with(&format!(",{base}"))
    }

    /// Check if LDAP is configured and available
    pub fn is_configured(&self) -> bool {
        !self.config.url.is_empty() && !self.config.base_dn.is_empty()
    }

    /// Get the LDAP server URL (for diagnostics)
    pub fn server_url(&self) -> &str {
        &self.config.url
    }

    /// Verify the configured service-account credentials via a real LDAP
    /// simple bind (admin "test connection" flow, #2486).
    ///
    /// Unlike [`check_health`], which is a liveness probe that silently
    /// passes when no service account is configured, this method exists to
    /// answer "are these settings actually valid?": it connects with the
    /// configured TLS/STARTTLS settings, performs a simple bind with the
    /// configured bind DN and password, then unbinds. Error classification
    /// (via [`Self::connect_and_bind`]) distinguishes a credential rejection
    /// (`AppError::Authentication`) from connection-level failures
    /// (`AppError::Internal`), and never includes the bind password.
    pub async fn verify_bind(&self) -> Result<()> {
        let (bind_dn, bind_pw) = match (&self.config.bind_dn, &self.config.bind_password) {
            (Some(dn), Some(pw)) if !dn.is_empty() => (dn.clone(), pw.clone()),
            _ => {
                return Err(AppError::Config(
                    "LDAP bind credentials not configured".into(),
                ))
            }
        };
        let mut ldap = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.connect_and_bind(&bind_dn, &bind_pw),
        )
        .await
        .map_err(|_| AppError::Internal("LDAP connection test timed out".into()))??;
        ldap.unbind().await.ok();
        Ok(())
    }

    /// Probe LDAP connectivity by attempting a service-account bind.
    ///
    /// If a service account is configured, performs a real bind to verify
    /// the LDAP server is reachable and credentials are valid. If no
    /// service account is configured, just verifies the URL is non-empty.
    pub async fn check_health(&self) -> Result<()> {
        if self.config.url.is_empty() {
            return Err(AppError::Config("LDAP URL not configured".into()));
        }
        if let (Some(bind_dn), Some(bind_pw)) = (&self.config.bind_dn, &self.config.bind_password) {
            let mut ldap = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.connect_and_bind(bind_dn, bind_pw),
            )
            .await
            .map_err(|_| AppError::Internal("LDAP health check timed out".into()))??;
            ldap.unbind().await.ok();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex to serialize tests that read/write shared environment variables.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn make_test_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            bind_address: "0.0.0.0:8080".into(),
            log_level: "info".into(),
            storage_backend: "filesystem".into(),
            environment: "development".into(),
            storage_path: "/tmp/artifacts".into(),
            s3_bucket: None,
            gcs_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "test-secret".into(),
            jwt_expiration_secs: 86400,
            jwt_access_token_expiry_minutes: 30,
            jwt_refresh_token_expiry_days: 7,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            ldap_url: Some("ldap://localhost:389".into()),
            ldap_base_dn: Some("dc=example,dc=com".into()),
            trivy_url: None,
            trivy_adapter_url: None,
            openscap_url: None,
            openscap_profile: "xccdf_org.ssgproject.content_profile_standard".into(),
            opensearch_url: None,
            opensearch_username: None,
            opensearch_password: None,
            opensearch_allow_invalid_certs: false,
            scan_workspace_path: "/scan-workspace".into(),
            demo_mode: false,
            guest_access_enabled: true,
            expose_detailed_health: false,
            setup_password_hint: None,
            grpc_reflection_enabled: false,
            plugins_require_signed: true,
            plugins_trusted_pubkey: None,
            peer_instance_name: "test".into(),
            peer_public_endpoint: "http://localhost:8080".into(),
            peer_api_key: "test-key".into(),
            dependency_track_url: None,
            dependency_track_enabled: false,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "test".into(),
            gc_schedule: "0 0 * * * *".into(),
            storage_stats_schedule: "0 0 */4 * * *".into(),
            blob_gc_enabled: false,
            blob_gc_sweep_grace_secs: 3600,
            lifecycle_check_interval_secs: 60,
            stuck_scan_threshold_secs: 1800,
            stuck_scan_check_interval_secs: 600,
            stuck_scan_reap_limit: 1000,
            max_upload_size_bytes: 10_737_418_240,
            allow_local_admin_login: false,
            sso_disable_admin_break_glass: false,
            metrics_port: None,
            database_max_connections: 20,
            database_min_connections: 5,
            database_acquire_timeout_secs: 30,
            database_idle_timeout_secs: 600,
            database_max_lifetime_secs: 1800,
            auth_max_concurrency: 8,
            global_max_concurrency: 512,
            global_request_timeout_secs: 120,
            rate_limit_enabled: true,
            rate_limit_auth_per_window: 120,
            rate_limit_api_per_window: 5000,
            rate_limit_search_per_window: 300,
            rate_limit_presign_per_window: 30,

            rate_limit_login_global_per_window: 8192,
            rate_limit_login_per_window: 10,
            rate_limit_login_window_secs: 900,
            rate_limit_password_change_per_window: 5,
            rate_limit_password_change_window_secs: 900,
            rate_limit_window_secs: 60,
            rate_limit_exempt_usernames: Vec::new(),
            rate_limit_exempt_service_accounts: false,
            rate_limit_trusted_cidrs: Vec::new(),
            rate_limit_trusted_proxy_cidrs: Vec::new(),
            account_lockout_threshold: 5,
            account_lockout_duration_minutes: 30,
            quarantine_enabled: false,
            quarantine_duration_minutes: 60,
            password_history_count: 0,
            password_expiry_days: 0,
            password_expiry_warning_days: vec![1, 7, 14],
            password_expiry_check_interval_secs: 3600,
            password_min_length: 8,
            password_max_length: 128,
            password_require_uppercase: false,
            password_require_lowercase: false,
            password_require_digit: false,
            password_require_special: false,
            password_min_strength: 0,
            presigned_downloads_enabled: false,
            presigned_download_expiry_secs: 300,
            proxy_singleflight_advisory_locks_enabled: false,
            proxy_singleflight_lock_poll_interval_ms: 200,
            proxy_singleflight_lock_wait_timeout_secs: 65,
            smtp_host: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            smtp_from_address: "noreply@artifact-keeper.local".to_string(),
            smtp_tls_mode: "starttls".to_string(),
            npm_packument_cache_enabled: true,
            npm_packument_cache_fresh_ttl_secs: 300,
            npm_packument_cache_stale_max_secs: 86_400,
            npm_packument_cache_redis_url: None,
            npm_upstream_feed_enabled: false,
            npm_upstream_feed_url: crate::services::upstream_feed::NPM_REPLICATION_FEED_DEFAULT_URL
                .into(),
            scan_token_ttl_seconds: 300,
        }
    }

    fn make_test_ldap_config() -> LdapConfig {
        LdapConfig {
            url: "ldap://ldap.example.com:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(uid={username})".to_string(),
            bind_dn: None,
            bind_password: None,
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            groups_attr: "memberOf".to_string(),
            group_base_dn: None,
            group_filter: None,
            group_name_attr: "cn".to_string(),
            admin_group_dn: Some("cn=admins,ou=groups,dc=example,dc=com".to_string()),
            use_starttls: false,
            ca_cert_path: None,
            ca_cert_pem: None,
            no_tls_verify: false,
        }
    }

    fn make_test_service(config: LdapConfig) -> LdapService {
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        LdapService::with_config(db, config)
    }

    #[test]
    fn test_sanitize_ldap_input() {
        assert_eq!(LdapService::sanitize_ldap_input("user"), "user");
        assert_eq!(LdapService::sanitize_ldap_input("user*"), "user\\2a");
        assert_eq!(LdapService::sanitize_ldap_input("(user)"), "\\28user\\29");
        assert_eq!(
            LdapService::sanitize_ldap_input("user\\name"),
            "user\\5cname"
        );
    }

    #[test]
    fn test_ldap_config_from_env() {
        let config = make_test_config();

        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_some());
        let ldap_config = ldap_config.unwrap();
        assert_eq!(ldap_config.url, "ldap://localhost:389");
        assert_eq!(ldap_config.base_dn, "dc=example,dc=com");
    }

    #[test]
    fn test_sanitize_ldap_input_null_byte() {
        assert_eq!(
            LdapService::sanitize_ldap_input("user\0name"),
            "user\\00name"
        );
    }

    #[test]
    fn test_sanitize_ldap_input_multiple_special_chars() {
        let input = "*()\\\0";
        let sanitized = LdapService::sanitize_ldap_input(input);
        assert_eq!(sanitized, "\\2a\\28\\29\\5c\\00");
    }

    #[test]
    fn test_sanitize_ldap_input_empty_string() {
        assert_eq!(LdapService::sanitize_ldap_input(""), "");
    }

    #[test]
    fn test_sanitize_ldap_input_normal_chars_unmodified() {
        let input = "john.doe@example.com";
        assert_eq!(LdapService::sanitize_ldap_input(input), input);
    }

    #[test]
    fn test_ldap_config_returns_none_without_url() {
        let mut config = make_test_config();
        config.ldap_url = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_config_returns_none_without_base_dn() {
        let mut config = make_test_config();
        config.ldap_base_dn = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_config_returns_none_without_both() {
        let mut config = make_test_config();
        config.ldap_url = None;
        config.ldap_base_dn = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_user_info_serialization_roundtrip() {
        let user_info = LdapUserInfo {
            dn: "uid=john,ou=users,dc=example,dc=com".to_string(),
            username: "john".to_string(),
            email: "john@example.com".to_string(),
            display_name: Some("John Doe".to_string()),
            groups: vec![
                "cn=developers,ou=groups,dc=example,dc=com".to_string(),
                "cn=admins,ou=groups,dc=example,dc=com".to_string(),
            ],
        };
        let json = serde_json::to_string(&user_info).unwrap();
        let deserialized: LdapUserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.dn, user_info.dn);
        assert_eq!(deserialized.username, user_info.username);
        assert_eq!(deserialized.email, user_info.email);
        assert_eq!(deserialized.display_name, user_info.display_name);
        assert_eq!(deserialized.groups, user_info.groups);
    }

    #[test]
    fn test_ldap_user_info_deserialization_minimal() {
        let json = r#"{
            "dn": "uid=test,dc=test",
            "username": "test",
            "email": "test@test.com",
            "display_name": null,
            "groups": []
        }"#;
        let user: LdapUserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "test");
        assert!(user.display_name.is_none());
        assert!(user.groups.is_empty());
    }

    #[test]
    fn test_ldap_config_is_configured_true() {
        let config = make_test_ldap_config();
        assert!(!config.url.is_empty());
        assert!(!config.base_dn.is_empty());
    }

    #[test]
    fn test_ldap_config_is_configured_empty_url() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        assert!(config.url.is_empty());
    }

    #[test]
    fn test_ldap_config_admin_group_dn() {
        let config = make_test_ldap_config();
        assert_eq!(
            config.admin_group_dn,
            Some("cn=admins,ou=groups,dc=example,dc=com".to_string())
        );
    }

    #[test]
    fn test_ldap_config_no_admin_group() {
        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        assert!(config.admin_group_dn.is_none());
    }

    #[test]
    fn test_ldap_config_starttls_default() {
        let config = make_test_ldap_config();
        assert!(!config.use_starttls);
    }

    #[test]
    fn test_ldap_config_default_attributes() {
        let config = make_test_ldap_config();
        assert_eq!(config.username_attr, "uid");
        assert_eq!(config.email_attr, "mail");
        assert_eq!(config.display_name_attr, "cn");
        assert_eq!(config.groups_attr, "memberOf");
    }

    #[test]
    fn test_ldap_config_custom_user_filter() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(sAMAccountName={username})".to_string();
        assert_eq!(config.user_filter, "(sAMAccountName={username})");
    }

    #[test]
    fn test_ldap_config_with_bind_credentials() {
        let mut config = make_test_ldap_config();
        config.bind_dn = Some("cn=service,dc=example,dc=com".to_string());
        config.bind_password = Some("secret".to_string());
        assert!(config.bind_dn.is_some());
        assert!(config.bind_password.is_some());
    }

    #[test]
    fn test_ldap_user_info_clone() {
        let user_info = LdapUserInfo {
            dn: "uid=alice,dc=test".to_string(),
            username: "alice".to_string(),
            email: "alice@test.com".to_string(),
            display_name: Some("Alice".to_string()),
            groups: vec!["cn=users,dc=test".to_string()],
        };
        let cloned = user_info.clone();
        assert_eq!(cloned.dn, user_info.dn);
        assert_eq!(cloned.username, user_info.username);
        assert_eq!(cloned.email, user_info.email);
        assert_eq!(cloned.groups, user_info.groups);
    }

    #[test]
    fn test_ldap_config_debug_redacts_bind_password() {
        let mut config = make_test_ldap_config();
        config.bind_dn = Some("cn=admin,dc=example,dc=com".to_string());
        config.bind_password = Some("super-secret-ldap-password".to_string());
        config.use_starttls = true;
        config.admin_group_dn = None;
        let debug = format!("{:?}", config);
        assert!(debug.contains("ldap.example.com"));
        assert!(debug.contains("dc=example,dc=com"));
        assert!(!debug.contains("super-secret-ldap-password"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_ldap_config_debug_shows_none_for_missing_password() {
        let config = make_test_ldap_config();
        let debug = format!("{:?}", config);
        assert!(debug.contains("None"));
    }

    // --- TLS configuration tests ---

    #[test]
    fn test_ldap_config_tls_defaults() {
        let config = make_test_ldap_config();
        assert!(config.ca_cert_path.is_none());
        assert!(!config.no_tls_verify);
    }

    #[test]
    fn test_ldap_config_with_ca_cert_path() {
        let mut config = make_test_ldap_config();
        config.ca_cert_path = Some("/etc/ssl/certs/ldap-ca.pem".to_string());
        assert_eq!(
            config.ca_cert_path.as_deref(),
            Some("/etc/ssl/certs/ldap-ca.pem")
        );
    }

    #[test]
    fn test_ldap_config_with_insecure_tls() {
        let mut config = make_test_ldap_config();
        config.no_tls_verify = true;
        assert!(config.no_tls_verify);
    }

    #[test]
    fn test_parse_pem_single_cert() {
        let pem = include_bytes!("../../tests/fixtures/test-ca.pem");
        let certs = LdapService::parse_pem_certificates(pem, "test-ca.pem");
        assert!(certs.is_ok());
        let certs = certs.expect("should parse test CA");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_parse_pem_multiple_certs() {
        let single = include_bytes!("../../tests/fixtures/test-ca.pem");
        let mut bundle = single.to_vec();
        bundle.extend_from_slice(single);
        let certs =
            LdapService::parse_pem_certificates(&bundle, "bundle.pem").expect("should parse");
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_parse_pem_empty_file() {
        let result = LdapService::parse_pem_certificates(b"", "empty.pem");
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("No valid PEM certificates")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_parse_pem_garbage_data() {
        let result = LdapService::parse_pem_certificates(b"not a certificate", "garbage.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pem_partial_markers() {
        let data = b"-----BEGIN CERTIFICATE-----\ngarbage";
        let result = LdapService::parse_pem_certificates(data, "partial.pem");
        assert!(result.is_err());
    }

    fn assert_conn_settings_ok(config: LdapConfig) {
        let svc = make_test_service(config);
        assert!(svc.build_conn_settings().is_ok());
    }

    fn assert_conn_settings_err(config: LdapConfig, expected_msg: &str) {
        let svc = make_test_service(config);
        let result = svc.build_conn_settings();
        match result {
            Err(e) => assert!(
                e.to_string().contains(expected_msg),
                "expected error containing '{expected_msg}', got: {e}"
            ),
            Ok(_) => panic!("expected error containing '{expected_msg}'"),
        }
    }

    #[tokio::test]
    async fn test_build_conn_settings_no_tls() {
        assert_conn_settings_ok(make_test_ldap_config());
    }

    #[tokio::test]
    async fn test_build_conn_settings_with_insecure_tls() {
        let mut config = make_test_ldap_config();
        config.no_tls_verify = true;
        assert_conn_settings_ok(config);
    }

    #[tokio::test]
    async fn test_build_conn_settings_missing_ca_file() {
        let mut config = make_test_ldap_config();
        config.ca_cert_path = Some("/nonexistent/ca.pem".to_string());
        assert_conn_settings_err(config, "Failed to read LDAP CA cert");
    }

    #[tokio::test]
    async fn test_build_conn_settings_with_valid_ca() {
        let mut config = make_test_ldap_config();
        config.ca_cert_path =
            Some(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-ca.pem").to_string());
        assert_conn_settings_ok(config);
    }

    #[tokio::test]
    async fn test_build_conn_settings_with_starttls() {
        let mut config = make_test_ldap_config();
        config.use_starttls = true;
        assert_conn_settings_ok(config);
    }

    #[tokio::test]
    async fn test_build_conn_settings_ca_plus_insecure() {
        let mut config = make_test_ldap_config();
        config.ca_cert_path =
            Some(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-ca.pem").to_string());
        config.no_tls_verify = true;
        assert_conn_settings_ok(config);
    }

    #[test]
    fn test_ldap_config_debug_shows_tls_fields() {
        let mut config = make_test_ldap_config();
        config.ca_cert_path = Some("/etc/ssl/certs/ca.pem".to_string());
        config.no_tls_verify = true;
        let debug = format!("{:?}", config);
        assert!(debug.contains("/etc/ssl/certs/ca.pem"));
        assert!(debug.contains("no_tls_verify"));
    }

    #[test]
    fn test_tls_from_env_defaults() {
        let (ca, insecure) = LdapConfig::tls_from_env();
        let _ = ca;
        assert!(!insecure || std::env::var("LDAP_INSECURE_TLS").is_ok());
    }

    #[tokio::test]
    async fn test_from_db_config_sets_tls_defaults() {
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        let svc = LdapService::from_db_config(
            db,
            "test-ldap",
            "ldaps://ad.example.com:636",
            Some("cn=svc,dc=example,dc=com"),
            Some("password"),
            "ou=users,dc=example,dc=com",
            "(sAMAccountName={username})",
            Some("ou=groups,dc=example,dc=com"),
            None,
            "sAMAccountName",
            "mail",
            "displayName",
            "memberOf",
            Some("cn=admins,dc=example,dc=com"),
            false,
            false,
            None,
        );
        assert!(!svc.config.no_tls_verify || std::env::var("LDAP_INSECURE_TLS").is_ok());
        assert_eq!(svc.config.url, "ldaps://ad.example.com:636");
        assert_eq!(svc.config.username_attr, "sAMAccountName");
        assert_eq!(
            svc.config.admin_group_dn.as_deref(),
            Some("cn=admins,dc=example,dc=com")
        );
    }

    /// #2782: the per-provider skip-verify toggle must relax verification on
    /// the resulting connector even when the `LDAP_INSECURE_TLS` env var is
    /// unset, and a per-provider inline CA must be carried through.
    #[tokio::test]
    async fn test_from_db_config_per_provider_skip_verify_and_inline_ca() {
        const TEST_CA_PEM: &str = include_str!("../../tests/fixtures/test-ca.pem");
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        let svc = LdapService::from_db_config(
            db,
            "test-ldap",
            "ldaps://ad.example.com:636",
            Some("cn=svc,dc=example,dc=com"),
            Some("password"),
            "ou=users,dc=example,dc=com",
            "(sAMAccountName={username})",
            None,
            None,
            "sAMAccountName",
            "mail",
            "displayName",
            "memberOf",
            None,
            false,
            true,
            Some(TEST_CA_PEM),
        );
        // Per-provider toggle relaxes verification regardless of the env var.
        assert!(svc.config.no_tls_verify);
        // Inline PEM is carried and the env file-path fallback is suppressed.
        assert_eq!(svc.config.ca_cert_pem.as_deref(), Some(TEST_CA_PEM));
        assert!(svc.config.ca_cert_path.is_none());
        // The connector builder honours both (parses the inline PEM +
        // accepts-invalid), i.e. no error is returned.
        svc.build_conn_settings()
            .expect("inline CA + skip-verify should build a connector");
    }

    /// #2782: with the per-provider toggle OFF and no env override, the
    /// connector must keep verifying certificates (secure-by-default).
    #[tokio::test]
    async fn test_from_db_config_default_keeps_verification() {
        // Only meaningful when the env override is not set in this process.
        if std::env::var("LDAP_INSECURE_TLS").is_ok() {
            return;
        }
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        let svc = LdapService::from_db_config(
            db,
            "test-ldap",
            "ldaps://ad.example.com:636",
            None,
            None,
            "ou=users,dc=example,dc=com",
            "(sAMAccountName={username})",
            None,
            None,
            "sAMAccountName",
            "mail",
            "displayName",
            "memberOf",
            None,
            false,
            false,
            None,
        );
        assert!(!svc.config.no_tls_verify);
        assert!(svc.config.ca_cert_pem.is_none());
    }

    #[tokio::test]
    async fn test_build_conn_settings_invalid_pem_content() {
        let tmp = std::env::temp_dir().join("bad-ldap-ca.pem");
        std::fs::write(
            &tmp,
            b"-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
        )
        .expect("write temp");
        let mut config = make_test_ldap_config();
        config.ca_cert_path = Some(tmp.to_string_lossy().to_string());
        let svc = make_test_service(config);
        let result = svc.build_conn_settings();
        assert!(result.is_err());
        std::fs::remove_file(&tmp).ok();
    }

    // --- is_configured() tests ---

    #[tokio::test]
    async fn test_is_configured_true() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        assert!(svc.is_configured());
    }

    #[tokio::test]
    async fn test_is_configured_empty_url() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        let svc = make_test_service(config);
        assert!(!svc.is_configured());
    }

    #[tokio::test]
    async fn test_is_configured_empty_base_dn() {
        let mut config = make_test_ldap_config();
        config.base_dn = String::new();
        let svc = make_test_service(config);
        assert!(!svc.is_configured());
    }

    #[tokio::test]
    async fn test_is_configured_both_empty() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        config.base_dn = String::new();
        let svc = make_test_service(config);
        assert!(!svc.is_configured());
    }

    // --- server_url() tests ---

    #[tokio::test]
    async fn test_server_url_returns_expected_value() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        assert_eq!(svc.server_url(), "ldap://ldap.example.com:389");
    }

    // --- extract_groups() tests ---

    #[tokio::test]
    async fn test_extract_groups_with_groups() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let user = LdapUserInfo {
            dn: "uid=alice,dc=example,dc=com".to_string(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            display_name: Some("Alice".to_string()),
            groups: vec![
                "cn=developers,ou=groups,dc=example,dc=com".to_string(),
                "cn=admins,ou=groups,dc=example,dc=com".to_string(),
            ],
        };
        let groups = svc.extract_groups(&user);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], "cn=developers,ou=groups,dc=example,dc=com");
        assert_eq!(groups[1], "cn=admins,ou=groups,dc=example,dc=com");
    }

    #[tokio::test]
    async fn test_extract_groups_empty() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let user = LdapUserInfo {
            dn: "uid=bob,dc=example,dc=com".to_string(),
            username: "bob".to_string(),
            email: "bob@example.com".to_string(),
            display_name: None,
            groups: vec![],
        };
        let groups = svc.extract_groups(&user);
        assert!(groups.is_empty());
    }

    // --- map_groups_to_roles() tests ---

    #[tokio::test]
    async fn test_map_groups_to_roles_default_user_role() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::remove_var("LDAP_GROUP_ROLE_MAP");

        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        let svc = make_test_service(config);
        let roles = svc.map_groups_to_roles(&[]);
        assert_eq!(roles, vec!["user"]);

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_admin_group_match() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::remove_var("LDAP_GROUP_ROLE_MAP");

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec!["cn=admins,ou=groups,dc=example,dc=com".to_string()];
        let roles = svc.map_groups_to_roles(&groups);
        assert!(roles.contains(&"admin".to_string()));
        assert!(roles.contains(&"user".to_string()));

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_admin_case_insensitive() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::remove_var("LDAP_GROUP_ROLE_MAP");

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec!["CN=Admins,OU=Groups,DC=Example,DC=Com".to_string()];
        let roles = svc.map_groups_to_roles(&groups);
        assert!(roles.contains(&"admin".to_string()));

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_with_env_mapping() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::set_var(
            "LDAP_GROUP_ROLE_MAP",
            "cn=developers,ou=groups,dc=example,dc=com:developer;cn=qa,ou=groups,dc=example,dc=com:tester",
        );

        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        let svc = make_test_service(config);
        let groups = vec![
            "cn=developers,ou=groups,dc=example,dc=com".to_string(),
            "cn=qa,ou=groups,dc=example,dc=com".to_string(),
        ];
        let roles = svc.map_groups_to_roles(&groups);
        assert!(roles.contains(&"user".to_string()));
        assert!(roles.contains(&"developer".to_string()));
        assert!(roles.contains(&"tester".to_string()));

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_dedup() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::set_var(
            "LDAP_GROUP_ROLE_MAP",
            "cn=devs,dc=example:developer;cn=engineers,dc=example:developer",
        );

        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        let svc = make_test_service(config);
        let groups = vec![
            "cn=devs,dc=example".to_string(),
            "cn=engineers,dc=example".to_string(),
        ];
        let roles = svc.map_groups_to_roles(&groups);
        let developer_count = roles.iter().filter(|r| *r == "developer").count();
        assert_eq!(developer_count, 1, "developer role should appear only once");

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_sorted() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_GROUP_ROLE_MAP").ok();
        std::env::set_var(
            "LDAP_GROUP_ROLE_MAP",
            "cn=devs,dc=example:zebra;cn=ops,dc=example:alpha",
        );

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec![
            "cn=devs,dc=example".to_string(),
            "cn=ops,dc=example".to_string(),
            "cn=admins,ou=groups,dc=example,dc=com".to_string(),
        ];
        let roles = svc.map_groups_to_roles(&groups);
        let mut sorted = roles.clone();
        sorted.sort();
        assert_eq!(roles, sorted, "roles should be sorted alphabetically");

        match saved {
            Some(val) => std::env::set_var("LDAP_GROUP_ROLE_MAP", val),
            None => std::env::remove_var("LDAP_GROUP_ROLE_MAP"),
        }
    }

    // --- build_user_dn() tests ---

    #[tokio::test]
    async fn test_build_user_dn_default_pattern() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_USER_DN_PATTERN").ok();
        std::env::remove_var("LDAP_USER_DN_PATTERN");

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let dn = svc.build_user_dn("jdoe");
        assert_eq!(dn, "uid=jdoe,dc=example,dc=com");

        match saved {
            Some(val) => std::env::set_var("LDAP_USER_DN_PATTERN", val),
            None => std::env::remove_var("LDAP_USER_DN_PATTERN"),
        }
    }

    #[tokio::test]
    async fn test_build_user_dn_custom_pattern() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let saved = std::env::var("LDAP_USER_DN_PATTERN").ok();
        std::env::set_var("LDAP_USER_DN_PATTERN", "cn={},ou=people,dc=corp,dc=com");

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let dn = svc.build_user_dn("alice");
        assert_eq!(dn, "cn=alice,ou=people,dc=corp,dc=com");

        match saved {
            Some(val) => std::env::set_var("LDAP_USER_DN_PATTERN", val),
            None => std::env::remove_var("LDAP_USER_DN_PATTERN"),
        }
    }

    // --- is_admin_from_groups() tests ---

    #[tokio::test]
    async fn test_is_admin_from_groups_matching() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec!["cn=admins,ou=groups,dc=example,dc=com".to_string()];
        assert!(svc.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_case_insensitive() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec!["CN=ADMINS,OU=GROUPS,DC=EXAMPLE,DC=COM".to_string()];
        assert!(svc.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_no_match() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let groups = vec!["cn=developers,ou=groups,dc=example,dc=com".to_string()];
        assert!(!svc.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_empty_groups() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        assert!(!svc.is_admin_from_groups(&[]));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_no_admin_group_configured() {
        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        let svc = make_test_service(config);
        let groups = vec!["cn=admins,ou=groups,dc=example,dc=com".to_string()];
        assert!(!svc.is_admin_from_groups(&groups));
    }

    // --- build_search_filter() tests ---

    #[tokio::test]
    async fn test_build_search_filter_default_username_placeholder() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("jdoe");
        assert_eq!(filter, "(uid=jdoe)");
    }

    #[tokio::test]
    async fn test_build_search_filter_zero_placeholder() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(sAMAccountName={0})".to_string();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("alice");
        assert_eq!(filter, "(sAMAccountName=alice)");
    }

    #[tokio::test]
    async fn test_build_search_filter_both_placeholders() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(|(uid={username})(cn={0}))".to_string();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("bob");
        assert_eq!(filter, "(|(uid=bob)(cn=bob))");
    }

    #[tokio::test]
    async fn test_build_search_filter_special_chars_in_username() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        // The method itself does not sanitize; it only replaces placeholders.
        // Sanitization happens before calling this method. Here we just verify
        // that placeholder replacement works with pre-sanitized input.
        let filter = svc.build_search_filter("john.doe@example.com");
        assert_eq!(filter, "(uid=john.doe@example.com)");
    }

    #[tokio::test]
    async fn test_build_search_filter_sanitizes_input() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("DOMAIN\\user");
        assert_eq!(filter, "(uid=DOMAIN\\5cuser)");
    }

    // --- user_search_attrs() tests ---

    #[tokio::test]
    async fn test_user_search_attrs_defaults() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let attrs = svc.user_search_attrs();
        assert_eq!(attrs, vec!["uid", "mail", "cn", "memberOf"]);
    }

    #[tokio::test]
    async fn test_user_search_attrs_custom() {
        let mut config = make_test_ldap_config();
        config.username_attr = "sAMAccountName".to_string();
        config.email_attr = "userPrincipalName".to_string();
        config.display_name_attr = "displayName".to_string();
        config.groups_attr = "memberOf".to_string();
        let svc = make_test_service(config);
        let attrs = svc.user_search_attrs();
        assert_eq!(
            attrs,
            vec![
                "sAMAccountName",
                "userPrincipalName",
                "displayName",
                "memberOf"
            ]
        );
    }

    // --- extract_user_from_entry() tests ---

    #[tokio::test]
    async fn test_extract_user_from_entry_full() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=testuser,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("uid".to_string(), vec!["testuser".to_string()]),
                ("mail".to_string(), vec!["test@example.com".to_string()]),
                ("cn".to_string(), vec!["Test User".to_string()]),
                (
                    "memberOf".to_string(),
                    vec![
                        "cn=developers,dc=example,dc=com".to_string(),
                        "cn=admins,dc=example,dc=com".to_string(),
                    ],
                ),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "testuser");
        assert_eq!(info.dn, "uid=testuser,dc=example,dc=com");
        assert_eq!(info.username, "testuser");
        assert_eq!(info.email, "test@example.com");
        assert_eq!(info.display_name, Some("Test User".to_string()));
        assert_eq!(info.groups.len(), 2);
        assert_eq!(info.groups[0], "cn=developers,dc=example,dc=com");
        assert_eq!(info.groups[1], "cn=admins,dc=example,dc=com");
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_missing_email() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=nomail,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("uid".to_string(), vec!["nomail".to_string()]),
                ("cn".to_string(), vec!["No Mail User".to_string()]),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "nomail");
        assert_eq!(info.email, "nomail@unknown");
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_missing_display_name() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=nodisplay,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("uid".to_string(), vec!["nodisplay".to_string()]),
                (
                    "mail".to_string(),
                    vec!["nodisplay@example.com".to_string()],
                ),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "nodisplay");
        assert!(info.display_name.is_none());
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_missing_groups() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=nogroups,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("uid".to_string(), vec!["nogroups".to_string()]),
                ("mail".to_string(), vec!["nogroups@example.com".to_string()]),
                ("cn".to_string(), vec!["No Groups".to_string()]),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "nogroups");
        assert!(info.groups.is_empty());
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_ad_ranged_member_of() {
        // Active Directory range retrieval: for users with many group
        // memberships AD returns the attribute under a ranged key
        // (`memberOf;range=0-1499`) instead of plain `memberOf`. The groups
        // must still be picked up (issue #2468).
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "CN=jdoe,OU=Users,DC=corp,DC=local".to_string(),
            attrs: HashMap::from([
                ("sAMAccountName".to_string(), vec!["jdoe".to_string()]),
                (
                    "memberOf;range=0-1499".to_string(),
                    vec![
                        "CN=devops_,OU=Global,DC=corp,DC=local".to_string(),
                        "CN=qa,OU=Global,DC=corp,DC=local".to_string(),
                    ],
                ),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "jdoe");
        assert_eq!(
            info.groups.len(),
            2,
            "AD ranged memberOf values must be extracted, got: {:?}",
            info.groups
        );
        assert!(info
            .groups
            .contains(&"CN=devops_,OU=Global,DC=corp,DC=local".to_string()));
    }

    // =======================================================================
    // Group synchronization (issue #2468): name resolution from AD-shaped
    // directory data — memberOf DNs, objectClass=group search entries, and
    // range-retrieval attribute keys.
    // =======================================================================

    #[test]
    fn test_dn_first_rdn_value_ad_group_dn() {
        assert_eq!(
            LdapService::dn_first_rdn_value("CN=devops_,OU=Global,DC=my_dn,DC=local"),
            Some("devops_".to_string())
        );
        assert_eq!(
            LdapService::dn_first_rdn_value("cn=developers,ou=groups,dc=example,dc=com"),
            Some("developers".to_string())
        );
        // Escaped comma inside the RDN value stays part of the name.
        assert_eq!(
            LdapService::dn_first_rdn_value("CN=Ops\\, Team,OU=Global,DC=corp,DC=local"),
            Some("Ops, Team".to_string())
        );
        assert_eq!(LdapService::dn_first_rdn_value("no-equals-sign"), None);
        assert_eq!(LdapService::dn_first_rdn_value("CN=,OU=Global"), None);
    }

    #[test]
    fn test_dn_under_base_scoping() {
        // Case-insensitive and whitespace-tolerant, as AD DNs mix casing.
        assert!(LdapService::dn_under_base(
            "CN=devops_,OU=Global,DC=my_dn,DC=local",
            "ou=global,dc=my_dn,dc=local"
        ));
        assert!(LdapService::dn_under_base(
            "CN=qa, OU=Global, DC=my_dn, DC=local",
            "OU=Global,DC=my_dn,DC=local"
        ));
        // A group outside the configured OU must be excluded.
        assert!(!LdapService::dn_under_base(
            "CN=other,OU=Elsewhere,DC=my_dn,DC=local",
            "OU=Global,DC=my_dn,DC=local"
        ));
        // Suffix match must respect RDN boundaries.
        assert!(!LdapService::dn_under_base(
            "CN=x,OU=NotGlobal,DC=my_dn,DC=local",
            "OU=Global,DC=my_dn,DC=local"
        ));
        assert!(LdapService::dn_under_base("CN=anything,DC=a", ""));
    }

    #[tokio::test]
    async fn test_resolve_group_names_from_ad_member_of_scoped_to_base() {
        // The exact configuration from issue #2468: AD returns memberOf DNs
        // on the user entry; only groups under LDAP_GROUP_BASE_DN sync, and
        // the group name is the DN's cn value — not the full DN.
        let mut config = make_test_ldap_config();
        config.group_base_dn = Some("OU=Global,DC=my_dn,DC=local".to_string());
        config.group_filter = Some("(memberOf={0})".to_string());
        let svc = make_test_service(config);
        assert!(svc.group_sync_configured());

        // No bind credentials in this config, so only the memberOf path runs.
        let names = svc
            .resolve_group_names(
                "CN=jdoe,OU=Users,DC=my_dn,DC=local",
                "jdoe",
                &[
                    "CN=devops_,OU=Global,DC=my_dn,DC=local".to_string(),
                    "CN=qa,OU=Global,DC=my_dn,DC=local".to_string(),
                    // Outside the group base DN: must not sync.
                    "CN=domain-users,CN=Builtin,DC=my_dn,DC=local".to_string(),
                ],
            )
            .await;
        assert_eq!(names, vec!["devops_".to_string(), "qa".to_string()]);
    }

    #[tokio::test]
    async fn test_resolve_group_names_without_base_uses_all_member_of() {
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(member={0})".to_string());
        let svc = make_test_service(config);

        let names = svc
            .resolve_group_names(
                "uid=jdoe,ou=users,dc=example,dc=com",
                "jdoe",
                &[
                    "cn=developers,ou=groups,dc=example,dc=com".to_string(),
                    "cn=admins,ou=groups,dc=example,dc=com".to_string(),
                ],
            )
            .await;
        assert_eq!(names, vec!["admins".to_string(), "developers".to_string()]);
    }

    #[tokio::test]
    async fn test_group_sync_configured_only_with_group_config() {
        let svc = make_test_service(make_test_ldap_config());
        assert!(
            !svc.group_sync_configured(),
            "no group_base_dn/group_filter -> sync stays off (pre-#2468 behaviour)"
        );

        let mut config = make_test_ldap_config();
        config.group_base_dn = Some("ou=groups,dc=example,dc=com".to_string());
        assert!(make_test_service(config).group_sync_configured());

        let mut config = make_test_ldap_config();
        config.group_filter = Some("(member={0})".to_string());
        assert!(make_test_service(config).group_sync_configured());
    }

    #[tokio::test]
    async fn test_build_group_filter_placeholder_substitution_and_escaping() {
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(member={0})".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("CN=jdoe,OU=Users,DC=corp,DC=local", "jdoe"),
            "(member=CN=jdoe,OU=Users,DC=corp,DC=local)"
        );

        // Filter metacharacters in the DN must be escaped (RFC 4515).
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(member={0})".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("CN=a\\, b(x)*,DC=corp", "j*doe"),
            "(member=CN=a\\5c, b\\28x\\29\\2a,DC=corp)"
        );

        // AD nested-group resolution: matching-rule-in-chain passes through.
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(member:1.2.840.113556.1.4.1941:={0})".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("CN=jdoe,DC=corp", "jdoe"),
            "(member:1.2.840.113556.1.4.1941:=CN=jdoe,DC=corp)"
        );

        // {1}/{username} placeholders (posixGroup style).
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(memberUid={1})".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("uid=jdoe,dc=x", "jdoe"),
            "(memberUid=jdoe)"
        );
    }

    #[tokio::test]
    async fn test_build_group_filter_static_filter_gets_membership_guard() {
        // A group-object filter with no user placeholder must NOT match every
        // group in the base for every user: it is AND-ed with the membership
        // disjunction instead.
        let mut config = make_test_ldap_config();
        config.group_filter = Some("(objectClass=group)".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("CN=jdoe,DC=corp", "jdoe"),
            "(&(objectClass=group)(|(member=CN=jdoe,DC=corp)(uniqueMember=CN=jdoe,DC=corp)(memberUid=jdoe)))"
        );
    }

    #[tokio::test]
    async fn test_build_group_filter_default_covers_ad_and_rfc4519() {
        let mut config = make_test_ldap_config();
        config.group_base_dn = Some("ou=groups,dc=example,dc=com".to_string());
        let svc = make_test_service(config);
        assert_eq!(
            svc.build_group_filter("uid=jdoe,dc=example,dc=com", "jdoe"),
            "(|(member=uid=jdoe,dc=example,dc=com)(uniqueMember=uid=jdoe,dc=example,dc=com)(memberUid=jdoe))"
        );
    }

    #[test]
    fn test_group_names_from_entries_ad_shaped() {
        use std::collections::HashMap;

        // AD-shaped group entries: objectClass=group, member DNs, cn.
        let entries = vec![
            ldap3::SearchEntry {
                dn: "CN=devops_,OU=Global,DC=my_dn,DC=local".to_string(),
                attrs: HashMap::from([
                    ("objectClass".to_string(), vec!["group".to_string()]),
                    ("cn".to_string(), vec!["devops_".to_string()]),
                    (
                        "member".to_string(),
                        vec!["CN=jdoe,OU=Users,DC=my_dn,DC=local".to_string()],
                    ),
                ]),
                bin_attrs: HashMap::new(),
            },
            // AD frequently returns attribute keys with server casing; the
            // lookup must be case-insensitive.
            ldap3::SearchEntry {
                dn: "CN=qa,OU=Global,DC=my_dn,DC=local".to_string(),
                attrs: HashMap::from([("CN".to_string(), vec!["qa".to_string()])]),
                bin_attrs: HashMap::new(),
            },
            // Entry without the name attribute falls back to the DN's RDN.
            ldap3::SearchEntry {
                dn: "CN=release-mgrs,OU=Global,DC=my_dn,DC=local".to_string(),
                attrs: HashMap::new(),
                bin_attrs: HashMap::new(),
            },
        ];
        assert_eq!(
            LdapService::group_names_from_entries(&entries, "cn"),
            vec![
                "devops_".to_string(),
                "qa".to_string(),
                "release-mgrs".to_string()
            ]
        );
    }

    #[test]
    fn test_ranged_attr_values_collects_ad_range_keys() {
        use std::collections::HashMap;
        let attrs: HashMap<String, Vec<String>> = HashMap::from([
            (
                "memberOf;range=0-1499".to_string(),
                vec!["CN=b,DC=x".to_string(), "CN=a,DC=x".to_string()],
            ),
            ("cn".to_string(), vec!["jdoe".to_string()]),
        ]);
        assert_eq!(
            LdapService::ranged_attr_values(&attrs, "memberOf"),
            vec!["CN=a,DC=x".to_string(), "CN=b,DC=x".to_string()]
        );
        // Case-insensitive plain key match too.
        let attrs: HashMap<String, Vec<String>> =
            HashMap::from([("memberof".to_string(), vec!["CN=g,DC=x".to_string()])]);
        assert_eq!(
            LdapService::ranged_attr_values(&attrs, "memberOf"),
            vec!["CN=g,DC=x".to_string()]
        );
        // Unrelated attributes never leak in.
        let attrs: HashMap<String, Vec<String>> = HashMap::from([(
            "memberOfSomethingElse".to_string(),
            vec!["CN=g,DC=x".to_string()],
        )]);
        assert!(LdapService::ranged_attr_values(&attrs, "memberOf").is_empty());
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_missing_username_attr() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=fallback,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("mail".to_string(), vec!["fallback@example.com".to_string()]),
                ("cn".to_string(), vec!["Fallback User".to_string()]),
            ]),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "input_username");
        assert_eq!(info.username, "input_username");
    }

    #[tokio::test]
    async fn test_extract_user_from_entry_empty_attrs() {
        use std::collections::HashMap;

        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let entry = ldap3::SearchEntry {
            dn: "uid=empty,dc=example,dc=com".to_string(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        let info = svc.extract_user_from_entry(entry, "fallback_user");
        assert_eq!(info.dn, "uid=empty,dc=example,dc=com");
        assert_eq!(info.username, "fallback_user");
        assert_eq!(info.email, "fallback_user@unknown");
        assert!(info.display_name.is_none());
        assert!(info.groups.is_empty());
    }

    // --- build_search_filter sanitization tests (PR #470 coverage) ---

    #[tokio::test]
    async fn test_build_search_filter_sanitizes_special_chars() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        // Asterisk, parens, and null byte should all be escaped by the
        // internal sanitize_ldap_input call inside build_search_filter.
        let filter = svc.build_search_filter("user*(\0)");
        assert_eq!(filter, "(uid=user\\2a\\28\\00\\29)");
    }

    #[tokio::test]
    async fn test_build_search_filter_with_zero_placeholder_sanitizes() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(sAMAccountName={0})".to_string();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("evil*user");
        assert_eq!(filter, "(sAMAccountName=evil\\2auser)");
    }

    #[tokio::test]
    async fn test_build_search_filter_both_placeholders_sanitized() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(|(uid={username})(cn={0}))".to_string();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("bad(user)");
        assert_eq!(filter, "(|(uid=bad\\28user\\29)(cn=bad\\28user\\29))");
    }

    #[tokio::test]
    async fn test_build_search_filter_normal_chars_unchanged() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        // Dots, @, hyphens, and underscores are not LDAP special chars
        // and should pass through without escaping.
        let filter = svc.build_search_filter("john.doe@example.com");
        assert_eq!(filter, "(uid=john.doe@example.com)");
    }

    #[tokio::test]
    async fn test_auth_timeout_constant() {
        assert_eq!(
            LdapService::AUTH_TIMEOUT,
            std::time::Duration::from_secs(15)
        );
    }

    #[tokio::test]
    async fn test_build_search_filter_backslash_in_domain_prefix() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        // A Windows-style domain login like CORP\jdoe should have the
        // backslash escaped to \5c in the resulting LDAP filter.
        let filter = svc.build_search_filter("CORP\\jdoe");
        assert_eq!(filter, "(uid=CORP\\5cjdoe)");
    }

    #[tokio::test]
    async fn test_build_search_filter_null_byte() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        let filter = svc.build_search_filter("admin\0extra");
        assert_eq!(filter, "(uid=admin\\00extra)");
    }

    #[tokio::test]
    async fn test_build_search_filter_parentheses_injection() {
        let config = make_test_ldap_config();
        let svc = make_test_service(config);
        // An LDAP injection attempt: )(uid=*)( should be fully escaped.
        let filter = svc.build_search_filter(")(uid=*)(");
        assert_eq!(filter, "(uid=\\29\\28uid=\\2a\\29\\28)");
    }

    // --- error classification helper tests ---

    #[tokio::test]
    async fn test_connection_error_returns_internal() {
        let err = LdapService::connection_error("test connection failure");
        match err {
            AppError::Internal(msg) => assert!(msg.contains("LDAP connection failed")),
            other => panic!("expected Internal, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bind_error_returns_authentication() {
        let err = LdapService::bind_error("test bind failure");
        match err {
            AppError::Authentication(msg) => assert_eq!(msg, "Invalid credentials"),
            other => panic!("expected Authentication, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_search_error_returns_internal() {
        let err = LdapService::search_error("test search failure");
        match err {
            AppError::Internal(msg) => assert!(msg.contains("LDAP search failed")),
            other => panic!("expected Internal, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bind_error_does_not_leak_details() {
        let err = LdapService::bind_error("secret LDAP server ldap://10.0.0.1 DN cn=admin");
        match err {
            AppError::Authentication(msg) => {
                assert_eq!(msg, "Invalid credentials");
                assert!(!msg.contains("ldap://"));
                assert!(!msg.contains("cn=admin"));
            }
            other => panic!("expected Authentication, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_connection_error_includes_detail_for_logging() {
        let err = LdapService::connection_error("io error: Connection refused");
        match err {
            AppError::Internal(msg) => assert!(msg.contains("Connection refused")),
            other => panic!("expected Internal, got {:?}", other),
        }
    }

    // --- check_health() and with_config() coverage tests ---

    #[tokio::test]
    async fn test_check_health_empty_url_returns_config_error() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        let svc = make_test_service(config);
        let result = svc.check_health().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Config(msg) => assert!(msg.contains("not configured")),
            other => panic!("expected Config error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_health_no_bind_credentials_with_url_succeeds() {
        // When URL is set but no bind credentials, check_health just verifies URL is non-empty
        let config = make_test_ldap_config(); // has URL but no bind_dn/bind_password
        let svc = make_test_service(config);
        let result = svc.check_health().await;
        assert!(
            result.is_ok(),
            "health check should pass with URL but no bind credentials"
        );
    }

    #[tokio::test]
    async fn test_with_config_insecure_tls_creates_valid_service() {
        let mut config = make_test_ldap_config();
        config.no_tls_verify = true;
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        let svc = LdapService::with_config(db, config);
        // Service created successfully despite insecure TLS (warning logged but no error)
        assert!(svc.is_configured());
        assert!(svc.config.no_tls_verify);
    }

    #[tokio::test]
    async fn test_with_config_normal_tls_no_warning() {
        let config = make_test_ldap_config(); // no_tls_verify = false
        let db = PgPool::connect_lazy("postgres://localhost/fake").expect("lazy pool");
        let svc = LdapService::with_config(db, config);
        assert!(svc.is_configured());
        assert!(!svc.config.no_tls_verify);
    }

    #[tokio::test]
    async fn test_check_health_empty_url_with_bind_credentials() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        config.bind_dn = Some("cn=admin,dc=test".to_string());
        config.bind_password = Some("secret".to_string());
        let svc = make_test_service(config);
        let result = svc.check_health().await;
        // Should fail on empty URL check before attempting bind
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // verify_bind (#2486): the admin test-connection flow must perform a real
    // LDAP bind and report its true outcome, not just TCP reachability.
    // -----------------------------------------------------------------------

    /// LDAP resultCode for a bindResponse.
    const LDAP_RC_SUCCESS: u8 = 0x00;
    /// invalidCredentials (49).
    const LDAP_RC_INVALID_CREDENTIALS: u8 = 0x31;

    /// Spawn a minimal mock LDAP server on 127.0.0.1 that answers the first
    /// request with a BER-encoded bindResponse (messageID 1) carrying the
    /// given resultCode, then drains the connection. This is a server that is
    /// perfectly REACHABLE over TCP — exactly the case where the old
    /// TCP-probe-only test reported "Connection Successful" regardless of
    /// whether the bind credentials were valid.
    async fn spawn_mock_ldap_server(result_code: u8) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ldap listener");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 512];
                // Read the client's bindRequest (single small frame).
                let _ = sock.read(&mut buf).await;
                // SEQUENCE { messageID 1, [APPLICATION 1] bindResponse {
                //   resultCode <rc>, matchedDN "", diagnosticMessage "" } }
                let resp = [
                    0x30,
                    0x0c,
                    0x02,
                    0x01,
                    0x01,
                    0x61,
                    0x07,
                    0x0a,
                    0x01,
                    result_code,
                    0x04,
                    0x00,
                    0x04,
                    0x00,
                ];
                let _ = sock.write_all(&resp).await;
                let _ = sock.flush().await;
                // Consume a possible unbindRequest before closing.
                let _ = sock.read(&mut buf).await;
            }
        });
        port
    }

    fn make_verify_bind_service(
        port: u16,
        bind_dn: Option<&str>,
        bind_pw: Option<&str>,
    ) -> LdapService {
        let mut config = make_test_ldap_config();
        config.url = format!("ldap://127.0.0.1:{port}");
        config.bind_dn = bind_dn.map(String::from);
        config.bind_password = bind_pw.map(String::from);
        make_test_service(config)
    }

    #[tokio::test]
    async fn test_verify_bind_rejected_credentials_reports_failure() {
        // The server accepts the TCP connection but rejects the bind: the
        // old reachability-only test reported success here (#2486); the
        // real bind must surface an authentication failure.
        let port = spawn_mock_ldap_server(LDAP_RC_INVALID_CREDENTIALS).await;
        let svc = make_verify_bind_service(
            port,
            Some("cn=wrong,dc=example,dc=com"),
            Some("bad-password"),
        );

        match svc.verify_bind().await {
            Err(AppError::Authentication(msg)) => {
                // The error must never leak the credentials being tested.
                assert!(!msg.contains("bad-password"));
                assert!(!msg.contains("cn=wrong"));
            }
            other => panic!("expected Authentication error for rejected bind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_verify_bind_accepted_credentials_reports_success() {
        let port = spawn_mock_ldap_server(LDAP_RC_SUCCESS).await;
        let svc = make_verify_bind_service(
            port,
            Some("cn=admin,dc=example,dc=com"),
            Some("correct-password"),
        );

        svc.verify_bind()
            .await
            .expect("bind accepted by server should verify");
    }

    #[tokio::test]
    async fn test_verify_bind_unreachable_server_is_connection_error() {
        // Reserve an ephemeral port, then drop the listener so the connect
        // is refused: this must classify as a connection-level error, not a
        // credential rejection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let svc =
            make_verify_bind_service(port, Some("cn=admin,dc=example,dc=com"), Some("password"));

        match svc.verify_bind().await {
            Err(AppError::Internal(_)) => {}
            other => panic!("expected Internal error for unreachable server, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_verify_bind_without_credentials_is_config_error() {
        let svc = make_verify_bind_service(1, None, None);
        match svc.verify_bind().await {
            Err(AppError::Config(_)) => {}
            other => panic!("expected Config error without credentials, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Group search against a mock LDAP server returning AD-shaped group
    // entries (issue #2468): objectClass=group entries named by cn.
    // -----------------------------------------------------------------------

    /// Encode a single-byte-length BER TLV (content must stay under 128
    /// bytes, which the short test DNs guarantee).
    fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128, "test BER helper: content too long");
        let mut out = vec![tag, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    /// Extract the messageID from a client LDAP frame (single-byte forms).
    fn ldap_message_id(frame: &[u8]) -> u8 {
        // SEQUENCE { 0x30 len 0x02 idlen id ... }
        if frame.len() >= 5 && frame[0] == 0x30 && frame[2] == 0x02 {
            frame[4]
        } else {
            1
        }
    }

    /// Spawn a mock LDAP server that accepts a bind, then answers the next
    /// searchRequest with the given AD-shaped group entries (dn + optional
    /// `cn` value) followed by searchResultDone.
    async fn spawn_mock_ldap_group_server(groups: Vec<(String, Option<String>)>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ldap listener");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];

                // bindRequest -> bindResponse success.
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let bind_id = ldap_message_id(&buf[..n]);
                let bind_resp = ber(
                    0x30,
                    &[
                        ber(0x02, &[bind_id]),
                        ber(
                            0x61,
                            &[[0x0a, 0x01, 0x00].to_vec(), ber(0x04, b""), ber(0x04, b"")].concat(),
                        ),
                    ]
                    .concat(),
                );
                let _ = sock.write_all(&bind_resp).await;

                // searchRequest -> one searchResultEntry per group + done.
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let search_id = ldap_message_id(&buf[..n]);
                for (dn, cn) in &groups {
                    // partialAttributeList: cn attribute when present.
                    let attrs = match cn {
                        Some(value) => ber(
                            0x30,
                            &ber(
                                0x30,
                                &[ber(0x04, b"cn"), ber(0x31, &ber(0x04, value.as_bytes()))]
                                    .concat(),
                            ),
                        ),
                        None => ber(0x30, b""),
                    };
                    let entry = ber(
                        0x30,
                        &[
                            ber(0x02, &[search_id]),
                            ber(0x64, &[ber(0x04, dn.as_bytes()), attrs].concat()),
                        ]
                        .concat(),
                    );
                    let _ = sock.write_all(&entry).await;
                }
                let done = ber(
                    0x30,
                    &[
                        ber(0x02, &[search_id]),
                        ber(
                            0x65,
                            &[[0x0a, 0x01, 0x00].to_vec(), ber(0x04, b""), ber(0x04, b"")].concat(),
                        ),
                    ]
                    .concat(),
                );
                let _ = sock.write_all(&done).await;
                let _ = sock.flush().await;

                // Consume a possible unbindRequest before closing.
                let _ = sock.read(&mut buf).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn test_resolve_group_names_via_ad_group_search() {
        // End-to-end over the wire: an AD-shaped directory where the user
        // entry carried no usable memberOf, so groups come from the group
        // search under group_base_dn (objectClass=group entries, named by
        // cn; the third entry has no cn and falls back to its DN RDN).
        let port = spawn_mock_ldap_group_server(vec![
            (
                "CN=devops_,OU=Global,DC=my_dn,DC=local".to_string(),
                Some("devops_".to_string()),
            ),
            (
                "CN=qa,OU=Global,DC=my_dn,DC=local".to_string(),
                Some("qa".to_string()),
            ),
            (
                "CN=release-mgrs,OU=Global,DC=my_dn,DC=local".to_string(),
                None,
            ),
        ])
        .await;

        let mut config = make_test_ldap_config();
        config.url = format!("ldap://127.0.0.1:{port}");
        config.bind_dn = Some("CN=svc,OU=Users,DC=my_dn,DC=local".to_string());
        config.bind_password = Some("secret".to_string());
        config.group_base_dn = Some("OU=Global,DC=my_dn,DC=local".to_string());
        config.group_filter = Some("(member={0})".to_string());
        let svc = make_test_service(config);

        let names = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            svc.resolve_group_names("CN=jdoe,OU=Users,DC=my_dn,DC=local", "jdoe", &[]),
        )
        .await
        .expect("group search must not hang");
        assert_eq!(
            names,
            vec![
                "devops_".to_string(),
                "qa".to_string(),
                "release-mgrs".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_resolve_group_names_search_failure_falls_back_to_member_of() {
        // Group search that cannot even connect must not fail login-time
        // resolution: the memberOf-derived names still come back.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let mut config = make_test_ldap_config();
        config.url = format!("ldap://127.0.0.1:{port}");
        config.bind_dn = Some("CN=svc,DC=my_dn,DC=local".to_string());
        config.bind_password = Some("secret".to_string());
        config.group_base_dn = Some("OU=Global,DC=my_dn,DC=local".to_string());
        let svc = make_test_service(config);

        let names = svc
            .resolve_group_names(
                "CN=jdoe,OU=Users,DC=my_dn,DC=local",
                "jdoe",
                &["CN=devops_,OU=Global,DC=my_dn,DC=local".to_string()],
            )
            .await;
        assert_eq!(names, vec!["devops_".to_string()]);
    }
}
